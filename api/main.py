"""FastAPI status, webhook, and full-cycle orchestration server for BountySweep Agent."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import Body, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from api.dashboard import DASHBOARD_HTML
from config.settings import Settings, get_settings
from discovery.scanner import BountyOpportunity, BountyScanner, normalize_github_issue
from evaluator.triage import BountyTriageEngine
from notifications.telegram_bot import TelegramBotService
from payouts.wallet_router import UnauthorizedDestinationError, WalletRouter
from sandbox.runner import DockerSandboxRunner

logger = logging.getLogger(__name__)

DEFAULT_DRY_RUN_BASE_COLD_WALLET = "0x1111111111111111111111111111111111111111"
DEFAULT_DRY_RUN_SOLANA_COLD_WALLET = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T"


class CycleRunRequest(BaseModel):
    """Request payload for triggering an orchestration cycle via POST /cycle/run."""

    use_mock_bounty: bool = Field(
        default=True,
        description="When True, uses a deterministic escrowed mock bounty for simulation.",
    )
    mock_bounty_override: dict[str, Any] | None = Field(
        default=None,
        description="Optional field overrides applied to the mock bounty opportunity.",
    )
    destination_wallet_override: str | None = Field(
        default=None,
        description="Optional payout destination override (used to verify whitelist enforcement).",
    )


class TelegramWebhookUpdate(BaseModel):
    """Telegram webhook update payload."""

    update_id: int | None = None
    message: dict[str, Any] | None = None


class BountySweepOrchestrator:
    """Coordinates discovery, AI triage, isolated Docker sandbox verification, PR submission, and USDC sweeps."""

    def __init__(
        self,
        settings: Settings | None = None,
        telegram_bot: TelegramBotService | None = None,
        scanner: BountyScanner | None = None,
        triage_engine: BountyTriageEngine | None = None,
        sandbox_runner: DockerSandboxRunner | None = None,
        wallet_router: WalletRouter | None = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self.telegram_bot: TelegramBotService = telegram_bot or TelegramBotService(
            settings=self.settings
        )
        self.scanner: BountyScanner = scanner or BountyScanner(settings=self.settings)
        self.triage_engine: BountyTriageEngine = triage_engine or BountyTriageEngine(
            settings=self.settings
        )
        self.sandbox_runner: DockerSandboxRunner = sandbox_runner or DockerSandboxRunner(
            settings=self.settings
        )
        self._wallet_router: WalletRouter | None = wallet_router
        self.cycle_history: list[dict[str, Any]] = []
        self.autopoll_enabled: bool = False
        self._autopoll_task: asyncio.Task[None] | None = None

    def _get_wallet_router(self) -> WalletRouter:
        """Lazily initialize or return the configured WalletRouter instance."""
        if self._wallet_router is not None:
            return self._wallet_router

        effective_settings = self.settings
        if not effective_settings.OWNER_COLD_WALLET_ADDRESS.strip() and effective_settings.DRY_RUN_MODE:
            fallback_wallet = (
                DEFAULT_DRY_RUN_BASE_COLD_WALLET
                if effective_settings.CHAIN_NETWORK == "base"
                else DEFAULT_DRY_RUN_SOLANA_COLD_WALLET
            )
            effective_settings = effective_settings.model_copy(
                update={"OWNER_COLD_WALLET_ADDRESS": fallback_wallet}
            )

        self._wallet_router = WalletRouter(settings=effective_settings)
        return self._wallet_router

    async def _autopoll_loop(self) -> None:
        """Background loop that continuously runs live discovery cycles every POLL_INTERVAL_SECONDS."""
        while self.autopoll_enabled:
            if not self.telegram_bot.is_paused:
                try:
                    await self.run_cycle(CycleRunRequest(use_mock_bounty=False))
                except Exception as exc:
                    logger.warning("Auto-poll cycle error: %s", exc)
            await asyncio.sleep(self.settings.POLL_INTERVAL_SECONDS)

    def start_autopoller(self) -> None:
        """Enable continuous background bounty polling."""
        if not self.autopoll_enabled:
            self.autopoll_enabled = True
            self._autopoll_task = asyncio.create_task(self._autopoll_loop())

    def stop_autopoller(self) -> None:
        """Stop continuous background bounty polling."""
        self.autopoll_enabled = False
        if self._autopoll_task is not None and not self._autopoll_task.done():
            self._autopoll_task.cancel()
        self._autopoll_task = None

    def get_status(self) -> dict[str, Any]:
        """Return full operational status, configuration, metrics, and recent alerts."""
        snap = self.telegram_bot.get_status_snapshot()
        cold_wallet = self.settings.OWNER_COLD_WALLET_ADDRESS
        worker_wallet = ""
        try:
            router = self._get_wallet_router()
            if not cold_wallet:
                cold_wallet = router.owner_cold_wallet_address
            worker_wallet = router.worker_wallet_address
        except Exception:
            pass

        return {
            "status": "paused" if self.telegram_bot.is_paused else "running",
            "paused": self.telegram_bot.is_paused,
            "dry_run_mode": self.settings.DRY_RUN_MODE,
            "chain_network": self.settings.CHAIN_NETWORK,
            "owner_cold_wallet_address": cold_wallet,
            "worker_wallet_address": worker_wallet,
            "sweep_threshold_usdc": self.settings.SWEEP_THRESHOLD_USDC,
            "autopoll_enabled": self.autopoll_enabled,
            "poll_interval_seconds": self.settings.POLL_INTERVAL_SECONDS,
            "seen_bounties_cached_24h": len(self.scanner.seen_cache.snapshot()),
            "raw_candidates_fetched": self.scanner.last_raw_candidates_fetched,
            "metrics": snap["metrics"],
            "recent_alerts": list(self.telegram_bot.sent_messages[-20:]),
            "cycles_executed": len(self.cycle_history),
            "last_cycle": self.cycle_history[-1] if self.cycle_history else None,
        }

    def _resolve_mock_bounty(
        self, override: dict[str, Any] | None = None
    ) -> BountyOpportunity:
        """Build the mock escrowed bounty with optional test/QA overrides."""
        base_bounty = self.scanner.generate_mock_escrowed_bounty()
        if not override:
            return base_bounty

        merged = {**base_bounty.model_dump(), **override}
        if "escrow_verified" not in override and any(
            k in override for k in ("title", "body", "labels", "reward_usdc")
        ):
            normalized = normalize_github_issue(merged)
            return normalized
        return BountyOpportunity.model_validate(merged)

    async def run_cycle(
        self, request: CycleRunRequest | None = None
    ) -> dict[str, Any]:
        """Execute a complete discovery -> triage -> sandbox -> PR -> wallet sweep cycle."""
        req = request or CycleRunRequest()

        if self.telegram_bot.is_paused:
            return {
                "status": "paused",
                "paused": True,
                "raw_candidates_fetched": 0,
                "detail": "BountySweep Agent is currently paused via kill-switch.",
            }

        # Step 1 & 2: Discovery, Escrow Marker Pre-Filter & AI Triage (up to 15 unseen candidates per cycle)
        if req.use_mock_bounty:
            raw_candidates_fetched = 1
            bounty = self._resolve_mock_bounty(req.mock_bounty_override)
            triage_result = await self.triage_engine.evaluate_bounty(bounty)
            if triage_result.security_rejected:
                await self.telegram_bot.alert_security_rejection(
                    bounty_id=bounty.bounty_id,
                    reasons=triage_result.security_reasons,
                    stage="triage",
                )
                result = {
                    "status": "security_rejected",
                    "stage": "triage",
                    "raw_candidates_fetched": raw_candidates_fetched,
                    "security_rejected": True,
                    "security_reasons": triage_result.security_reasons,
                    "bounty": bounty.model_dump(),
                    "triage": triage_result.model_dump(),
                }
                self.cycle_history.append(result)
                return result

            if not triage_result.approved:
                if not triage_result.escrow_verified:
                    await self.telegram_bot.alert_security_rejection(
                        bounty_id=bounty.bounty_id,
                        reasons=[triage_result.rationale],
                        stage="escrow_verification",
                    )
                result = {
                    "status": "rejected",
                    "stage": "triage",
                    "raw_candidates_fetched": raw_candidates_fetched,
                    "security_rejected": False,
                    "bounty": bounty.model_dump(),
                    "triage": triage_result.model_dump(),
                }
                self.cycle_history.append(result)
                return result
        else:
            approved_bounty, approved_triage, batch_log = (
                await self.scanner.poll_verified_batch_until_approved(
                    triage_evaluator=self.triage_engine,
                )
            )
            raw_candidates_fetched = self.scanner.last_raw_candidates_fetched
            if not batch_log:
                result = {
                    "status": "no_bounties_found",
                    "paused": False,
                    "raw_candidates_fetched": raw_candidates_fetched,
                    "detail": "No new open USDC bounties discovered during scan (seen bounties skipped for 24h).",
                }
                self.cycle_history.append(result)
                return result

            for entry in batch_log:
                if entry["status"] == "security_rejected":
                    await self.telegram_bot.alert_security_rejection(
                        bounty_id=entry["bounty_id"],
                        reasons=[entry["reason"]],
                        stage="triage",
                    )

            if approved_bounty is None or approved_triage is None:
                last_entry = batch_log[-1]
                last_bounty: BountyOpportunity = last_entry["bounty"]
                last_triage = last_entry["triage"]
                result = {
                    "status": "security_rejected" if last_entry["security_rejected"] else "rejected",
                    "stage": "triage_batch",
                    "raw_candidates_fetched": raw_candidates_fetched,
                    "security_rejected": bool(last_entry["security_rejected"]),
                    "candidates_evaluated": len(batch_log),
                    "rejected_bounty_ids": [e["bounty_id"] for e in batch_log],
                    "bounty": last_bounty.model_dump(),
                    "triage": last_triage.model_dump() if last_triage is not None else None,
                    "detail": last_entry["reason"],
                }
                self.cycle_history.append(result)
                return result

            bounty = approved_bounty
            triage_result = approved_triage

        # Step 3: Claim Bounty with Worker Hot Wallet & Send [Bounty Claimed] Alert
        wallet_router = self._get_wallet_router()
        claim_receipt = wallet_router.sign_task_claim(
            bounty_id=bounty.bounty_id,
            submission_url=bounty.issue_url,
        )
        await self.telegram_bot.alert_bounty_claimed(
            bounty_id=bounty.bounty_id,
            title=bounty.title,
            reward_usdc=bounty.reward_usdc,
            issue_url=bounty.issue_url,
        )

        # Step 4: Generate Patch & Execute Tests in Ephemeral Isolated Sandbox
        generated_patch = await self.triage_engine.generate_patch(bounty)
        effective_repo_url = (
            f"mock://github.com/{bounty.repo_owner}/{bounty.repo_name}"
            if (req.use_mock_bounty or self.settings.DRY_RUN_MODE)
            else bounty.repo_url
        )
        sandbox_report = self.sandbox_runner.verify_bounty_patch(
            bounty_id=bounty.bounty_id,
            repo_url=effective_repo_url,
            file_patches={generated_patch.target_file: generated_patch.patched_code},
            regression_tests={
                generated_patch.test_file: generated_patch.regression_test_code
            },
        )

        if not sandbox_report.submission_approved:
            if not req.use_mock_bounty:
                self.scanner.mark_seen(bounty.bounty_id, status="sandbox_failed")
            result = {
                "status": "sandbox_failed",
                "stage": "sandbox",
                "raw_candidates_fetched": raw_candidates_fetched,
                "bounty": bounty.model_dump(),
                "triage": triage_result.model_dump(),
                "claim_receipt": claim_receipt.model_dump(),
                "sandbox": sandbox_report.model_dump(),
            }
            self.cycle_history.append(result)
            return result

        # Step 5: Submit Solution PR (or log draft in DRY_RUN_MODE) & Alert
        pr_url = f"{bounty.repo_url.rstrip('/')}/pull/{bounty.issue_number + 100}"
        await self.telegram_bot.alert_solution_submitted(
            bounty_id=bounty.bounty_id,
            pr_url=pr_url,
            tests_passed=sandbox_report.patched_run.passed_count,
            regression_tests_added=sandbox_report.regression_tests_added,
            dry_run=self.settings.DRY_RUN_MODE,
        )

        # Step 6: Settle & Sweep USDC Payout exclusively to OWNER_COLD_WALLET_ADDRESS
        try:
            sweep_receipt = await wallet_router.sweep_usdc(
                current_balance_usdc=bounty.reward_usdc,
                destination_address=req.destination_wallet_override,
            )
        except UnauthorizedDestinationError as exc:
            if not req.use_mock_bounty:
                self.scanner.mark_seen(bounty.bounty_id, status="security_rejected")
            await self.telegram_bot.alert_security_rejection(
                bounty_id=bounty.bounty_id,
                reasons=[str(exc)],
                stage="payout_sweep",
            )
            result = {
                "status": "security_rejected",
                "stage": "payout_sweep",
                "raw_candidates_fetched": raw_candidates_fetched,
                "security_rejected": True,
                "security_reasons": [str(exc)],
                "bounty": bounty.model_dump(),
                "triage": triage_result.model_dump(),
                "claim_receipt": claim_receipt.model_dump(),
                "sandbox": sandbox_report.model_dump(),
                "pr_url": pr_url,
            }
            self.cycle_history.append(result)
            return result

        sweep_dump: dict[str, Any] | None = None
        if sweep_receipt is not None:
            sweep_dump = sweep_receipt.model_dump()
            await self.telegram_bot.alert_payout_settled(
                bounty_id=bounty.bounty_id,
                amount_usdc=sweep_receipt.amount_usdc,
                tx_hash=sweep_receipt.tx_hash,
                destination_address=sweep_receipt.destination_address,
                chain=sweep_receipt.chain,
                dry_run=sweep_receipt.dry_run,
            )

        if not req.use_mock_bounty:
            self.scanner.mark_seen(bounty.bounty_id, status="completed")

        result = {
            "status": "completed",
            "paused": False,
            "dry_run": self.settings.DRY_RUN_MODE,
            "raw_candidates_fetched": raw_candidates_fetched,
            "bounty": bounty.model_dump(),
            "triage": triage_result.model_dump(),
            "claim_receipt": claim_receipt.model_dump(),
            "patch": generated_patch.model_dump(),
            "sandbox": sandbox_report.model_dump(),
            "pr_url": pr_url,
            "sweep_receipt": sweep_dump,
        }
        self.cycle_history.append(result)
        return result


def create_app(
    orchestrator: BountySweepOrchestrator | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application with attached orchestrator state."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI):
        orch_instance: BountySweepOrchestrator = app_instance.state.orchestrator
        poll_task: asyncio.Task[None] | None = None
        if orch_instance.settings.telegram_bot_token_str.strip():
            async def _tg_loop() -> None:
                offset: int | None = None
                while True:
                    offset = await orch_instance.telegram_bot.poll_updates_once(offset=offset)
                    await asyncio.sleep(2.0)

            poll_task = asyncio.create_task(_tg_loop())
        try:
            yield
        finally:
            if poll_task is not None and not poll_task.done():
                poll_task.cancel()

    fastapi_app = FastAPI(title="BountySweep Agent", version="1.0.0", lifespan=lifespan)
    fastapi_app.state.orchestrator = orchestrator or BountySweepOrchestrator()

    def _get_orch(request: Request) -> BountySweepOrchestrator:
        return request.app.state.orchestrator

    @fastapi_app.get("/", response_class=HTMLResponse)
    @fastapi_app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(content=DASHBOARD_HTML)

    @fastapi_app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "BountySweep Agent"}

    @fastapi_app.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        orch = _get_orch(request)
        return orch.get_status()

    @fastapi_app.post("/control/pause")
    async def control_pause(request: Request) -> dict[str, Any]:
        orch = _get_orch(request)
        authorized_chat = orch.settings.TELEGRAM_CHAT_ID or None
        reply = await orch.telegram_bot.handle_command("/pause", chat_id=authorized_chat)
        return {
            "status": "paused",
            "paused": orch.telegram_bot.is_paused,
            "message": reply,
        }

    @fastapi_app.post("/control/resume")
    async def control_resume(request: Request) -> dict[str, Any]:
        orch = _get_orch(request)
        authorized_chat = orch.settings.TELEGRAM_CHAT_ID or None
        reply = await orch.telegram_bot.handle_command("/resume", chat_id=authorized_chat)
        return {
            "status": "running",
            "paused": orch.telegram_bot.is_paused,
            "message": reply,
        }

    @fastapi_app.post("/control/autopoll/start")
    async def control_autopoll_start(request: Request) -> dict[str, Any]:
        orch = _get_orch(request)
        orch.start_autopoller()
        return {"autopoll_enabled": orch.autopoll_enabled}

    @fastapi_app.post("/control/autopoll/stop")
    async def control_autopoll_stop(request: Request) -> dict[str, Any]:
        orch = _get_orch(request)
        orch.stop_autopoller()
        return {"autopoll_enabled": orch.autopoll_enabled}

    @fastapi_app.post("/telegram/webhook")
    async def telegram_webhook(
        request: Request,
        update: TelegramWebhookUpdate,
    ) -> dict[str, Any]:
        orch = _get_orch(request)
        msg = update.message or {}
        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id")) if chat.get("id") is not None else None
        text = str(msg.get("text") or "").strip()

        reply = await orch.telegram_bot.handle_command(text, chat_id=chat_id)
        rejected = reply.startswith(TelegramBotService.ALERT_TAG_SECURITY_REJECTION)
        return {
            "ok": not rejected,
            "paused": orch.telegram_bot.is_paused,
            "reply": reply,
        }

    @fastapi_app.post("/cycle/run")
    async def cycle_run(
        request: Request,
        payload: CycleRunRequest = Body(default_factory=CycleRunRequest),
    ) -> Any:
        orch = _get_orch(request)
        if orch.telegram_bot.is_paused:
            return JSONResponse(
                status_code=409,
                content={
                    "status": "paused",
                    "paused": True,
                    "detail": "BountySweep Agent is currently paused via kill-switch.",
                },
            )
        return await orch.run_cycle(payload)

    return fastapi_app


app = create_app()
