"""Real-time Telegram alerting and kill-switch command controller for BountySweep Agent."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)


class TelegramBotService:
    """Async state and alert controller for Telegram notifications and operational kill-switch."""

    ALERT_TAG_BOUNTY_CLAIMED = "[Bounty Claimed]"
    ALERT_TAG_SOLUTION_SUBMITTED = "[PR/Solution Submitted]"
    ALERT_TAG_PAYOUT_SETTLED = "[USDC Payout Settled + TX Hash]"
    ALERT_TAG_SECURITY_REJECTION = "[Security Rejection]"

    def __init__(
        self,
        settings: Settings | None = None,
        http_client: httpx.AsyncClient | None = None,
        status_callback: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        self._http_client: httpx.AsyncClient | None = http_client
        self._status_callback: Callable[[], dict[str, Any]] | None = status_callback
        self.is_paused: bool = False
        self.sent_messages: list[dict[str, Any]] = []
        self.metrics: dict[str, Any] = {
            "bounties_claimed": 0,
            "solutions_submitted": 0,
            "bounties_rejected": 0,
            "payouts_settled_count": 0,
            "total_usdc_swept": 0.0,
        }

    async def _send_telegram_message(
        self,
        tag: str,
        text: str,
        metadata: dict[str, Any] | None = None,
        chat_id: str | None = None,
    ) -> dict[str, Any]:
        """Dispatch a Telegram notification or record it in dry-run / unconfigured mode."""
        target_chat_id = chat_id if chat_id is not None else self.settings.TELEGRAM_CHAT_ID
        token = self.settings.telegram_bot_token_str
        dry_run = bool(self.settings.DRY_RUN_MODE or not token)

        record: dict[str, Any] = {
            "tag": tag,
            "text": text,
            "chat_id": target_chat_id,
            "dry_run": dry_run,
            "delivered": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }

        if not dry_run and token:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                "chat_id": target_chat_id,
                "text": text,
                "disable_web_page_preview": True,
            }
            try:
                if self._http_client is not None:
                    response = await self._http_client.post(url, json=payload, timeout=10.0)
                else:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        response = await client.post(url, json=payload)
                response.raise_for_status()
                record["delivered"] = True
                record["telegram_response"] = response.json()
            except Exception as exc:
                logger.warning("Failed to send live Telegram notification (%s): %s", tag, exc)
                record["error"] = str(exc)
        else:
            record["delivered"] = True

        self.sent_messages.append(record)
        return record

    async def alert_bounty_claimed(
        self,
        bounty_id: str,
        title: str,
        reward_usdc: float,
        issue_url: str,
    ) -> dict[str, Any]:
        """Emit a [Bounty Claimed] notification and increment claimed counter."""
        self.metrics["bounties_claimed"] += 1
        tag = self.ALERT_TAG_BOUNTY_CLAIMED
        text = (
            f"{tag}\n"
            f"Bounty ID: {bounty_id}\n"
            f"Title: {title}\n"
            f"Reward: {reward_usdc:.2f} USDC\n"
            f"Issue: {issue_url}"
        )
        return await self._send_telegram_message(
            tag=tag,
            text=text,
            metadata={
                "bounty_id": bounty_id,
                "title": title,
                "reward_usdc": float(reward_usdc),
                "issue_url": issue_url,
            },
        )

    async def alert_solution_submitted(
        self,
        bounty_id: str,
        pr_url: str,
        tests_passed: int,
        regression_tests_added: int,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Emit a [PR/Solution Submitted] notification after sandbox test verification."""
        self.metrics["solutions_submitted"] += 1
        tag = self.ALERT_TAG_SOLUTION_SUBMITTED
        mode_label = "DRY-RUN" if dry_run else "LIVE"
        text = (
            f"{tag} ({mode_label})\n"
            f"Bounty ID: {bounty_id}\n"
            f"PR URL: {pr_url}\n"
            f"Tests Passed: {tests_passed}\n"
            f"Regression Tests Added: {regression_tests_added}"
        )
        return await self._send_telegram_message(
            tag=tag,
            text=text,
            metadata={
                "bounty_id": bounty_id,
                "pr_url": pr_url,
                "tests_passed": int(tests_passed),
                "regression_tests_added": int(regression_tests_added),
                "dry_run": bool(dry_run),
            },
        )

    async def alert_payout_settled(
        self,
        bounty_id: str,
        amount_usdc: float,
        tx_hash: str,
        destination_address: str,
        chain: str,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Emit a [USDC Payout Settled + TX Hash] notification when funds are swept."""
        self.metrics["payouts_settled_count"] += 1
        self.metrics["total_usdc_swept"] = round(
            float(self.metrics["total_usdc_swept"]) + float(amount_usdc), 6
        )
        tag = self.ALERT_TAG_PAYOUT_SETTLED
        mode_label = "DRY-RUN" if dry_run else "LIVE"
        text = (
            f"{tag} ({mode_label})\n"
            f"Bounty ID: {bounty_id}\n"
            f"Amount: {amount_usdc:.2f} USDC\n"
            f"Chain: {chain}\n"
            f"Destination: {destination_address}\n"
            f"TX Hash: {tx_hash}"
        )
        return await self._send_telegram_message(
            tag=tag,
            text=text,
            metadata={
                "bounty_id": bounty_id,
                "amount_usdc": float(amount_usdc),
                "tx_hash": tx_hash,
                "destination_address": destination_address,
                "chain": chain,
                "dry_run": bool(dry_run),
            },
        )

    async def alert_security_rejection(
        self,
        bounty_id: str,
        reasons: list[str],
        stage: str = "triage",
    ) -> dict[str, Any]:
        """Emit a [Security Rejection] notification when a security check blocks an action."""
        self.metrics["bounties_rejected"] += 1
        tag = self.ALERT_TAG_SECURITY_REJECTION
        joined_reasons = "; ".join(reasons) if reasons else "unspecified security policy violation"
        text = (
            f"{tag}\n"
            f"Bounty ID: {bounty_id}\n"
            f"Stage: {stage}\n"
            f"Reasons: {joined_reasons}"
        )
        return await self._send_telegram_message(
            tag=tag,
            text=text,
            metadata={
                "bounty_id": bounty_id,
                "reasons": list(reasons),
                "stage": stage,
            },
        )

    def get_status_snapshot(self) -> dict[str, Any]:
        """Return a structured snapshot of current operational state and metrics."""
        extra_status = self._status_callback() if self._status_callback is not None else {}
        merged_metrics = dict(self.metrics)
        if isinstance(extra_status.get("metrics"), dict):
            merged_metrics.update(extra_status["metrics"])

        return {
            "state": "paused" if self.is_paused else "running",
            "paused": self.is_paused,
            "dry_run_mode": self.settings.DRY_RUN_MODE,
            "chain_network": self.settings.CHAIN_NETWORK,
            "owner_cold_wallet_address": self.settings.OWNER_COLD_WALLET_ADDRESS,
            "sweep_threshold_usdc": self.settings.SWEEP_THRESHOLD_USDC,
            "metrics": merged_metrics,
        }

    async def handle_command(self, command_text: str, chat_id: str | None = None) -> str:
        """Process incoming Telegram control commands (/status, /pause, /resume)."""
        configured_chat_id = str(self.settings.TELEGRAM_CHAT_ID or "").strip()
        if configured_chat_id:
            incoming_chat_id = str(chat_id if chat_id is not None else "").strip()
            if incoming_chat_id != configured_chat_id:
                rejection_msg = (
                    f"{self.ALERT_TAG_SECURITY_REJECTION} Unauthorized chat_id: "
                    f"{incoming_chat_id or 'missing'}"
                )
                await self.alert_security_rejection(
                    bounty_id="telegram-command",
                    reasons=[f"Unauthorized chat_id '{incoming_chat_id or 'missing'}'"],
                    stage="telegram_auth",
                )
                return rejection_msg

        raw = (command_text or "").strip()
        cmd = raw.split()[0].lower() if raw else ""
        if "@" in cmd:
            cmd = cmd.split("@", 1)[0]

        if cmd == "/pause":
            self.is_paused = True
            msg = (
                "⏸️ Kill-switch activated: BountySweep Agent is now PAUSED. "
                "All new bounty claims, sandbox executions, and wallet sweeps are halted."
            )
            await self._send_telegram_message(
                tag="[Control: Paused]",
                text=msg,
                metadata={"command": "/pause", "paused": True},
                chat_id=chat_id,
            )
            return msg

        if cmd == "/resume":
            self.is_paused = False
            msg = (
                "▶️ Kill-switch cleared: BountySweep Agent has RESUMED normal operations."
            )
            await self._send_telegram_message(
                tag="[Control: Resumed]",
                text=msg,
                metadata={"command": "/resume", "paused": False},
                chat_id=chat_id,
            )
            return msg

        if cmd in ("/status", "/start"):
            snap = self.get_status_snapshot()
            metrics = snap["metrics"]
            status_text = (
                f"📊 BountySweep Agent Status: {snap['state'].upper()}\n"
                f"• Paused: {snap['paused']}\n"
                f"• Dry-Run Mode: {snap['dry_run_mode']}\n"
                f"• Chain Network: {snap['chain_network']}\n"
                f"• Cold Wallet: {snap['owner_cold_wallet_address']}\n"
                f"• Sweep Threshold: {snap['sweep_threshold_usdc']:.2f} USDC\n"
                f"• Bounties Claimed: {metrics['bounties_claimed']}\n"
                f"• Solutions Submitted: {metrics['solutions_submitted']}\n"
                f"• Bounties Rejected: {metrics['bounties_rejected']}\n"
                f"• Total USDC Swept: {metrics['total_usdc_swept']:.2f} USDC\n"
                f"\nCommands: /status | /pause | /resume"
            )
            await self._send_telegram_message(
                tag="[Control: Status]",
                text=status_text,
                metadata={"command": cmd, "snapshot": snap},
                chat_id=chat_id,
            )
            return status_text

        help_msg = (
            f"Unknown command '{raw}'. Supported commands: /status, /pause, /resume"
        )
        return help_msg

    async def poll_updates_once(self, offset: int | None = None) -> int | None:
        """Poll Telegram getUpdates API once and process any incoming /start, /status, /pause, /resume commands."""
        token = self.settings.telegram_bot_token_str.strip()
        if not token:
            return offset

        url = f"https://api.telegram.org/bot{token}/getUpdates"
        params: dict[str, Any] = {"timeout": 2}
        if offset is not None:
            params["offset"] = offset

        close_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient(timeout=10.0)
        next_offset = offset
        try:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("result", []):
                    update_id = item.get("update_id")
                    if isinstance(update_id, int):
                        next_offset = update_id + 1
                    msg = item.get("message") or {}
                    text = str(msg.get("text") or "").strip()
                    chat = msg.get("chat") or {}
                    chat_id = str(chat.get("id")) if chat.get("id") is not None else None
                    if text.startswith("/"):
                        await self.handle_command(text, chat_id=chat_id)
        except Exception as exc:
            logger.debug("Telegram poll_updates_once error: %s", exc)
        finally:
            if close_client:
                await client.aclose()
        return next_offset

