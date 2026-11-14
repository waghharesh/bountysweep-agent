"""Standalone CLI runner for executing autonomous BountySweep cycles on free cloud VMs / GitHub Actions."""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
from pathlib import Path
import sys
from typing import Any

from api.main import BountySweepOrchestrator, CycleRunRequest


def _write_github_step_summary(status: dict[str, Any], cycle_results: list[dict[str, Any]]) -> None:
    """Write a rich Markdown Mission Control summary to GitHub Actions $GITHUB_STEP_SUMMARY."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    metrics = status.get("metrics", {})
    cold_wallet = status.get("owner_cold_wallet_address", "")
    worker_wallet = status.get("worker_wallet_address", "")
    seen_cached = status.get("seen_bounties_cached_24h", 0)

    lines = [
        "# 🛡️ BountySweep Autonomous Cloud Agent — Run Telemetry",
        "",
        "| Parameter | Value |",
        "| :--- | :--- |",
        f"| **Status** | `{status.get('status', 'running').upper()}` |",
        f"| **Chain Network** | `{status.get('chain_network', 'base').upper()}` (USDC) |",
        f"| **Owner Cold Wallet** | [`{cold_wallet}`](https://basescan.org/address/{cold_wallet}) |",
        f"| **Burner Worker Wallet** | [`{worker_wallet}`](https://basescan.org/address/{worker_wallet}) |",
        f"| **Seen Bounties Cached (24h TTL)** | `{seen_cached}` |",
        f"| **Total Scanned / Approved / Swept** | `{metrics.get('bounties_scanned', 0)}` / `{metrics.get('bounties_approved', 0)}` / `${metrics.get('total_swept_usdc', 0.0):.2f} USDC` |",
        "",
        "## 🔄 Cycle Outcomes",
        "",
        "| Cycle | Outcome | Bounty ID | Value (USDC) | Batch Evaluated | Reason |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for idx, res in enumerate(cycle_results, start=1):
        bounty = res.get("bounty") or {}
        triage = res.get("triage") or {}
        batch_count = len(res.get("batch_evaluated", []))
        bounty_id = bounty.get("bounty_id") or "—"
        val = f"${bounty.get('value_usdc', 0.0):.2f}" if bounty else "—"
        reason = (triage.get("reasoning") or res.get("message") or "—")[:120]
        lines.append(
            f"| #{idx} | `{res.get('outcome', 'unknown')}` | `{bounty_id}` | {val} | {batch_count} | {reason} |"
        )

    lines.append("")
    lines.append(
        "> 🌐 **Live Web Dashboard**: [https://waghharesh.github.io/bountysweep-agent/](https://waghharesh.github.io/bountysweep-agent/)"
    )

    try:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError:
        pass


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute BountySweep Agent discovery, triage, sandbox verification, and USDC sweep cycle."
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run against the deterministic mock escrowed bounty instead of live GitHub/Algora polling.",
    )
    parser.add_argument(
        "--loops",
        type=int,
        default=1,
        help="Number of consecutive polling cycles to run before exiting (default: 1).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Sleep interval in seconds between loops when --loops > 1 (default: 300).",
    )
    args = parser.parse_args()

    from config.settings import get_settings

    settings = get_settings()
    if args.mock and not settings.DRY_RUN_MODE:
        settings = settings.model_copy(update={"DRY_RUN_MODE": True})

    orchestrator = BountySweepOrchestrator(settings=settings)
    cycle_results: list[dict[str, Any]] = []

    for i in range(args.loops):
        result = await orchestrator.run_cycle(
            CycleRunRequest(use_mock_bounty=args.mock)
        )
        cycle_results.append(result)
        print(f"=== Cycle {i + 1}/{args.loops} Result ===")
        print(json.dumps(result, indent=2))
        if i + 1 < args.loops:
            await asyncio.sleep(args.interval)

    status_payload = orchestrator.get_status()
    status_payload["last_updated_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    status_payload["latest_run_cycles"] = cycle_results

    docs_dir = Path(__file__).resolve().parent / "docs"
    try:
        docs_dir.mkdir(parents=True, exist_ok=True)
        (docs_dir / "status.json").write_text(
            json.dumps(status_payload, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass

    _write_github_step_summary(status_payload, cycle_results)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
