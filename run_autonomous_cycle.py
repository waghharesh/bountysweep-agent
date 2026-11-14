"""Standalone CLI runner for executing autonomous BountySweep cycles on free cloud VMs / GitHub Actions."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from api.main import BountySweepOrchestrator, CycleRunRequest


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
    for i in range(args.loops):
        result = await orchestrator.run_cycle(
            CycleRunRequest(use_mock_bounty=args.mock)
        )
        print(f"=== Cycle {i + 1}/{args.loops} Result ===")
        print(json.dumps(result, indent=2))
        if i + 1 < args.loops:
            await asyncio.sleep(args.interval)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
