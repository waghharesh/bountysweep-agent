"""Regression tests replaying exact false-positive bounty payloads vs genuine escrowed Python issues."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import DockerException

from config.settings import Settings
from discovery.scanner import (
    has_verified_escrow_signature_or_marker,
    is_aggregator_or_digest_issue,
    is_non_usdc_ledger_bounty,
    normalize_github_issue,
)
from evaluator.triage import (
    BountyTriageEngine,
    is_cross_repo_mirror_or_relay_issue,
    verify_strict_bot_or_onchain_escrow,
)
from sandbox.runner import DockerSandboxRunner


PLANTGUIDE_9_PAYLOAD = {
    "number": 9,
    "title": "[50 MRG] FastAPI: POST /identify and GET /species/{id}/care",
    "user": {"login": "TUPM96"},
    "labels": [
        {"name": "bounty"},
        {"name": "bounty: feature"},
        {"name": "api"},
        {"name": "reward:50-mrg"},
    ],
    "html_url": "https://github.com/mergeos-bounties/PlantGuide/issues/9",
    "repository_url": "https://api.github.com/repos/mergeos-bounties/PlantGuide",
    "body": (
        "## Bounty: 50 MRG\n\n"
        "Optional FastAPI under src/plantguide/api/ for plant apps.\n\n"
        "## Acceptance\n\n"
        "- [ ] Documented uvicorn entry\n"
        "- [ ] TestClient tests\n\n\n"
        "## Claim (MergeOS MRG)\n\n"
        "1. Star https://github.com/mergeos-bounties/PlantGuide and https://github.com/mergeos-bounties/mergeos  \n"
        "2. Comment on **this issue**: `I claim this bounty`  \n"
        "3. Comment on MergeOS [Claim Token #1](https://github.com/mergeos-bounties/mergeos/issues/1) with a link to this issue  \n"
        "4. Open a PR to **PlantGuide** (public product repo) with `Fixes #<this-issue>`\n\n"
        "Policy: [docs/BOUNTY.md](../blob/master/docs/BOUNTY.md)\n\n"
        "## Important\n\n"
        "Work lands on **https://github.com/mergeos-bounties/PlantGuide**.\n\n"
        "## Payout\n\n"
        "Maintainer reviews PR → merge on PlantGuide → **MRG credit** on MergeOS ledger to `github:<author>` (25/50/100/200 scale).\n"
    ),
    "comments_list": [],
}

BOUNTYSCOUT_505_PAYLOAD = {
    "number": 505,
    "title": "🎯 Bounty Alert: 17 New Opportunityies found",
    "user": {"login": "github-actions[bot]"},
    "labels": [{"name": "bounty-alert"}],
    "html_url": "https://github.com/dev-kp-eloper/BountyScout/issues/505",
    "repository_url": "https://api.github.com/repos/dev-kp-eloper/BountyScout",
    "body": (
        "### Active Bounty Scan Results\n\n"
        "**Scan Time:** 2026-07-17 07:19 UTC\n\n"
        "#### 1. [[Bug bounty] Antigravity POSIX PreInvocation hook exits 127 without jq](https://github.com/monk-io/monk-plugin/issues/24)\n"
        "- **Repository:** [monk-io/monk-plugin](https://github.com/monk-io/monk-plugin)\n"
        "#### 8. [[$25 BOUNTY] [Python] Add complete type hints to build.py functions](https://github.com/cuentaprueba244w-dotcom/zeroeye/issues/7)\n"
        "- **Repository:** [cuentaprueba244w-dotcom/zeroeye](https://github.com/cuentaprueba244w-dotcom/zeroeye)\n"
    ),
    "comments_list": [
        {
            "user": {"login": "JoTalbot"},
            "body": "Octopus automation reviewed this bounty as a potential contribution target. Issue: 🎯 Bounty Alert: 17 New Opportunityies found. Reward: 25.0.",
        }
    ],
}

PROTOCOL_CONFORMANCE_RELAY_2_PAYLOAD = {
    "number": 2,
    "title": "[Escrowed $600 USDC] Tighten 32-bit subregister zero-extension parity across conditional joins (`refine_bpf_tnum_frames`)",
    "user": {"login": "IES-BoilerRoom"},
    "labels": [{"name": "bounty"}],
    "html_url": "https://github.com/IES-BoilerRoom/protocol-conformance-relay/issues/2",
    "repository_url": "https://api.github.com/repos/IES-BoilerRoom/protocol-conformance-relay",
    "body": (
        "> **Automated CI Conformance Mirror Notice**: Automated CI build and specification relay issue; "
        "manual pull requests from human engineers are not reviewed on this mirror.\n\n"
        "- **Escrow Rail**: https://algora.io / https://polar.sh / https://opire.dev\n"
        "- **Funding Status**: Held in escrow — Reward: $600 USDC\n"
        "- **Primary Batch Suite**: https://github.com/IES-BoilerRoom/Furnace/issues/2\n"
        "- **Domain Conformance Suite**: https://github.com/IES-BoilerRoom/ebpf-verifier-reg-bounds/issues/1\n\n"
        "Clone `IES-BoilerRoom/ebpf-verifier-reg-bounds`, calibrate `TNUM_KNOWN_VALUE_MASK` and "
        "`ALU64_SCALAR_WITNESS` in `verifier/tnum_bounds.py`, and pass `python3 selftests/run_alu64_range.py --strict-ci`."
    ),
    "comments_list": [
        {"user": {"login": "toddkenner502-sys"}, "body": "/claim"},
        {"user": {"login": "nazarijlarin402-pixel"}, "body": "Hi! I can help with your posted task."},
    ],
}

VALID_ALGORA_PYTHON_ISSUE_PAYLOAD = {
    "number": 412,
    "title": "Fix async FastAPI Pydantic serialization bug in Python SDK",
    "user": {"login": "maintainer-dev"},
    "labels": [{"name": "bounty"}, {"name": "python"}, {"name": "bug"}],
    "html_url": "https://github.com/py-org/fastapi-sdk/issues/412",
    "repository_url": "https://api.github.com/repos/py-org/fastapi-sdk",
    "body": (
        "## Problem\n"
        "When serializing nested Pydantic models in FastAPI responses, Decimal fields lose precision.\n\n"
        "## Acceptance Criteria\n"
        "- Fix Decimal serialization in `serializer.py`.\n"
        "- Add `pytest` regression tests reproducing the failure.\n"
    ),
    "comments_list": [
        {
            "user": {"login": "algora-pbc[bot]"},
            "body": "💎 $150.00 bounty funded! Solve at https://console.algora.io/org/py-org/bounties/412",
        }
    ],
}


@pytest.mark.asyncio
async def test_exact_false_positive_payloads_rejected_and_genuine_algora_approved() -> None:
    """Replay PlantGuide#9, BountyScout#505, protocol-conformance-relay#2 (all rejected) and a valid algora-pbc[bot] Python issue (approved)."""
    engine = BountyTriageEngine(settings=Settings(DRY_RUN_MODE=True, MIN_TRIAGE_SCORE=70))

    # 1. PlantGuide#9 (MergeOS non-USDC MRG ledger, no escrow bot comment) -> REJECTED
    plantguide = normalize_github_issue(PLANTGUIDE_9_PAYLOAD)
    assert plantguide.escrow_verified is False
    assert is_non_usdc_ledger_bounty(
        plantguide.title, plantguide.body, plantguide.labels, repo_owner=plantguide.repo_owner
    ) is True
    assert has_verified_escrow_signature_or_marker(plantguide) is False
    triage_pg = await engine.evaluate_bounty(plantguide)
    assert triage_pg.escrow_verified is False
    assert triage_pg.approved is False
    assert triage_pg.total_score == 0

    # 2. BountyScout#505 (github-actions[bot], bounty-alert label, aggregator digest) -> REJECTED
    bountyscout = normalize_github_issue(BOUNTYSCOUT_505_PAYLOAD)
    assert bountyscout.escrow_verified is False
    assert is_aggregator_or_digest_issue(bountyscout) is True
    assert has_verified_escrow_signature_or_marker(bountyscout) is False
    triage_bs = await engine.evaluate_bounty(bountyscout)
    assert triage_bs.escrow_verified is False
    assert triage_bs.approved is False
    assert triage_bs.total_score == 0

    # 3. protocol-conformance-relay#2 (mirror notice, links/Held in escrow in body without bot comment, cross-repo clone) -> REJECTED
    relay = normalize_github_issue(PROTOCOL_CONFORMANCE_RELAY_2_PAYLOAD)
    assert relay.escrow_verified is False
    assert is_aggregator_or_digest_issue(relay) is True
    assert has_verified_escrow_signature_or_marker(relay) is False
    is_mirror, _ = is_cross_repo_mirror_or_relay_issue(relay)
    assert is_mirror is True

    # Even if forced escrow_verified=True by a caller, triage must reject it!
    forced_relay = relay.model_copy(update={"escrow_verified": True, "reward_usdc": 600.0})
    ok_escrow, _ = verify_strict_bot_or_onchain_escrow(forced_relay)
    assert ok_escrow is False
    triage_relay = await engine.evaluate_bounty(forced_relay)
    assert triage_relay.escrow_verified is False
    assert triage_relay.approved is False
    assert triage_relay.total_score == 0

    # 4. Valid algora-pbc[bot] commented Python issue -> APPROVED
    valid_bounty = normalize_github_issue(VALID_ALGORA_PYTHON_ISSUE_PAYLOAD)
    assert valid_bounty.escrow_verified is True
    assert valid_bounty.escrow_provider == "algora"
    assert valid_bounty.reward_usdc == 150.0
    assert has_verified_escrow_signature_or_marker(valid_bounty) is True

    ok_valid, _ = verify_strict_bot_or_onchain_escrow(valid_bounty)
    assert ok_valid is True
    triage_valid = await engine.evaluate_bounty(valid_bounty)
    assert triage_valid.security_rejected is False
    assert triage_valid.escrow_verified is True
    assert triage_valid.approved is True
    assert triage_valid.total_score >= 70


def test_sandbox_falls_back_to_python_m_unittest_discover_on_pytest_exit_5(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When pytest returns exit code 5 (no tests collected), sandbox/runner.py must fall back to python -m unittest discover."""
    monkeypatch.setattr(
        "sandbox.runner.docker.from_env",
        MagicMock(side_effect=DockerException("Docker socket unavailable in test VM")),
    )

    (tmp_path / "pkg.py").write_text("def double(x: int) -> int:\n    return x * 2\n", encoding="utf-8")
    # Named check_pkg.py (not test_*.py) so pytest collects 0 tests (exit code 5), while unittest discover finds it
    # or test_unit.py using unittest.TestCase
    (tmp_path / "test_unit.py").write_text(
        "import unittest\n"
        "from pkg import double\n\n"
        "class TestPkg(unittest.TestCase):\n"
        "    def test_double(self) -> None:\n"
        "        self.assertEqual(double(3), 6)\n",
        encoding="utf-8",
    )

    runner = DockerSandboxRunner(
        settings=Settings(DRY_RUN_MODE=True, SANDBOX_TIMEOUT_SECONDS=60),
        allow_local_fallback=True,
    )
    # Simulate pytest returning exit code 5 directly via _run_single_command_in_container
    orig_single = runner._run_single_command_in_container
    calls: list[list[str] | str | None] = []

    def spy_single(workspace_path: Path, command=None, is_fallback_script: bool = False):
        calls.append(command)
        if command is None:
            from sandbox.runner import SandboxTestRunResult

            return (
                SandboxTestRunResult(
                    passed=False,
                    exit_code=5,
                    passed_count=0,
                    failed_count=0,
                    total_count=0,
                    stdout="no tests ran in 0.01s",
                ),
                runner._build_container_kwargs(workspace_path, command=command),
            )
        return orig_single(workspace_path, command=command, is_fallback_script=is_fallback_script)

    monkeypatch.setattr(runner, "_run_single_command_in_container", spy_single)

    result, _ = runner.run_pytest_in_container(tmp_path)
    assert ["python", "-m", "unittest", "discover"] in calls
    assert result.passed is True
    assert result.passed_count == 1
