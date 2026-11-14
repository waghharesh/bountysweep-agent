"""Evaluator package for security screening, bounty triage, and patch generation."""

from evaluator.triage import (
    STRICT_ESCROW_BOT_LOGINS,
    BountyTriageEngine,
    GeneratedPatch,
    TriageResult,
    is_cross_repo_mirror_or_relay_issue,
    screen_for_malicious_intent,
    verify_strict_bot_or_onchain_escrow,
)

__all__ = [
    "STRICT_ESCROW_BOT_LOGINS",
    "BountyTriageEngine",
    "GeneratedPatch",
    "TriageResult",
    "is_cross_repo_mirror_or_relay_issue",
    "screen_for_malicious_intent",
    "verify_strict_bot_or_onchain_escrow",
]
