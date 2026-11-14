"""Bounty discovery package."""

from discovery.scanner import (
    MAX_CANDIDATES_PER_CYCLE,
    VERIFIED_ESCROW_BOT_LOGINS,
    AlgoraBountyPoller,
    BaseUSDCBountyPoller,
    BountyBoardAdapter,
    BountyOpportunity,
    BountyScanner,
    GitHubEscrowBountyPoller,
    OnChainTaskBoardAdapter,
    SeenBountiesCache,
    generate_mock_escrowed_bounty,
    has_verified_escrow_signature_or_marker,
    is_aggregator_or_digest_issue,
    is_non_usdc_ledger_bounty,
    normalize_github_issue,
)

__all__ = [
    "MAX_CANDIDATES_PER_CYCLE",
    "VERIFIED_ESCROW_BOT_LOGINS",
    "AlgoraBountyPoller",
    "BaseUSDCBountyPoller",
    "BountyBoardAdapter",
    "BountyOpportunity",
    "BountyScanner",
    "GitHubEscrowBountyPoller",
    "OnChainTaskBoardAdapter",
    "SeenBountiesCache",
    "generate_mock_escrowed_bounty",
    "has_verified_escrow_signature_or_marker",
    "is_aggregator_or_digest_issue",
    "is_non_usdc_ledger_bounty",
    "normalize_github_issue",
]
