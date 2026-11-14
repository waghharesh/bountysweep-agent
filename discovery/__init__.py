"""Discovery package for polling and normalizing escrowed software bounties."""

from discovery.scanner import (
    AlgoraBountyPoller,
    BountyBoardAdapter,
    BountyOpportunity,
    BountyScanner,
    GitHubEscrowBountyPoller,
    OnChainTaskBoardAdapter,
    generate_mock_escrowed_bounty,
    normalize_github_issue,
)

__all__ = [
    "AlgoraBountyPoller",
    "BountyBoardAdapter",
    "BountyOpportunity",
    "BountyScanner",
    "GitHubEscrowBountyPoller",
    "OnChainTaskBoardAdapter",
    "generate_mock_escrowed_bounty",
    "normalize_github_issue",
]
