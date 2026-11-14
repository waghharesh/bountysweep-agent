"""Bounty discovery engine polling Algora, GitHub escrow issues, and on-chain task boards."""

from __future__ import annotations

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx
from pydantic import BaseModel, Field

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

_REWARD_DOLLAR_RE = re.compile(
    r"(?:💎|/bounty|bounty[:\s]+|reward[:\s]+|\bUSD[C]?\s*)\s*\$\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)"
    r"|\$\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*(?:USDC|USD|bounty|💎)",
    re.IGNORECASE,
)
_GENERIC_DOLLAR_RE = re.compile(r"\$\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)")

_ESCROW_PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("algora", re.compile(r"(?:console\.algora\.io|algora\.io|/bounty\s+\$|💎\s*\$|\[escrow:algora\])", re.IGNORECASE)),
    ("polar", re.compile(r"(?:polar\.sh|\[escrow:polar\])", re.IGNORECASE)),
    ("opire", re.compile(r"(?:opire\.dev|\[escrow:opire\])", re.IGNORECASE)),
    ("gitcoin", re.compile(r"(?:gitcoin\.co|\[escrow:gitcoin\])", re.IGNORECASE)),
    ("verified-escrow", re.compile(r"\[escrow:verified\]", re.IGNORECASE)),
]

_PROMISE_TO_PAY_RE = re.compile(
    r"(?:promise\s+to\s+pay|will\s+pay\s+after|pay\s+upon\s+merge\s+manually|unfunded|bounty\s+tbd|no\s+escrow|payment\s+pending\s+sponsor)",
    re.IGNORECASE,
)

_KNOWN_TECH_KEYWORDS: dict[str, str] = {
    "python": "python",
    "pytest": "pytest",
    "fastapi": "fastapi",
    "pydantic": "pydantic",
    "playwright": "playwright",
    "asyncio": "asyncio",
    "httpx": "httpx",
    "scraping": "data-parsing",
    "parser": "data-parsing",
    "json": "data-parsing",
    "csv": "data-parsing",
    "bug": "bug",
    "regression": "bug",
}


class BountyOpportunity(BaseModel):
    """Normalized representation of a software or task bounty."""

    bounty_id: str
    platform: str = Field(description="Source platform e.g. 'algora', 'github', 'onchain'")
    repo_owner: str
    repo_name: str
    repo_url: str
    issue_number: int
    issue_url: str
    title: str
    body: str
    labels: list[str] = Field(default_factory=list)
    reward_usdc: float = 0.0
    escrow_verified: bool = False
    escrow_provider: str | None = None
    tech_tags: list[str] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


def extract_tech_tags(title: str, body: str, labels: list[str]) -> list[str]:
    """Extract normalized technical capability tags from issue text and labels."""
    combined = f"{title}\n{body}\n{' '.join(labels)}".lower()
    tags: set[str] = set()
    for keyword, normalized_tag in _KNOWN_TECH_KEYWORDS.items():
        if re.search(rf"\b{re.escape(keyword)}\b", combined):
            tags.add(normalized_tag)
    return sorted(tags)


def parse_reward_usd_from_text(text: str) -> float:
    """Parse a USD/USDC bounty amount from labels or issue text."""
    if not text:
        return 0.0
    match = _REWARD_DOLLAR_RE.search(text)
    if match:
        amount_str = (match.group(1) or match.group(2) or "0").replace(",", "")
        try:
            return float(amount_str)
        except ValueError:
            return 0.0
    generic = _GENERIC_DOLLAR_RE.search(text)
    if generic:
        try:
            return float(generic.group(1).replace(",", ""))
        except ValueError:
            return 0.0
    return 0.0


def normalize_github_issue(issue_data: dict[str, Any]) -> BountyOpportunity:
    """Normalize a GitHub REST or GraphQL issue payload into a BountyOpportunity.

    Explicitly verifies escrow markers and rejects unfunded / 'promise-to-pay' issues.
    """
    raw_labels = issue_data.get("labels", [])
    if isinstance(raw_labels, dict) and "nodes" in raw_labels:
        raw_labels = raw_labels["nodes"]

    labels: list[str] = []
    for lbl in raw_labels:
        if isinstance(lbl, str):
            labels.append(lbl)
        elif isinstance(lbl, dict) and "name" in lbl:
            labels.append(str(lbl["name"]))

    title = str(issue_data.get("title") or "")
    body = str(issue_data.get("body") or "")
    issue_number = int(issue_data.get("number") or issue_data.get("issue_number") or 0)
    html_url = str(
        issue_data.get("html_url")
        or issue_data.get("url")
        or issue_data.get("issue_url")
        or ""
    )

    repo_owner = str(issue_data.get("repo_owner") or "")
    repo_name = str(issue_data.get("repo_name") or "")
    repo_url = str(issue_data.get("repo_url") or "")

    if not (repo_owner and repo_name):
        repository = issue_data.get("repository") or {}
        if isinstance(repository, dict):
            owner_obj = repository.get("owner") or {}
            repo_owner = repo_owner or str(
                owner_obj.get("login") if isinstance(owner_obj, dict) else owner_obj or ""
            )
            repo_name = repo_name or str(repository.get("name") or "")
            repo_url = repo_url or str(repository.get("url") or repository.get("html_url") or "")

    if not (repo_owner and repo_name):
        repo_api_url = str(issue_data.get("repository_url") or html_url)
        parts = [p for p in repo_api_url.rstrip("/").split("/") if p]
        if "repos" in parts:
            idx = parts.index("repos")
            if len(parts) > idx + 2:
                repo_owner = parts[idx + 1]
                repo_name = parts[idx + 2]
        elif "github.com" in parts:
            idx = parts.index("github.com")
            if len(parts) > idx + 2:
                repo_owner = parts[idx + 1]
                repo_name = parts[idx + 2]

    repo_owner = repo_owner or "unknown"
    repo_name = repo_name or "unknown"
    if not repo_url:
        repo_url = f"https://github.com/{repo_owner}/{repo_name}"
    if not html_url:
        html_url = f"{repo_url}/issues/{issue_number}"

    # Parse reward from explicit metadata, labels, or body
    reward_usdc = 0.0
    if "reward_usdc" in issue_data and issue_data["reward_usdc"] is not None:
        reward_usdc = float(issue_data["reward_usdc"])
    elif "reward_cents" in issue_data and issue_data["reward_cents"] is not None:
        reward_usdc = round(float(issue_data["reward_cents"]) / 100.0, 2)
    else:
        for lbl in labels:
            amt = parse_reward_usd_from_text(lbl)
            if amt > 0:
                reward_usdc = amt
                break
        if reward_usdc <= 0:
            reward_usdc = parse_reward_usd_from_text(f"{title}\n{body}")

    combined_text = f"{' '.join(labels)}\n{title}\n{body}"
    has_promise_to_pay = bool(_PROMISE_TO_PAY_RE.search(combined_text))

    escrow_provider: str | None = issue_data.get("escrow_provider")
    explicit_escrow_flag = issue_data.get("escrow_verified")

    if not escrow_provider:
        for provider_name, pattern in _ESCROW_PROVIDER_PATTERNS:
            if pattern.search(combined_text):
                escrow_provider = provider_name
                break

    has_diamond_amount_label = any("💎" in lbl and "$" in lbl for lbl in labels)
    if has_diamond_amount_label and not escrow_provider:
        escrow_provider = "algora"

    if explicit_escrow_flag is not None:
        escrow_verified = bool(explicit_escrow_flag) and not has_promise_to_pay and reward_usdc > 0
    else:
        escrow_verified = (
            bool(escrow_provider)
            and reward_usdc > 0
            and not has_promise_to_pay
        )

    bounty_id = str(
        issue_data.get("bounty_id")
        or f"github:{repo_owner}/{repo_name}#{issue_number}"
    )

    tech_tags = issue_data.get("tech_tags") or extract_tech_tags(title, body, labels)

    return BountyOpportunity(
        bounty_id=bounty_id,
        platform=str(issue_data.get("platform") or "github"),
        repo_owner=repo_owner,
        repo_name=repo_name,
        repo_url=repo_url,
        issue_number=issue_number,
        issue_url=html_url,
        title=title,
        body=body,
        labels=labels,
        reward_usdc=reward_usdc,
        escrow_verified=escrow_verified,
        escrow_provider=escrow_provider if escrow_verified else None,
        tech_tags=list(tech_tags),
        raw_metadata=issue_data,
    )


class BountyBoardAdapter(ABC):
    """Abstract base adapter for any bounty board or task marketplace."""

    @abstractmethod
    async def fetch_open_bounties(self) -> list[BountyOpportunity]:
        """Fetch and normalize currently open bounties from the provider."""


class OnChainTaskBoardAdapter(BountyBoardAdapter):
    """Extensible adapter for on-chain task boards (e.g., Base / Solana escrow contracts)."""

    def __init__(
        self,
        endpoint_url: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url
        self._client = http_client

    async def fetch_open_bounties(self) -> list[BountyOpportunity]:
        """Query an on-chain indexer endpoint if configured, otherwise return empty list."""
        if not self.endpoint_url:
            return []

        close_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=15.0)
        try:
            response = await client.get(self.endpoint_url)
            response.raise_for_status()
            payload = response.json()
            items = payload.get("bounties", payload if isinstance(payload, list) else [])
            results: list[BountyOpportunity] = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                item_copy = dict(item)
                item_copy.setdefault("platform", "onchain")
                item_copy.setdefault("escrow_provider", "onchain-escrow")
                results.append(normalize_github_issue(item_copy))
            return results
        except Exception as exc:
            logger.warning("OnChainTaskBoardAdapter poll failed: %s", exc)
            return []
        finally:
            if close_client:
                await client.aclose()


class AlgoraBountyPoller(BountyBoardAdapter):
    """Async poller for Algora active bounties with verified escrow."""

    def __init__(
        self,
        settings: Settings | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = http_client

    def normalize_algora_item(self, item: dict[str, Any]) -> BountyOpportunity:
        """Normalize a single Algora bounty entry into a BountyOpportunity."""
        issue = item.get("issue") or {}
        repo = item.get("repository") or issue.get("repository") or {}

        repo_owner = str(
            item.get("repo_owner")
            or repo.get("owner")
            or item.get("org")
            or "algora-org"
        )
        repo_name = str(
            item.get("repo_name")
            or repo.get("name")
            or item.get("repo")
            or "unknown-repo"
        )
        issue_number = int(
            item.get("issue_number")
            or issue.get("number")
            or item.get("number")
            or 0
        )
        repo_url = str(
            item.get("repo_url")
            or repo.get("url")
            or f"https://github.com/{repo_owner}/{repo_name}"
        )
        issue_url = str(
            item.get("issue_url")
            or issue.get("html_url")
            or issue.get("url")
            or f"{repo_url}/issues/{issue_number}"
        )
        title = str(item.get("title") or issue.get("title") or "")
        body = str(item.get("body") or issue.get("body") or "")

        labels_raw = item.get("labels") or issue.get("labels") or []
        labels: list[str] = [
            str(lbl["name"] if isinstance(lbl, dict) and "name" in lbl else lbl)
            for lbl in labels_raw
        ]

        # Algora rewards may be specified in reward_usdc, amount_usd, or cents
        if "reward_usdc" in item and item["reward_usdc"] is not None:
            reward_usdc = float(item["reward_usdc"])
        elif "reward_usd" in item and item["reward_usd"] is not None:
            reward_usdc = float(item["reward_usd"])
        elif "reward_cents" in item and item["reward_cents"] is not None:
            reward_usdc = round(float(item["reward_cents"]) / 100.0, 2)
        elif "amount" in item and item["amount"] is not None:
            raw_amt = float(item["amount"])
            # Treat integer cents if status/currency indicates cents or >= 10000 with cents flag
            if item.get("amount_in_cents", False):
                reward_usdc = round(raw_amt / 100.0, 2)
            else:
                reward_usdc = raw_amt
        else:
            reward_usdc = parse_reward_usd_from_text(f"{' '.join(labels)}\n{title}\n{body}")

        status_str = str(item.get("status") or "open").lower()
        escrow_flag = item.get("escrow_verified")
        if escrow_flag is None:
            escrow_verified = status_str in {"open", "active", "funded", "verified"} and reward_usdc > 0
        else:
            escrow_verified = bool(escrow_flag) and reward_usdc > 0

        if _PROMISE_TO_PAY_RE.search(f"{title}\n{body}"):
            escrow_verified = False

        raw_id = item.get("id") or item.get("bounty_id") or f"{repo_owner}/{repo_name}#{issue_number}"
        bounty_id = str(raw_id) if str(raw_id).startswith("algora:") else f"algora:{raw_id}"

        tech_tags = item.get("tech_tags") or extract_tech_tags(title, body, labels)

        return BountyOpportunity(
            bounty_id=bounty_id,
            platform="algora",
            repo_owner=repo_owner,
            repo_name=repo_name,
            repo_url=repo_url,
            issue_number=issue_number,
            issue_url=issue_url,
            title=title,
            body=body,
            labels=labels,
            reward_usdc=reward_usdc,
            escrow_verified=escrow_verified,
            escrow_provider="algora" if escrow_verified else None,
            tech_tags=list(tech_tags),
            raw_metadata=item,
        )

    async def fetch_open_bounties(self) -> list[BountyOpportunity]:
        """Poll the Algora API for open escrowed bounties."""
        url = f"{self.settings.ALGORA_API_URL.rstrip('/')}/bounties"
        close_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        try:
            response = await client.get(
                url,
                params={"status": "open", "limit": 50},
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            items = (
                data.get("bounties")
                or data.get("items")
                or data.get("data")
                or (data if isinstance(data, list) else [])
            )
            return [
                self.normalize_algora_item(item)
                for item in items
                if isinstance(item, dict)
            ]
        except Exception as exc:
            logger.warning("AlgoraBountyPoller failed to fetch from %s: %s", url, exc)
            return []
        finally:
            if close_client:
                await client.aclose()


class GitHubEscrowBountyPoller(BountyBoardAdapter):
    """Async poller for GitHub issues with verified escrow labels (💎 / bounty)."""

    def __init__(
        self,
        settings: Settings | None = None,
        http_client: httpx.AsyncClient | None = None,
        search_query: str = "is:issue is:open label:bounty python",
    ) -> None:
        self.settings = settings or get_settings()
        self._client = http_client
        self.search_query = search_query

    @staticmethod
    def normalize_github_issue(issue_data: dict[str, Any]) -> BountyOpportunity:
        """Delegate to module-level normalizer for GitHub issues."""
        return normalize_github_issue(issue_data)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token_str:
            headers["Authorization"] = f"Bearer {self.settings.github_token_str}"
        return headers

    async def fetch_open_bounties(self) -> list[BountyOpportunity]:
        """Search GitHub REST API for open bounty issues and normalize results."""
        url = f"{self.settings.GITHUB_API_URL.rstrip('/')}/search/issues"
        close_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        try:
            response = await client.get(
                url,
                params={"q": self.search_query, "per_page": 30, "sort": "updated", "order": "desc"},
                headers=self._headers(),
            )
            response.raise_for_status()
            payload = response.json()
            items = payload.get("items", [])
            return [
                normalize_github_issue(item)
                for item in items
                if isinstance(item, dict) and "pull_request" not in item
            ]
        except Exception as exc:
            logger.warning("GitHubEscrowBountyPoller failed to fetch from %s: %s", url, exc)
            return []
        finally:
            if close_client:
                await client.aclose()


def generate_mock_escrowed_bounty() -> BountyOpportunity:
    """Return a realistic verified-escrow Python/FastAPI bug-fix bounty for dry-run simulations."""
    return BountyOpportunity(
        bounty_id="algora:acme-fin/payment-router#402",
        platform="algora",
        repo_owner="acme-fin",
        repo_name="payment-router",
        repo_url="https://github.com/acme-fin/payment-router",
        issue_number=402,
        issue_url="https://github.com/acme-fin/payment-router/issues/402",
        title="Fix precision rounding bug in USDC fee calculator for fractional cents",
        body=(
            "## Bug Description\n"
            "When calculating protocol fees in `fee_calculator.py`, floating-point multiplication "
            "causes off-by-one micro-USDC rounding drift on amounts like `19.99` with `25` bps fee.\n\n"
            "## Acceptance Criteria\n"
            "- Use `Decimal` with `ROUND_HALF_UP` to 6 decimal places in `calculate_net_payout`.\n"
            "- Raise `ValueError` on negative gross amounts.\n"
            "- Add `pytest` regression tests covering fractional cent precision and negative inputs.\n\n"
            "💎 $150.00 bounty escrowed via Algora [escrow:verified]"
        ),
        labels=["💎 $150", "bounty", "python", "fastapi", "bug"],
        reward_usdc=150.0,
        escrow_verified=True,
        escrow_provider="algora",
        tech_tags=["bug", "fastapi", "pytest", "python"],
        raw_metadata={"mock": True, "escrow_contract": "algora_verified_v2"},
    )


class BountyScanner:
    """Concurrent multi-platform bounty discovery coordinator."""

    def __init__(
        self,
        adapters: list[BountyBoardAdapter] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = [
                AlgoraBountyPoller(settings=self.settings),
                GitHubEscrowBountyPoller(settings=self.settings),
            ]

    async def scan_all(self, verified_only: bool = False) -> list[BountyOpportunity]:
        """Concurrently poll all configured bounty adapters and deduplicate by bounty_id."""
        tasks = [adapter.fetch_open_bounties() for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        deduped: dict[str, BountyOpportunity] = {}
        for res in results:
            if isinstance(res, Exception):
                logger.warning("Bounty adapter raised exception during scan: %s", res)
                continue
            for bounty in res:
                if verified_only and not bounty.escrow_verified:
                    continue
                if bounty.bounty_id not in deduped:
                    deduped[bounty.bounty_id] = bounty

        return list(deduped.values())

    @staticmethod
    def generate_mock_escrowed_bounty() -> BountyOpportunity:
        """Convenience wrapper returning the canonical dry-run mock escrowed bounty."""
        return generate_mock_escrowed_bounty()
