"""Bounty discovery engine polling Algora, GitHub 3-query discovery funnel, and on-chain task boards."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, Field

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

DEFAULT_SEEN_CACHE_TTL_SECONDS = 86_400  # 24 hours
DEFAULT_SEEN_CACHE_PATH = Path("/tmp/bountysweep_seen_bounties.json")
MAX_CANDIDATES_PER_CYCLE = 15

THREE_QUERY_DISCOVERY_FUNNEL: tuple[str, str, str] = (
    'is:open is:issue "algora.io"',
    'is:open is:issue "opire.dev"',
    'is:open is:issue "USDC" "bounty" -label:bounty-alert',
)

VERIFIED_ESCROW_BOT_LOGINS: frozenset[str] = frozenset(
    {
        "algora-pbc[bot]",
        "opire-bot[bot]",
        "polar-sh[bot]",
    }
)

AGGREGATOR_BOT_LOGINS: frozenset[str] = frozenset(
    {
        "github-actions[bot]",
        "github-actions",
    }
)

AGGREGATOR_LABELS: frozenset[str] = frozenset(
    {
        "bounty-alert",
        "bounty-digest",
        "automated-digest",
    }
)

_REWARD_DOLLAR_RE = re.compile(
    r"(?:💎|/bounty|bounty[:\s]+|reward[:\s]+|\bUSD[C]?\s*)\s*\$\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)"
    r"|\$\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*(?:USDC|USD|bounty|💎)",
    re.IGNORECASE,
)
_USDC_AMOUNT_RE = re.compile(
    r"\b([0-9][0-9,]*(?:\.[0-9]{1,2})?)\s*USDC\b",
    re.IGNORECASE,
)
_GENERIC_DOLLAR_RE = re.compile(r"\$\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)")

_NON_USDC_LEDGER_RE = re.compile(
    r"(?:\[\s*\d+\s*MRG\s*\]|\b\d+\s*MRG\b|reward:\d+-mrg|\bMRG\s+credit\b|"
    r"\bMergeOS\s+ledger\b|mergeos-bounties|\[\$0\]|"
    r"\b\d+\s*(?:XP|kudos|rep\s+points|karma\s+points)\b|"
    r"\bBountyScout\b|\bAF\s+alert:\s*\d+\s+new\s+paid\s+opportunit|"
    r"🎯\s*Bounty\s+Alert:)",
    re.IGNORECASE,
)

# Verified escrow bot signatures or USDC escrow links/markers (does NOT require 'Base' in issue body)
_EXPLICIT_USDC_OR_BASE_ESCROW_RE = re.compile(
    r"(?:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913|"
    r"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48|"
    r"\[escrow:(?:verified|base|usdc|algora|opire|polar|gitcoin|bountycaster|dework|superteam)\]|"
    r"algora-pbc\[bot\]|opire-bot\[bot\]|polar-sh\[bot\]|"
    r"https?://(?:console\.)?algora\.io/[^\s)\"']*|"
    r"https?://(?:app\.)?opire\.dev/[^\s)\"']*|"
    r"https?://polar\.sh/[^\s)\"']*|"
    r"https?://(?:basescan\.org|etherscan\.io|arbiscan\.io|optimistic\.etherscan\.io)/tx/0x[a-fA-F0-9]+|"
    r"console\.algora\.io|algora\.io|opire\.dev|polar\.sh|bountycaster\.xyz|"
    r"/bounty\s+\$\s*[0-9]+|💎\s*\$\s*[0-9]+|"
    r"\b[0-9][0-9,]*(?:\.[0-9]{1,2})?\s*USDC\b|"
    r"\$\s*[0-9][0-9,]*(?:\.[0-9]{1,2})?\s*USDC\b)",
    re.IGNORECASE,
)

_ESCROW_PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "base-usdc",
        re.compile(
            r"(?:\bUSDC\b[^\n]{0,50}\bBase\b|\bBase\b[^\n]{0,50}\bUSDC\b|"
            r"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913|\[escrow:base\])",
            re.IGNORECASE,
        ),
    ),
    (
        "algora",
        re.compile(
            r"(?:algora-pbc\[bot\]|console\.algora\.io|algora\.io|/bounty\s+\$|💎\s*\$|\[escrow:algora\])",
            re.IGNORECASE,
        ),
    ),
    (
        "opire",
        re.compile(
            r"(?:opire-bot\[bot\]|app\.opire\.dev|opire\.dev|\[escrow:opire\])",
            re.IGNORECASE,
        ),
    ),
    (
        "polar",
        re.compile(
            r"(?:polar-sh\[bot\]|polar\.sh|\[escrow:polar\])",
            re.IGNORECASE,
        ),
    ),
    ("gitcoin", re.compile(r"(?:gitcoin\.co|\[escrow:gitcoin\])", re.IGNORECASE)),
    ("bountycaster", re.compile(r"(?:bountycaster\.xyz|\[escrow:bountycaster\])", re.IGNORECASE)),
    ("dework", re.compile(r"(?:dework\.xyz|\[escrow:dework\])", re.IGNORECASE)),
    ("superteam", re.compile(r"(?:superteam\.fun|\[escrow:superteam\])", re.IGNORECASE)),
    ("verified-escrow", re.compile(r"\[escrow:verified\]", re.IGNORECASE)),
    (
        "usdc-escrow",
        re.compile(
            r"(?:\b[0-9][0-9,]*(?:\.[0-9]{1,2})?\s*USDC\b|\$\s*[0-9][0-9,]*(?:\.[0-9]{1,2})?\s*USDC\b|\[escrow:usdc\])",
            re.IGNORECASE,
        ),
    ),
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
    platform: str = Field(description="Source platform e.g. 'algora', 'github', 'base-usdc', 'onchain'")
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


class SeenBountiesCache:
    """Persistent disk-backed TTL cache that skips processed or rejected bounty_ids for 24 hours."""

    def __init__(
        self,
        cache_path: str | Path | None = DEFAULT_SEEN_CACHE_PATH,
        ttl_seconds: int = DEFAULT_SEEN_CACHE_TTL_SECONDS,
    ) -> None:
        self.cache_path: Path | None = Path(cache_path) if cache_path else None
        self.ttl_seconds: int = int(ttl_seconds)
        self._entries: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        """Load persisted seen bounty entries from disk if available."""
        if self.cache_path is None or not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._entries = {
                    str(k): v
                    for k, v in raw.items()
                    if isinstance(v, dict) and "timestamp" in v
                }
                self.prune_expired()
        except Exception as exc:
            logger.warning("Failed to load seen_bounties cache from %s: %s", self.cache_path, exc)

    def _save(self) -> None:
        """Persist current seen bounty entries to disk atomically."""
        if self.cache_path is None:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.cache_path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(self._entries, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            tmp_path.replace(self.cache_path)
        except Exception as exc:
            logger.warning("Failed to save seen_bounties cache to %s: %s", self.cache_path, exc)

    def prune_expired(self, now: float | None = None) -> int:
        """Remove entries older than ttl_seconds and return count removed."""
        current_ts = time.time() if now is None else float(now)
        expired_keys = [
            bounty_id
            for bounty_id, meta in self._entries.items()
            if (current_ts - float(meta.get("timestamp", 0.0))) >= self.ttl_seconds
        ]
        for key in expired_keys:
            self._entries.pop(key, None)
        if expired_keys:
            self._save()
        return len(expired_keys)

    def is_seen(self, bounty_id: str, now: float | None = None) -> bool:
        """Return True if bounty_id was processed/rejected within the last ttl_seconds (24h)."""
        current_ts = time.time() if now is None else float(now)
        entry = self._entries.get(bounty_id)
        if entry is None:
            return False
        age = current_ts - float(entry.get("timestamp", 0.0))
        if age >= self.ttl_seconds:
            self._entries.pop(bounty_id, None)
            self._save()
            return False
        return True

    def mark_seen(
        self,
        bounty_id: str,
        status: str = "processed",
        now: float | None = None,
    ) -> None:
        """Record bounty_id in the 24-hour seen cache and persist to disk."""
        current_ts = time.time() if now is None else float(now)
        self._entries[bounty_id] = {
            "timestamp": current_ts,
            "status": status,
        }
        self._save()

    def clear(self) -> None:
        """Clear all entries in memory and on disk."""
        self._entries.clear()
        if self.cache_path is not None and self.cache_path.exists():
            try:
                self.cache_path.unlink()
            except OSError:
                pass

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """Return a copy of active (non-expired) seen bounty entries."""
        self.prune_expired()
        return dict(self._entries)


_ALREADY_AWARDED_COMMENT_RE = re.compile(
    r"(?:has\s+been\s+awarded|console\.algora\.io/awards/|🎉🎈|bounty\s+has\s+been\s+(?:paid|claimed\s+and\s+closed))",
    re.IGNORECASE,
)

_PR_CLAIM_ONLY_COMMENT_RE = re.compile(
    r"💡\s*@[A-Za-z0-9_.-]+\s+submitted\s+a\s+\[pull\s+request\]",
    re.IGNORECASE,
)


def is_aggregator_or_digest_issue(
    issue_data_or_bounty: dict[str, Any] | BountyOpportunity,
) -> bool:
    """Return True if an issue is created by github-actions[bot], labeled 'bounty-alert', or is an aggregator/mirror digest."""
    if isinstance(issue_data_or_bounty, BountyOpportunity):
        raw = issue_data_or_bounty.raw_metadata or {}
        labels = [lbl.strip().lower() for lbl in issue_data_or_bounty.labels]
        title = issue_data_or_bounty.title
        body = issue_data_or_bounty.body
        repo_owner = issue_data_or_bounty.repo_owner
        repo_name = issue_data_or_bounty.repo_name
    else:
        raw = issue_data_or_bounty
        raw_labels = raw.get("labels") or []
        if isinstance(raw_labels, dict) and "nodes" in raw_labels:
            raw_labels = raw_labels["nodes"]
        labels = [
            str(lbl.get("name") if isinstance(lbl, dict) else lbl).strip().lower()
            for lbl in raw_labels
        ]
        title = str(raw.get("title") or "")
        body = str(raw.get("body") or "")
        repo_owner = str(raw.get("repo_owner") or "")
        repo_name = str(raw.get("repo_name") or "")

    user_obj = raw.get("user") or raw.get("author") or {}
    user_login = (
        str(user_obj.get("login") if isinstance(user_obj, dict) else user_obj or "")
        .strip()
        .lower()
    )
    if user_login in AGGREGATOR_BOT_LOGINS:
        return True

    if any(lbl in AGGREGATOR_LABELS for lbl in labels):
        return True

    combined = f"{title}\n{body}\n{repo_owner}\n{repo_name}"
    if re.search(
        r"(?:\bBountyScout\b|\bAF\s+alert:\s*\d+\s+new\s+paid\s+opportunit|"
        r"🎯\s*Bounty\s+Alert:|Active\s+Bounty\s+Scan\s+Results|"
        r"Automated\s+CI\s+Conformance\s+Mirror\s+Notice|"
        r"specification\s+relay\s+issue|"
        r"manual\s+pull\s+requests\s+from\s+human\s+engineers\s+are\s+not\s+reviewed\s+on\s+this\s+mirror)",
        combined,
        re.IGNORECASE,
    ):
        return True

    return False


def _extract_comments_metadata(raw: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Extract lowercase comment author logins, all comment bodies, and verified-bot-only comment bodies."""
    comments_list = raw.get("comments_list") or raw.get("comments_data") or []
    comment_logins: list[str] = []
    comment_bodies: list[str] = []
    bot_comment_bodies: list[str] = []
    if isinstance(comments_list, list):
        for comment in comments_list:
            if isinstance(comment, dict):
                c_user = comment.get("user") or comment.get("author") or {}
                c_login = (
                    str(c_user.get("login") if isinstance(c_user, dict) else c_user or "")
                    .strip()
                    .lower()
                )
                c_body = str(comment.get("body") or "")
                if c_login:
                    comment_logins.append(c_login)
                if c_body:
                    comment_bodies.append(c_body)
                if c_login in VERIFIED_ESCROW_BOT_LOGINS and c_body:
                    bot_comment_bodies.append(c_body)
    return comment_logins, comment_bodies, bot_comment_bodies


def has_verified_escrow_signature_or_marker(
    issue_data_or_bounty: dict[str, Any] | BountyOpportunity,
) -> bool:
    """Strictly verify escrow: never accept links or 'Held in escrow' text in the issue body alone.

    Requires comments_list to contain an active (unclaimed/unawarded) comment authored specifically by
    'algora-pbc[bot]', 'opire-bot[bot]', or 'polar-sh[bot]' (or a direct on-chain/Algora API response).
    """
    if isinstance(issue_data_or_bounty, BountyOpportunity):
        bounty = issue_data_or_bounty
        raw = bounty.raw_metadata or {}
        labels = bounty.labels
        title = bounty.title
        body = bounty.body
        platform = bounty.platform
    else:
        raw = issue_data_or_bounty
        raw_labels = raw.get("labels") or []
        if isinstance(raw_labels, dict) and "nodes" in raw_labels:
            raw_labels = raw_labels["nodes"]
        labels = [
            str(lbl.get("name") if isinstance(lbl, dict) else lbl)
            for lbl in raw_labels
        ]
        title = str(raw.get("title") or "")
        body = str(raw.get("body") or "")
        platform = str(raw.get("platform") or "github")

    combined_issue = f"{' '.join(labels)}\n{title}\n{body}"
    if _PROMISE_TO_PAY_RE.search(combined_issue):
        return False

    # 1. Check comments_list for a comment authored specifically by algora-pbc[bot], opire-bot[bot], or polar-sh[bot]
    comments_list = raw.get("comments_list") or raw.get("comments_data") or []
    if isinstance(comments_list, list) and comments_list:
        has_active_bot_comment = False
        for comment in comments_list:
            if not isinstance(comment, dict):
                continue
            c_user = comment.get("user") or comment.get("author") or {}
            c_login = (
                str(c_user.get("login") if isinstance(c_user, dict) else c_user or "")
                .strip()
                .lower()
            )
            c_body = str(comment.get("body") or "")
            if c_login in VERIFIED_ESCROW_BOT_LOGINS:
                if _ALREADY_AWARDED_COMMENT_RE.search(c_body):
                    return False
                if not _PR_CLAIM_ONLY_COMMENT_RE.search(c_body):
                    has_active_bot_comment = True
        if has_active_bot_comment:
            return True

    # 2. Check verified on-chain escrow API response or direct Algora API /bounties payload
    if platform == "onchain":
        return True

    if platform == "algora" and ("id" in raw or "reward_cents" in raw or "status" in raw):
        return True

    return False


def is_non_usdc_ledger_bounty(
    title: str,
    body: str,
    labels: list[str] | None = None,
    repo_owner: str = "",
) -> bool:
    """Return True if the issue rewards non-USDC ledger/points tokens (such as MergeOS MRG)."""
    combined = "\n".join(
        [
            title or "",
            body or "",
            " ".join(labels or []),
            repo_owner or "",
        ]
    )
    if not _NON_USDC_LEDGER_RE.search(combined):
        return False
    has_real_usdc = bool(_USDC_AMOUNT_RE.search(combined) or _REWARD_DOLLAR_RE.search(combined))
    if has_real_usdc and "[$0]" not in combined.lower():
        return False
    return True


def extract_tech_tags(title: str, body: str, labels: list[str]) -> list[str]:
    """Extract normalized technical capability tags from issue text and labels."""
    combined = f"{title}\n{body}\n{' '.join(labels)}".lower()
    tags: set[str] = set()
    for keyword, normalized_tag in _KNOWN_TECH_KEYWORDS.items():
        if re.search(rf"\b{re.escape(keyword)}\b", combined):
            tags.add(normalized_tag)
    return sorted(tags)


def parse_reward_usd_from_text(text: str) -> float:
    """Parse a USD/USDC bounty amount from labels, issue text, or escrow bot comments."""
    if not text:
        return 0.0
    match = _REWARD_DOLLAR_RE.search(text)
    if match:
        amount_str = (match.group(1) or match.group(2) or "0").replace(",", "")
        try:
            val = float(amount_str)
            if val > 0:
                return val
        except ValueError:
            pass
    usdc_match = _USDC_AMOUNT_RE.search(text)
    if usdc_match:
        try:
            val = float(usdc_match.group(1).replace(",", ""))
            if val > 0:
                return val
        except ValueError:
            pass
    generic = _GENERIC_DOLLAR_RE.search(text)
    if generic:
        try:
            return float(generic.group(1).replace(",", ""))
        except ValueError:
            return 0.0
    return 0.0


def normalize_github_issue(issue_data: dict[str, Any]) -> BountyOpportunity:
    """Normalize a GitHub REST or GraphQL issue payload into a BountyOpportunity.

    Strictly verifies escrow via comments authored by official escrow bots (algora-pbc[bot], opire-bot[bot],
    polar-sh[bot]). Never marks escrow_verified=True based on links or 'Held in escrow' text in the issue body.
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

    comment_logins, _, bot_comment_bodies = _extract_comments_metadata(issue_data)
    bot_comments_text = "\n".join(bot_comment_bodies)

    # Check non-USDC ledger token or aggregator/digest filter
    non_usdc_or_aggregator = is_non_usdc_ledger_bounty(
        title, body, labels, repo_owner=repo_owner
    ) or is_aggregator_or_digest_issue(
        {
            **issue_data,
            "repo_owner": repo_owner,
            "repo_name": repo_name,
        }
    )

    # Parse reward from explicit metadata, verified escrow bot comments, labels, or issue body
    reward_usdc = 0.0
    if "reward_usdc" in issue_data and issue_data["reward_usdc"] is not None:
        reward_usdc = float(issue_data["reward_usdc"])
    elif "reward_cents" in issue_data and issue_data["reward_cents"] is not None:
        reward_usdc = round(float(issue_data["reward_cents"]) / 100.0, 2)
    elif not non_usdc_or_aggregator:
        if bot_comments_text:
            reward_usdc = parse_reward_usd_from_text(bot_comments_text)
        if reward_usdc <= 0:
            for lbl in labels:
                amt = parse_reward_usd_from_text(lbl)
                if amt > 0:
                    reward_usdc = amt
                    break
        if reward_usdc <= 0:
            reward_usdc = parse_reward_usd_from_text(f"{title}\n{body}")

    combined_issue_text = f"{' '.join(labels)}\n{title}\n{body}"
    has_promise_to_pay = bool(_PROMISE_TO_PAY_RE.search(combined_issue_text))

    escrow_provider: str | None = issue_data.get("escrow_provider")
    if not escrow_provider:
        if any(login == "algora-pbc[bot]" for login in comment_logins):
            escrow_provider = "algora"
        elif any(login == "opire-bot[bot]" for login in comment_logins):
            escrow_provider = "opire"
        elif any(login == "polar-sh[bot]" for login in comment_logins):
            escrow_provider = "polar"

    has_verified_marker = has_verified_escrow_signature_or_marker(issue_data)

    # If an official escrow bot comment (algora-pbc[bot], opire-bot[bot], polar-sh[bot]) confirmed escrow
    # via an SVG badge where the dollar amount is embedded in an image URL rather than plain text, assign a floor
    if (
        not non_usdc_or_aggregator
        and not has_promise_to_pay
        and reward_usdc <= 0
        and has_verified_marker
    ):
        reward_usdc = 50.0

    if non_usdc_or_aggregator:
        escrow_verified = False
        escrow_provider = None
    else:
        escrow_verified = (
            has_verified_marker
            and reward_usdc > 0
            and not has_promise_to_pay
        )
        if escrow_verified and not escrow_provider:
            escrow_provider = "onchain-escrow" if str(issue_data.get("platform")) == "onchain" else "verified-escrow"

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


async def fetch_and_attach_issue_comments(
    client: httpx.AsyncClient,
    issue_data: dict[str, Any],
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    """Fetch issue comments from GitHub comments_url to inspect for official escrow bot confirmations."""
    if "comments_list" in issue_data and isinstance(issue_data["comments_list"], list):
        return issue_data["comments_list"]
    if "comments_data" in issue_data and isinstance(issue_data["comments_data"], list):
        return issue_data["comments_data"]

    comments_url = str(issue_data.get("comments_url") or "").strip()
    comments_count = int(issue_data.get("comments", 1) if "comments" in issue_data else 1)
    if not comments_url or comments_count <= 0:
        return []

    try:
        resp = await client.get(
            comments_url,
            params={"per_page": 30},
            headers=headers,
        )
        resp.raise_for_status()
        payload = resp.json()
        if isinstance(payload, list):
            issue_data["comments_list"] = payload
            return payload
    except Exception as exc:
        logger.debug("Failed to fetch issue comments from %s: %s", comments_url, exc)
    return []


class BountyBoardAdapter(ABC):
    """Abstract base adapter for any bounty board or task marketplace."""

    last_raw_candidates_fetched: int = 0

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
        self.last_raw_candidates_fetched: int = 0

    async def fetch_open_bounties(self) -> list[BountyOpportunity]:
        """Query an on-chain indexer endpoint if configured, otherwise return empty list."""
        self.last_raw_candidates_fetched = 0
        if not self.endpoint_url:
            return []

        close_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        try:
            response = await client.get(self.endpoint_url)
            response.raise_for_status()
            payload = response.json()
            items = payload.get("bounties", payload if isinstance(payload, list) else [])
            if isinstance(items, list):
                self.last_raw_candidates_fetched = len(items)
            results: list[BountyOpportunity] = []
            for item in items:
                if not isinstance(item, dict) or is_aggregator_or_digest_issue(item):
                    continue
                item_copy = dict(item)
                item_copy.setdefault("platform", "onchain")
                item_copy.setdefault("escrow_provider", "onchain-escrow")
                bounty = normalize_github_issue(item_copy)
                if not is_non_usdc_ledger_bounty(
                    bounty.title, bounty.body, bounty.labels, repo_owner=bounty.repo_owner
                ):
                    results.append(bounty)
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
        self.last_raw_candidates_fetched: int = 0

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

        if (
            _PROMISE_TO_PAY_RE.search(f"{title}\n{body}")
            or is_non_usdc_ledger_bounty(title, body, labels, repo_owner=repo_owner)
            or is_aggregator_or_digest_issue(item)
        ):
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
        self.last_raw_candidates_fetched = 0
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
            if isinstance(items, list):
                self.last_raw_candidates_fetched = len(items)
            results: list[BountyOpportunity] = []
            for item in items:
                if not isinstance(item, dict) or is_aggregator_or_digest_issue(item):
                    continue
                bounty = self.normalize_algora_item(item)
                if not is_non_usdc_ledger_bounty(
                    bounty.title, bounty.body, bounty.labels, repo_owner=bounty.repo_owner
                ):
                    results.append(bounty)
            return results
        except Exception as exc:
            logger.warning("AlgoraBountyPoller failed to fetch from %s: %s", url, exc)
            return []
        finally:
            if close_client:
                await client.aclose()


class GitHubEscrowBountyPoller(BountyBoardAdapter):
    """Async poller for GitHub issues using the 3-query discovery funnel and issue comment escrow verification."""

    DEFAULT_QUERIES: tuple[str, ...] = THREE_QUERY_DISCOVERY_FUNNEL

    def __init__(
        self,
        settings: Settings | None = None,
        http_client: httpx.AsyncClient | None = None,
        search_query: str | None = None,
        search_queries: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = http_client
        if search_queries is not None:
            self.search_queries: tuple[str, ...] = tuple(search_queries)
        elif search_query is not None:
            self.search_queries = (search_query,)
        else:
            self.search_queries = self.DEFAULT_QUERIES
        self.search_query = self.search_queries[0]
        self.last_raw_candidates_fetched: int = 0

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
        """Search GitHub REST API using the configured discovery funnel and inspect issue comments for escrow bots."""
        self.last_raw_candidates_fetched = 0
        url = f"{self.settings.GITHUB_API_URL.rstrip('/')}/search/issues"
        close_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        headers = self._headers()
        discovered: dict[str, BountyOpportunity] = {}
        comments_fetched = 0
        try:
            for query in self.search_queries:
                try:
                    response = await client.get(
                        url,
                        params={"q": query, "per_page": 25, "sort": "updated", "order": "desc"},
                        headers=headers,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    items = payload.get("items", [])
                    if isinstance(items, list):
                        self.last_raw_candidates_fetched += len(items)
                    for item in items:
                        if not isinstance(item, dict) or "pull_request" in item:
                            continue
                        if is_aggregator_or_digest_issue(item):
                            logger.debug("Skipping aggregator/digest issue from user or label.")
                            continue
                        item_copy = dict(item)
                        if comments_fetched < MAX_CANDIDATES_PER_CYCLE and item_copy.get("comments_url"):
                            await fetch_and_attach_issue_comments(client, item_copy, headers)
                            comments_fetched += 1
                        bounty = normalize_github_issue(item_copy)
                        if is_non_usdc_ledger_bounty(
                            bounty.title, bounty.body, bounty.labels, repo_owner=bounty.repo_owner
                        ):
                            logger.debug("Skipping non-USDC ledger bounty: %s", bounty.bounty_id)
                            continue
                        if bounty.bounty_id not in discovered:
                            discovered[bounty.bounty_id] = bounty
                except Exception as query_exc:
                    logger.warning("GitHubEscrowBountyPoller query '%s' failed: %s", query, query_exc)
            return list(discovered.values())
        finally:
            if close_client:
                await client.aclose()


class BaseUSDCBountyPoller(BountyBoardAdapter):
    """3-query discovery funnel poller verifying escrow via issue comments (algora-pbc[bot], opire-bot[bot], polar-sh[bot]) or USDC links."""

    DEFAULT_QUERIES: tuple[str, ...] = THREE_QUERY_DISCOVERY_FUNNEL

    def __init__(
        self,
        settings: Settings | None = None,
        http_client: httpx.AsyncClient | None = None,
        search_queries: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = http_client
        self.search_queries = tuple(search_queries) if search_queries else self.DEFAULT_QUERIES
        self.last_raw_candidates_fetched: int = 0

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token_str:
            headers["Authorization"] = f"Bearer {self.settings.github_token_str}"
        return headers

    async def fetch_open_bounties(self) -> list[BountyOpportunity]:
        """Execute the 3-query discovery funnel and inspect issue comments for official escrow confirmations."""
        self.last_raw_candidates_fetched = 0
        url = f"{self.settings.GITHUB_API_URL.rstrip('/')}/search/issues"
        close_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
        headers = self._headers()
        discovered: dict[str, BountyOpportunity] = {}
        comments_fetched = 0
        try:
            for query in self.search_queries:
                try:
                    response = await client.get(
                        url,
                        params={"q": query, "per_page": 25, "sort": "updated", "order": "desc"},
                        headers=headers,
                    )
                    response.raise_for_status()
                    payload = response.json()
                    items = payload.get("items", [])
                    if isinstance(items, list):
                        self.last_raw_candidates_fetched += len(items)
                    for item in payload.get("items", []):
                        if not isinstance(item, dict) or "pull_request" in item:
                            continue
                        if is_aggregator_or_digest_issue(item):
                            continue
                        item_copy = dict(item)
                        if comments_fetched < MAX_CANDIDATES_PER_CYCLE and item_copy.get("comments_url"):
                            await fetch_and_attach_issue_comments(client, item_copy, headers)
                            comments_fetched += 1
                        bounty = normalize_github_issue(item_copy)
                        if is_non_usdc_ledger_bounty(
                            bounty.title,
                            bounty.body,
                            bounty.labels,
                            repo_owner=bounty.repo_owner,
                        ):
                            continue
                        if bounty.bounty_id not in discovered:
                            discovered[bounty.bounty_id] = bounty
                except Exception as query_exc:
                    logger.warning("BaseUSDCBountyPoller query '%s' failed: %s", query, query_exc)
            return list(discovered.values())
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
        raw_metadata={
            "mock": True,
            "escrow_contract": "algora_verified_v2",
            "escrow_bot": "algora-pbc[bot]",
            "comments_list": [
                {
                    "user": {"login": "algora-pbc[bot]"},
                    "body": "💎 $150.00 bounty escrowed via Algora [escrow:verified]",
                }
            ],
        },
    )


class BountyScanner:
    """Concurrent multi-platform bounty discovery coordinator with 24-hour persistent seen_bounties cache."""

    def __init__(
        self,
        adapters: list[BountyBoardAdapter] | None = None,
        settings: Settings | None = None,
        seen_cache: SeenBountiesCache | None = None,
        seen_cache_path: str | Path | None = DEFAULT_SEEN_CACHE_PATH,
        seen_ttl_seconds: int = DEFAULT_SEEN_CACHE_TTL_SECONDS,
        max_candidates_per_cycle: int = MAX_CANDIDATES_PER_CYCLE,
    ) -> None:
        self.settings = settings or get_settings()
        self.max_candidates_per_cycle = int(max_candidates_per_cycle)
        self.last_raw_candidates_fetched: int = 0
        self.seen_cache = seen_cache or SeenBountiesCache(
            cache_path=seen_cache_path if adapters is None else None,
            ttl_seconds=seen_ttl_seconds,
        )
        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = [
                AlgoraBountyPoller(settings=self.settings),
                BaseUSDCBountyPoller(settings=self.settings),
            ]

    def is_seen(self, bounty_id: str, now: float | None = None) -> bool:
        """Check if a bounty_id is currently suppressed in the 24-hour seen cache."""
        return self.seen_cache.is_seen(bounty_id, now=now)

    def mark_seen(
        self,
        bounty_id: str,
        status: str = "processed",
        now: float | None = None,
    ) -> None:
        """Mark a bounty_id as processed/rejected in the 24-hour seen cache."""
        self.seen_cache.mark_seen(bounty_id, status=status, now=now)

    async def scan_all(
        self,
        verified_only: bool = False,
        skip_seen: bool = True,
    ) -> list[BountyOpportunity]:
        """Concurrently poll all configured bounty adapters, pre-filter non-USDC & aggregator issues, and skip seen bounties."""
        tasks = [adapter.fetch_open_bounties() for adapter in self.adapters]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_total = 0
        deduped: dict[str, BountyOpportunity] = {}
        for adapter, res in zip(self.adapters, results):
            if isinstance(res, Exception):
                logger.warning("Bounty adapter raised exception during scan: %s", res)
                continue
            adapter_raw = int(getattr(adapter, "last_raw_candidates_fetched", 0) or 0)
            raw_total += adapter_raw if adapter_raw > 0 else len(res)
            for bounty in res:
                if is_aggregator_or_digest_issue(bounty):
                    continue
                if is_non_usdc_ledger_bounty(
                    bounty.title,
                    bounty.body,
                    bounty.labels,
                    repo_owner=bounty.repo_owner,
                ):
                    continue
                if skip_seen and self.seen_cache.is_seen(bounty.bounty_id):
                    logger.debug("Skipping recently seen bounty (24h cache): %s", bounty.bounty_id)
                    continue
                if verified_only and not (
                    bounty.escrow_verified and has_verified_escrow_signature_or_marker(bounty)
                ):
                    continue
                if bounty.bounty_id not in deduped:
                    deduped[bounty.bounty_id] = bounty

        self.last_raw_candidates_fetched = raw_total
        ordered = list(deduped.values())
        ordered.sort(
            key=lambda b: (
                has_verified_escrow_signature_or_marker(b),
                b.escrow_verified,
                b.reward_usdc,
            ),
            reverse=True,
        )
        return ordered

    async def poll_verified_batch_until_approved(
        self,
        triage_evaluator: Any,
        max_candidates: int | None = None,
    ) -> tuple[BountyOpportunity | None, Any | None, list[dict[str, Any]]]:
        """Iterate through up to 15 unseen candidate issues per poll cycle, verifying escrow via issue comments
        or USDC links and caching every rejected bounty_id in seen_bounties until one is approved.
        """
        limit = int(max_candidates or self.max_candidates_per_cycle)
        unseen_candidates = await self.scan_all(verified_only=False, skip_seen=True)
        batch = unseen_candidates[:limit]

        evaluated_log: list[dict[str, Any]] = []
        for candidate in batch:
            # Direct pre-filter for verified escrow bot signatures or verified USDC escrow links
            if not (candidate.escrow_verified and has_verified_escrow_signature_or_marker(candidate)):
                self.mark_seen(candidate.bounty_id, status="rejected_unverified_escrow_marker")
                evaluated_log.append(
                    {
                        "bounty_id": candidate.bounty_id,
                        "status": "rejected_unverified_escrow_marker",
                        "escrow_verified": False,
                        "security_rejected": False,
                        "reason": (
                            "Rejected before triage: missing official escrow bot confirmation "
                            "(algora-pbc[bot], opire-bot[bot], polar-sh[bot]) or verified USDC escrow link."
                        ),
                        "bounty": candidate,
                        "triage": None,
                    }
                )
                continue

            triage_result = await triage_evaluator.evaluate_bounty(candidate)
            if triage_result.security_rejected:
                self.mark_seen(candidate.bounty_id, status="security_rejected")
                evaluated_log.append(
                    {
                        "bounty_id": candidate.bounty_id,
                        "status": "security_rejected",
                        "escrow_verified": triage_result.escrow_verified,
                        "security_rejected": True,
                        "reason": "; ".join(triage_result.security_reasons),
                        "bounty": candidate,
                        "triage": triage_result,
                    }
                )
                continue

            if not triage_result.approved:
                self.mark_seen(candidate.bounty_id, status="rejected")
                evaluated_log.append(
                    {
                        "bounty_id": candidate.bounty_id,
                        "status": "rejected",
                        "escrow_verified": triage_result.escrow_verified,
                        "security_rejected": False,
                        "reason": triage_result.rationale,
                        "bounty": candidate,
                        "triage": triage_result,
                    }
                )
                continue

            # Approved escrowed bounty found!
            evaluated_log.append(
                {
                    "bounty_id": candidate.bounty_id,
                    "status": "approved",
                    "escrow_verified": True,
                    "security_rejected": False,
                    "reason": triage_result.rationale,
                    "bounty": candidate,
                    "triage": triage_result,
                }
            )
            return candidate, triage_result, evaluated_log

        return None, None, evaluated_log

    @staticmethod
    def generate_mock_escrowed_bounty() -> BountyOpportunity:
        """Convenience wrapper returning the canonical dry-run mock escrowed bounty."""
        return generate_mock_escrowed_bounty()
