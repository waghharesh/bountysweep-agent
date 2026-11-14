"""Typed Pydantic configuration for BountySweep Agent."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _normalize_no_proxy_env() -> None:
    """Remove bare IPv6 loopback tokens ('::1', '[::1]') from NO_PROXY/no_proxy that break httpx URLPattern."""
    for var in ("NO_PROXY", "no_proxy"):
        val = os.environ.get(var)
        if val and "::1" in val:
            cleaned = ",".join(
                part.strip()
                for part in val.split(",")
                if part.strip() and part.strip() not in ("::1", "[::1]")
            )
            os.environ[var] = cleaned


_normalize_no_proxy_env()



class Settings(BaseSettings):
    """Immutable-aware application configuration loaded from environment / .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # AI / LLM Configuration
    GEMINI_API_KEY: SecretStr = Field(
        default=SecretStr(""),
        description="Gemini API key (compatible with standard AIza... or AQ... prefixed keys).",
    )
    GEMINI_MODEL: str = Field(
        default="gemini-3-flash-preview",
        description="Gemini model identifier used for bounty triage and patch generation.",
    )

    # GitHub & Discovery Configuration
    GITHUB_TOKEN: SecretStr = Field(
        default=SecretStr(""),
        description="Fine-grained GitHub PAT with public_repo scope only.",
    )
    GITHUB_API_URL: str = Field(
        default="https://api.github.com",
        description="GitHub REST API base URL.",
    )
    GITHUB_GRAPHQL_URL: str = Field(
        default="https://api.github.com/graphql",
        description="GitHub GraphQL API endpoint.",
    )
    ALGORA_API_URL: str = Field(
        default="https://console.algora.io/api",
        description="Algora bounty platform API base URL.",
    )
    POLL_INTERVAL_SECONDS: int = Field(
        default=300,
        ge=10,
        description="Polling interval in seconds for continuous bounty discovery.",
    )

    # Triage & Evaluation Thresholds
    MIN_TRIAGE_SCORE: int = Field(
        default=70,
        ge=0,
        le=100,
        description="Minimum triage score (0-100) required to attempt solving a bounty.",
    )

    # Docker Sandbox Isolation Limits
    SANDBOX_IMAGE: str = Field(
        default="python:3.12-slim",
        description="Base container image for isolated test execution.",
    )
    SANDBOX_TIMEOUT_SECONDS: int = Field(
        default=120,
        ge=5,
        le=600,
        description="Hard execution timeout in seconds for container test runs.",
    )
    SANDBOX_CPU_PERIOD: int = Field(
        default=100_000,
        description="Docker CPU period in microseconds.",
    )
    SANDBOX_CPU_QUOTA: int = Field(
        default=100_000,
        description="Docker CPU quota in microseconds (100000 / 100000 = 1 vCPU).",
    )
    SANDBOX_MEM_LIMIT: str = Field(
        default="1g",
        description="Docker memory cap (1GB RAM).",
    )

    # Wallet & Payout Settlement Configuration
    WORKER_PRIVATE_KEY: SecretStr = Field(
        default=SecretStr(""),
        description="Isolated burner hot wallet private key for signing claims and gas only.",
    )
    OWNER_COLD_WALLET_ADDRESS: str = Field(
        default="",
        description="Immutable cold wallet destination address for all settled USDC payouts.",
    )
    CHAIN_NETWORK: Literal["base", "solana"] = Field(
        default="base",
        description="Target settlement network ('base' or 'solana').",
    )
    SWEEP_THRESHOLD_USDC: float = Field(
        default=5.0,
        gt=0.0,
        description="USDC balance threshold above which funds are swept to OWNER_COLD_WALLET_ADDRESS.",
    )
    BASE_RPC_URL: str = Field(
        default="https://mainnet.base.org",
        description="Base EVM JSON-RPC endpoint.",
    )
    BASE_USDC_CONTRACT_ADDRESS: str = Field(
        default="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        description="Canonical USDC ERC-20 contract address on Base mainnet (6 decimals).",
    )
    SOLANA_RPC_URL: str = Field(
        default="https://api.mainnet-beta.solana.com",
        description="Solana JSON-RPC endpoint.",
    )
    SOLANA_USDC_MINT_ADDRESS: str = Field(
        default="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        description="Canonical USDC SPL token mint address on Solana mainnet (6 decimals).",
    )

    # Operational Safety & Alerting
    DRY_RUN_MODE: bool = Field(
        default=True,
        description="When True, logs PR drafts and wallet actions without broadcasting live transactions.",
    )
    TELEGRAM_BOT_TOKEN: SecretStr = Field(
        default=SecretStr(""),
        description="Telegram Bot token for real-time notifications and kill-switch commands.",
    )
    TELEGRAM_CHAT_ID: str = Field(
        default="",
        description="Authorized Telegram chat ID for notifications and control commands.",
    )

    @field_validator("GEMINI_API_KEY", mode="before")
    @classmethod
    def validate_gemini_key(cls, value: str | SecretStr | None) -> SecretStr:
        """Accept empty string (for dry-run/tests), standard keys, or 'AQ' prefixed keys."""
        if value is None:
            return SecretStr("")
        raw = value.get_secret_value() if isinstance(value, SecretStr) else str(value).strip()
        return SecretStr(raw)

    @field_validator("CHAIN_NETWORK", mode="before")
    @classmethod
    def normalize_chain_network(cls, value: str) -> str:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("OWNER_COLD_WALLET_ADDRESS", mode="before")
    @classmethod
    def strip_cold_wallet(cls, value: str | None) -> str:
        if value is None:
            return ""
        return str(value).strip()

    @property
    def gemini_api_key_str(self) -> str:
        """Return unwrapped Gemini API key string (supports standard or AQ-prefixed keys)."""
        return self.GEMINI_API_KEY.get_secret_value()

    @property
    def is_aq_prefixed_gemini_key(self) -> bool:
        """Check whether the configured Gemini API key uses the 'AQ' prefix format."""
        return self.gemini_api_key_str.startswith("AQ")

    @property
    def github_token_str(self) -> str:
        """Return unwrapped GitHub token string."""
        return self.GITHUB_TOKEN.get_secret_value()

    @property
    def worker_private_key_str(self) -> str:
        """Return unwrapped worker hot wallet private key string."""
        return self.WORKER_PRIVATE_KEY.get_secret_value()

    @property
    def telegram_bot_token_str(self) -> str:
        """Return unwrapped Telegram bot token string."""
        return self.TELEGRAM_BOT_TOKEN.get_secret_value()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()
