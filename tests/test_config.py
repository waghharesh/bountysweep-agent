"""Unit tests for config/settings.py and .env.example."""

from pathlib import Path
import pytest
from pydantic import ValidationError

from config.settings import Settings


def test_env_example_contains_required_keys() -> None:
    env_example = Path("/home/antigravity/.env.example").read_text(encoding="utf-8")
    required_keys = [
        "GEMINI_API_KEY=",
        "GITHUB_TOKEN=",
        "WORKER_PRIVATE_KEY=",
        "OWNER_COLD_WALLET_ADDRESS=",
        "CHAIN_NETWORK=base",
        "SWEEP_THRESHOLD_USDC=5.0",
        "DRY_RUN_MODE=true",
        "TELEGRAM_BOT_TOKEN=",
        "TELEGRAM_CHAT_ID=",
    ]
    for key in required_keys:
        assert key in env_example, f"Missing {key} in .env.example"


def test_settings_supports_standard_and_aq_prefixed_gemini_keys() -> None:
    std_settings = Settings(GEMINI_API_KEY="AIzaSyStandardKey12345")
    assert std_settings.gemini_api_key_str == "AIzaSyStandardKey12345"
    assert std_settings.is_aq_prefixed_gemini_key is False

    aq_settings = Settings(GEMINI_API_KEY="AQ.Ab8RN6L1234567890_token")
    assert aq_settings.gemini_api_key_str == "AQ.Ab8RN6L1234567890_token"
    assert aq_settings.is_aq_prefixed_gemini_key is True


def test_settings_frozen_immutability() -> None:
    settings = Settings(
        OWNER_COLD_WALLET_ADDRESS="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        CHAIN_NETWORK="base",
        SWEEP_THRESHOLD_USDC=5.0,
        DRY_RUN_MODE=True,
    )
    with pytest.raises(ValidationError):
        settings.OWNER_COLD_WALLET_ADDRESS = "0x1111111111111111111111111111111111111111"  # type: ignore[misc]
