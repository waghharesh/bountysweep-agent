"""Unit and security tests for payouts/wallet_router.py."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import SecretStr
from solders.hash import Hash
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from web3 import Web3

from config.settings import Settings
from payouts.wallet_router import (
    EVM_ZERO_ADDRESS,
    UnauthorizedDestinationError,
    WalletRouter,
)

# Deterministic test fixtures
TEST_BASE_WORKER_KEY = (
    "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
)
TEST_BASE_COLD_WALLET = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
TEST_BASE_ATTACKER_WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

TEST_SOLANA_WORKER_KP = Keypair.from_seed(b"\x11" * 32)
TEST_SOLANA_COLD_KP = Keypair.from_seed(b"\x22" * 32)
TEST_SOLANA_ATTACKER_KP = Keypair.from_seed(b"\x33" * 32)


def _make_base_settings(
    *,
    cold_wallet: str = TEST_BASE_COLD_WALLET,
    worker_key: str = TEST_BASE_WORKER_KEY,
    threshold: float = 5.0,
    dry_run: bool = True,
) -> Settings:
    return Settings(
        CHAIN_NETWORK="base",
        OWNER_COLD_WALLET_ADDRESS=cold_wallet,
        WORKER_PRIVATE_KEY=SecretStr(worker_key),
        SWEEP_THRESHOLD_USDC=threshold,
        DRY_RUN_MODE=dry_run,
    )


def _make_solana_settings(
    *,
    cold_wallet: str = str(TEST_SOLANA_COLD_KP.pubkey()),
    worker_key: str = str(TEST_SOLANA_WORKER_KP),
    threshold: float = 5.0,
    dry_run: bool = True,
) -> Settings:
    return Settings(
        CHAIN_NETWORK="solana",
        OWNER_COLD_WALLET_ADDRESS=cold_wallet,
        WORKER_PRIVATE_KEY=SecretStr(worker_key),
        SWEEP_THRESHOLD_USDC=threshold,
        DRY_RUN_MODE=dry_run,
    )


class TestSecurityAndWhitelistEnforcement:
    """Tests for strict destination whitelist and immutability."""

    def test_empty_cold_wallet_rejected_at_init(self) -> None:
        settings = _make_base_settings(cold_wallet="")
        with pytest.raises(UnauthorizedDestinationError, match="non-empty"):
            WalletRouter(settings=settings)

    def test_zero_evm_address_rejected_at_init(self) -> None:
        settings = _make_base_settings(cold_wallet=EVM_ZERO_ADDRESS)
        with pytest.raises(UnauthorizedDestinationError, match="Zero address"):
            WalletRouter(settings=settings)

    def test_invalid_evm_address_rejected_at_init(self) -> None:
        settings = _make_base_settings(cold_wallet="0xNotAnAddress")
        with pytest.raises(UnauthorizedDestinationError, match="Invalid EVM address"):
            WalletRouter(settings=settings)

    def test_zero_solana_pubkey_rejected_at_init(self) -> None:
        settings = _make_solana_settings(
            cold_wallet="11111111111111111111111111111111"
        )
        with pytest.raises(UnauthorizedDestinationError, match="System program"):
            WalletRouter(settings=settings)

    def test_invalid_solana_pubkey_rejected_at_init(self) -> None:
        settings = _make_solana_settings(cold_wallet="invalid_base58_pubkey!!!")
        with pytest.raises(UnauthorizedDestinationError, match="Invalid Solana"):
            WalletRouter(settings=settings)

    def test_owner_cold_wallet_immutability(self) -> None:
        router = WalletRouter(settings=_make_base_settings())
        with pytest.raises(UnauthorizedDestinationError):
            router.owner_cold_wallet_address = TEST_BASE_ATTACKER_WALLET  # type: ignore[misc]
        with pytest.raises(UnauthorizedDestinationError):
            router._owner_cold_wallet = TEST_BASE_ATTACKER_WALLET
        with pytest.raises(UnauthorizedDestinationError):
            del router._owner_cold_wallet

    def test_validate_destination_blocks_non_whitelisted_base_address(self) -> None:
        router = WalletRouter(settings=_make_base_settings())
        # Exact match (case-insensitive input normalized to EIP-55) succeeds
        assert (
            router.validate_destination(TEST_BASE_COLD_WALLET.lower())
            == Web3.to_checksum_address(TEST_BASE_COLD_WALLET)
        )
        # Attacker address raises UnauthorizedDestinationError
        with pytest.raises(UnauthorizedDestinationError, match="Unauthorized payout destination"):
            router.validate_destination(TEST_BASE_ATTACKER_WALLET)

    def test_validate_destination_blocks_non_whitelisted_solana_address(self) -> None:
        router = WalletRouter(settings=_make_solana_settings())
        assert router.validate_destination(str(TEST_SOLANA_COLD_KP.pubkey())) == str(
            TEST_SOLANA_COLD_KP.pubkey()
        )
        with pytest.raises(UnauthorizedDestinationError, match="Unauthorized payout destination"):
            router.validate_destination(str(TEST_SOLANA_ATTACKER_KP.pubkey()))

    @pytest.mark.asyncio
    async def test_sweep_usdc_immediately_blocks_unauthorized_destination_even_below_threshold(
        self,
    ) -> None:
        router = WalletRouter(settings=_make_base_settings(threshold=50.0))
        with pytest.raises(UnauthorizedDestinationError):
            await router.sweep_usdc(
                current_balance_usdc=1.0,
                destination_address=TEST_BASE_ATTACKER_WALLET,
            )


class TestWorkerHotWalletClaimSigning:
    """Tests for low-balance Worker Hot Wallet claim signature generation."""

    def test_base_claim_signature_verification(self) -> None:
        router = WalletRouter(settings=_make_base_settings())
        receipt = router.sign_task_claim(
            bounty_id="algora-42",
            submission_url="https://github.com/org/repo/pull/99",
        )
        assert receipt.chain == "base"
        assert receipt.bounty_id == "algora-42"
        assert receipt.worker_wallet_address == router.worker_wallet_address
        assert (
            receipt.payload
            == "BountySweep Claim | bounty=algora-42 | url=https://github.com/org/repo/pull/99"
        )

        # Cryptographically recover signer address from receipt
        recovered = Account.recover_message(
            encode_defunct(text=receipt.payload),
            signature=receipt.signature,
        )
        assert Web3.to_checksum_address(recovered) == router.worker_wallet_address

    def test_solana_claim_signature_verification(self) -> None:
        router = WalletRouter(settings=_make_solana_settings())
        receipt = router.sign_task_claim(
            bounty_id="sol-bounty-7",
            submission_url="https://github.com/solana-labs/example/pull/12",
        )
        assert receipt.chain == "solana"
        assert receipt.worker_wallet_address == str(TEST_SOLANA_WORKER_KP.pubkey())
        assert len(receipt.signature) > 40

    def test_ephemeral_worker_wallet_in_dry_run_when_key_empty(self) -> None:
        base_router = WalletRouter(settings=_make_base_settings(worker_key="", dry_run=True))
        assert Web3.is_address(base_router.worker_wallet_address)

        sol_router = WalletRouter(settings=_make_solana_settings(worker_key="", dry_run=True))
        assert isinstance(Pubkey.from_string(sol_router.worker_wallet_address), Pubkey)


class TestThresholdAndSweepExecution:
    """Tests for SWEEP_THRESHOLD_USDC and transaction building on Base and Solana."""

    @pytest.mark.asyncio
    async def test_balance_below_or_equal_threshold_does_not_sweep(self) -> None:
        router = WalletRouter(
            settings=_make_base_settings(threshold=5.0),
            simulated_balance_usdc=4.5,
        )
        assert await router.sweep_usdc() is None
        # Exactly at threshold (5.0 <= 5.0) also does not sweep
        assert await router.sweep_usdc(current_balance_usdc=5.0) is None

    @pytest.mark.asyncio
    async def test_base_usdc_dry_run_sweep_above_threshold(self) -> None:
        router = WalletRouter(
            settings=_make_base_settings(threshold=5.0, dry_run=True),
            simulated_balance_usdc=150.25,
        )
        receipt = await router.sweep_usdc()
        assert receipt is not None
        assert receipt.chain == "base"
        assert receipt.destination_address == Web3.to_checksum_address(
            TEST_BASE_COLD_WALLET
        )
        assert receipt.amount_usdc == pytest.approx(150.25)
        assert receipt.amount_base_units == 150_250_000
        assert receipt.dry_run is True
        assert receipt.broadcasted is False
        assert receipt.status == "dry_run_signed"
        assert receipt.tx_hash.startswith("0x")
        assert len(receipt.tx_hash) == 66

    @pytest.mark.asyncio
    async def test_solana_usdc_dry_run_sweep_above_threshold(self) -> None:
        router = WalletRouter(
            settings=_make_solana_settings(threshold=5.0, dry_run=True),
            simulated_balance_usdc=42.5,
        )
        receipt = await router.sweep_usdc()
        assert receipt is not None
        assert receipt.chain == "solana"
        assert receipt.destination_address == str(TEST_SOLANA_COLD_KP.pubkey())
        assert receipt.amount_usdc == pytest.approx(42.5)
        assert receipt.amount_base_units == 42_500_000
        assert receipt.dry_run is True
        assert receipt.broadcasted is False
        assert receipt.status == "dry_run_signed"
        assert len(receipt.tx_hash) > 32

    @pytest.mark.asyncio
    async def test_base_live_broadcast_mocked(self) -> None:
        w3 = Web3()
        w3.eth.get_transaction_count = MagicMock(return_value=7)  # type: ignore[method-assign]
        type(w3.eth).gas_price = property(lambda self: Web3.to_wei(0.1, "gwei"))  # type: ignore[method-assign]
        type(w3.eth).chain_id = property(lambda self: 8453)  # type: ignore[method-assign]
        w3.eth.send_raw_transaction = MagicMock(return_value=b"\xab" * 32)  # type: ignore[method-assign]

        router = WalletRouter(
            settings=_make_base_settings(threshold=5.0, dry_run=False),
            web3_client=w3,
            simulated_balance_usdc=25.0,
        )
        receipt = await router.sweep_usdc()
        assert receipt is not None
        assert receipt.broadcasted is True
        assert receipt.dry_run is False
        assert receipt.status == "broadcasted"
        assert receipt.destination_address == Web3.to_checksum_address(
            TEST_BASE_COLD_WALLET
        )
        w3.eth.send_raw_transaction.assert_called_once()

    @pytest.mark.asyncio
    async def test_solana_live_broadcast_mocked(self) -> None:
        mock_sol_client = AsyncMock()
        mock_sol_client.get_latest_blockhash.return_value = SimpleNamespace(
            value=SimpleNamespace(blockhash=Hash.default())
        )
        mock_sol_client.send_raw_transaction.return_value = SimpleNamespace(
            value="5MockedSolanaTxSignature11111111111111111111111"
        )

        router = WalletRouter(
            settings=_make_solana_settings(threshold=5.0, dry_run=False),
            solana_client=mock_sol_client,
            simulated_balance_usdc=80.0,
        )
        receipt = await router.sweep_usdc()
        assert receipt is not None
        assert receipt.broadcasted is True
        assert receipt.dry_run is False
        assert receipt.status == "broadcasted"
        assert receipt.destination_address == str(TEST_SOLANA_COLD_KP.pubkey())
        assert receipt.tx_hash == "5MockedSolanaTxSignature11111111111111111111111"
        mock_sol_client.send_raw_transaction.assert_called_once()
