"""Crypto Payouts & Security Router for Base (EVM) and Solana USDC settlements.

Enforces strict destination whitelisting to OWNER_COLD_WALLET_ADDRESS and separates
the low-balance Worker Hot Wallet (used exclusively for claim signatures and gas)
from the immutable Owner Cold Wallet.
"""

from __future__ import annotations

import hmac
import logging
import struct
from typing import Any, Literal

from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import BaseModel, ConfigDict, Field
from solana.rpc.async_api import AsyncClient
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from web3 import Web3

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

# Constants
USDC_DECIMALS = 6
USDC_BASE_MULTIPLIER = 10**USDC_DECIMALS
EVM_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
BASE_MAINNET_CHAIN_ID = 8453
SPL_TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string(
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
)

# Minimal ERC-20 ABI for balanceOf and transfer
ERC20_MINIMAL_ABI: list[dict[str, Any]] = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": "function",
    },
]


class UnauthorizedDestinationError(PermissionError):
    """Raised on any attempt to route funds to a non-whitelisted destination address
    or mutate the immutable OWNER_COLD_WALLET_ADDRESS."""


class ClaimSignatureReceipt(BaseModel):
    """Cryptographic receipt produced by the Worker Hot Wallet when claiming a bounty."""

    model_config = ConfigDict(frozen=True)

    bounty_id: str = Field(..., description="Unique identifier of the claimed bounty.")
    chain: Literal["base", "solana"] = Field(
        ..., description="Settlement blockchain network ('base' or 'solana')."
    )
    worker_wallet_address: str = Field(
        ..., description="Public address of the low-balance Worker Hot Wallet."
    )
    payload: str = Field(..., description="Canonical claim message that was signed.")
    signature: str = Field(..., description="Hex or base58 encoded cryptographic signature.")
    dry_run: bool = Field(..., description="Whether the signature was generated in dry-run mode.")


class SweepTransactionReceipt(BaseModel):
    """Receipt of a USDC sweep transaction from the Worker Hot Wallet to OWNER_COLD_WALLET_ADDRESS."""

    model_config = ConfigDict(frozen=True)

    chain: Literal["base", "solana"] = Field(
        ..., description="Settlement blockchain network ('base' or 'solana')."
    )
    worker_wallet_address: str = Field(
        ..., description="Source Worker Hot Wallet public address."
    )
    destination_address: str = Field(
        ..., description="Verified OWNER_COLD_WALLET_ADDRESS receiving the swept funds."
    )
    amount_usdc: float = Field(..., gt=0.0, description="Swept USDC amount in human units.")
    amount_base_units: int = Field(
        ..., gt=0, description="Swept USDC amount in 6-decimal base units."
    )
    tx_hash: str = Field(..., description="Transaction hash (hex for Base, base58 for Solana).")
    dry_run: bool = Field(..., description="Whether the sweep ran in dry-run mode.")
    broadcasted: bool = Field(
        ..., description="Whether the signed transaction was broadcasted to the network."
    )
    status: str = Field(..., description="Sweep execution status.")


class WalletRouter:
    """Dual-chain (Base EVM & Solana) wallet router with strict destination whitelist enforcement."""

    _locked: bool = False

    def __init__(
        self,
        settings: Settings | None = None,
        web3_client: Web3 | None = None,
        solana_client: AsyncClient | None = None,
        simulated_balance_usdc: float | None = None,
    ) -> None:
        resolved_settings = settings or get_settings()
        chain: Literal["base", "solana"] = resolved_settings.CHAIN_NETWORK

        # Validate and normalize the immutable cold wallet destination at init
        raw_cold_wallet = resolved_settings.OWNER_COLD_WALLET_ADDRESS.strip()
        if not raw_cold_wallet:
            raise UnauthorizedDestinationError(
                "OWNER_COLD_WALLET_ADDRESS must be configured and non-empty."
            )

        normalized_cold_wallet = self._normalize_and_validate_address(raw_cold_wallet, chain)

        object.__setattr__(self, "_settings", resolved_settings)
        object.__setattr__(self, "_chain", chain)
        object.__setattr__(self, "_owner_cold_wallet", normalized_cold_wallet)
        object.__setattr__(self, "_simulated_balance_usdc", simulated_balance_usdc)

        # Initialize clients
        if chain == "base":
            w3 = web3_client or Web3(Web3.HTTPProvider(resolved_settings.BASE_RPC_URL))
            object.__setattr__(self, "_w3", w3)
            object.__setattr__(self, "_solana_client", None)
        else:
            sol_client = solana_client or AsyncClient(resolved_settings.SOLANA_RPC_URL)
            object.__setattr__(self, "_w3", None)
            object.__setattr__(self, "_solana_client", sol_client)

        # Initialize low-balance Worker Hot Wallet
        self._init_worker_wallet(resolved_settings, chain)

        # Lock critical attributes against post-init tampering
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_locked", False) and name in {
            "owner_cold_wallet_address",
            "_owner_cold_wallet",
            "_chain",
            "_settings",
            "settings",
        }:
            raise UnauthorizedDestinationError(
                f"Security violation: cannot mutate immutable attribute '{name}' on WalletRouter."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name in {
            "owner_cold_wallet_address",
            "_owner_cold_wallet",
            "_chain",
            "_settings",
            "settings",
        }:
            raise UnauthorizedDestinationError(
                f"Security violation: cannot delete immutable attribute '{name}' on WalletRouter."
            )
        object.__delattr__(self, name)

    def _init_worker_wallet(
        self, settings: Settings, chain: Literal["base", "solana"]
    ) -> None:
        raw_key = settings.worker_private_key_str.strip()

        if chain == "base":
            if not raw_key:
                if settings.DRY_RUN_MODE:
                    logger.warning(
                        "WORKER_PRIVATE_KEY is empty in DRY_RUN_MODE; generating ephemeral Base worker wallet."
                    )
                    acct = Account.create()
                else:
                    raise ValueError(
                        "WORKER_PRIVATE_KEY is required when DRY_RUN_MODE=False on Base."
                    )
            else:
                normalized_key = raw_key if raw_key.startswith("0x") else f"0x{raw_key}"
                acct = Account.from_key(normalized_key)

            object.__setattr__(self, "_evm_account", acct)
            object.__setattr__(self, "_solana_keypair", None)
            object.__setattr__(
                self, "_worker_wallet_address", Web3.to_checksum_address(acct.address)
            )
        else:
            if not raw_key:
                if settings.DRY_RUN_MODE:
                    logger.warning(
                        "WORKER_PRIVATE_KEY is empty in DRY_RUN_MODE; generating ephemeral Solana worker wallet."
                    )
                    kp = Keypair()
                else:
                    raise ValueError(
                        "WORKER_PRIVATE_KEY is required when DRY_RUN_MODE=False on Solana."
                    )
            else:
                kp = self._parse_solana_private_key(raw_key)

            object.__setattr__(self, "_evm_account", None)
            object.__setattr__(self, "_solana_keypair", kp)
            object.__setattr__(self, "_worker_wallet_address", str(kp.pubkey()))

    @staticmethod
    def _parse_solana_private_key(raw_key: str) -> Keypair:
        """Parse a Solana private key from base58 string, hex string, or JSON byte array."""
        cleaned = raw_key.strip()
        if cleaned.startswith("[") and cleaned.endswith("]"):
            import json

            byte_list = json.loads(cleaned)
            return Keypair.from_bytes(bytes(byte_list))
        try:
            return Keypair.from_base58_string(cleaned)
        except Exception:
            hex_str = cleaned[2:] if cleaned.startswith("0x") else cleaned
            raw_bytes = bytes.fromhex(hex_str)
            if len(raw_bytes) == 32:
                return Keypair.from_seed(raw_bytes)
            return Keypair.from_bytes(raw_bytes)

    @staticmethod
    def _normalize_and_validate_address(
        address: str, chain: Literal["base", "solana"]
    ) -> str:
        """Validate address format and reject zero/burn addresses."""
        if not address or not isinstance(address, str) or not address.strip():
            raise UnauthorizedDestinationError("Destination address cannot be empty.")

        candidate = address.strip()

        if chain == "base":
            if not Web3.is_address(candidate):
                raise UnauthorizedDestinationError(
                    f"Invalid EVM address format on Base: '{candidate}'."
                )
            checksummed = Web3.to_checksum_address(candidate)
            if checksummed.lower() == EVM_ZERO_ADDRESS.lower():
                raise UnauthorizedDestinationError(
                    "Zero address (0x0000...0000) is forbidden as a payout destination."
                )
            return checksummed

        if chain == "solana":
            try:
                pubkey = Pubkey.from_string(candidate)
            except Exception as exc:
                raise UnauthorizedDestinationError(
                    f"Invalid Solana base58 Pubkey: '{candidate}'."
                ) from exc

            if bytes(pubkey) == b"\x00" * 32 or str(pubkey) == "11111111111111111111111111111111":
                raise UnauthorizedDestinationError(
                    "System program / zero pubkey (1111...1111) is forbidden as a payout destination."
                )
            return str(pubkey)

        raise UnauthorizedDestinationError(f"Unsupported chain network: '{chain}'.")

    @property
    def settings(self) -> Settings:
        """Return router configuration settings."""
        return self._settings

    @property
    def chain(self) -> Literal["base", "solana"]:
        """Return active settlement chain ('base' or 'solana')."""
        return self._chain

    @property
    def owner_cold_wallet_address(self) -> str:
        """Return the immutable whitelisted OWNER_COLD_WALLET_ADDRESS."""
        return self._owner_cold_wallet

    @property
    def worker_wallet_address(self) -> str:
        """Return the public address of the Worker Hot Wallet."""
        return self._worker_wallet_address

    def set_simulated_balance(self, balance_usdc: float | None) -> None:
        """Set or clear simulated worker USDC balance for dry-run / testing."""
        object.__setattr__(self, "_simulated_balance_usdc", balance_usdc)

    def validate_destination(self, target_address: str | None = None) -> str:
        """Enforce strict destination whitelist against OWNER_COLD_WALLET_ADDRESS.

        Raises UnauthorizedDestinationError if target_address is invalid or does not
        exactly match the configured OWNER_COLD_WALLET_ADDRESS.
        """
        whitelisted = self._owner_cold_wallet
        if not whitelisted:
            raise UnauthorizedDestinationError(
                "OWNER_COLD_WALLET_ADDRESS is not configured."
            )

        if target_address is None:
            return whitelisted

        normalized_target = self._normalize_and_validate_address(
            target_address, self._chain
        )

        if not hmac.compare_digest(
            normalized_target.encode("utf-8"), whitelisted.encode("utf-8")
        ):
            raise UnauthorizedDestinationError(
                f"Unauthorized payout destination '{target_address}'. "
                f"Only OWNER_COLD_WALLET_ADDRESS ('{whitelisted}') is permitted."
            )

        return whitelisted

    def sign_task_claim(self, bounty_id: str, submission_url: str) -> ClaimSignatureReceipt:
        """Sign a canonical bounty claim message with the Worker Hot Wallet."""
        clean_bounty_id = bounty_id.strip()
        clean_url = submission_url.strip()
        if not clean_bounty_id or not clean_url:
            raise ValueError("Both bounty_id and submission_url must be non-empty.")

        payload = f"BountySweep Claim | bounty={clean_bounty_id} | url={clean_url}"

        if self._chain == "base":
            message = encode_defunct(text=payload)
            signed = Account.sign_message(message, private_key=self._evm_account.key)
            sig_hex = signed.signature.hex()
            signature_str = sig_hex if sig_hex.startswith("0x") else f"0x{sig_hex}"
        else:
            sig = self._solana_keypair.sign_message(payload.encode("utf-8"))
            signature_str = str(sig)

        return ClaimSignatureReceipt(
            bounty_id=clean_bounty_id,
            chain=self._chain,
            worker_wallet_address=self._worker_wallet_address,
            payload=payload,
            signature=signature_str,
            dry_run=self._settings.DRY_RUN_MODE,
        )

    @staticmethod
    def derive_associated_token_address(owner: Pubkey, mint: Pubkey) -> Pubkey:
        """Derive the canonical Associated Token Account (ATA) PDA on Solana."""
        ata, _bump = Pubkey.find_program_address(
            [bytes(owner), bytes(SPL_TOKEN_PROGRAM_ID), bytes(mint)],
            ASSOCIATED_TOKEN_PROGRAM_ID,
        )
        return ata

    async def get_worker_usdc_balance(self) -> float:
        """Query the Worker Hot Wallet's USDC balance (or return simulated balance if set)."""
        if self._simulated_balance_usdc is not None:
            return float(self._simulated_balance_usdc)

        if self._chain == "base":
            usdc_address = Web3.to_checksum_address(
                self._settings.BASE_USDC_CONTRACT_ADDRESS
            )
            contract = self._w3.eth.contract(
                address=usdc_address, abi=ERC20_MINIMAL_ABI
            )
            raw_balance: int = contract.functions.balanceOf(
                self._worker_wallet_address
            ).call()
            return raw_balance / USDC_BASE_MULTIPLIER

        # Solana SPL Token balance query
        owner_pubkey = Pubkey.from_string(self._worker_wallet_address)
        mint_pubkey = Pubkey.from_string(self._settings.SOLANA_USDC_MINT_ADDRESS)
        ata_pubkey = self.derive_associated_token_address(owner_pubkey, mint_pubkey)

        resp = await self._solana_client.get_token_account_balance(ata_pubkey)
        value = getattr(resp, "value", None)
        if value is None:
            return 0.0
        ui_amount = getattr(value, "ui_amount", None)
        if ui_amount is not None:
            return float(ui_amount)
        amount_str = getattr(value, "amount", "0")
        return int(amount_str) / USDC_BASE_MULTIPLIER

    async def sweep_usdc(
        self,
        current_balance_usdc: float | None = None,
        destination_address: str | None = None,
    ) -> SweepTransactionReceipt | None:
        """Sweep USDC above SWEEP_THRESHOLD_USDC exclusively to OWNER_COLD_WALLET_ADDRESS.

        Always validates destination_address first before checking threshold so any
        unauthorized destination attempt raises UnauthorizedDestinationError immediately.
        """
        verified_destination = self.validate_destination(destination_address)

        balance = (
            float(current_balance_usdc)
            if current_balance_usdc is not None
            else await self.get_worker_usdc_balance()
        )

        if balance <= self._settings.SWEEP_THRESHOLD_USDC:
            logger.info(
                "Worker USDC balance (%.6f) is at or below threshold (%.6f); skipping sweep.",
                balance,
                self._settings.SWEEP_THRESHOLD_USDC,
            )
            return None

        amount_base_units = int(round(balance * USDC_BASE_MULTIPLIER))
        if amount_base_units <= 0:
            return None

        if self._chain == "base":
            return await self._sweep_base_usdc(
                verified_destination=verified_destination,
                amount_usdc=balance,
                amount_base_units=amount_base_units,
            )

        return await self._sweep_solana_usdc(
            verified_destination=verified_destination,
            amount_usdc=balance,
            amount_base_units=amount_base_units,
        )

    async def _sweep_base_usdc(
        self,
        verified_destination: str,
        amount_usdc: float,
        amount_base_units: int,
    ) -> SweepTransactionReceipt:
        """Build, sign, and optionally broadcast an ERC-20 USDC transfer on Base."""
        # Double-check destination whitelist immediately prior to building tx
        target_checksum = self.validate_destination(verified_destination)
        usdc_contract_addr = Web3.to_checksum_address(
            self._settings.BASE_USDC_CONTRACT_ADDRESS
        )
        contract = self._w3.eth.contract(
            address=usdc_contract_addr, abi=ERC20_MINIMAL_ABI
        )

        if self._settings.DRY_RUN_MODE:
            nonce = 0
            gas_price = Web3.to_wei(0.05, "gwei")
            chain_id = BASE_MAINNET_CHAIN_ID
        else:
            nonce = self._w3.eth.get_transaction_count(self._worker_wallet_address)
            gas_price = self._w3.eth.gas_price
            chain_id = self._w3.eth.chain_id

        tx_dict = contract.functions.transfer(
            target_checksum, amount_base_units
        ).build_transaction(
            {
                "chainId": chain_id,
                "gas": 65_000,
                "gasPrice": gas_price,
                "nonce": nonce,
                "from": self._worker_wallet_address,
            }
        )

        signed_tx = self._w3.eth.account.sign_transaction(
            tx_dict, private_key=self._evm_account.key
        )

        if self._settings.DRY_RUN_MODE:
            tx_hash_hex = signed_tx.hash.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = f"0x{tx_hash_hex}"
            logger.info(
                "[DRY-RUN] Signed Base USDC sweep of %.6f USDC to %s (tx_hash=%s)",
                amount_usdc,
                target_checksum,
                tx_hash_hex,
            )
            return SweepTransactionReceipt(
                chain="base",
                worker_wallet_address=self._worker_wallet_address,
                destination_address=target_checksum,
                amount_usdc=amount_usdc,
                amount_base_units=amount_base_units,
                tx_hash=tx_hash_hex,
                dry_run=True,
                broadcasted=False,
                status="dry_run_signed",
            )

        raw_tx = getattr(signed_tx, "raw_transaction", None) or getattr(
            signed_tx, "rawTransaction"
        )
        sent_hash = self._w3.eth.send_raw_transaction(raw_tx)
        tx_hash_hex = sent_hash.hex() if hasattr(sent_hash, "hex") else str(sent_hash)
        if not tx_hash_hex.startswith("0x"):
            tx_hash_hex = f"0x{tx_hash_hex}"

        return SweepTransactionReceipt(
            chain="base",
            worker_wallet_address=self._worker_wallet_address,
            destination_address=target_checksum,
            amount_usdc=amount_usdc,
            amount_base_units=amount_base_units,
            tx_hash=tx_hash_hex,
            dry_run=False,
            broadcasted=True,
            status="broadcasted",
        )

    async def _sweep_solana_usdc(
        self,
        verified_destination: str,
        amount_usdc: float,
        amount_base_units: int,
    ) -> SweepTransactionReceipt:
        """Build, sign, and optionally broadcast an SPL Token TransferChecked tx on Solana."""
        target_pubkey_str = self.validate_destination(verified_destination)

        worker_pubkey = self._solana_keypair.pubkey()
        owner_cold_pubkey = Pubkey.from_string(target_pubkey_str)
        mint_pubkey = Pubkey.from_string(self._settings.SOLANA_USDC_MINT_ADDRESS)

        source_ata = self.derive_associated_token_address(worker_pubkey, mint_pubkey)
        destination_ata = self.derive_associated_token_address(
            owner_cold_pubkey, mint_pubkey
        )

        # SPL Token TransferChecked instruction (index 12 + u64 amount LE + u8 decimals)
        ix_data = struct.pack("<BQB", 12, amount_base_units, USDC_DECIMALS)
        transfer_ix = Instruction(
            program_id=SPL_TOKEN_PROGRAM_ID,
            accounts=[
                AccountMeta(pubkey=source_ata, is_signer=False, is_writable=True),
                AccountMeta(pubkey=mint_pubkey, is_signer=False, is_writable=False),
                AccountMeta(pubkey=destination_ata, is_signer=False, is_writable=True),
                AccountMeta(pubkey=worker_pubkey, is_signer=True, is_writable=False),
            ],
            data=ix_data,
        )

        if self._settings.DRY_RUN_MODE:
            recent_blockhash = Hash.default()
        else:
            bh_resp = await self._solana_client.get_latest_blockhash()
            recent_blockhash = bh_resp.value.blockhash

        msg = MessageV0.try_compile(
            payer=worker_pubkey,
            instructions=[transfer_ix],
            address_lookup_table_accounts=[],
            recent_blockhash=recent_blockhash,
        )
        tx = VersionedTransaction(msg, [self._solana_keypair])
        tx_sig = str(tx.signatures[0])

        if self._settings.DRY_RUN_MODE:
            logger.info(
                "[DRY-RUN] Signed Solana USDC sweep of %.6f USDC to %s (sig=%s)",
                amount_usdc,
                target_pubkey_str,
                tx_sig,
            )
            return SweepTransactionReceipt(
                chain="solana",
                worker_wallet_address=self._worker_wallet_address,
                destination_address=target_pubkey_str,
                amount_usdc=amount_usdc,
                amount_base_units=amount_base_units,
                tx_hash=tx_sig,
                dry_run=True,
                broadcasted=False,
                status="dry_run_signed",
            )

        send_resp = await self._solana_client.send_raw_transaction(bytes(tx))
        broadcast_sig = str(getattr(send_resp, "value", tx_sig))

        return SweepTransactionReceipt(
            chain="solana",
            worker_wallet_address=self._worker_wallet_address,
            destination_address=target_pubkey_str,
            amount_usdc=amount_usdc,
            amount_base_units=amount_base_units,
            tx_hash=broadcast_sig,
            dry_run=False,
            broadcasted=True,
            status="broadcasted",
        )
