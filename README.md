# BountySweep Agent

Autonomous Python 3.12+ coding and automation bounty discovery, Gemini triage, isolated Docker sandbox verification, and immutable cold-wallet USDC settlement service.

---

## Architecture Overview

```
bountysweep-agent/
├── config/
│   └── settings.py          # Typed, frozen Pydantic settings (.env loader)
├── discovery/
│   └── scanner.py           # Async Algora + GitHub escrow pollers & on-chain task board adapters
├── evaluator/
│   └── triage.py            # google-genai triage (0–100 score) + prompt-injection & malicious-repo filter
├── sandbox/
│   └── runner.py            # Ephemeral Docker sandbox (network_mode="none", 1 vCPU, 1GB RAM, 120s timeout, ro rootfs)
├── payouts/
│   └── wallet_router.py     # Worker burner wallet claim signer + Base (EVM) / Solana USDC sweep to OWNER_COLD_WALLET_ADDRESS
├── notifications/
│   └── telegram_bot.py      # Async Telegram alerts & /status, /pause, /resume kill-switch commands
├── api/
│   └── main.py              # FastAPI status, webhook, and autonomous cycle orchestration server
├── tests/                   # Comprehensive pytest unit & integration test suite
├── Dockerfile               # Production Python 3.12-slim container image
├── docker-compose.yml       # Compose service definition with resource caps
└── .env.example             # Configuration template
```

---

## Quick Start & Environment Setup

### 1. Create a Python 3.12+ Virtual Environment & Install Dependencies

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### 2. Create the Isolated Burner Worker Hot Wallet (`WORKER_PRIVATE_KEY`)

The **Worker Hot Wallet** is an isolated, low-balance burner wallet used **solely** for signing task claims/submissions and paying negligible L2/Solana gas fees to sweep settled USDC. Never store treasury funds in the worker wallet.

#### Option A: Base (EVM) Burner Wallet
Generate a fresh EVM burner keypair locally using Python:

```bash
.venv/bin/python -c "from eth_account import Account; acct = Account.create(); print('WORKER_ADDRESS:', acct.address); print('WORKER_PRIVATE_KEY:', acct.key.hex())"
```
Fund the printed `WORKER_ADDRESS` with ~$1–$2 worth of Base ETH for gas only.

#### Option B: Solana Burner Wallet
Generate a fresh Solana burner keypair locally using `solders`:

```bash
.venv/bin/python -c "from solders.keypair import Keypair; kp = Keypair(); print('WORKER_PUBKEY:', kp.pubkey()); print('WORKER_PRIVATE_KEY:', str(kp))"
```
Fund the printed `WORKER_PUBKEY` with ~0.02 SOL for transaction fees only.

---

### 3. Configure `OWNER_COLD_WALLET_ADDRESS` & `.env`

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Set your hardware/cold wallet address in `OWNER_COLD_WALLET_ADDRESS`:
- **Strict Whitelist Enforcement**: `payouts/wallet_router.py` binds `OWNER_COLD_WALLET_ADDRESS` as an immutable, read-only destination at initialization and validates every transfer with constant-time comparison (`hmac.compare_digest`).
- Any attempt to pass or mutate a destination address other than `OWNER_COLD_WALLET_ADDRESS` raises `UnauthorizedDestinationError` and emits a `[Security Rejection]` alert via Telegram.
- Whenever the Worker Hot Wallet's USDC balance exceeds `SWEEP_THRESHOLD_USDC` (default `5.0` USDC), the excess balance is automatically swept to `OWNER_COLD_WALLET_ADDRESS`.

Required `.env` variables:
- `GEMINI_API_KEY`: Standard `AIza...` or `AQ...` prefixed Gemini API key.
- `GITHUB_TOKEN`: Fine-grained GitHub PAT scoped strictly to `public_repo`.
- `WORKER_PRIVATE_KEY`: Hex private key (Base) or base58 keypair string (Solana) for the burner worker wallet.
- `OWNER_COLD_WALLET_ADDRESS`: Your cold wallet address on Base (`0x...`) or Solana (base58 Pubkey).
- `CHAIN_NETWORK`: `base` or `solana`.
- `SWEEP_THRESHOLD_USDC`: `5.0` (minimum USDC balance that triggers an automatic sweep).
- `TELEGRAM_BOT_TOKEN` & `TELEGRAM_CHAT_ID`: Telegram bot credentials for real-time notifications (`[Bounty Claimed]`, `[PR/Solution Submitted]`, `[USDC Payout Settled + TX Hash]`, `[Security Rejection]`) and `/status` & `/pause` kill-switch control.

---

### 4. Switching from `DRY_RUN_MODE=true` to `DRY_RUN_MODE=false`

By default, `DRY_RUN_MODE=true` is enabled so initial runs log PR drafts, sandbox test results, and signed wallet sweep payloads without broadcasting live transactions or opening public PRs.

Before switching to live production (`DRY_RUN_MODE=false`):
1. Run the verification test suite:
   ```bash
   .venv/bin/pytest -v
   ```
2. Start the server in dry-run mode and trigger a test cycle:
   ```bash
   .venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000
   ```
   ```bash
   curl -X POST http://localhost:8000/cycle/run -H "Content-Type: application/json" -d '{"use_mock_bounty": true}'
   ```
3. Verify in the logs/status (`GET /status`) that `OWNER_COLD_WALLET_ADDRESS` matches your cold storage wallet character-for-character and that Telegram alerts arrive in your configured chat.
4. Update `.env`:
   ```ini
   DRY_RUN_MODE=false
   ```
5. Restart the service via Docker Compose:
   ```bash
   docker compose up -d --build
   ```
