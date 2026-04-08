# clear-msig-ika

A clear-sign multisig wallet for Solana, with native support for **cross-chain signing via [Ika](https://ika.xyz) dWallets**. Signers approve human-readable messages via ed25519 signatures instead of signing opaque transactions — and the same flow can drive a 2PC-MPC-secured signature on Ethereum, Bitcoin, ERC-20 tokens, and any future chain Ika supports.

Fork of [`ChewingGlass/clear-msig`](https://github.com/ChewingGlass/clear-msig) extending it with Ika dWallet binding, per-dWallet ownership locks, chain-specific transaction builders (EIP-1559, BIP143 P2WPKH, ERC-20 transfer), and one-shot `proposal execute --broadcast` that drives the dwallet network sign and pushes the signed tx to the destination chain in a single command.

Built with [Quasar](https://github.com/blueshift-gg/quasar).

## How It Works

**Wallets** hold a set of **intents** — pre-configured transaction blueprints that define what the wallet can do. Each intent specifies its own proposers, approvers, thresholds, and timelock.

Three meta-intents are created with every wallet:
- **AddIntent** (index 0) — add new intents
- **RemoveIntent** (index 1) — disable existing intents
- **UpdateIntent** (index 2) — replace an intent's definition

Custom intents define parameters, accounts, instructions, and a human-readable template. For example, a SOL transfer intent with template `"transfer {1} lamports to {0}"` produces messages like:

```
expires 2030-01-01 00:00:00: approve transfer 1000000000 lamports to 9abc... | wallet: treasury proposal: 42
```

Signers see exactly what they're approving.

## Architecture

```
Wallet (PDA: ["clear_wallet", sha256(name)])
  └── Vault (PDA: ["vault", wallet]) — holds Solana funds, signs CPIs
  └── Intent 0: AddIntent
  └── Intent 1: RemoveIntent
  └── Intent 2: UpdateIntent
  └── Intent 3+: Custom intents (transfer SOL, EVM/BTC sign, etc.)

Proposal (PDA: ["proposal", intent, index_le_bytes])
  └── params_data: encoded parameter values
  └── approval_bitmap / cancellation_bitmap: u16 bitmaps over approver list
  └── rent_refund: address to receive rent on cleanup

Per-(wallet, chain) dWallet binding (only for cross-chain intents)
IkaConfig (PDA: ["ika_config", wallet, chain_kind])
  └── (wallet, dwallet, user_pubkey, signature_scheme)

Per-dWallet ownership lock
DwalletOwnership (PDA: ["dwallet_owner", dwallet])
  └── (wallet, dwallet) — first binder wins, immutable thereafter
```

### Proposal Lifecycle

1. **Propose** — a proposer signs a human-readable message and submits it with parameters
2. **Approve** — approvers sign the same message; bitmap tracks who approved
3. **Execute** — once threshold is met and timelock elapsed, anyone can execute
4. **Cleanup** — reclaim rent from executed/cancelled proposals

Vote switching is supported: approving clears your cancellation, and vice versa.

## Project Structure

```
programs/clear-wallet/          # On-chain program (Quasar)
  src/
    state/                      # Wallet, Intent, Proposal, IkaConfig, DwalletOwnership
    instructions/               # create_wallet, propose, approve, cancel, execute,
                                # cleanup, bind_dwallet, ika_sign
    chains/                     # EVM/BTC preimage builders (chain-specific tx
                                # serializers used by ika_sign)
    utils/                      # Message building, base58, datetime, sha256, ika_cpi
  client/                       # Off-chain helpers (PDA derivation, intent builder, JSON parsing)
cli/                            # CLI tool (clear-msig)
  src/
    chains/                     # CLI-side broadcast adapters (mirror of programs/.../chains)
    quasar_client/              # Vendored quasar-generated instruction structs
examples/intents/               # Example intent JSON files (SOL, EVM, BTC, ERC-20, ...)
```

## Prerequisites

- Rust
- [Quasar CLI](https://github.com/blueshift-gg/quasar)
- Agave (Solana validator) **v3.1+** — required for the SBPFv2 r2 data pointer feature

```bash
agave-install init 3.1.12
```

## Build

```bash
# Build the on-chain program
cd programs/clear-wallet
quasar build

# Build the CLI
cargo build -p clear-msig-cli
```

## Test

```bash
# Run the on-chain + client test suites
cargo test
```

## Deploy to Localnet

```bash
# Start a local validator
solana-test-validator --reset &

# Build (from the program directory)
cd programs/clear-wallet
quasar build

# Deploy (from the workspace root, where target/deploy/ lives)
cd ../..
quasar deploy -u http://localhost:8899 --skip-build \
  --program-keypair target/deploy/clear_wallet-keypair.json

# Point CLI at localnet
clear-msig config set --url http://localhost:8899
clear-msig config set --signer ~/.config/solana/id.json
```

## CLI Usage

### Create a Wallet

```bash
clear-msig wallet create \
  --name "treasury" \
  --proposers <addr1>,<addr2> \
  --approvers <addr1>,<addr2> \
  --threshold 2 \
  --cancellation-threshold 1 \
  --timelock 3600
```

### Add a Custom Intent

Intent definitions are JSON files with parameters, accounts, instructions, and a template. Governance (proposers, approvers, threshold) comes from CLI flags.

```bash
clear-msig intent add \
  --wallet "treasury" \
  --file examples/intents/transfer_sol.json \
  --proposers <addr1> \
  --approvers <addr1>,<addr2> \
  --threshold 2
```

This creates a proposal via AddIntent. Approve and execute it to activate.

### Propose, Approve, Execute

```bash
# Create a proposal against a custom intent
clear-msig proposal create \
  --wallet "treasury" \
  --intent-index 3 \
  --param destination=<address> \
  --param amount=1000000000

# Approve it
clear-msig proposal approve \
  --wallet "treasury" \
  --proposal <proposal-address>

# Execute once threshold is met
clear-msig proposal execute \
  --wallet "treasury" \
  --proposal <proposal-address>
```

### Other Commands

```bash
clear-msig wallet show --name "treasury"
clear-msig intent list --wallet "treasury"
clear-msig proposal list --wallet "treasury"
clear-msig proposal show --proposal <address>
clear-msig proposal cleanup --proposal <address>
clear-msig config show
```

All commands output JSON to stdout.

## End-to-End Example

Full localnet walkthrough — create a wallet, add a SOL transfer intent, transfer 1 SOL from the vault:

```bash
# Setup
SELF=$(solana address)
clear-msig config set --url http://localhost:8899
clear-msig config set --signer ~/.config/solana/id.json

# 1. Create wallet
clear-msig wallet create \
  --name "demo" \
  --proposers "$SELF" \
  --approvers "$SELF" \
  --threshold 1

# 2. Add a SOL transfer intent (proposes via AddIntent)
clear-msig intent add \
  --wallet "demo" \
  --file examples/intents/transfer_sol.json \
  --proposers "$SELF" \
  --approvers "$SELF" \
  --threshold 1
# Note the proposal address from the output

# 3. Approve and execute the add-intent proposal
clear-msig proposal approve --wallet "demo" --proposal <add-proposal>
clear-msig proposal execute --wallet "demo" --proposal <add-proposal>

# 4. Verify the new intent (index 3)
clear-msig intent list --wallet "demo"

# 5. Fund the vault
VAULT=$(clear-msig wallet show --name "demo" | jq -r .vault)
solana transfer "$VAULT" 2 --allow-unfunded-recipient

# 6. Create a transfer proposal
clear-msig proposal create \
  --wallet "demo" \
  --intent-index 3 \
  --param "destination=<recipient-address>" \
  --param "amount=1000000000"

# 7. Approve and execute the transfer
clear-msig proposal approve --wallet "demo" --proposal <transfer-proposal>
clear-msig proposal execute --wallet "demo" --proposal <transfer-proposal>

# 8. Verify
solana balance <recipient-address>  # Should show 1 SOL
```

## Intent JSON Format

Intent files define the transaction blueprint without governance fields:

```json
{
  "params": [
    { "name": "destination", "type": "address" },
    { "name": "amount", "type": "u64" }
  ],
  "accounts": [
    { "source": { "static": "11111111111111111111111111111111" }, "signer": false, "writable": false },
    { "source": "vault", "signer": true, "writable": true },
    { "source": { "param": 0 }, "signer": false, "writable": true }
  ],
  "instructions": [
    {
      "program_account_index": 0,
      "account_indexes": [1, 2],
      "data_segments": [
        { "literal": [2, 0, 0, 0] },
        { "param": { "param_index": 1, "encoding": "le_u64" } }
      ]
    }
  ],
  "template": "transfer {1} lamports to {0}"
}
```

### Account Sources

| Source | Description |
|--------|-------------|
| `{ "static": "<address>" }` | Hardcoded address (e.g., system program) |
| `{ "param": <index> }` | Address from a parameter |
| `"vault"` | The wallet's vault PDA |
| `{ "pda": { "program_account_index": N, "seeds": [...] } }` | Derived PDA |
| `{ "has_one": { "account_index": N, "byte_offset": M } }` | Read address from another account's data |

### Parameter Types

`address` (32-byte Solana pubkey), `u64`, `i64`, `string`, `bool`, `u8`, `u16`, `u32`, `u128`, `bytes20` (EVM addresses, Bitcoin HASH160), `bytes32` (tx hashes, scriptPubKey hashes)

### Data Encodings

`raw_address`, `le_u64`, `le_i64`, `bool`, `le_u8`, `le_u16`, `le_u32`, `le_u128`

### Template Format Specs

A template `{N}` substitutes the Nth parameter using its default rendering. For numeric params you can append a decimal-shift spec to display fixed-point values:

```
"send {2:10^18} ETH to {1} (nonce {0})"
```

`{2:10^18}` divides `param[2]` (a `u64` wei value) by 10¹⁸ and prints the result with trailing zeros trimmed — so `100000000000000` renders as `0.0001`. Works for any decimal scale up to `10^19`. Use `10^9` for gwei, `10^6` for USDC, etc. Both the on-chain renderer (in `programs/clear-wallet/src/utils/message.rs`) and the CLI's renderer (in `cli/src/message.rs`) implement this byte-for-byte identically so the signed message verifies on chain.

See `examples/intents/transfer_sol.json` and `examples/intents/transfer_tokens.json` for complete examples.

## Two-Identity Model

The CLI manages two distinct identities:

- **Payer** — standard Solana keypair that signs transactions and pays fees
- **Signer** — ed25519 identity for multisig message signing (proposer/approver)

These can be the same keypair (default) or different — e.g., a relayer pays gas while a hardware wallet holder signs messages.

```bash
clear-msig config set --keypair ~/payer.json
clear-msig config set --signer ~/signer.json
```

## Cross-Chain Signing via Ika dWallets

clear-msig-ika integrates with the [Ika](https://ika.xyz) 2PC-MPC dWallet network so a Solana multisig can custody and sign transactions on **other** chains. The flow is the same propose / approve / execute as a local Solana intent, but at execute time the program drives an `ika_sign` instead of a vault CPI.

### Supported chains (pre-alpha)

| `chain` value      | What it signs                                            |
|--------------------|----------------------------------------------------------|
| `evm_1559`         | Native EVM EIP-1559 transactions (ETH, mainnet/L2s/Sepolia) |
| `evm_1559_erc20`   | ERC-20 `transfer(address,uint256)` calls inside an EIP-1559 envelope |
| `bitcoin_p2wpkh`   | BIP143 P2WPKH spends (segwit v0)                          |

Each chain has its own preimage builder under `programs/clear-wallet/src/chains/` that takes the intent's params + `tx_template` and produces the exact bytes the destination chain hashes for signing. The same preimage builder runs on the off-chain CLI before broadcast, so the bytes that get signed and the bytes that get broadcast cannot diverge.

### How a multisig owns a dWallet

The Ika dWallet program enforces a single canonical CPI authority per caller program: `find_program_address(&[CPI_AUTHORITY_SEED], caller_program_id)`. That means every clear-msig wallet under the same program ID *would* share the same on-chain authority over any dWallet bound to it — anyone could squat the binding by creating an `IkaConfig` pointing at a dWallet that someone else funded.

clear-msig-ika fixes this one layer up with a **per-dWallet ownership lock**: a `DwalletOwnership` PDA at `["dwallet_owner", dwallet]` is created on the first `bind_dwallet` call and records which clear-msig wallet did the binding. Every subsequent `bind_dwallet` (e.g. fanning the same dWallet out to a second `chain_kind`) and every `ika_sign` re-reads this account and rejects if the calling wallet doesn't match. Once a dWallet has been bound, no other multisig under the same program can drive a sign against it — even though the dWallet's actual on-chain authority is still the program-wide CPI PDA.

### Bind a dWallet to a chain

```bash
clear-msig wallet add-chain \
  --wallet "treasury" \
  --chain evm_1559 \
  --dwallet-program <ika-dwallet-program-id>
```

This runs Ika DKG via gRPC, transfers the freshly-DKG'd dWallet's authority to the clear-wallet CPI PDA, claims the `DwalletOwnership` lock for `"treasury"`, and creates an `IkaConfig` PDA. The output JSON has the dWallet pubkey — derive the destination-chain address from that (e.g. `keccak256(uncompressed_pubkey)[12..]` for EVM).

To fan an existing dWallet out to a second chain (so a single dWallet pubkey covers both EVM-native sends and ERC-20 transfers):

```bash
clear-msig wallet add-chain \
  --wallet "treasury" \
  --chain evm_1559_erc20 \
  --dwallet-program <ika-dwallet-program-id> \
  --existing-dwallet-pubkey <hex-33-bytes> \
  --existing-dwallet-addr <hex-32-bytes>
```

The `--existing-dwallet-addr` is the 32-byte Ika session identifier from a prior binding's `wallet chains` output. If another `IkaConfig` on the same wallet already references this dWallet, the CLI auto-recovers it and the flag becomes optional.

### Propose, approve, broadcast in one shot

```bash
# 1. Add a Sepolia transfer intent (the format spec gives clear-sign 0.0001 ETH instead of raw wei)
cat > /tmp/sepolia.json <<'EOF'
{
  "chain": "evm_1559",
  "tx_template": {
    "evm_1559": { "chain_id": 11155111, "gas_limit": 21000,
                  "max_priority_fee_per_gas": 1500000000,
                  "max_fee_per_gas": 30000000000 }
  },
  "params": [
    { "name": "nonce",     "type": "u64" },
    { "name": "to",        "type": "bytes20" },
    { "name": "value_wei", "type": "u64" },
    { "name": "data",      "type": "string" }
  ],
  "template": "send {2:10^18} ETH to {1} (sepolia nonce {0})"
}
EOF

clear-msig intent add --wallet "treasury" --file /tmp/sepolia.json \
  --proposers <addr> --approvers <addr1>,<addr2> --threshold 2

# 2. Approve + execute the AddIntent (standard local flow)
# ... assume the new intent is at index 3 ...

# 3. Propose the cross-chain transaction
clear-msig proposal create --wallet "treasury" --intent-index 3 \
  --param nonce=0 --param to=0x000000000000000000000000000000000000dEaD \
  --param value_wei=100000000000000 --param data=

# 4. Approvers sign — same flow as any local intent
clear-msig proposal approve --wallet "treasury" --proposal <P>
clear-msig proposal approve --wallet "treasury" --proposal <P> \
  --signer-ledger --ledger-account 0       # hardware approver

# 5. Execute and broadcast in one shot
clear-msig proposal execute --wallet "treasury" --proposal <P> \
  --dwallet-program <ika-dwallet-program-id> \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --broadcast
```

Step 5 builds the chain-specific preimage from the intent's params, sends an `ika_sign` instruction (which writes a `MessageApproval` PDA), waits for the dwallet network to commit the signature, recovers `v` for ECDSA, splices the signature into an EIP-1559 RLP envelope (or builds the segwit witness for BTC, or the ABI-encoded calldata for ERC-20), and posts the signed transaction to the destination chain via `eth_sendRawTransaction` / Esplora `POST /tx`. The output JSON includes the destination-chain `tx_id` so you can paste it straight into a block explorer.

Without `--broadcast` the CLI returns the raw signed bytes in the JSON output and the caller is responsible for pushing them.

### Hardware wallet approvers

`clear-msig` works with the Ledger Solana app for the multisig signing step. Use `--signer-ledger` (with optional `--ledger-account <N>`) on any command that needs a signer (`proposal approve`, `proposal create`, `intent add`, etc.). The signed message body is the same human-readable string the device displays — Ledger users see exactly what they're approving.

```bash
clear-msig proposal approve --wallet "treasury" --proposal <P> \
  --signer-ledger --ledger-account 0
```

## Known Issues

- `proposal cleanup` fails on localnet due to a quasar framework issue with `close` attribute. Works conceptually but blocked by quasar-svm's `UnbalancedInstruction` error in tests and a `MissingRequiredSignature` on the real validator.
- Requires Agave v3.1+ for the SBPFv2 r2 data pointer. Earlier versions crash with `Access violation at address 0xfffffffffffffff8`.
