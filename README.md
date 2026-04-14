# clear-msig-ika

A clear-sign multisig wallet on Solana that controls assets on **any chain** via [Ika](https://ika.xyz) dWallet 2PC-MPC signing. Signers approve human-readable messages via Ed25519 signatures — the same flow drives native transactions on Solana, Ethereum, Bitcoin, Zcash, and any future chain Ika supports.

All transaction signing goes through the Ika dWallet network. There is no vault PDA — the dWallet's public key IS the address on each chain.

Built with [Quasar](https://github.com/blueshift-gg/quasar). Fork of [`ChewingGlass/clear-msig`](https://github.com/ChewingGlass/clear-msig).

## Supported Chains

| `chain` value | Curve | Signing Scheme | What it signs |
|---|---|---|---|
| `solana` | Curve25519 | EdDSA + SHA-512 | SOL transfers via durable nonce |
| `evm_1559` | Secp256k1 | ECDSA + Keccak-256 | Native EVM EIP-1559 (ETH/L2s) |
| `evm_1559_erc20` | Secp256k1 | ECDSA + Keccak-256 | ERC-20 `transfer(address,uint256)` |
| `bitcoin_p2wpkh` | Secp256k1 | ECDSA + Double-SHA-256 | BIP143 P2WPKH spends |
| `zcash_transparent` | Secp256k1 | ECDSA + BLAKE2b-256 | ZIP-243 Sapling transparent P2PKH |

## How It Works

**Wallets** hold **intents** — pre-configured transaction blueprints. Each intent specifies its chain, parameters, proposers, approvers, thresholds, and timelock.

Three meta-intents are created with every wallet:
- **AddIntent** (0), **RemoveIntent** (1), **UpdateIntent** (2)

Custom intents (index 3+) define the chain-specific transaction. Approvers see a human-readable message:

```
expires 2030-01-01 00:00:00: approve transfer 1000000000 lamports to 9abc... | wallet: treasury proposal: 42
```

### Execution Flow (all chains)

```
propose → approve (2-of-3) → execute:
  1. On-chain ika_sign builds preimage → keccak256 → MessageApproval PDA
  2. CLI presign via Ika gRPC
  3. CLI sign via Ika gRPC → 64-byte signature
  4. CLI assembles chain-native transaction + broadcasts
```

## Architecture

```
Wallet (PDA: ["clear_wallet", sha256(name)])
  └── Intent 0: AddIntent (meta)
  └── Intent 1: RemoveIntent (meta)
  └── Intent 2: UpdateIntent (meta)
  └── Intent 3+: Custom (Solana/EVM/BTC/ZEC transfers)

IkaConfig (PDA: ["ika_config", wallet, chain_kind])
  └── (wallet, dwallet, user_pubkey, signature_scheme)

DwalletOwnership (PDA: ["dwallet_owner", dwallet])
  └── First binder wins — immutable ownership lock

Proposal (PDA: ["proposal", intent, index])
  └── params_data, approval/cancellation bitmaps
```

## Quick Start

### Prerequisites

- Rust, [Quasar CLI](https://github.com/blueshift-gg/quasar), Agave v3.1+

### Build

```bash
quasar build                        # On-chain program
cargo build -p clear-msig-cli       # CLI
```

### Deploy + Configure

```bash
solana program deploy target/deploy/clear_wallet.so
clear-msig config set --url https://api.devnet.solana.com
clear-msig config set --signer ~/.config/solana/id.json
```

### Create a 2-of-3 Multisig

```bash
clear-msig wallet create \
  --name "treasury" \
  --proposers $S1,$S2,$S3 \
  --approvers $S1,$S2,$S3 \
  --threshold 2
```

### Add a Chain

```bash
# Solana (Curve25519 Ed25519 dWallet)
clear-msig wallet add-chain --wallet "treasury" --chain solana \
  --dwallet-program <DWALLET_PROGRAM_ID>

# EVM (Secp256k1 ECDSA dWallet)
clear-msig wallet add-chain --wallet "treasury" --chain evm_1559 \
  --dwallet-program <DWALLET_PROGRAM_ID>

# Check addresses
clear-msig wallet chains --wallet "treasury"
```

### Propose + Approve + Execute

```bash
# Add a transfer intent
clear-msig intent add --wallet "treasury" \
  --file examples/intents/solana_transfer.json \
  --proposers $S1,$S2,$S3 --approvers $S1,$S2,$S3 --threshold 2
# Approve + execute the AddIntent proposal...

# Propose a SOL transfer
clear-msig proposal create --wallet "treasury" --intent-index 3 \
  --param "destination=<RECIPIENT>" \
  --param "amount=1000000000" \
  --param "nonce_value=0x<NONCE_HEX>"

# Approve (2 of 3)
clear-msig proposal approve --wallet "treasury" --proposal <P> --signer signer2.json
clear-msig proposal approve --wallet "treasury" --proposal <P> --signer signer3.json

# Execute + broadcast
clear-msig proposal execute --wallet "treasury" --proposal <P> \
  --dwallet-program <DWALLET_PROGRAM_ID> \
  --rpc-url https://api.devnet.solana.com --broadcast
```

### EVM Example (Sepolia)

```bash
clear-msig proposal create --wallet "treasury" --intent-index 4 \
  --param nonce=0 \
  --param to=0x000000000000000000000000000000000000dEaD \
  --param value_wei=1000000000000000 \
  --param data=

# After 2/3 approval:
clear-msig proposal execute --wallet "treasury" --proposal <P> \
  --dwallet-program <DWALLET_PROGRAM_ID> \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com --broadcast
```

## Intent JSON Format

```json
{
  "chain": "solana",
  "tx_template": { "solana": { "nonce_account": "<NONCE_PUBKEY>" } },
  "params": [
    { "name": "destination", "type": "address" },
    { "name": "amount", "type": "u64" },
    { "name": "nonce_value", "type": "bytes32" }
  ],
  "template": "transfer {1} lamports to {0}"
}
```

See `examples/intents/` for all chain examples: `solana_transfer.json`, `evm_transfer.json`, `erc20_transfer.json`, `btc_transfer.json`, `zcash_transfer.json`.

### Parameter Types

`address`, `u64`, `i64`, `string`, `bool`, `u8`, `u16`, `u32`, `u128`, `bytes20`, `bytes32`

### Template Decimal Shift

`{2:10^18}` renders `100000000000000` as `0.0001` (wei to ETH).

## Two-Identity Model

- **Payer** — Solana keypair that signs transactions and pays fees
- **Signer** — Ed25519 identity for multisig message signing (can be Ledger)

```bash
clear-msig config set --keypair ~/payer.json
clear-msig config set --signer ~/signer.json
# Or: --signer-ledger --ledger-account 0
```

## dWallet Ownership Model

The Ika dWallet program has a single CPI authority per caller program. clear-msig adds a **per-dWallet ownership lock** (`DwalletOwnership` PDA) so each multisig wallet truly owns its dWallet — no other wallet under the same program can sign with it.

## Project Structure

```
programs/clear-wallet/src/
  state/          Wallet, Intent, Proposal, IkaConfig, DwalletOwnership
  instructions/   create_wallet, propose, approve, cancel, execute (meta-intents),
                  cleanup, bind_dwallet, ika_sign
  chains/         Solana, EVM, Bitcoin, Zcash preimage builders
  utils/          Message building, ika_cpi, hashing
  client/         PDA derivation, intent builder, JSON parsing

cli/src/
  commands/       wallet, intent, proposal, config
  chains/         Solana, EVM, Bitcoin, Zcash broadcast adapters
  ika.rs          gRPC DKG/presign/sign, PDA helpers, preimage builders

examples/intents/ Intent JSON files for all chains
```

## Known Issues

- Requires Agave v3.1+ (SBPFv2 r2 data pointer)
- Ika pre-alpha: mock signer, not production MPC
- Solana intents require a durable nonce account with authority set to the dWallet pubkey
