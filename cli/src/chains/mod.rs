//! Destination-chain transaction assembly + broadcast.
//!
//! Mirrors `clear_wallet::chains` (which builds the on-chain *preimage* per
//! chain) on the off-chain side: this module takes the dwallet network's
//! 64-byte ECDSA signature, the signing preimage, and the dwallet's pubkey,
//! and produces a chain-native signed transaction that can be broadcast to
//! the destination chain's RPC.
//!
//! Adding a new chain: implement a sub-module exposing `assemble_signed` +
//! `broadcast`, then add a dispatch arm in [`broadcast_signed_tx`]. The CLI
//! command surface stays the same (`proposal execute --broadcast --rpc-url
//! <URL>`); only this dispatcher needs to know about the new chain.

use crate::error::*;
use serde::Serialize;

pub mod bitcoin;
pub mod evm;
pub mod solana_broadcast;
pub mod zcash;

/// Chain-specific data the broadcast layer needs in addition to the
/// `(preimage, signature, pubkey)` triple. EVM is purely defined by the
/// EIP-1559 RLP envelope it signed (which is the preimage), so it carries
/// no extra fields. Bitcoin BIP143 commits to its outputs as a *hash*
/// (`hashOutputs = sha256d(amount || script)`) inside the preimage —
/// to assemble the actual segwit transaction we need the original outputs
/// back, so they're plumbed in here from the proposal's params.
pub enum BroadcastInputs {
    /// Solana SOL transfer via dWallet Ed25519 signature.
    Solana {
        destination: [u8; 32],
        amount_lamports: u64,
    },
    /// EVM EIP-1559 native transfer or ERC-20 — nothing extra needed.
    Evm,
    /// Bitcoin P2WPKH single-input single-output spend.
    BitcoinP2wpkh {
        prev_txid: [u8; 32],
        prev_vout: u32,
        sequence: u32,
        recipient_pkh: [u8; 20],
        send_amount_sats: u64,
        lock_time: u32,
    },
    /// Zcash transparent P2PKH single-input single-output spend.
    ZcashTransparent {
        header: u32,
        version_group_id: u32,
        prev_txid: [u8; 32],
        prev_vout: u32,
        sender_pkh: [u8; 20],
        recipient_pkh: [u8; 20],
        send_amount_zat: u64,
        lock_time: u32,
        expiry_height: u32,
    },
}

/// Result of broadcasting a signed transaction to a destination chain.
///
/// Chain-agnostic shape so the CLI can emit a uniform JSON record regardless
/// of which chain we're on. `tx_id` is the chain-native identifier (Ethereum
/// tx hash, Bitcoin txid, etc.); `explorer_url` is best-effort and may be
/// `None` for chains we don't have a default explorer for.
#[derive(Debug, Serialize)]
pub struct BroadcastResult {
    pub chain: &'static str,
    pub chain_kind: u8,
    pub tx_id: String,
    pub raw_tx_hex: String,
    pub recovery_v: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
}

/// Build a signed transaction for `chain_kind` from the dwallet network's
/// `(r, s)` and broadcast it via `rpc_url`. The CLI calls this from
/// `proposal execute --broadcast` after `ika_sign` + presign + sign have
/// completed and the 64-byte signature is in hand.
///
/// `dwallet_pubkey_compressed` is the 33-byte SEC1 compressed secp256k1
/// pubkey of the signing dwallet — needed to recover `v` for ECDSA chains
/// and to push the witness item for P2WPKH spends.
///
/// `inputs` carries any chain-specific data that isn't recoverable from
/// the preimage alone — see [`BroadcastInputs`].
pub fn broadcast_signed_tx(
    chain_kind: u8,
    inputs: BroadcastInputs,
    preimage: &[u8],
    signature: &[u8],
    dwallet_pubkey_compressed: &[u8],
    rpc_url: &str,
) -> Result<BroadcastResult> {
    if signature.len() != 64 {
        return Err(anyhow!(
            "expected 64-byte ECDSA signature (r||s), got {} bytes",
            signature.len()
        ));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..]);

    match chain_kind {
        // 0 = solana — Ed25519 signed transaction.
        0 => {
            let BroadcastInputs::Solana { destination, amount_lamports } = inputs else {
                return Err(anyhow!("solana chain_kind requires BroadcastInputs::Solana"));
            };
            solana_broadcast::assemble_and_broadcast(
                destination,
                amount_lamports,
                signature,
                dwallet_pubkey_compressed,
                rpc_url,
            )
        }
        // 1 = evm_1559, 4 = evm_1559_erc20 — same EIP-1559 envelope.
        1 | 4 => {
            if !matches!(inputs, BroadcastInputs::Evm) {
                return Err(anyhow!("EVM chain_kind requires BroadcastInputs::Evm"));
            }
            evm::assemble_and_broadcast(preimage, &r, &s, dwallet_pubkey_compressed, rpc_url)
        }
        // 2 = bitcoin_p2wpkh — BIP143 witness assembly + Esplora REST.
        2 => {
            let BroadcastInputs::BitcoinP2wpkh {
                prev_txid,
                prev_vout,
                sequence,
                recipient_pkh,
                send_amount_sats,
                lock_time,
            } = inputs
            else {
                return Err(anyhow!(
                    "bitcoin_p2wpkh chain_kind requires BroadcastInputs::BitcoinP2wpkh"
                ));
            };
            bitcoin::assemble_and_broadcast(
                bitcoin::SpendInputs {
                    prev_txid,
                    prev_vout,
                    sequence,
                    recipient_pkh,
                    send_amount_sats,
                    lock_time,
                },
                &r,
                &s,
                dwallet_pubkey_compressed,
                rpc_url,
            )
        }
        // 3 = zcash_transparent — P2PKH assembly + lightwalletd or Zcash RPC.
        3 => {
            let BroadcastInputs::ZcashTransparent {
                header, version_group_id,
                prev_txid, prev_vout, sender_pkh,
                recipient_pkh, send_amount_zat,
                lock_time, expiry_height,
            } = inputs
            else {
                return Err(anyhow!(
                    "zcash_transparent chain_kind requires BroadcastInputs::ZcashTransparent"
                ));
            };
            zcash::assemble_and_broadcast(
                zcash::SpendInputs {
                    header, version_group_id,
                    prev_txid, prev_vout, sender_pkh,
                    recipient_pkh, send_amount_zat,
                    lock_time, expiry_height,
                },
                &r, &s,
                dwallet_pubkey_compressed,
                rpc_url,
            )
        }
        // 0 = solana — local CPI executor, never goes through this path.
        n => Err(anyhow!(
            "broadcast not implemented for chain_kind {n}"
        )),
    }
}
