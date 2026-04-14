//! Solana transaction broadcast via dWallet Ed25519 signature.
//!
//! Takes the pre-built transaction message (with durable nonce) and the
//! Ed25519 signature from Ika, assembles a wire-format transaction, and
//! sends it via Solana RPC.

use crate::error::*;
use super::BroadcastResult;

/// Broadcast a signed Solana transaction.
///
/// `signature` is the 64-byte Ed25519 signature from the dWallet network.
/// `dwallet_pubkey` is the 32-byte Ed25519 public key (= Solana address).
/// `rpc_url` is the Solana RPC endpoint.
pub fn assemble_and_broadcast(
    destination: [u8; 32],
    amount_lamports: u64,
    signature: &[u8],
    dwallet_pubkey: &[u8],
    rpc_url: &str,
) -> Result<BroadcastResult> {
    if signature.len() != 64 {
        return Err(anyhow!(
            "expected 64-byte Ed25519 signature, got {} bytes",
            signature.len()
        ));
    }
    if dwallet_pubkey.len() != 32 {
        return Err(anyhow!(
            "expected 32-byte Ed25519 pubkey, got {} bytes",
            dwallet_pubkey.len()
        ));
    }

    // The sign_message sent to Ika was the full Solana transaction message.
    // We need to reconstruct it to build the wire transaction.
    // Read the nonce account and nonce value from the intent params
    // (passed via BroadcastInputs).
    //
    // For now, the broadcast is done by directly assembling the wire format:
    // [num_signatures(compact-u16)] [signature(64)] [message_bytes]
    //
    // But we need the message bytes. They're not passed to us directly.
    // Let's use the Solana SDK to rebuild the transaction.

    let _ = destination;
    let _ = amount_lamports;

    // The actual broadcast happens in execute_via_ika where we have access
    // to the full sign_message. For Solana, we assemble the wire tx there
    // instead of going through the broadcast dispatcher.
    //
    // This function is a placeholder — the real Solana broadcast is handled
    // directly in the execute flow.
    Err(anyhow!(
        "Solana broadcast should use the direct path in execute_via_ika, not the chain dispatcher"
    ))
}
