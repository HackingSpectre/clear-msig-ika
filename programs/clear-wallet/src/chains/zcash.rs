//! Zcash transparent P2PKH (single-input, single-output) preimage builder.
//!
//! Builds a **simplified preimage** for Zcash Sapling (v4) transparent-only
//! transactions. The final signing digest is `BLAKE2b-256(preimage,
//! "ZcashSigHash" || consensus_branch_id)`, computed off-chain by the dWallet
//! network via `DWalletSignatureScheme::EcdsaBlake2b256` with
//! `Blake2bMessageMetadata { personal: "ZcashSigHash\xbb\x09\xb8\x76" }`.
//!
//! Unlike Bitcoin BIP143 where `sha256d` sub-hashes are built on-chain
//! (Solana has a sha256 syscall), Zcash ZIP-243 needs BLAKE2b for the
//! intermediate `hashPrevouts` / `hashSequence` / `hashOutputs` which Solana
//! does NOT have as a syscall. So the on-chain program builds a deterministic
//! byte representation of the transaction fields, and the CLI independently
//! builds the full ZIP-243 preimage off-chain for signing. Both sides produce
//! the same simplified bytes for `keccak256` → MessageApproval PDA derivation.
//!
//! # Tx template format (20 bytes)
//!
//!   header             (4, LE u32) — 0x80000004 (v4 + fOverwintered)
//!   version_group_id   (4, LE u32) — 0x892f2085 (Sapling)
//!   lock_time          (4, LE u32)
//!   expiry_height      (4, LE u32)
//!   consensus_branch_id(4, LE u32) — 0x76b809bb (Sapling) / 0xc2d6d0b4 (NU5)
//!
//! # Param schema
//!
//!   param[0] = prev_txid          : Bytes32  (input UTXO txid, internal byte order)
//!   param[1] = prev_vout          : U64      (input UTXO index; low 32 bits)
//!   param[2] = prev_amount_zat    : U64      (value of UTXO in zatoshi)
//!   param[3] = sender_pkh         : Bytes20  (HASH160 of sender's compressed pubkey)
//!   param[4] = recipient_pkh      : Bytes20  (HASH160 of recipient's pubkey for P2PKH)
//!   param[5] = send_amount_zat    : U64      (output value in zatoshi)

use quasar_lang::prelude::*;
use crate::state::intent::Intent;
use super::{read_bytes20, read_bytes32, read_u64};

pub const TX_TEMPLATE_LEN: usize = 20;

/// Simplified preimage length:
/// header(4) + version_group_id(4) + prev_txid(32) + prev_vout(4) +
/// prev_amount(8) + sender_pkh(20) + recipient_pkh(20) + send_amount(8) +
/// lock_time(4) + expiry_height(4) + sighash_type(4) = 112 bytes
const PREIMAGE_LEN: usize = 112;

pub fn build_preimage(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    out: &mut [u8],
) -> Result<usize, ProgramError> {
    if tx_template.len() != TX_TEMPLATE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    if out.len() < PREIMAGE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let header = &tx_template[0..4];
    let version_group_id = &tx_template[4..8];
    let lock_time = &tx_template[8..12];
    let expiry_height = &tx_template[12..16];
    // consensus_branch_id at [16..20] is used by the CLI for the BLAKE2b
    // personalization, not embedded in the simplified preimage.

    let prev_txid = read_bytes32(intent, params_data, 0)?;
    let prev_vout = read_u64(intent, params_data, 1)? as u32;
    let prev_amount = read_u64(intent, params_data, 2)?;
    let sender_pkh = read_bytes20(intent, params_data, 3)?;
    let recipient_pkh = read_bytes20(intent, params_data, 4)?;
    let send_amount = read_u64(intent, params_data, 5)?;

    // Assemble the simplified preimage — deterministic byte repr of all
    // transaction fields. Both on-chain and off-chain produce these exact
    // bytes for keccak256 → MessageApproval PDA.
    let mut p = 0;
    out[p..p + 4].copy_from_slice(header);                    p += 4;
    out[p..p + 4].copy_from_slice(version_group_id);          p += 4;
    out[p..p + 32].copy_from_slice(&prev_txid);               p += 32;
    out[p..p + 4].copy_from_slice(&prev_vout.to_le_bytes());  p += 4;
    out[p..p + 8].copy_from_slice(&prev_amount.to_le_bytes());p += 8;
    out[p..p + 20].copy_from_slice(&sender_pkh);              p += 20;
    out[p..p + 20].copy_from_slice(&recipient_pkh);           p += 20;
    out[p..p + 8].copy_from_slice(&send_amount.to_le_bytes());p += 8;
    out[p..p + 4].copy_from_slice(lock_time);                 p += 4;
    out[p..p + 4].copy_from_slice(expiry_height);             p += 4;
    // SIGHASH_ALL = 0x01
    out[p..p + 4].copy_from_slice(&1u32.to_le_bytes());       p += 4;

    debug_assert_eq!(p, PREIMAGE_LEN);
    Ok(PREIMAGE_LEN)
}

/// ZIP-243 preimage length (transparent-only, no shielded):
/// header(4) + version_group_id(4) + hashPrevouts(32) + hashSequence(32) +
/// hashOutputs(32) + hashJoinSplits(32) + hashShieldedSpends(32) +
/// hashShieldedOutputs(32) + lock_time(4) + expiry_height(4) +
/// valueBalance(8) + sighash_type(4) + outpoint(36) + scriptCode(26) +
/// prev_amount(8) + sequence(4) = 294 bytes
const ZIP243_PREIMAGE_LEN: usize = 294;

/// Build the full ZIP-243 preimage from intent fields + pre-computed BLAKE2b hashes.
/// `blake2b_hashes` = [hashPrevouts(32) || hashSequence(32) || hashOutputs(32)].
pub fn build_zip243_preimage(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    blake2b_hashes: &[u8; 96],
    out: &mut [u8],
) -> Result<usize, ProgramError> {
    if tx_template.len() != TX_TEMPLATE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    if out.len() < ZIP243_PREIMAGE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let header = &tx_template[0..4];
    let version_group_id = &tx_template[4..8];
    let lock_time = &tx_template[8..12];
    let expiry_height = &tx_template[12..16];

    let prev_txid = read_bytes32(intent, params_data, 0)?;
    let prev_vout = read_u64(intent, params_data, 1)? as u32;
    let prev_amount = read_u64(intent, params_data, 2)?;
    let sender_pkh = read_bytes20(intent, params_data, 3)?;
    let send_amount = read_u64(intent, params_data, 5)?;
    let _ = send_amount; // used by hashOutputs (pre-computed)

    let sighash_type: u32 = 1; // SIGHASH_ALL
    let sequence: u32 = 0xfffffffe;

    // outpoint = prev_txid(32) || prev_vout(4)
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&prev_txid);
    outpoint[32..36].copy_from_slice(&prev_vout.to_le_bytes());

    // scriptCode for P2PKH: 0x19 76 a9 14 {sender_pkh} 88 ac
    let mut script_code = [0u8; 26];
    script_code[0] = 0x19;
    script_code[1] = 0x76;
    script_code[2] = 0xa9;
    script_code[3] = 0x14;
    script_code[4..24].copy_from_slice(&sender_pkh);
    script_code[24] = 0x88;
    script_code[25] = 0xac;

    let hash_prevouts = &blake2b_hashes[0..32];
    let hash_sequence = &blake2b_hashes[32..64];
    let hash_outputs = &blake2b_hashes[64..96];

    let mut p = 0;
    out[p..p + 4].copy_from_slice(header);              p += 4;
    out[p..p + 4].copy_from_slice(version_group_id);    p += 4;
    out[p..p + 32].copy_from_slice(hash_prevouts);      p += 32;
    out[p..p + 32].copy_from_slice(hash_sequence);      p += 32;
    out[p..p + 32].copy_from_slice(hash_outputs);       p += 32;
    out[p..p + 32].copy_from_slice(&[0u8; 32]);         p += 32; // hashJoinSplits
    out[p..p + 32].copy_from_slice(&[0u8; 32]);         p += 32; // hashShieldedSpends
    out[p..p + 32].copy_from_slice(&[0u8; 32]);         p += 32; // hashShieldedOutputs
    out[p..p + 4].copy_from_slice(lock_time);           p += 4;
    out[p..p + 4].copy_from_slice(expiry_height);       p += 4;
    out[p..p + 8].copy_from_slice(&0i64.to_le_bytes()); p += 8;  // valueBalance
    out[p..p + 4].copy_from_slice(&sighash_type.to_le_bytes()); p += 4;
    out[p..p + 36].copy_from_slice(&outpoint);          p += 36;
    out[p..p + 26].copy_from_slice(&script_code);       p += 26;
    out[p..p + 8].copy_from_slice(&prev_amount.to_le_bytes()); p += 8;
    out[p..p + 4].copy_from_slice(&sequence.to_le_bytes());    p += 4;

    debug_assert_eq!(p, ZIP243_PREIMAGE_LEN);
    Ok(ZIP243_PREIMAGE_LEN)
}
