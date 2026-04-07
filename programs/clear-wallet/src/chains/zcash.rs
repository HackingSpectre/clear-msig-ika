//! Zcash transparent v5 (NU5+) sighash per ZIP-244.
//!
//! Spec: https://zips.z.cash/zip-0244
//!
//! Single-input, single-output transparent transaction. No shielded bundles
//! (sapling/orchard digests are the empty-bundle constants).
//!
//! ⚠ **PRE-ALPHA — UNTESTED AGAINST FIXTURES.**
//! ZIP-244 is fiddly: personalization strings, branch IDs, and digest order
//! are easy to get wrong. This implementation follows the spec text, but the
//! correct way to validate it is against zcashd's `getrawtransaction` test
//! vectors. Treat the output as unverified until that's done.
//!
//! # Overview
//!
//! `txid_digest = blake2b256("ZcashTxHash_<branch_id>",
//!     header_digest || transparent_digest || sapling_digest || orchard_digest)`
//!
//! For sighashing transparent inputs (`SIGHASH_ALL`, single input):
//!
//!   `sig_digest = blake2b256("ZcashTxHash_<branch_id>",
//!       header_digest || transparent_sig_digest || sapling_digest || orchard_digest)`
//!
//! where `transparent_sig_digest` rebinds the transparent_digest to include
//! the per-input signing context (the input being signed).
//!
//! # Tx template format
//!
//! 16 bytes:
//!   header_version_group_id (4, LE u32) — 0x26A7270A for v5
//!   consensus_branch_id     (4, LE u32) — e.g., 0xC8E71055 for NU5
//!   lock_time               (4, LE u32)
//!   expiry_height           (4, LE u32)
//!
//! # Param schema
//!
//!   param[0] = prev_txid       : Bytes32  (input UTXO txid)
//!   param[1] = prev_vout       : U64      (first 4 bytes used)
//!   param[2] = prev_amount     : U64      (zatoshis)
//!   param[3] = sender_pkh      : Bytes20  (HASH160 of input pubkey)
//!   param[4] = recipient_pkh   : Bytes20  (HASH160 of recipient)
//!   param[5] = send_amount     : U64      (zatoshis)

use blake2::{
    digest::{consts::U32, FixedOutput, Mac},
    Blake2bMac,
};
use quasar_lang::prelude::*;

use crate::state::intent::Intent;
use super::{read_bytes20, read_bytes32, read_u64};

pub const TX_TEMPLATE_LEN: usize = 16;

const TX_VERSION: u32 = 5;
const HASH_TYPE_SIGHASH_ALL: u8 = 0x01;

pub fn build_sighash(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
) -> Result<[u8; 32], ProgramError> {
    if tx_template.len() != TX_TEMPLATE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let version_group_id = u32::from_le_bytes(tx_template[0..4].try_into().unwrap());
    let consensus_branch_id = u32::from_le_bytes(tx_template[4..8].try_into().unwrap());
    let lock_time = u32::from_le_bytes(tx_template[8..12].try_into().unwrap());
    let expiry_height = u32::from_le_bytes(tx_template[12..16].try_into().unwrap());

    let prev_txid = read_bytes32(intent, params_data, 0)?;
    let prev_vout = read_u64(intent, params_data, 1)? as u32;
    let prev_amount = read_u64(intent, params_data, 2)?;
    let sender_pkh = read_bytes20(intent, params_data, 3)?;
    let recipient_pkh = read_bytes20(intent, params_data, 4)?;
    let send_amount = read_u64(intent, params_data, 5)?;

    // ── header_digest ──
    // ZIP-244 §T.1: blake2b-256 personalized "ZTxIdHeadersHash" of:
    //   tx_version (4 LE, with overwinter bit) || version_group_id (4 LE)
    //   || consensus_branch_id (4 LE) || lock_time (4 LE) || expiry_height (4 LE)
    let mut header_input = [0u8; 20];
    let tx_version_with_overwinter = TX_VERSION | 0x8000_0000;
    header_input[0..4].copy_from_slice(&tx_version_with_overwinter.to_le_bytes());
    header_input[4..8].copy_from_slice(&version_group_id.to_le_bytes());
    header_input[8..12].copy_from_slice(&consensus_branch_id.to_le_bytes());
    header_input[12..16].copy_from_slice(&lock_time.to_le_bytes());
    header_input[16..20].copy_from_slice(&expiry_height.to_le_bytes());
    let header_digest = blake2b_256(b"ZTxIdHeadersHash", &header_input);

    // ── transparent_sig_digest ──
    // ZIP-244 §T.2 + §S.2: per-input transparent sig digest. For SIGHASH_ALL
    // with one input, it's:
    //
    //   blake2b-256("ZTxIdTranspaHash", hash_type || prevouts_sig_digest
    //       || amounts_sig_digest || scripts_sig_digest || sequence_sig_digest
    //       || outputs_sig_digest || txin_sig_digest)
    //
    // (Note the personalization typo "Transpa" — that is the actual byte
    // string in the spec.)

    // outpoint = txid (32) || vout (4 LE)
    let mut outpoint = [0u8; 36];
    outpoint[..32].copy_from_slice(&prev_txid);
    outpoint[32..36].copy_from_slice(&prev_vout.to_le_bytes());

    let prevouts_sig_digest = blake2b_256(b"ZTxIdPrevoutHash", &outpoint);
    let amounts_sig_digest = blake2b_256(b"ZTxTrAmountsHash", &prev_amount.to_le_bytes());

    // scriptCode for the input being signed: P2PKH-style
    //   OP_DUP OP_HASH160 <20 bytes pkh> OP_EQUALVERIFY OP_CHECKSIG
    let mut script_code = [0u8; 25];
    script_code[0] = 0x76; // OP_DUP
    script_code[1] = 0xa9; // OP_HASH160
    script_code[2] = 0x14; // push20
    script_code[3..23].copy_from_slice(&sender_pkh);
    script_code[23] = 0x88; // OP_EQUALVERIFY
    script_code[24] = 0xac; // OP_CHECKSIG
    // The "scripts_sig_digest" hashes scriptCode bytes prefixed with their CompactSize length.
    let mut script_with_len = [0u8; 26];
    script_with_len[0] = script_code.len() as u8;
    script_with_len[1..].copy_from_slice(&script_code);
    let scripts_sig_digest = blake2b_256(b"ZTxTrScriptsHash", &script_with_len);

    // sequence for the single input — we use 0xfffffffe to opt out of locktime
    let sequence: u32 = 0xfffffffe;
    let sequence_sig_digest = blake2b_256(b"ZTxIdSequencHash", &sequence.to_le_bytes());

    // outputs_sig_digest: sha256d-style? No — blake2b256 personalized.
    // P2PKH output: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes
    // Output serialization: amount (8 LE) || script_len (compactsize 25) || script
    let mut output_buf = [0u8; 8 + 1 + 25];
    output_buf[..8].copy_from_slice(&send_amount.to_le_bytes());
    output_buf[8] = 25;
    output_buf[9] = 0x76;
    output_buf[10] = 0xa9;
    output_buf[11] = 0x14;
    output_buf[12..32].copy_from_slice(&recipient_pkh);
    output_buf[32] = 0x88;
    output_buf[33] = 0xac;
    let outputs_sig_digest = blake2b_256(b"ZTxIdOutputsHash", &output_buf);

    // txin_sig_digest: per-input data being signed.
    //   outpoint(36) || amount(8) || script_len(1) || script(25) || sequence(4)
    let mut txin = [0u8; 36 + 8 + 1 + 25 + 4];
    let mut p = 0;
    txin[p..p + 36].copy_from_slice(&outpoint); p += 36;
    txin[p..p + 8].copy_from_slice(&prev_amount.to_le_bytes()); p += 8;
    txin[p] = 25; p += 1;
    txin[p..p + 25].copy_from_slice(&script_code); p += 25;
    txin[p..p + 4].copy_from_slice(&sequence.to_le_bytes()); p += 4;
    debug_assert_eq!(p, txin.len());
    let txin_sig_digest = blake2b_256(b"Zcash___TxInHash", &txin);

    // Combine into transparent_sig_digest.
    let mut transparent_input = [0u8; 1 + 32 * 6];
    transparent_input[0] = HASH_TYPE_SIGHASH_ALL;
    transparent_input[1..33].copy_from_slice(&prevouts_sig_digest);
    transparent_input[33..65].copy_from_slice(&amounts_sig_digest);
    transparent_input[65..97].copy_from_slice(&scripts_sig_digest);
    transparent_input[97..129].copy_from_slice(&sequence_sig_digest);
    transparent_input[129..161].copy_from_slice(&outputs_sig_digest);
    transparent_input[161..193].copy_from_slice(&txin_sig_digest);
    let transparent_sig_digest = blake2b_256(b"ZTxIdTranspaHash", &transparent_input);

    // Empty sapling and orchard digests (per ZIP-244 §T.3, T.4 the empty-bundle constants).
    let sapling_digest = blake2b_256(b"ZTxIdSaplingHash", &[]);
    let orchard_digest = blake2b_256(b"ZTxIdOrchardHash", &[]);

    // ── final sig digest ──
    // Personalization: "ZcashTxHash_" + 4-byte LE consensus_branch_id (16 bytes total).
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZcashTxHash_");
    personal[12..16].copy_from_slice(&consensus_branch_id.to_le_bytes());

    let mut combined = [0u8; 32 * 4];
    combined[0..32].copy_from_slice(&header_digest);
    combined[32..64].copy_from_slice(&transparent_sig_digest);
    combined[64..96].copy_from_slice(&sapling_digest);
    combined[96..128].copy_from_slice(&orchard_digest);

    Ok(blake2b_256(&personal, &combined))
}

/// Blake2b-256 with a 16-byte personalization string (left-padded with zeros
/// if shorter than 16 bytes).
fn blake2b_256(personal: &[u8], data: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 16];
    let n = personal.len().min(16);
    padded[..n].copy_from_slice(&personal[..n]);

    let mut hasher = Blake2bMac::<U32>::new_with_salt_and_personal(&[], &[], &padded)
        .expect("blake2b-256 personalization is 16 bytes");
    Mac::update(&mut hasher, data);
    let out = hasher.finalize_fixed();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}
