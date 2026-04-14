//! Solana dWallet intent — SOL transfers signed by Ika dWallet (Ed25519).
//!
//! Uses durable nonces so the transaction message is deterministic at
//! proposal time (no expiring blockhash). The dWallet's Curve25519 pubkey
//! IS the Solana address holding funds.
//!
//! # Tx template format (32 bytes)
//!
//!   nonce_account (32 bytes) — the durable nonce account address
//!
//! # Param schema
//!
//!   param[0] = destination  : Address (32 bytes, Solana pubkey)
//!   param[1] = amount       : U64    (lamports)
//!   param[2] = nonce_value  : Bytes32 (current nonce, read at propose time)

use quasar_lang::prelude::*;
use crate::state::intent::Intent;
use super::{read_bytes32, read_u64};

/// SysvarRecentBlockHashes pubkey (required by AdvanceNonceAccount).
const SYSVAR_RECENT_BLOCKHASHES: [u8; 32] = [
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
    0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
    0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
];

/// System program pubkey.
const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];

/// Build the full Solana transaction message for a SOL transfer with
/// durable nonce. Identical bytes on-chain and off-chain.
///
/// The signer_pubkey (dWallet Ed25519 pubkey) must be passed in because
/// `dispatch_sighash` doesn't have access to the IkaConfig.
pub fn build_preimage(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    out: &mut [u8],
) -> Result<usize, ProgramError> {
    // For Solana, we need the dWallet pubkey. Since dispatch_sighash doesn't
    // have it, we build a simplified preimage here. The CLI builds the full
    // Solana message independently (same approach as Zcash).
    //
    // Simplified: op(1) + destination(32) + amount(8) + nonce_value(32) = 73 bytes.
    if tx_template.len() != 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if out.len() < 73 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let destination = read_bytes32(intent, params_data, 0)?;
    let amount = read_u64(intent, params_data, 1)?;
    let nonce_value = read_bytes32(intent, params_data, 2)?;

    let mut p = 0;
    out[p] = 0x00; p += 1; // op = Solana transfer
    out[p..p + 32].copy_from_slice(&destination); p += 32;
    out[p..p + 8].copy_from_slice(&amount.to_le_bytes()); p += 8;
    out[p..p + 32].copy_from_slice(&nonce_value); p += 32;

    Ok(p)
}

/// Build the actual Solana transaction message for a SOL transfer with
/// durable nonce. This produces identical bytes to what the CLI builds,
/// so keccak256(message) matches on both sides for the MA PDA.
pub fn build_tx_message(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    signer_pubkey: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, ProgramError> {
    if tx_template.len() != 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let destination = read_bytes32(intent, params_data, 0)?;
    let amount = read_u64(intent, params_data, 1)?;
    let nonce_value = read_bytes32(intent, params_data, 2)?;
    let nonce_account = tx_template;

    // SysvarRecentBlockHashes
    let sysvar: [u8; 32] = [
        0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
        0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
        0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
        0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
    ];
    let system_program: [u8; 32] = [0u8; 32];

    let mut p = 0;

    // Header
    out[p] = 1; p += 1;  // num_required_signatures
    out[p] = 0; p += 1;  // num_readonly_signed
    out[p] = 2; p += 1;  // num_readonly_unsigned (sysvar + system_program)

    // Account keys (5)
    out[p] = 5; p += 1;
    out[p..p + 32].copy_from_slice(signer_pubkey);    p += 32;
    out[p..p + 32].copy_from_slice(nonce_account);     p += 32;
    out[p..p + 32].copy_from_slice(&destination);      p += 32;
    out[p..p + 32].copy_from_slice(&sysvar);           p += 32;
    out[p..p + 32].copy_from_slice(&system_program);   p += 32;

    // Recent blockhash = nonce value
    out[p..p + 32].copy_from_slice(&nonce_value);      p += 32;

    // Instructions (2)
    out[p] = 2; p += 1;

    // Instruction 0: AdvanceNonceAccount
    out[p] = 4; p += 1;  // program_id_index = system_program
    out[p] = 3; p += 1;  // accounts len
    out[p] = 1; p += 1;  // nonce_account
    out[p] = 3; p += 1;  // sysvar
    out[p] = 0; p += 1;  // authority (signer)
    out[p] = 4; p += 1;  // data len
    out[p..p + 4].copy_from_slice(&[4, 0, 0, 0]); p += 4; // AdvanceNonceAccount

    // Instruction 1: Transfer
    out[p] = 4; p += 1;  // program_id_index = system_program
    out[p] = 2; p += 1;  // accounts len
    out[p] = 0; p += 1;  // from (signer)
    out[p] = 2; p += 1;  // to (destination)
    out[p] = 12; p += 1; // data len
    out[p..p + 4].copy_from_slice(&2u32.to_le_bytes()); p += 4; // Transfer instruction
    out[p..p + 8].copy_from_slice(&amount.to_le_bytes()); p += 8;

    Ok(p)
}
