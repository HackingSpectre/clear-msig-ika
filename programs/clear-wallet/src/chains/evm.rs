//! EVM EIP-1559 transaction preimage builder.
//!
//! Builds the type-2 (EIP-1559) RLP-encoded **preimage** that an Ethereum
//! verifier ec_recovers against. This module no longer hashes the preimage —
//! the on-chain `MessageApproval.message_hash` is computed by
//! [`crate::chains::dispatch_sighash`] as `keccak256(preimage)` so that every
//! chain stores the same kind of uniqueness key, and the dwallet network
//! independently re-applies `keccak256` (via `hash_scheme = Keccak256`) to
//! produce the actual ECDSA signing digest off-chain.
//!
//! Per EIP-1559: signed payload is `0x02 || rlp([chain_id, nonce, max_priority_fee,
//! max_fee, gas_limit, to, value, data, access_list])`. That's exactly what
//! [`build_preimage`] writes into `out`; the consumer is responsible for
//! hashing it (with `keccak256` for both the on-chain lookup and the
//! signing digest, which for EVM happen to coincide).
//!
//! # Tx template format
//!
//! 36 bytes:
//!   chain_id   (8, LE u64) — e.g., 1 for mainnet, 8453 for Base
//!   gas_limit  (8, LE u64)
//!   max_fee_per_gas (16, LE u128)
//!   max_priority_fee_per_gas (16, LE u128)
//!
//! Wait — that's 48 bytes. Let me recount: 8+8+16+16 = 48.
//!
//! Actually for pre-alpha simplicity we cap fees at u64 (16 EH gas at 18 Gwei is
//! still well within u64 range for a single tx), so:
//!
//!   chain_id (8) + gas_limit (8) + max_priority_fee (8) + max_fee (8) = 32 bytes.
//!
//! # Param schema (must match the intent definition)
//!
//!   param[0] = nonce       : U64
//!   param[1] = to          : Bytes20
//!   param[2] = value (wei) : U64    (capped at u64; for >u64 amounts, extend)
//!   param[3] = data        : String (raw call data; pass empty string for value transfers)
//!
//! Approvers see a template like:
//!   `"send {2} wei to 0x{1} (nonce {0})"`

use quasar_lang::prelude::*;

use crate::state::intent::Intent;
use super::{read_bytes20, read_param, read_u128, read_u64};

/// ERC-20 `transfer(address,uint256)` function selector.
/// = `keccak256("transfer(address,uint256)")[0..4]`
pub const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

const EIP1559_TYPE: u8 = 0x02;

/// Tx template fixed length.
pub const TX_TEMPLATE_LEN: usize = 32;

pub fn build_preimage(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    out: &mut [u8],
) -> Result<usize, ProgramError> {
    if tx_template.len() != TX_TEMPLATE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let chain_id = u64::from_le_bytes(tx_template[0..8].try_into().unwrap());
    let gas_limit = u64::from_le_bytes(tx_template[8..16].try_into().unwrap());
    let max_priority_fee = u64::from_le_bytes(tx_template[16..24].try_into().unwrap());
    let max_fee = u64::from_le_bytes(tx_template[24..32].try_into().unwrap());

    let nonce = read_u64(intent, params_data, 0)?;
    let to = read_bytes20(intent, params_data, 1)?;
    let value = read_u64(intent, params_data, 2)?;
    let data_param = read_param(intent, params_data, 3)?;
    // String params are length-prefixed: [len: u8, bytes...]
    let call_data = if data_param.is_empty() {
        &[][..]
    } else {
        let len = data_param[0] as usize;
        &data_param[1..1 + len]
    };

    // Build the RLP list into a local stack buffer first; we don't know the
    // exact length until it's encoded, and the EIP-1559 envelope needs that
    // length up front for its outer list header. Total upper bound:
    //   chain_id(9) + nonce(9) + max_prio(9) + max_fee(9) + gas(9) + to(21)
    //   + value(9) + data(<256 bytes typical) + access_list(1) + outer_hdr(3) ≈ 350 bytes
    let mut inner = [0u8; 1024];
    let mut inner_len = 0usize;

    rlp_u64(&mut inner, &mut inner_len, chain_id)?;
    rlp_u64(&mut inner, &mut inner_len, nonce)?;
    rlp_u64(&mut inner, &mut inner_len, max_priority_fee)?;
    rlp_u64(&mut inner, &mut inner_len, max_fee)?;
    rlp_u64(&mut inner, &mut inner_len, gas_limit)?;
    rlp_bytes(&mut inner, &mut inner_len, &to)?;
    rlp_u64(&mut inner, &mut inner_len, value)?;
    rlp_bytes(&mut inner, &mut inner_len, call_data)?;
    // Empty access_list = empty list = 0xc0
    rlp_empty_list(&mut inner, &mut inner_len)?;

    // Write the final envelope into the caller-provided output buffer:
    //   0x02 || rlp_list_header(inner_len) || inner
    let mut out_len = 0usize;
    push(out, &mut out_len, EIP1559_TYPE)?;
    rlp_list_header(out, &mut out_len, inner_len)?;
    push_slice(out, &mut out_len, &inner[..inner_len])?;

    Ok(out_len)
}

/// Build the EIP-1559 preimage for an ERC-20 `transfer(address,uint256)` call.
///
/// Wraps the same envelope as [`build_preimage`], but constructs the calldata
/// from typed (recipient, amount) params instead of taking opaque bytes —
/// so approvers see "transfer X tokens to Y" in the clear-signing template
/// and the on-chain code is the only thing that can produce the actual
/// calldata bytes. There's no path for a relayer to substitute different
/// calldata between approval and signing.
///
/// # Tx template format
///
/// Same as [`build_preimage`] (32 bytes): chain_id(8) + gas_limit(8)
/// + max_priority_fee(8) + max_fee(8). All u64 LE.
///
/// # Param schema
///
///   param[0] = nonce          : U64
///   param[1] = token_contract : Bytes20  (the ERC-20 contract address)
///   param[2] = recipient      : Bytes20  (transfer destination)
///   param[3] = amount         : U128     (token amount in smallest unit)
///
/// # Calldata layout
///
///   selector(4) || pad32(recipient) || u256_be(amount)  = 68 bytes
///
/// `pad32(recipient)` is the 20-byte address left-padded with 12 zero bytes
/// (per Solidity ABI encoding for `address`).
pub fn build_preimage_erc20(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    out: &mut [u8],
) -> Result<usize, ProgramError> {
    if tx_template.len() != TX_TEMPLATE_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let chain_id = u64::from_le_bytes(tx_template[0..8].try_into().unwrap());
    let gas_limit = u64::from_le_bytes(tx_template[8..16].try_into().unwrap());
    let max_priority_fee = u64::from_le_bytes(tx_template[16..24].try_into().unwrap());
    let max_fee = u64::from_le_bytes(tx_template[24..32].try_into().unwrap());

    let nonce = read_u64(intent, params_data, 0)?;
    let token_contract = read_bytes20(intent, params_data, 1)?;
    let recipient = read_bytes20(intent, params_data, 2)?;
    let amount = read_u128(intent, params_data, 3)?;

    // ERC-20 calldata: selector(4) || pad32(recipient)(32) || u256_be(amount)(32)
    let mut calldata = [0u8; 68];
    calldata[0..4].copy_from_slice(&ERC20_TRANSFER_SELECTOR);
    // pad32 left-pads the 20-byte address with 12 zero bytes (Solidity ABI)
    calldata[4 + 12..4 + 32].copy_from_slice(&recipient);
    // u256_be amount: 16 zero bytes then 16 bytes of u128 big-endian
    calldata[4 + 32 + 16..4 + 32 + 32].copy_from_slice(&amount.to_be_bytes());

    // Same EIP-1559 envelope as native: to=token_contract, value=0, data=calldata
    let mut inner = [0u8; 1024];
    let mut inner_len = 0usize;
    rlp_u64(&mut inner, &mut inner_len, chain_id)?;
    rlp_u64(&mut inner, &mut inner_len, nonce)?;
    rlp_u64(&mut inner, &mut inner_len, max_priority_fee)?;
    rlp_u64(&mut inner, &mut inner_len, max_fee)?;
    rlp_u64(&mut inner, &mut inner_len, gas_limit)?;
    rlp_bytes(&mut inner, &mut inner_len, &token_contract)?;
    rlp_u64(&mut inner, &mut inner_len, 0)?; // value = 0 for token transfers
    rlp_bytes(&mut inner, &mut inner_len, &calldata)?;
    rlp_empty_list(&mut inner, &mut inner_len)?;

    let mut out_len = 0usize;
    push(out, &mut out_len, EIP1559_TYPE)?;
    rlp_list_header(out, &mut out_len, inner_len)?;
    push_slice(out, &mut out_len, &inner[..inner_len])?;

    Ok(out_len)
}

// --- Minimal RLP encoder ---
//
// Only the subset needed for EIP-1559 sighashing:
//   * positive integers (no leading zero bytes)
//   * byte strings (with single-byte and short-string headers)
//   * list headers
//
// Spec: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/

fn rlp_u64(buf: &mut [u8], len: &mut usize, val: u64) -> Result<(), ProgramError> {
    if val == 0 {
        // The empty byte string encodes 0 in RLP.
        return rlp_bytes(buf, len, &[]);
    }
    let bytes = val.to_be_bytes();
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    rlp_bytes(buf, len, &bytes[leading_zeros..])
}

fn rlp_bytes(buf: &mut [u8], len: &mut usize, data: &[u8]) -> Result<(), ProgramError> {
    if data.len() == 1 && data[0] < 0x80 {
        // Single byte < 0x80 encodes as itself.
        push(buf, len, data[0])
    } else if data.len() < 56 {
        push(buf, len, 0x80 + data.len() as u8)?;
        push_slice(buf, len, data)
    } else {
        // Long string: 0xb7 + len_of_len, then big-endian length, then data.
        let mut len_buf = [0u8; 8];
        let len_slice = encode_len_be(data.len(), &mut len_buf);
        push(buf, len, 0xb7 + len_slice.len() as u8)?;
        push_slice(buf, len, len_slice)?;
        push_slice(buf, len, data)
    }
}

fn rlp_list_header(buf: &mut [u8], len: &mut usize, payload_len: usize) -> Result<(), ProgramError> {
    if payload_len < 56 {
        push(buf, len, 0xc0 + payload_len as u8)
    } else {
        let mut len_buf = [0u8; 8];
        let len_slice = encode_len_be(payload_len, &mut len_buf);
        push(buf, len, 0xf7 + len_slice.len() as u8)?;
        push_slice(buf, len, len_slice)
    }
}

fn rlp_empty_list(buf: &mut [u8], len: &mut usize) -> Result<(), ProgramError> {
    push(buf, len, 0xc0)
}

fn push(buf: &mut [u8], len: &mut usize, byte: u8) -> Result<(), ProgramError> {
    if *len >= buf.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    buf[*len] = byte;
    *len += 1;
    Ok(())
}

fn push_slice(buf: &mut [u8], len: &mut usize, data: &[u8]) -> Result<(), ProgramError> {
    if *len + data.len() > buf.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    buf[*len..*len + data.len()].copy_from_slice(data);
    *len += data.len();
    Ok(())
}

/// Writes minimal big-endian length bytes into `buf`, returning the populated slice.
fn encode_len_be<'a>(len: usize, buf: &'a mut [u8; 8]) -> &'a [u8] {
    let bytes = (len as u64).to_be_bytes();
    let leading = bytes.iter().take_while(|&&b| b == 0).count();
    let kept_len = 8 - leading;
    buf[..kept_len].copy_from_slice(&bytes[leading..]);
    &buf[..kept_len]
}
