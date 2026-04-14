//! Destination-chain transaction builders.
//!
//! Each chain implements the same shape:
//!
//!   `build_preimage(intent, params_data, tx_template, out) -> usize`
//!
//! The chain module writes the chain-native signing **preimage** (the bytes
//! the destination network will eventually hash and ec_recover against) into
//! the caller-supplied `out` buffer and returns its length. The dispatcher
//! then takes a single `keccak256` over that preimage to produce the
//! `MessageApproval.message_hash` that gets stored on chain.
//!
//! ## Why always keccak256, regardless of chain
//!
//! The on-chain `MessageApproval.message_hash` is **not** the digest the
//! dwallet network ultimately signs — it's a uniqueness key, used as the
//! third PDA seed (`["message_approval", dwallet, hash]`) so the dwallet
//! program can dedupe approvals and route signatures back to the right
//! pending request. The dwallet program treats it as opaque 32 bytes.
//!
//! Using `keccak256` for that uniqueness key everywhere has three benefits:
//!   1. It maps to Solana's cheap on-chain `keccak` syscall.
//!   2. The dwallet program stays chain-agnostic — adding a new destination
//!      chain doesn't touch its instruction handlers.
//!   3. The lookup hash is fully decoupled from the signing digest. The
//!      dwallet network is responsible for hashing the same preimage with
//!      whichever chain-native scheme (`keccak256` for EVM, `sha256d` for
//!      Bitcoin BIP143, personalized BLAKE2b-256 for Zcash NU5, etc.) the
//!      destination consumer expects, via the `hash_scheme` field on the
//!      gRPC `Sign` request. That happens off-chain; clear-wallet only
//!      builds the preimage and computes the lookup key.
//!
//! For chains where the lookup hash and the signing digest happen to be the
//! same value (EVM is one — both `keccak256(rlp_envelope)`) the coincidence
//! is exactly that: a coincidence. The dwallet program never compares the
//! two and the dwallet network never reads the on-chain hash; the only
//! cross-link is "use the same preimage on both sides."
//!
//! Adding a new chain: implement a `build_preimage` function in a new
//! sub-module, give it a `ChainKind` discriminant, and add a dispatch arm in
//! `dispatch_sighash` below. No changes to the dwallet program required.

use quasar_lang::prelude::*;

use crate::state::intent::Intent;
use crate::utils::keccak::keccak256;

pub mod bitcoin;
pub mod evm;
pub mod solana_dwallet;
pub mod zcash;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// Solana via Ika dWallet (Ed25519/Curve25519). The dWallet pubkey IS
    /// the Solana address. Signed by the dWallet network with `EddsaSha512`.
    Solana = 0,
    /// EVM EIP-1559 native-token transfer (ETH/native gas-token send).
    Evm1559 = 1,
    /// Bitcoin P2WPKH (single-input, single-output) BIP143 sighash.
    BitcoinP2wpkh = 2,
    /// Zcash transparent P2PKH (single-input, single-output). Uses BLAKE2b-256
    /// with personalized "ZcashSigHash" || consensus_branch_id for signing.
    ZcashTransparent = 3,
    /// EVM EIP-1559 ERC-20 token transfer. Same envelope as `Evm1559`, but
    /// the calldata is `transfer(address,uint256)` constructed on-chain from
    /// typed (recipient, amount) params, so approvers can clear-sign
    /// "transfer X tokens to Y" instead of opaque bytes.
    Evm1559Erc20 = 4,
}

// Note: there is no `Solana*Dwallet` variant. For Solana-side intents the
// local CPI executor (`ChainKind::Solana = 0` + the existing
// `examples/intents/transfer_sol.json` / `transfer_tokens.json`) is strictly
// simpler — clear-wallet's vault PDA signs natively via `invoke_signed`
// without any Ika roundtrip. The dWallet path only adds value when the asset
// can't be moved into a PDA (BTC, EVM, Zcash, etc.) so the address has to
// remain a single Ed25519/secp256k1 key controlled by Ika MPC.

impl ChainKind {
    pub fn from_u8(v: u8) -> Result<Self, ProgramError> {
        match v {
            0 => Ok(Self::Solana),
            1 => Ok(Self::Evm1559),
            2 => Ok(Self::BitcoinP2wpkh),
            3 => Ok(Self::ZcashTransparent),
            4 => Ok(Self::Evm1559Erc20),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// All chains go through `ika_sign`.
    pub fn is_remote(self) -> bool {
        true
    }
}

/// Maximum chain-preimage size we're willing to handle on-chain. EIP-1559
/// envelopes with non-trivial calldata are the largest realistic preimage —
/// 1 KiB is comfortably above what any current `chain_kind` produces.
pub const MAX_PREIMAGE_LEN: usize = 1024;

/// Build the chain-native preimage for the active intent and return its
/// `keccak256`. The hash is the on-chain `MessageApproval.message_hash`
/// (the lookup key, **not** the digest the dwallet network signs).
///
/// `tx_template` is the chain-specific template stored in the intent's byte
/// pool. `params_data` is the proposer-supplied per-call data that has
/// already been validated by `validate_param_constraints`.
pub fn dispatch_sighash(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
    blake2b_hashes: &[u8; 96],
    signer_pubkey: Option<&[u8; 32]>,
) -> Result<[u8; 32], ProgramError> {
    let kind = ChainKind::from_u8(intent.chain_kind)?;
    let mut buf = [0u8; MAX_PREIMAGE_LEN];
    let preimage_len = match kind {
        ChainKind::Solana => {
            if let Some(pk) = signer_pubkey {
                solana_dwallet::build_tx_message(intent, params_data, tx_template, pk, &mut buf)?
            } else {
                solana_dwallet::build_preimage(intent, params_data, tx_template, &mut buf)?
            }
        }
        ChainKind::Evm1559 => {
            evm::build_preimage(intent, params_data, tx_template, &mut buf)?
        }
        ChainKind::Evm1559Erc20 => {
            evm::build_preimage_erc20(intent, params_data, tx_template, &mut buf)?
        }
        ChainKind::BitcoinP2wpkh => {
            bitcoin::build_preimage(intent, params_data, tx_template, &mut buf)?
        }
        ChainKind::ZcashTransparent => {
            if *blake2b_hashes != [0u8; 96] {
                zcash::build_zip243_preimage(intent, params_data, tx_template, blake2b_hashes, &mut buf)?
            } else {
                zcash::build_preimage(intent, params_data, tx_template, &mut buf)?
            }
        }
    };
    Ok(keccak256(&buf[..preimage_len]))
}

/// Build the `message_metadata_digest` for the MessageApproval PDA.
///
/// For Zcash: BCS-serialize Blake2bMessageMetadata { personal, salt },
/// then keccak256 the result. For all other chains: zeros.
pub fn dispatch_metadata_digest(
    chain_kind: u8,
    tx_template: &[u8],
) -> [u8; 32] {
    let kind = match ChainKind::from_u8(chain_kind) {
        Ok(k) => k,
        Err(_) => return [0u8; 32],
    };
    match kind {
        ChainKind::ZcashTransparent => {
            if tx_template.len() < 20 {
                return [0u8; 32];
            }
            let branch_id = u32::from_le_bytes(
                tx_template[16..20].try_into().unwrap_or([0; 4]),
            );
            // "ZcashSigHash" (12 bytes) + branch_id LE (4 bytes) = 16 bytes
            let mut personal = [0u8; 16];
            personal[..12].copy_from_slice(b"ZcashSigHash");
            personal[12..16].copy_from_slice(&branch_id.to_le_bytes());
            // BCS-serialize Blake2bMessageMetadata { personal, salt: [] }
            // BCS Vec<u8> = ULEB128 length + bytes
            // personal: 16 bytes → ULEB128(16) = 0x10, then 16 bytes
            // salt: 0 bytes → ULEB128(0) = 0x00
            let mut bcs_buf = [0u8; 19]; // 1 + 16 + 1 + 0 + 1 = worst case 19
            bcs_buf[0] = 16; // personal length
            bcs_buf[1..17].copy_from_slice(&personal);
            bcs_buf[17] = 0; // salt length
            keccak256(&bcs_buf[..18])
        }
        _ => [0u8; 32],
    }
}

// --- Param-reading helpers shared by all chain serializers ---

/// Reads a parameter from `params_data` at `param_index`, returning the raw
/// bytes (not including length prefixes for variable-length types).
pub(crate) fn read_param<'a>(
    intent: &Intent<'_>,
    params_data: &'a [u8],
    param_index: u8,
) -> Result<&'a [u8], ProgramError> {
    intent.read_param_bytes(params_data, param_index)
}

/// Reads a u64 LE param.
pub(crate) fn read_u64(
    intent: &Intent<'_>,
    params_data: &[u8],
    param_index: u8,
) -> Result<u64, ProgramError> {
    let bytes = read_param(intent, params_data, param_index)?;
    if bytes.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

/// Reads a u128 LE param.
pub(crate) fn read_u128(
    intent: &Intent<'_>,
    params_data: &[u8],
    param_index: u8,
) -> Result<u128, ProgramError> {
    let bytes = read_param(intent, params_data, param_index)?;
    if bytes.len() < 16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(u128::from_le_bytes(bytes[..16].try_into().unwrap()))
}

/// Reads a Bytes20 (or any 20-byte fixed param).
pub(crate) fn read_bytes20(
    intent: &Intent<'_>,
    params_data: &[u8],
    param_index: u8,
) -> Result<[u8; 20], ProgramError> {
    let bytes = read_param(intent, params_data, param_index)?;
    if bytes.len() < 20 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[..20]);
    Ok(out)
}

/// Reads a Bytes32 (or any 32-byte fixed param: Address, Bytes32, etc.).
pub(crate) fn read_bytes32(
    intent: &Intent<'_>,
    params_data: &[u8],
    param_index: u8,
) -> Result<[u8; 32], ProgramError> {
    let bytes = read_param(intent, params_data, param_index)?;
    if bytes.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Ok(out)
}
