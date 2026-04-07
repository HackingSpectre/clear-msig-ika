//! Destination-chain transaction builders.
//!
//! Each chain implements the same shape:
//!
//!   `build_sighash(intent, params_data, tx_template) -> [u8; 32]`
//!
//! The returned 32-byte hash is what `ika_sign` passes to Ika `approve_message`.
//! Approvers signed a human-readable template; this module is responsible for
//! turning the template's params into the bytes the destination chain will
//! actually verify, then computing the chain's sighash over those bytes.
//!
//! Adding a new chain: implement a `build_sighash` function in a new
//! sub-module, give it a `ChainKind` discriminant, and add a dispatch arm in
//! `dispatch_sighash` below.

use quasar_lang::prelude::*;

use crate::state::intent::Intent;

pub mod bitcoin;
pub mod evm;
#[cfg(feature = "chain-zcash")]
pub mod zcash;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// Local Solana CPI execution (uses the existing `execute` path; never
    /// goes through `ika_sign`).
    Solana = 0,
    /// EVM EIP-1559 transaction (legacy is intentionally omitted — modern
    /// EVMs all support 1559 and the sighash is unambiguous).
    Evm1559 = 1,
    /// Bitcoin P2WPKH (single-input, single-output) BIP143 sighash.
    BitcoinP2wpkh = 2,
    /// Zcash transparent ZIP-244 (NU5+) sighash. Single-input, single-output.
    ZcashTransparent = 3,
}

impl ChainKind {
    pub fn from_u8(v: u8) -> Result<Self, ProgramError> {
        match v {
            0 => Ok(Self::Solana),
            1 => Ok(Self::Evm1559),
            2 => Ok(Self::BitcoinP2wpkh),
            3 => Ok(Self::ZcashTransparent),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// Whether this chain goes through `ika_sign` rather than `execute`.
    pub fn is_remote(self) -> bool {
        !matches!(self, Self::Solana)
    }
}

/// Dispatch a sighash build to the right chain handler.
///
/// `tx_template` is the chain-specific template stored in the intent's byte
/// pool. `params_data` is the proposer-supplied per-call data that has already
/// been validated by `validate_param_constraints`.
pub fn dispatch_sighash(
    intent: &Intent<'_>,
    params_data: &[u8],
    tx_template: &[u8],
) -> Result<[u8; 32], ProgramError> {
    let kind = ChainKind::from_u8(intent.chain_kind)?;
    match kind {
        ChainKind::Solana => Err(ProgramError::InvalidArgument),
        ChainKind::Evm1559 => evm::build_sighash(intent, params_data, tx_template),
        ChainKind::BitcoinP2wpkh => bitcoin::build_sighash(intent, params_data, tx_template),
        #[cfg(feature = "chain-zcash")]
        ChainKind::ZcashTransparent => zcash::build_sighash(intent, params_data, tx_template),
        #[cfg(not(feature = "chain-zcash"))]
        ChainKind::ZcashTransparent => Err(ProgramError::InvalidArgument),
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
