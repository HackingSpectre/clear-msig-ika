use quasar_lang::prelude::*;

/// Per-(wallet, chain) binding to an Ika dWallet.
///
/// Created by `bind_dwallet`. The bound dWallet's authority is set to the
/// clear-wallet program's CPI authority PDA, and this account is the on-chain
/// proof that *this specific clear-msig wallet* controls the dWallet for the
/// given chain. A single wallet can fan out to multiple chains by creating
/// one IkaConfig per chain_kind.
///
/// PDA: `["ika_config", wallet, &[chain_kind]]`
///
/// Stored as a plain `repr(C)` byte layout — no Quasar zero-copy macro,
/// because the struct has no variable-length fields and Quasar's `#[account]`
/// macro strips lifetime parameters from such structs (which then breaks the
/// `Account<T<'info>>` derivation in instruction structs). The handler reads
/// it manually from the account data via `read` / `write`.
///
/// Layout: discriminator(1) + wallet(32) + dwallet(32) + user_pubkey(32)
///       + chain_kind(1) + signature_scheme(2) + bump(1) = 101 bytes
pub const IKA_CONFIG_DISCRIMINATOR: u8 = 4;
pub const IKA_CONFIG_LEN: usize = 1 + 32 + 32 + 32 + 1 + 2 + 1; // 101

pub struct IkaConfig {
    pub wallet: Address,
    pub dwallet: Address,
    pub user_pubkey: Address,
    pub chain_kind: u8,
    pub signature_scheme: u16,
    pub bump: u8,
}

impl IkaConfig {
    /// Decode an IkaConfig from raw account data.
    pub fn read(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < IKA_CONFIG_LEN || data[0] != IKA_CONFIG_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut wallet = [0u8; 32];
        wallet.copy_from_slice(&data[1..33]);
        let mut dwallet = [0u8; 32];
        dwallet.copy_from_slice(&data[33..65]);
        let mut user_pubkey = [0u8; 32];
        user_pubkey.copy_from_slice(&data[65..97]);
        let signature_scheme = u16::from_le_bytes(
            data[98..100].try_into().map_err(|_| ProgramError::InvalidAccountData)?
        );
        Ok(Self {
            wallet: Address::new_from_array(wallet),
            dwallet: Address::new_from_array(dwallet),
            user_pubkey: Address::new_from_array(user_pubkey),
            chain_kind: data[97],
            signature_scheme,
            bump: data[100],
        })
    }
}
