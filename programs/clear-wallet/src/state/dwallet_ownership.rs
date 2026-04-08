use quasar_lang::prelude::*;

/// Per-dWallet ownership lock.
///
/// Records which clear-msig wallet first bound a given dWallet. Created by
/// `bind_dwallet` on the first bind, immutable thereafter. Both `bind_dwallet`
/// (subsequent binds) and `ika_sign` re-read this account and reject if the
/// calling wallet doesn't match the recorded `wallet`.
///
/// This is the layer that gives a multisig *true* ownership of a dWallet:
/// even though the dWallet's on-chain authority is the program-wide CPI
/// authority PDA (a constraint enforced by the dWallet program itself), the
/// clear-wallet program will only drive `ika_sign` against the dWallet on
/// behalf of the wallet that owns this lock.
///
/// PDA: `["dwallet_owner", dwallet]`
///
/// Layout: discriminator(1) + wallet(32) + dwallet(32) + bump(1) = 66 bytes
pub const DWALLET_OWNERSHIP_DISCRIMINATOR: u8 = 5;
pub const DWALLET_OWNERSHIP_LEN: usize = 1 + 32 + 32 + 1; // 66
pub const DWALLET_OWNERSHIP_SEED: &[u8] = b"dwallet_owner";

pub struct DwalletOwnership {
    pub wallet: Address,
    pub dwallet: Address,
    pub bump: u8,
}

impl DwalletOwnership {
    /// Decode a DwalletOwnership from raw account data.
    pub fn read(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < DWALLET_OWNERSHIP_LEN || data[0] != DWALLET_OWNERSHIP_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut wallet = [0u8; 32];
        wallet.copy_from_slice(&data[1..33]);
        let mut dwallet = [0u8; 32];
        dwallet.copy_from_slice(&data[33..65]);
        Ok(Self {
            wallet: Address::new_from_array(wallet),
            dwallet: Address::new_from_array(dwallet),
            bump: data[65],
        })
    }
}
