//! Bind a dWallet to a clear-msig wallet for a given destination chain.
//!
//! Creates an `IkaConfig` PDA at `["ika_config", wallet, &[chain_kind]]`
//! storing the (dwallet, user_pubkey, signature_scheme) triple, and CPIs the
//! Ika program to transfer the dWallet's authority to clear-wallet's CPI
//! authority PDA. After binding, only proposals against this clear-msig
//! wallet can drive `ika_sign` against this dWallet (the IkaConfig PDA is
//! the on-chain witness of the binding).
//!
//! ## Pre-conditions
//!
//! The dWallet's *current* authority must already be clear-wallet's CPI
//! authority PDA. Bootstrapping that initial transfer is the dWallet owner's
//! responsibility (off-chain): they call Ika `transfer_ownership` once to
//! hand the dWallet to `find_program_address(&[CPI_AUTHORITY_SEED], &clear_wallet::ID).0`.
//! From there, this instruction can re-transfer (no-op) and create the binding.
//!
//! Future versions may add a separate "claim" flow that does the initial
//! transfer in-program if the dWallet is owned by a Solana keypair signer.

use quasar_lang::{cpi::Seed, prelude::*, sysvars::Sysvar as _};

use crate::{
    chains::ChainKind,
    state::wallet::ClearWallet,
    utils::ika_cpi::{DWalletContext, CPI_AUTHORITY_SEED},
};

#[derive(Accounts)]
pub struct BindDwallet<'info> {
    pub payer: &'info mut Signer,
    pub wallet: Account<ClearWallet<'info>>,
    /// The IkaConfig PDA being created. Verified to be at
    /// `["ika_config", wallet, &[chain_kind]]` inside the handler (since the
    /// chain_kind isn't available as an Anchor seed expression).
    #[account(mut)]
    pub ika_config: &'info mut UncheckedAccount,
    /// The dWallet account whose authority is being bound. Must currently
    /// have clear-wallet's CPI authority PDA as its `dwallet.authority`.
    #[account(mut)]
    pub dwallet: &'info mut UncheckedAccount,
    /// Clear-wallet's CPI authority PDA, derived from `[CPI_AUTHORITY_SEED]`.
    pub cpi_authority: &'info UncheckedAccount,
    /// The clear-wallet program account itself (executable). Required by
    /// Ika's `verify_signer_or_cpi`.
    pub caller_program: &'info UncheckedAccount,
    /// The Ika dWallet program.
    pub dwallet_program: &'info UncheckedAccount,
    pub system_program: &'info Program<System>,
}

pub struct BindDwalletArgs {
    pub chain_kind: u8,
    pub user_pubkey: [u8; 32],
    pub signature_scheme: u8,
    pub cpi_authority_bump: u8,
}

impl<'info> BindDwallet<'info> {
    pub fn bind(&mut self, args: BindDwalletArgs) -> Result<(), ProgramError> {
        // Validate chain_kind and that it's not the local Solana variant
        // (Solana intents don't go through ika_sign and don't need a binding).
        let kind = ChainKind::from_u8(args.chain_kind)?;
        require!(kind.is_remote(), ProgramError::InvalidArgument);

        // Derive and verify the IkaConfig PDA: ["ika_config", wallet, &[chain_kind]]
        let wallet_addr = *self.wallet.address();
        let chain_byte = [args.chain_kind];
        let (expected_cfg, cfg_bump) = Address::find_program_address(
            &[b"ika_config", wallet_addr.as_ref(), &chain_byte],
            &crate::ID,
        );
        require_keys_eq!(
            *self.ika_config.address(),
            expected_cfg,
            ProgramError::InvalidSeeds
        );
        require!(
            self.ika_config.to_account_view().data_len() == 0,
            ProgramError::AccountAlreadyInitialized
        );

        // Verify the CPI authority PDA matches.
        let (expected_cpi_auth, _) = Address::find_program_address(
            &[CPI_AUTHORITY_SEED],
            &crate::ID,
        );
        require_keys_eq!(
            *self.cpi_authority.address(),
            expected_cpi_auth,
            ProgramError::InvalidSeeds
        );

        // Create the IkaConfig PDA.
        let space = 1 // discriminator
            + 32       // wallet
            + 32       // dwallet
            + 32       // user_pubkey
            + 1        // chain_kind
            + 1        // signature_scheme
            + 1; // bump
        let rent = Rent::get()?;
        let lamports = rent.try_minimum_balance(space)?;

        let cfg_bump_byte = [cfg_bump];
        let seeds: &[Seed] = &[
            Seed::from(b"ika_config" as &[u8]),
            Seed::from(wallet_addr.as_ref()),
            Seed::from(&chain_byte as &[u8]),
            Seed::from(&cfg_bump_byte as &[u8]),
        ];
        self.system_program
            .create_account(
                self.payer.to_account_view(),
                self.ika_config.to_account_view(),
                lamports,
                space as u64,
                &crate::ID,
            )
            .invoke_signed(seeds)?;

        // Write the IkaConfig contents.
        let dwallet_addr = *self.dwallet.address();
        let cfg_view = unsafe {
            &mut *(self.ika_config as *mut UncheckedAccount as *mut AccountView)
        };
        let ptr = cfg_view.data_mut_ptr();
        unsafe {
            *ptr = 4; // IkaConfig discriminator
            core::ptr::copy_nonoverlapping(wallet_addr.as_ref().as_ptr(), ptr.add(1), 32);
            core::ptr::copy_nonoverlapping(dwallet_addr.as_ref().as_ptr(), ptr.add(33), 32);
            core::ptr::copy_nonoverlapping(args.user_pubkey.as_ptr(), ptr.add(65), 32);
            *ptr.add(97) = args.chain_kind;
            *ptr.add(98) = args.signature_scheme;
            *ptr.add(99) = cfg_bump;
        }

        // CPI Ika `transfer_ownership` to confirm/refresh the dWallet's
        // authority. This is a no-op if the authority is already our CPI
        // PDA, but it serves as a runtime check that the binding's
        // pre-conditions hold.
        let ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            cpi_authority_bump: args.cpi_authority_bump,
        };
        ctx.transfer_dwallet(self.dwallet.to_account_view(), expected_cpi_auth.to_bytes())?;

        Ok(())
    }
}
