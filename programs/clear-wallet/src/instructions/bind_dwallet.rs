//! Bind a dWallet to a clear-msig wallet for a given destination chain.
//!
//! Creates two PDAs:
//!
//!   1. `IkaConfig` at `["ika_config", wallet, &[chain_kind]]` storing the
//!      `(dwallet, user_pubkey, signature_scheme)` triple. One per
//!      (wallet, chain_kind), so a single wallet can fan out to multiple
//!      chains for the same dWallet.
//!   2. `DwalletOwnership` at `["dwallet_owner", dwallet]` recording which
//!      clear-msig wallet *first* bound this dWallet. Init-once and
//!      immutable. Subsequent binds (for additional chain_kinds) and every
//!      `ika_sign` call re-read this account and reject if `wallet` doesn't
//!      match — that's how a multisig truly owns a dWallet, despite the
//!      dWallet program enforcing only a single program-wide CPI authority.
//!
//! Then CPIs Ika `transfer_ownership` to confirm/refresh the dWallet's
//! authority. This is a no-op if the authority already equals the
//! program-wide CPI PDA, but it serves as a runtime check that the
//! pre-condition holds.
//!
//! ## Pre-conditions
//!
//! The dWallet's *current* authority must already be clear-wallet's CPI
//! authority PDA. The CLI's `wallet add-chain` flow runs the initial
//! `transfer_ownership` (signed by the dWallet owner) before calling this
//! instruction.

use quasar_lang::{cpi::Seed, prelude::*, sysvars::Sysvar as _, traits::Id};

use crate::{
    chains::ChainKind,
    state::{
        dwallet_ownership::{
            DwalletOwnership, DWALLET_OWNERSHIP_DISCRIMINATOR, DWALLET_OWNERSHIP_LEN,
            DWALLET_OWNERSHIP_SEED,
        },
        wallet::ClearWallet,
    },
    utils::ika_cpi::{DWalletContext, CPI_AUTHORITY_SEED},
};

/// Marker type for the clear-wallet program itself, so we can declare the
/// `caller_program` field as `&'info Program<ClearWalletProgram>`. Quasar's
/// `Program<T>` wrapper applies the `NODUP_EXECUTABLE` header check, which
/// matches what the runtime supplies for executable program accounts. The
/// alternative — declaring it as `UncheckedAccount` — fails account-validation
/// because the runtime tags executable accounts with `NODUP_EXECUTABLE` and
/// `UncheckedAccount` expects plain `NODUP`.
pub struct ClearWalletProgram;
impl Id for ClearWalletProgram {
    const ID: Address = crate::ID;
}

/// Marker type for the Ika dWallet program. We accept ANY address here
/// because the program ID may differ across networks (devnet vs mainnet vs
/// local mock); the actual address is verified in `utils::ika_cpi` when we
/// CPI into it. We use `Interface<T>` rather than `Program<T>` so we can
/// override `matches` to always return true.
pub struct DWalletProgramInterface;
impl quasar_lang::traits::ProgramInterface for DWalletProgramInterface {
    fn matches(_address: &Address) -> bool { true }
}

#[derive(Accounts)]
pub struct BindDwallet<'info> {
    pub payer: &'info mut Signer,
    pub wallet: Account<ClearWallet<'info>>,
    /// The IkaConfig PDA being created. Verified to be at
    /// `["ika_config", wallet, &[chain_kind]]` inside the handler (since the
    /// chain_kind isn't available as an Anchor seed expression).
    #[account(mut)]
    pub ika_config: &'info mut UncheckedAccount,
    /// The DwalletOwnership PDA at `["dwallet_owner", dwallet]`. Created
    /// on the first bind for this dWallet (init-once, immutable). On
    /// subsequent binds (e.g. fanning out the same dWallet to a second
    /// chain_kind), the handler verifies the recorded `wallet` equals
    /// `self.wallet` and rejects otherwise.
    #[account(mut)]
    pub dwallet_ownership: &'info mut UncheckedAccount,
    /// The dWallet account whose authority is being bound. Must currently
    /// have clear-wallet's CPI authority PDA as its `dwallet.authority`.
    #[account(mut)]
    pub dwallet: &'info mut UncheckedAccount,
    /// Clear-wallet's CPI authority PDA, derived from `[CPI_AUTHORITY_SEED]`.
    pub cpi_authority: &'info UncheckedAccount,
    /// The clear-wallet program account itself (executable). Required by
    /// Ika's `verify_signer_or_cpi`.
    pub caller_program: &'info Program<ClearWalletProgram>,
    /// The Ika dWallet program (executable). Address validated implicitly via
    /// the CPI into it; here we just need the executable header check.
    pub dwallet_program: &'info Interface<DWalletProgramInterface>,
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

        let wallet_addr = *self.wallet.address();
        let dwallet_addr = *self.dwallet.address();

        // Derive and verify the IkaConfig PDA: ["ika_config", wallet, &[chain_kind]]
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

        // Derive and verify the DwalletOwnership PDA: ["dwallet_owner", dwallet]
        let (expected_ownership, ownership_bump) = Address::find_program_address(
            &[DWALLET_OWNERSHIP_SEED, dwallet_addr.as_ref()],
            &crate::ID,
        );
        require_keys_eq!(
            *self.dwallet_ownership.address(),
            expected_ownership,
            ProgramError::InvalidSeeds
        );

        // Verify the program-wide CPI authority PDA matches.
        let (expected_cpi_auth, _) = Address::find_program_address(
            &[CPI_AUTHORITY_SEED],
            &crate::ID,
        );
        require_keys_eq!(
            *self.cpi_authority.address(),
            expected_cpi_auth,
            ProgramError::InvalidSeeds
        );

        // ── Init-or-verify the DwalletOwnership lock ──
        //
        // First binder for this dWallet creates the lock claiming itself.
        // Subsequent binds (e.g. the same wallet adding another chain_kind)
        // re-verify the recorded wallet matches. Any other wallet trying to
        // bind the same dWallet hits `InvalidArgument` here.
        let ownership_view = self.dwallet_ownership.to_account_view();
        if ownership_view.data_len() == 0 {
            // First bind — create the lock.
            let rent = Rent::get()?;
            let lamports = rent.try_minimum_balance(DWALLET_OWNERSHIP_LEN)?;

            let ownership_bump_byte = [ownership_bump];
            let ownership_seeds: &[Seed] = &[
                Seed::from(DWALLET_OWNERSHIP_SEED),
                Seed::from(dwallet_addr.as_ref()),
                Seed::from(&ownership_bump_byte as &[u8]),
            ];
            self.system_program
                .create_account(
                    self.payer.to_account_view(),
                    self.dwallet_ownership.to_account_view(),
                    lamports,
                    DWALLET_OWNERSHIP_LEN as u64,
                    &crate::ID,
                )
                .invoke_signed(ownership_seeds)?;

            // SAFETY: clear-wallet now owns this PDA; we just allocated it.
            let view = unsafe {
                &mut *(self.dwallet_ownership as *mut UncheckedAccount as *mut AccountView)
            };
            let ptr = view.data_mut_ptr();
            unsafe {
                *ptr = DWALLET_OWNERSHIP_DISCRIMINATOR;
                core::ptr::copy_nonoverlapping(wallet_addr.as_ref().as_ptr(), ptr.add(1), 32);
                core::ptr::copy_nonoverlapping(dwallet_addr.as_ref().as_ptr(), ptr.add(33), 32);
                *ptr.add(65) = ownership_bump;
            }
        } else {
            // Already exists — recorded wallet must match this caller.
            // SAFETY: clear-wallet owns the DwalletOwnership PDA, no other
            // accounts in this instruction alias it.
            let data = unsafe { ownership_view.borrow_unchecked() };
            let ownership = DwalletOwnership::read(data)?;
            require_keys_eq!(
                ownership.wallet,
                wallet_addr,
                ProgramError::InvalidArgument
            );
            require_keys_eq!(
                ownership.dwallet,
                dwallet_addr,
                ProgramError::InvalidArgument
            );
        }

        // ── Create the IkaConfig PDA ──
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
        // pre-conditions hold (and signing with the wrong PDA fails here).
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
