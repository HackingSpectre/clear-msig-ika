//! Drive an approved proposal through Ika `approve_message`.
//!
//! Parallel execution path to `execute`. Where `execute` runs Solana CPIs
//! locally, `ika_sign`:
//!
//!   1. Verifies the proposal is Approved and timelock-elapsed.
//!   2. Looks up the (wallet, chain_kind) → dWallet binding from `IkaConfig`.
//!   3. Builds the destination-chain transaction sighash from the intent's
//!      params + tx_template via `crate::chains::dispatch_sighash`.
//!   4. CPIs Ika `approve_message` so the dWallet network will produce a
//!      signature valid for the destination chain.
//!
//! After this instruction succeeds, the proposal is marked Executed and the
//! resulting `MessageApproval` PDA exists on-chain. An off-chain relayer can
//! then ferry the signature back to the destination chain.

use quasar_lang::{prelude::*, sysvars::Sysvar as _};

use crate::{
    chains::{dispatch_sighash, ChainKind},
    instructions::bind_dwallet::{ClearWalletProgram, DWalletProgramInterface},
    state::{
        dwallet_ownership::{DwalletOwnership, DWALLET_OWNERSHIP_SEED},
        ika_config::IkaConfig,
        intent::Intent,
        proposal::{Proposal, ProposalStatus},
        wallet::ClearWallet,
    },
    utils::ika_cpi::{DWalletContext, CPI_AUTHORITY_SEED},
};

#[derive(Accounts)]
pub struct IkaSign<'info> {
    pub payer: &'info mut Signer,
    pub wallet: Account<ClearWallet<'info>>,
    #[account(
        mut,
        has_one = wallet,
        constraint = intent.is_approved() @ ProgramError::InvalidArgument,
    )]
    pub intent: Account<Intent<'info>>,
    #[account(
        mut,
        has_one = wallet,
        has_one = intent,
        constraint = proposal.status == ProposalStatus::Approved @ ProgramError::InvalidArgument
    )]
    pub proposal: Account<Proposal<'info>>,
    /// IkaConfig PDA at `["ika_config", wallet, &[intent.chain_kind]]`.
    /// Decoded manually inside the handler — see `IkaConfig::read`.
    pub ika_config: &'info UncheckedAccount,
    /// DwalletOwnership PDA at `["dwallet_owner", dwallet]`. Verified to
    /// claim `self.wallet` — that's how a non-owning clear-msig wallet is
    /// blocked from driving `ika_sign` against a dWallet bound by someone
    /// else, even if it has its own IkaConfig pointing at the same dWallet.
    pub dwallet_ownership: &'info UncheckedAccount,
    /// Verified to equal `ika_config.dwallet`.
    #[account(mut)]
    pub dwallet: &'info mut UncheckedAccount,
    /// MessageApproval PDA created by the Ika program. Caller passes its
    /// expected address; bump is supplied as an arg.
    #[account(mut)]
    pub message_approval: &'info mut UncheckedAccount,
    /// Clear-wallet's CPI authority PDA.
    pub cpi_authority: &'info UncheckedAccount,
    /// Clear-wallet program account (executable).
    pub caller_program: &'info Program<ClearWalletProgram>,
    /// Ika dWallet program (executable).
    pub dwallet_program: &'info Interface<DWalletProgramInterface>,
    pub system_program: &'info Program<System>,
}

pub struct IkaSignArgs {
    pub message_approval_bump: u8,
    pub cpi_authority_bump: u8,
}

impl<'info> IkaSign<'info> {
    pub fn ika_sign(&mut self, args: IkaSignArgs) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        let approved_at = self.proposal.approved_at.get();
        let timelock = self.intent.timelock_seconds.get() as i64;
        require!(
            clock.unix_timestamp.get() >= approved_at + timelock,
            ProgramError::InvalidArgument
        );

        // The intent must be a remote-chain intent — Solana intents go through
        // `execute`.
        let kind = ChainKind::from_u8(self.intent.chain_kind)?;
        require!(kind.is_remote(), ProgramError::InvalidArgument);

        // Decode and verify the IkaConfig binding (wallet, chain_kind, dwallet).
        // SAFETY: clear-wallet owns the IkaConfig PDA, no other accounts in
        // this instruction alias it.
        let cfg_data = unsafe { self.ika_config.to_account_view().borrow_unchecked() };
        let ika_config = IkaConfig::read(cfg_data)?;

        // Also verify the IkaConfig PDA address matches the expected derivation.
        let chain_byte = [self.intent.chain_kind];
        let (expected_cfg, _) = Address::find_program_address(
            &[b"ika_config", self.wallet.address().as_ref(), &chain_byte],
            &crate::ID,
        );
        require_keys_eq!(
            *self.ika_config.address(),
            expected_cfg,
            ProgramError::InvalidSeeds
        );

        require_keys_eq!(
            ika_config.wallet,
            *self.wallet.address(),
            ProgramError::InvalidArgument
        );
        require!(
            ika_config.chain_kind == self.intent.chain_kind,
            ProgramError::InvalidArgument
        );
        require_keys_eq!(
            ika_config.dwallet,
            *self.dwallet.address(),
            ProgramError::InvalidArgument
        );

        // Build the destination-chain sighash from intent + proposal params.
        let params_data = self.proposal.params_data();
        let tx_template = self.intent.tx_template_bytes()?;
        let message_hash = dispatch_sighash(&self.intent, params_data, tx_template)?;

        // CPI Ika `approve_message`.
        // Verify the program-wide CPI authority PDA (defense in depth).
        let (expected_cpi_auth, _) = Address::find_program_address(
            &[CPI_AUTHORITY_SEED],
            &crate::ID,
        );
        require_keys_eq!(
            *self.cpi_authority.address(),
            expected_cpi_auth,
            ProgramError::InvalidSeeds
        );

        // Verify the DwalletOwnership lock claims this wallet. The dwallet's
        // on-chain authority is shared (program-wide CPI PDA), so we enforce
        // per-wallet ownership here at the clear-wallet layer.
        let wallet_addr = *self.wallet.address();
        let dwallet_addr = *self.dwallet.address();
        let (expected_ownership, _) = Address::find_program_address(
            &[DWALLET_OWNERSHIP_SEED, dwallet_addr.as_ref()],
            &crate::ID,
        );
        require_keys_eq!(
            *self.dwallet_ownership.address(),
            expected_ownership,
            ProgramError::InvalidSeeds
        );
        // SAFETY: clear-wallet owns the DwalletOwnership PDA; no aliases.
        let ownership_data = unsafe { self.dwallet_ownership.to_account_view().borrow_unchecked() };
        let ownership = DwalletOwnership::read(ownership_data)?;
        require_keys_eq!(ownership.wallet, wallet_addr, ProgramError::InvalidArgument);
        require_keys_eq!(ownership.dwallet, dwallet_addr, ProgramError::InvalidArgument);

        let ctx = DWalletContext {
            dwallet_program: self.dwallet_program.to_account_view(),
            cpi_authority: self.cpi_authority.to_account_view(),
            caller_program: self.caller_program.to_account_view(),
            cpi_authority_bump: args.cpi_authority_bump,
        };

        let user_pubkey: [u8; 32] = ika_config.user_pubkey.to_bytes();
        ctx.approve_message(
            self.message_approval.to_account_view(),
            self.dwallet.to_account_view(),
            self.payer.to_account_view(),
            self.system_program.to_account_view(),
            message_hash,
            user_pubkey,
            ika_config.signature_scheme,
            args.message_approval_bump,
        )?;

        // Mark the proposal Executed and decrement the intent's open count.
        self.proposal.status = ProposalStatus::Executed;
        let count = self.intent.active_proposal_count.get();
        self.intent.active_proposal_count = PodU16::from(count).saturating_sub(1);

        Ok(())
    }
}
