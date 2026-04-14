//! CPI helpers for the Ika dWallet program, written against Quasar's CPI types.
//!
//! Mirrors the `ika-dwallet-pinocchio` crate from the ika-pre-alpha SDK.
//! The wire format (instruction discriminators, account ordering, data layout)
//! is identical to the pinocchio version — only the host types differ because
//! clear-wallet is a Quasar program.

use quasar_lang::{
    cpi::{CpiAccount, InstructionAccount, InstructionView, Seed, Signer},
    prelude::*,
};

/// Seed for deriving the program-wide CPI authority PDA.
///
/// The dWallet program enforces a single canonical CPI authority per caller
/// program — `find_program_address(&[CPI_AUTHORITY_SEED], caller_program_id)`.
/// Wallet-scoping cannot happen here; per-wallet ownership of a dWallet is
/// enforced one layer up via [`crate::state::dwallet_ownership::DwalletOwnership`],
/// which records which clear-msig wallet first bound a given dWallet and
/// rejects any later bind/sign attempt from a different wallet.
pub const CPI_AUTHORITY_SEED: &[u8] = b"__ika_cpi_authority";

// Instruction discriminators — must match `IkaDWalletInstructionDiscriminators`.
const IX_APPROVE_MESSAGE: u8 = 8;
const IX_TRANSFER_OWNERSHIP: u8 = 24;

/// CPI context for invoking Ika dWallet instructions.
///
/// The clear-wallet program signs via its program-wide CPI authority PDA,
/// which the dWallet program verifies through `verify_signer_or_cpi`.
pub struct DWalletContext<'a> {
    /// The Ika dWallet program account.
    pub dwallet_program: &'a AccountView,
    /// The CPI authority PDA derived from `[CPI_AUTHORITY_SEED]`.
    pub cpi_authority: &'a AccountView,
    /// The clear-wallet program account (must be executable).
    pub caller_program: &'a AccountView,
    /// Bump seed for the CPI authority PDA.
    pub cpi_authority_bump: u8,
}

impl<'a> DWalletContext<'a> {
    /// CPI into Ika `approve_message`.
    ///
    /// Creates a `MessageApproval` PDA on behalf of the clear-wallet program.
    /// The dWallet's authority must be set to this program's CPI authority PDA
    /// (done once via `transfer_dwallet`).
    ///
    /// # Accounts
    ///
    /// 0. `[readonly]`         coordinator — DWalletCoordinator PDA (for epoch)
    /// 1. `[writable]`         message_approval — PDA to create
    /// 2. `[readonly]`         dwallet — program-owned dWallet account
    /// 3. `[readonly]`         caller_program — clear-wallet program (executable)
    /// 4. `[readonly, signer]` cpi_authority — clear-wallet's CPI authority PDA
    /// 5. `[writable, signer]` payer — pays for the new PDA's rent
    /// 6. `[readonly]`         system_program
    pub fn approve_message(
        &self,
        coordinator: &'a AccountView,
        message_approval: &'a AccountView,
        dwallet: &'a AccountView,
        payer: &'a AccountView,
        system_program: &'a AccountView,
        message_digest: [u8; 32],
        message_metadata_digest: [u8; 32],
        user_pubkey: [u8; 32],
        signature_scheme: u16,
        message_approval_bump: u8,
    ) -> Result<(), ProgramError> {
        // [discriminator(1), bump(1), message_digest(32),
        //  message_metadata_digest(32), user_pubkey(32), scheme(2)] = 100 bytes
        let mut ix_data = [0u8; 100];
        ix_data[0] = IX_APPROVE_MESSAGE;
        ix_data[1] = message_approval_bump;
        ix_data[2..34].copy_from_slice(&message_digest);
        ix_data[34..66].copy_from_slice(&message_metadata_digest);
        ix_data[66..98].copy_from_slice(&user_pubkey);
        ix_data[98..100].copy_from_slice(&signature_scheme.to_le_bytes());

        let ix_accounts = [
            InstructionAccount::new(coordinator.address(), false, false),
            InstructionAccount::new(message_approval.address(), true, false),
            InstructionAccount::new(dwallet.address(), false, false),
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(payer.address(), true, true),
            InstructionAccount::new(system_program.address(), false, false),
        ];

        let cpi_accts = [
            CpiAccount::from(coordinator),
            CpiAccount::from(message_approval),
            CpiAccount::from(dwallet),
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(payer),
            CpiAccount::from(system_program),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.dwallet_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }

    /// CPI into Ika `transfer_ownership` to set a dWallet's authority to a new pubkey.
    ///
    /// # Accounts
    ///
    /// 0. `[readonly]`         caller_program
    /// 1. `[readonly, signer]` cpi_authority
    /// 2. `[writable]`         dwallet
    pub fn transfer_dwallet(
        &self,
        dwallet: &'a AccountView,
        new_authority: [u8; 32],
    ) -> Result<(), ProgramError> {
        let mut ix_data = [0u8; 33];
        ix_data[0] = IX_TRANSFER_OWNERSHIP;
        ix_data[1..33].copy_from_slice(&new_authority);

        let ix_accounts = [
            InstructionAccount::new(self.caller_program.address(), false, false),
            InstructionAccount::new(self.cpi_authority.address(), false, true),
            InstructionAccount::new(dwallet.address(), true, false),
        ];

        let cpi_accts = [
            CpiAccount::from(self.caller_program),
            CpiAccount::from(self.cpi_authority),
            CpiAccount::from(dwallet),
        ];

        let bump_byte = [self.cpi_authority_bump];
        let signer_seeds: [Seed; 2] = [
            Seed::from(CPI_AUTHORITY_SEED),
            Seed::from(&bump_byte as &[u8]),
        ];
        let signers = [Signer::from(&signer_seeds[..])];

        let instruction = InstructionView {
            program_id: self.dwallet_program.address(),
            accounts: &ix_accounts,
            data: &ix_data,
        };

        unsafe {
            solana_instruction_view::cpi::invoke_signed_unchecked(
                &instruction,
                &cpi_accts,
                &signers,
            );
        }
        Ok(())
    }
}
