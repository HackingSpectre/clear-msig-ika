use quasar_lang::prelude::*;

use crate::{error::WalletError, state::proposal::{Proposal, ProposalStatus}};

#[derive(Accounts)]
pub struct CleanupProposal<'info> {
    #[account(
        has_one = rent_refund,
        close = rent_refund,
        constraint = proposal.status == ProposalStatus::Executed
            || proposal.status == ProposalStatus::Cancelled
            @ WalletError::ProposalNotFinalized
    )]
    pub proposal: Account<Proposal<'info>>,
    #[account(mut)]
    pub rent_refund: &'info mut UncheckedAccount,
}

impl<'info> CleanupProposal<'info> {
    pub fn cleanup(&mut self) -> Result<(), ProgramError> {
        Ok(())
    }
}
