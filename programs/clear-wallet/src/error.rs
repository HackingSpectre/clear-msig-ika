use quasar_lang::prelude::*;

#[error_code]
pub enum WalletError {
    /// Too many proposers provided (max 16).
    TooManyProposers = 6000,
    /// Too many approvers provided (max 16).
    TooManyApprovers,
    /// Approval threshold must be > 0 and <= approver count.
    InvalidApprovalThreshold,
    /// Cancellation threshold must be > 0 and <= approver count.
    InvalidCancellationThreshold,
    /// The proposal is not in the Active state.
    ProposalNotActive,
    /// The proposal is not in an Approved state.
    ProposalNotApproved,
    /// The proposal has not been executed or cancelled yet.
    ProposalNotFinalized,
    /// The transaction expiry has passed.
    Expired,
    /// The timelock period has not elapsed since approval.
    TimelockNotElapsed,
    /// This approver has already approved this proposal.
    AlreadyApproved,
    /// This approver has already cancelled this proposal.
    AlreadyCancelled,
    /// The approver/canceller index is out of bounds.
    InvalidMemberIndex,
    /// The proposal index does not match the wallet's current index.
    InvalidProposalIndex,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// The signer is not a proposer on this intent.
    NotProposer,
    /// The intent has not been approved.
    IntentNotApproved,
    /// The intent still has active proposals and cannot be removed or updated.
    IntentHasActiveProposals,
    /// Maximum number of intents reached.
    TooManyIntents,
    /// Active proposal count overflow.
    TooManyActiveProposals,
    /// Too many accounts in the intent definition (max 32).
    TooManyAccounts,
    /// Account count does not match intent definition.
    AccountCountMismatch,
    /// Remaining account address does not match the expected address.
    AccountAddressMismatch,
    /// A parameter value violates its intent constraint.
    ParamConstraintViolation,
}
