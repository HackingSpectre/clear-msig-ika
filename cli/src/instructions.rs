use crate::quasar_client::approve::ApproveInstruction;
use crate::quasar_client::bind_dwallet::BindDwalletInstruction;
use crate::quasar_client::create_wallet::CreateWalletInstruction;
use crate::quasar_client::execute::ExecuteInstruction;
use crate::quasar_client::ika_sign::IkaSignInstruction;
use crate::quasar_client::propose::ProposeInstruction;
use quasar_lang::client::{DynBytes, DynVec, TailBytes};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// The clear-wallet program ID.
pub fn program_id() -> Pubkey {
    // C1earWa11etMSig1111111111111111111111111111
    let addr = clear_wallet_client::ID;
    Pubkey::new_from_array(addr.to_bytes())
}

/// Convert a `solana_sdk::Pubkey` to a `solana_address::Address` (used by the
/// vendored quasar client which lives on a different solana crate version).
fn pk_to_addr(p: Pubkey) -> solana_address::Address {
    solana_address::Address::new_from_array(p.to_bytes())
}

/// Convert a `solana_instruction_v3::Instruction` produced by the vendored
/// quasar client (which uses `solana_address::Address`) into the
/// `solana_sdk::Instruction` shape the RPC client expects.
fn sdk_ix_from_ext(ix: solana_instruction_v3::Instruction) -> Instruction {
    Instruction {
        program_id: Pubkey::new_from_array(ix.program_id.to_bytes()),
        accounts: ix
            .accounts
            .into_iter()
            .map(|m| AccountMeta {
                pubkey: Pubkey::new_from_array(m.pubkey.to_bytes()),
                is_signer: m.is_signer,
                is_writable: m.is_writable,
            })
            .collect(),
        data: ix.data,
    }
}

pub struct CreateWalletArgs<'a> {
    pub payer: Pubkey,
    pub name_hash: Pubkey,
    pub wallet: Pubkey,
    pub add_intent: Pubkey,
    pub remove_intent: Pubkey,
    pub update_intent: Pubkey,
    pub name: &'a str,
    pub threshold: u8,
    pub cancel_threshold: u8,
    pub timelock: u32,
    pub proposers: &'a [Pubkey],
    pub approvers: &'a [Pubkey],
}

/// Build create_wallet instruction (Quasar discriminator 0).
pub fn create_wallet(args: CreateWalletArgs<'_>) -> Instruction {
    let ext_ix: solana_instruction_v3::Instruction = CreateWalletInstruction {
        payer: pk_to_addr(args.payer),
        name_hash: pk_to_addr(args.name_hash),
        wallet: pk_to_addr(args.wallet),
        add_intent: pk_to_addr(args.add_intent),
        remove_intent: pk_to_addr(args.remove_intent),
        update_intent: pk_to_addr(args.update_intent),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        approval_threshold: args.threshold,
        cancellation_threshold: args.cancel_threshold,
        timelock_seconds: args.timelock,
        name: DynBytes::from(args.name.as_bytes().to_vec()),
        proposers: DynVec::new(args.proposers.iter().map(|p| p.to_bytes()).collect()),
        approvers: DynVec::new(args.approvers.iter().map(|a| a.to_bytes()).collect()),
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

pub struct ProposeArgs<'a> {
    pub payer: Pubkey,
    pub wallet: Pubkey,
    pub intent: Pubkey,
    pub proposal: Pubkey,
    pub proposal_index: u64,
    pub expiry: i64,
    pub proposer_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub params_data: &'a [u8],
}

/// Build propose instruction (Quasar discriminator 1) via the vendored client.
pub fn propose(args: ProposeArgs<'_>) -> Instruction {
    let ext_ix: solana_instruction_v3::Instruction = ProposeInstruction {
        payer: pk_to_addr(args.payer),
        wallet: pk_to_addr(args.wallet),
        intent: pk_to_addr(args.intent),
        proposal: pk_to_addr(args.proposal),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        proposal_index: args.proposal_index,
        expiry: args.expiry,
        proposer_pubkey: args.proposer_pubkey,
        signature: args.signature,
        params_data: TailBytes(args.params_data.to_vec()),
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

/// Build approve instruction (Quasar discriminator 2) via the vendored client.
pub fn approve(
    wallet: Pubkey, intent: Pubkey, proposal: Pubkey,
    expiry: i64, approver_index: u8, signature: [u8; 64],
) -> Instruction {
    let ext_ix: solana_instruction_v3::Instruction = ApproveInstruction {
        wallet: pk_to_addr(wallet),
        intent: pk_to_addr(intent),
        proposal: pk_to_addr(proposal),
        expiry,
        approver_index,
        signature,
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

/// Build cancel instruction.
pub fn cancel(
    wallet: Pubkey, intent: Pubkey, proposal: Pubkey,
    expiry: i64, canceller_index: u8, signature: [u8; 64],
) -> Instruction {
    let accounts = vec![
        AccountMeta::new_readonly(wallet, false),
        AccountMeta::new(intent, false),
        AccountMeta::new(proposal, false),
    ];

    let mut data = vec![3u8];
    data.extend_from_slice(&expiry.to_le_bytes());
    data.push(canceller_index);
    data.extend_from_slice(&signature);

    Instruction { program_id: program_id(), accounts, data }
}

/// Build execute instruction (Quasar discriminator 4) via the vendored client.
pub fn execute(
    wallet: Pubkey, vault: Pubkey, intent: Pubkey, proposal: Pubkey,
    remaining_accounts: Vec<AccountMeta>,
) -> Instruction {
    let ext_remaining: Vec<solana_instruction_v3::AccountMeta> = remaining_accounts
        .into_iter()
        .map(|m| solana_instruction_v3::AccountMeta {
            pubkey: pk_to_addr(m.pubkey),
            is_signer: m.is_signer,
            is_writable: m.is_writable,
        })
        .collect();
    let ext_ix: solana_instruction_v3::Instruction = ExecuteInstruction {
        wallet: pk_to_addr(wallet),
        vault: pk_to_addr(vault),
        intent: pk_to_addr(intent),
        proposal: pk_to_addr(proposal),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        remaining_accounts: ext_remaining,
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

/// Build cleanup_proposal instruction.
pub fn cleanup(proposal: Pubkey, rent_refund: Pubkey) -> Instruction {
    let accounts = vec![
        AccountMeta::new(proposal, false),
        AccountMeta::new(rent_refund, false),
    ];
    Instruction { program_id: program_id(), accounts, data: vec![5u8] }
}

// =============================================================================
// Cross-chain (dWallet via Ika) instructions
// =============================================================================
//
// All wire formats below match the auto-generated Quasar client at
// `target/client/rust/clear-wallet-client/src/instructions/`. Re-run
// `quasar build` and re-cross-check if signatures change upstream.

/// Build bind_dwallet (disc 6).
///
/// Build bind_dwallet instruction (Quasar discriminator 6) via the vendored
/// quasar client. wincode encoding required.
#[allow(clippy::too_many_arguments)]
pub fn bind_dwallet(
    payer: Pubkey,
    wallet: Pubkey,
    ika_config: Pubkey,
    dwallet_ownership: Pubkey,
    dwallet: Pubkey,
    cpi_authority: Pubkey,
    dwallet_program: Pubkey,
    chain_kind: u8,
    user_pubkey: [u8; 32],
    signature_scheme: u16,
    cpi_authority_bump: u8,
) -> Instruction {
    let ext_ix: solana_instruction_v3::Instruction = BindDwalletInstruction {
        payer: pk_to_addr(payer),
        wallet: pk_to_addr(wallet),
        ika_config: pk_to_addr(ika_config),
        dwallet_ownership: pk_to_addr(dwallet_ownership),
        dwallet: pk_to_addr(dwallet),
        cpi_authority: pk_to_addr(cpi_authority),
        caller_program: pk_to_addr(program_id()),
        dwallet_program: pk_to_addr(dwallet_program),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        chain_kind,
        user_pubkey,
        signature_scheme,
        cpi_authority_bump,
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

/// Build ika_sign instruction (Quasar discriminator 7) via the vendored client.
#[allow(clippy::too_many_arguments)]
pub fn ika_sign(
    payer: Pubkey,
    wallet: Pubkey,
    intent: Pubkey,
    proposal: Pubkey,
    ika_config: Pubkey,
    dwallet_ownership: Pubkey,
    dwallet: Pubkey,
    message_approval: Pubkey,
    coordinator: Pubkey,
    cpi_authority: Pubkey,
    dwallet_program: Pubkey,
    message_approval_bump: u8,
    cpi_authority_bump: u8,
    blake2b_hashes: [u8; 96],
) -> Instruction {
    let ext_ix: solana_instruction_v3::Instruction = IkaSignInstruction {
        payer: pk_to_addr(payer),
        wallet: pk_to_addr(wallet),
        intent: pk_to_addr(intent),
        proposal: pk_to_addr(proposal),
        ika_config: pk_to_addr(ika_config),
        dwallet_ownership: pk_to_addr(dwallet_ownership),
        dwallet: pk_to_addr(dwallet),
        message_approval: pk_to_addr(message_approval),
        coordinator: pk_to_addr(coordinator),
        cpi_authority: pk_to_addr(cpi_authority),
        caller_program: pk_to_addr(program_id()),
        dwallet_program: pk_to_addr(dwallet_program),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        message_approval_bump,
        cpi_authority_bump,
        blake2b_hashes,
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

/// Build the raw `transfer_ownership` (Ika dWallet program disc 24)
/// instruction. Used to hand off authority of a freshly-DKG'd dWallet to
/// clear-wallet's CPI authority PDA before `bind_dwallet`.
pub fn ika_transfer_ownership(
    dwallet_program: Pubkey,
    payer: Pubkey,
    dwallet: Pubkey,
    new_authority: Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new_readonly(payer, true),
        AccountMeta::new(dwallet, false),
    ];
    let mut data = Vec::with_capacity(33);
    data.push(24u8);
    data.extend_from_slice(new_authority.as_ref());
    Instruction { program_id: dwallet_program, accounts, data }
}
