use crate::quasar_client::approve::ApproveInstruction;
use crate::quasar_client::bind_dwallet::BindDwalletInstruction;
use crate::quasar_client::create_wallet::CreateWalletInstruction;
use crate::quasar_client::execute::ExecuteInstruction;
use crate::quasar_client::ika_sign::IkaSignInstruction;
use crate::quasar_client::propose::ProposeInstruction;
use quasar_lang::client::{DynBytes, TailBytes};
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

/// Build create_wallet instruction (Quasar discriminator 0).
///
/// Delegates to the vendored `quasar_client::create_wallet` builder which uses
/// `wincode::serialize_into` for each field — the program rejects raw byte
/// appends since clear-wallet is a Quasar program with custom encoding.
pub fn create_wallet(
    payer: Pubkey, name_hash: Pubkey, wallet: Pubkey,
    add_intent: Pubkey, remove_intent: Pubkey, update_intent: Pubkey,
    name: &str, threshold: u8, cancel_threshold: u8, timelock: u32,
    proposers: &[Pubkey], approvers: &[Pubkey],
) -> Instruction {
    let mut remaining_accounts: Vec<solana_instruction_v3::AccountMeta> =
        Vec::with_capacity(proposers.len() + approvers.len());
    for p in proposers {
        remaining_accounts.push(solana_instruction_v3::AccountMeta {
            pubkey: pk_to_addr(*p),
            is_signer: false,
            is_writable: false,
        });
    }
    for a in approvers {
        remaining_accounts.push(solana_instruction_v3::AccountMeta {
            pubkey: pk_to_addr(*a),
            is_signer: false,
            is_writable: false,
        });
    }

    let ext_ix: solana_instruction_v3::Instruction = CreateWalletInstruction {
        payer: pk_to_addr(payer),
        name_hash: pk_to_addr(name_hash),
        wallet: pk_to_addr(wallet),
        add_intent: pk_to_addr(add_intent),
        remove_intent: pk_to_addr(remove_intent),
        update_intent: pk_to_addr(update_intent),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        approval_threshold: threshold,
        cancellation_threshold: cancel_threshold,
        timelock_seconds: timelock,
        num_proposers: proposers.len() as u8,
        name: DynBytes::from(name.as_bytes().to_vec()),
        remaining_accounts,
    }
    .into();
    sdk_ix_from_ext(ext_ix)
}

/// Build propose instruction (Quasar discriminator 1) via the vendored client.
pub fn propose(
    payer: Pubkey, wallet: Pubkey, intent: Pubkey, proposal: Pubkey,
    expiry: i64, proposer_pubkey: [u8; 32], signature: [u8; 64],
    params_data: &[u8],
) -> Instruction {
    let ext_ix: solana_instruction_v3::Instruction = ProposeInstruction {
        payer: pk_to_addr(payer),
        wallet: pk_to_addr(wallet),
        intent: pk_to_addr(intent),
        proposal: pk_to_addr(proposal),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        expiry,
        proposer_pubkey,
        signature,
        params_data: TailBytes(params_data.to_vec()),
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
    signature_scheme: u8,
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
    cpi_authority: Pubkey,
    dwallet_program: Pubkey,
    message_approval_bump: u8,
    cpi_authority_bump: u8,
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
        cpi_authority: pk_to_addr(cpi_authority),
        caller_program: pk_to_addr(program_id()),
        dwallet_program: pk_to_addr(dwallet_program),
        system_program: pk_to_addr(solana_sdk::system_program::id()),
        message_approval_bump,
        cpi_authority_bump,
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
