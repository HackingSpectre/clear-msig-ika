use std::vec::Vec;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use super::ID;
use quasar_lang::client::{DynBytes};

pub struct CreateWalletInstruction {
    pub payer: Address,
    pub name_hash: Address,
    pub wallet: Address,
    pub add_intent: Address,
    pub remove_intent: Address,
    pub update_intent: Address,
    pub system_program: Address,
    pub approval_threshold: u8,
    pub cancellation_threshold: u8,
    pub timelock_seconds: u32,
    pub num_proposers: u8,
    pub name: DynBytes,
    pub remaining_accounts: Vec<AccountMeta>,
}

impl From<CreateWalletInstruction> for Instruction {
    fn from(ix: CreateWalletInstruction) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(ix.payer, true),
            AccountMeta::new_readonly(ix.name_hash, false),
            AccountMeta::new(ix.wallet, false),
            AccountMeta::new(ix.add_intent, false),
            AccountMeta::new(ix.remove_intent, false),
            AccountMeta::new(ix.update_intent, false),
            AccountMeta::new_readonly(ix.system_program, false),
        ];
        accounts.extend(ix.remaining_accounts);
        let mut data = vec![0];
        wincode::serialize_into(&mut data, &ix.approval_threshold).unwrap();
        wincode::serialize_into(&mut data, &ix.cancellation_threshold).unwrap();
        wincode::serialize_into(&mut data, &ix.timelock_seconds).unwrap();
        wincode::serialize_into(&mut data, &ix.num_proposers).unwrap();
        wincode::serialize_into(&mut data, &ix.name).unwrap();
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
