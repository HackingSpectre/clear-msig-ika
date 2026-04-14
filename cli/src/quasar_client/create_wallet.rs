use solana_address::Address;
use solana_instruction_v3::{AccountMeta, Instruction};
use super::ID;
use quasar_lang::client::{DynBytes, DynVec};

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
    pub name: DynBytes,
    pub proposers: DynVec<[u8; 32]>,
    pub approvers: DynVec<[u8; 32]>,
}

impl From<CreateWalletInstruction> for Instruction {
    fn from(ix: CreateWalletInstruction) -> Instruction {
        let accounts = vec![
            AccountMeta::new(ix.payer, true),
            AccountMeta::new_readonly(ix.name_hash, false),
            AccountMeta::new(ix.wallet, false),
            AccountMeta::new(ix.add_intent, false),
            AccountMeta::new(ix.remove_intent, false),
            AccountMeta::new(ix.update_intent, false),
            AccountMeta::new_readonly(ix.system_program, false),
        ];
        let mut data = vec![0];
        wincode::serialize_into(&mut data, &ix.approval_threshold).unwrap();
        wincode::serialize_into(&mut data, &ix.cancellation_threshold).unwrap();
        wincode::serialize_into(&mut data, &ix.timelock_seconds).unwrap();
        wincode::serialize_into(&mut data, &ix.name).unwrap();
        wincode::serialize_into(&mut data, &ix.proposers).unwrap();
        wincode::serialize_into(&mut data, &ix.approvers).unwrap();
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
