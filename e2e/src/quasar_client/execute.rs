use std::vec::Vec;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use super::ID;

pub struct ExecuteInstruction {
    pub wallet: Address,
    pub vault: Address,
    pub intent: Address,
    pub proposal: Address,
    pub system_program: Address,
    pub remaining_accounts: Vec<AccountMeta>,
}

impl From<ExecuteInstruction> for Instruction {
    fn from(ix: ExecuteInstruction) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(ix.wallet, false),
            AccountMeta::new(ix.vault, false),
            AccountMeta::new(ix.intent, false),
            AccountMeta::new(ix.proposal, false),
            AccountMeta::new_readonly(ix.system_program, false),
        ];
        accounts.extend(ix.remaining_accounts);
        let data = vec![4];
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
