use solana_address::Address;
use solana_instruction_v3::{AccountMeta, Instruction};
use super::ID;

pub struct ApproveInstruction {
    pub wallet: Address,
    pub intent: Address,
    pub proposal: Address,
    pub expiry: i64,
    pub approver_index: u8,
    pub signature: [u8; 64],
}

impl From<ApproveInstruction> for Instruction {
    fn from(ix: ApproveInstruction) -> Instruction {
        let accounts = vec![
            AccountMeta::new_readonly(ix.wallet, false),
            AccountMeta::new(ix.intent, false),
            AccountMeta::new(ix.proposal, false),
        ];
        let mut data = vec![2];
        wincode::serialize_into(&mut data, &ix.expiry).unwrap();
        wincode::serialize_into(&mut data, &ix.approver_index).unwrap();
        wincode::serialize_into(&mut data, &ix.signature).unwrap();
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
