use solana_address::Address;
use solana_instruction_v3::{AccountMeta, Instruction};
use super::ID;
use quasar_lang::client::TailBytes;

pub struct ProposeInstruction {
    pub payer: Address,
    pub wallet: Address,
    pub intent: Address,
    pub proposal: Address,
    pub system_program: Address,
    pub proposal_index: u64,
    pub expiry: i64,
    pub proposer_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub params_data: TailBytes,
}

impl From<ProposeInstruction> for Instruction {
    fn from(ix: ProposeInstruction) -> Instruction {
        let accounts = vec![
            AccountMeta::new(ix.payer, true),
            AccountMeta::new(ix.wallet, false),
            AccountMeta::new(ix.intent, false),
            AccountMeta::new(ix.proposal, false),
            AccountMeta::new_readonly(ix.system_program, false),
        ];
        let mut data = vec![1];
        wincode::serialize_into(&mut data, &ix.proposal_index).unwrap();
        wincode::serialize_into(&mut data, &ix.expiry).unwrap();
        wincode::serialize_into(&mut data, &ix.proposer_pubkey).unwrap();
        wincode::serialize_into(&mut data, &ix.signature).unwrap();
        wincode::serialize_into(&mut data, &ix.params_data).unwrap();
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
