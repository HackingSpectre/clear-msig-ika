use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use super::ID;

pub struct IkaSignInstruction {
    pub payer: Address,
    pub wallet: Address,
    pub intent: Address,
    pub proposal: Address,
    pub ika_config: Address,
    pub dwallet: Address,
    pub message_approval: Address,
    pub cpi_authority: Address,
    pub caller_program: Address,
    pub dwallet_program: Address,
    pub system_program: Address,
    pub message_approval_bump: u8,
    pub cpi_authority_bump: u8,
}

impl From<IkaSignInstruction> for Instruction {
    fn from(ix: IkaSignInstruction) -> Instruction {
        let accounts = vec![
            AccountMeta::new(ix.payer, true),
            AccountMeta::new_readonly(ix.wallet, false),
            AccountMeta::new(ix.intent, false),
            AccountMeta::new(ix.proposal, false),
            AccountMeta::new_readonly(ix.ika_config, false),
            AccountMeta::new(ix.dwallet, false),
            AccountMeta::new(ix.message_approval, false),
            AccountMeta::new_readonly(ix.cpi_authority, false),
            AccountMeta::new_readonly(ix.caller_program, false),
            AccountMeta::new_readonly(ix.dwallet_program, false),
            AccountMeta::new_readonly(ix.system_program, false),
        ];
        let mut data = vec![7];
        wincode::serialize_into(&mut data, &ix.message_approval_bump).unwrap();
        wincode::serialize_into(&mut data, &ix.cpi_authority_bump).unwrap();
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
