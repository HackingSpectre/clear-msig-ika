use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use super::ID;

pub struct BindDwalletInstruction {
    pub payer: Address,
    pub wallet: Address,
    pub ika_config: Address,
    pub dwallet: Address,
    pub cpi_authority: Address,
    pub caller_program: Address,
    pub dwallet_program: Address,
    pub system_program: Address,
    pub chain_kind: u8,
    pub user_pubkey: [u8; 32],
    pub signature_scheme: u8,
    pub cpi_authority_bump: u8,
}

impl From<BindDwalletInstruction> for Instruction {
    fn from(ix: BindDwalletInstruction) -> Instruction {
        let accounts = vec![
            AccountMeta::new(ix.payer, true),
            AccountMeta::new_readonly(ix.wallet, false),
            AccountMeta::new(ix.ika_config, false),
            AccountMeta::new(ix.dwallet, false),
            AccountMeta::new_readonly(ix.cpi_authority, false),
            AccountMeta::new_readonly(ix.caller_program, false),
            AccountMeta::new_readonly(ix.dwallet_program, false),
            AccountMeta::new_readonly(ix.system_program, false),
        ];
        let mut data = vec![6];
        wincode::serialize_into(&mut data, &ix.chain_kind).unwrap();
        wincode::serialize_into(&mut data, &ix.user_pubkey).unwrap();
        wincode::serialize_into(&mut data, &ix.signature_scheme).unwrap();
        wincode::serialize_into(&mut data, &ix.cpi_authority_bump).unwrap();
        Instruction {
            program_id: ID,
            accounts,
            data,
        }
    }
}
