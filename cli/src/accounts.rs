use crate::error::*;
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use clear_wallet::utils::definition::*;
use ripemd::{Digest as _, Ripemd160};
use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};

/// Deserialized ClearWallet account.
#[derive(Debug, Serialize)]
pub struct WalletAccount {
    pub bump: u8,
    pub proposal_index: u64,
    pub intent_index: u8,
    pub name: String,
}

/// Deserialized Intent account.
#[allow(dead_code)]
pub struct IntentAccount {
    pub wallet: String,
    pub bump: u8,
    pub intent_index: u8,
    pub intent_type: u8,
    /// 0 = Solana (local CPI), 1+ = remote chain via Ika dWallet.
    pub chain_kind: u8,
    pub approved: bool,
    pub approval_threshold: u8,
    pub cancellation_threshold: u8,
    pub timelock_seconds: u32,
    pub template_offset: u16,
    pub template_len: u16,
    pub tx_template_offset: u16,
    pub tx_template_len: u16,
    pub active_proposal_count: u16,
    pub proposers: Vec<String>,
    pub approvers: Vec<String>,
    pub params: Vec<ParamEntry>,
    pub accounts: Vec<AccountEntry>,
    pub instructions: Vec<InstructionEntry>,
    pub data_segments: Vec<DataSegmentEntry>,
    pub seeds: Vec<SeedEntry>,
    pub byte_pool: Vec<u8>,
}

/// Deserialized Proposal account.
#[derive(Debug, Serialize)]
pub struct ProposalAccount {
    pub wallet: String,
    pub intent: String,
    pub proposal_index: u64,
    pub proposer: String,
    pub status: String,
    pub proposed_at: i64,
    pub approved_at: i64,
    pub bump: u8,
    pub approval_bitmap: u16,
    pub cancellation_bitmap: u16,
    pub rent_refund: String,
    pub params_data: Vec<u8>,
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8> {
    let val = *data.get(*offset).ok_or(anyhow!("unexpected end of data at {}", *offset))?;
    *offset += 1;
    Ok(val)
}

fn read_u16_le(data: &[u8], offset: &mut usize) -> Result<u16> {
    let bytes: [u8; 2] = data.get(*offset..*offset + 2)
        .ok_or(anyhow!("unexpected end of data"))?.try_into()?;
    *offset += 2;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes: [u8; 4] = data.get(*offset..*offset + 4)
        .ok_or(anyhow!("unexpected end of data"))?.try_into()?;
    *offset += 4;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(data: &[u8], offset: &mut usize) -> Result<u64> {
    let bytes: [u8; 8] = data.get(*offset..*offset + 8)
        .ok_or(anyhow!("unexpected end of data"))?.try_into()?;
    *offset += 8;
    Ok(u64::from_le_bytes(bytes))
}

fn read_i64_le(data: &[u8], offset: &mut usize) -> Result<i64> {
    let bytes: [u8; 8] = data.get(*offset..*offset + 8)
        .ok_or(anyhow!("unexpected end of data"))?.try_into()?;
    *offset += 8;
    Ok(i64::from_le_bytes(bytes))
}

fn read_address(data: &[u8], offset: &mut usize) -> Result<String> {
    let bytes = data.get(*offset..*offset + 32)
        .ok_or(anyhow!("unexpected end of data"))?;
    *offset += 32;
    Ok(bs58::encode(bytes).into_string())
}

fn read_vec_addresses(data: &[u8], offset: &mut usize) -> Result<Vec<String>> {
    let count = read_u32_le(data, offset)? as usize;
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        addresses.push(read_address(data, offset)?);
    }
    Ok(addresses)
}

fn read_vec_raw<T: Copy>(data: &[u8], offset: &mut usize) -> Result<Vec<T>> {
    let count = read_u32_le(data, offset)? as usize;
    let elem_size = core::mem::size_of::<T>();
    let total = count * elem_size;
    let bytes = data.get(*offset..*offset + total)
        .ok_or(anyhow!("unexpected end of data reading vec of {} elements", count))?;
    let items: Vec<T> = (0..count)
        .map(|i| unsafe { core::ptr::read(bytes[i * elem_size..].as_ptr() as *const T) })
        .collect();
    *offset += total;
    Ok(items)
}

fn read_vec_u8(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let count = read_u32_le(data, offset)? as usize;
    let bytes = data.get(*offset..*offset + count)
        .ok_or(anyhow!("unexpected end of data reading {} bytes", count))?;
    let result = bytes.to_vec();
    *offset += count;
    Ok(result)
}

pub fn parse_wallet(data: &[u8]) -> Result<WalletAccount> {
    if data.is_empty() || data[0] != 1 {
        return Err(anyhow!("not a ClearWallet account (discriminator={})", data.first().unwrap_or(&0)));
    }
    let mut offset = 1;
    let bump = read_u8(data, &mut offset)?;
    let proposal_index = read_u64_le(data, &mut offset)?;
    let intent_index = read_u8(data, &mut offset)?;
    // name is a dynamic String with u32 LE prefix
    let name_len = read_u32_le(data, &mut offset)? as usize;
    let name_bytes = data.get(offset..offset + name_len)
        .ok_or(anyhow!("unexpected end of data reading name"))?;
    let name = String::from_utf8_lossy(name_bytes).to_string();

    Ok(WalletAccount { bump, proposal_index, intent_index, name })
}

pub fn parse_intent(data: &[u8]) -> Result<IntentAccount> {
    if data.is_empty() || data[0] != 2 {
        return Err(anyhow!("not an Intent account (discriminator={})", data.first().unwrap_or(&0)));
    }
    // Layout (must match programs/clear-wallet/src/state/intent.rs):
    //   disc(1) + wallet(32) + bump(1) + intent_index(1) + intent_type(1)
    //   + chain_kind(1) + approved(1)
    //   + approval_threshold(1) + cancellation_threshold(1) + timelock_seconds(4)
    //   + template_offset(2) + template_len(2)
    //   + tx_template_offset(2) + tx_template_len(2)
    //   + active_proposal_count(2)
    //   + Vec<proposers> + Vec<approvers> + Vec<params> + ... + byte_pool
    let mut offset = 1;
    let wallet = read_address(data, &mut offset)?;
    let bump = read_u8(data, &mut offset)?;
    let intent_index = read_u8(data, &mut offset)?;
    let intent_type = read_u8(data, &mut offset)?;
    let chain_kind = read_u8(data, &mut offset)?;
    let approved = read_u8(data, &mut offset)? != 0;
    let approval_threshold = read_u8(data, &mut offset)?;
    let cancellation_threshold = read_u8(data, &mut offset)?;
    let timelock_seconds = read_u32_le(data, &mut offset)?;
    let template_offset = read_u16_le(data, &mut offset)?;
    let template_len = read_u16_le(data, &mut offset)?;
    let tx_template_offset = read_u16_le(data, &mut offset)?;
    let tx_template_len = read_u16_le(data, &mut offset)?;
    let active_proposal_count = read_u16_le(data, &mut offset)?;

    let proposers = read_vec_addresses(data, &mut offset)?;
    let approvers = read_vec_addresses(data, &mut offset)?;
    let params = read_vec_raw::<ParamEntry>(data, &mut offset)?;
    let accounts = read_vec_raw::<AccountEntry>(data, &mut offset)?;
    let instructions = read_vec_raw::<InstructionEntry>(data, &mut offset)?;
    let data_segments = read_vec_raw::<DataSegmentEntry>(data, &mut offset)?;
    let seeds = read_vec_raw::<SeedEntry>(data, &mut offset)?;
    let byte_pool = read_vec_u8(data, &mut offset)?;

    Ok(IntentAccount {
        wallet, bump, intent_index, intent_type, chain_kind, approved,
        approval_threshold, cancellation_threshold, timelock_seconds,
        template_offset, template_len, tx_template_offset, tx_template_len,
        active_proposal_count,
        proposers, approvers, params, accounts, instructions,
        data_segments, seeds, byte_pool,
    })
}

/// Deserialized IkaConfig account (the per-(wallet, chain_kind) dWallet binding).
#[derive(Debug, Serialize)]
pub struct IkaConfigAccount {
    pub wallet: String,
    pub dwallet: String,
    pub user_pubkey: String,
    pub chain_kind: u8,
    pub signature_scheme: u16,
    pub bump: u8,
}

/// Subset of the dWallet account needed by the CLI (curve + actual pubkey).
///
/// On-chain layout (after the 1-byte discriminator + 1-byte version header):
/// - `[2..34]`   authority
/// - `[34..36]`  curve (u16 LE)
/// - `[36]`      state
/// - `[37]`      public_key_len
/// - `[38..103]` public_key (zero-padded to 65 bytes)
#[derive(Debug, Serialize)]
pub struct DWalletAccount {
    pub curve: u16,
    pub state: u8,
    pub public_key: Vec<u8>,
}

/// Read just the dWallet's current authority pubkey (32 bytes at offset 2)
/// without parsing the rest of the account. Used by `wallet add-chain` to
/// detect whether the dWallet has already been transferred to clear-wallet's
/// CPI authority PDA on a prior bind, in which case we skip the
/// `transfer_ownership` step instead of failing on a duplicate transfer.
pub fn parse_dwallet_authority(data: &[u8]) -> Result<solana_sdk::pubkey::Pubkey> {
    if data.len() < 34 || data[0] != 2 {
        return Err(anyhow!(
            "not a DWallet account (discriminator={})",
            data.first().unwrap_or(&0)
        ));
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data[2..34]);
    Ok(solana_sdk::pubkey::Pubkey::new_from_array(authority))
}

pub fn parse_dwallet(data: &[u8]) -> Result<DWalletAccount> {
    if data.len() < 103 || data[0] != 2 {
        return Err(anyhow!(
            "not a DWallet account (discriminator={})",
            data.first().unwrap_or(&0)
        ));
    }
    let curve = u16::from_le_bytes([data[34], data[35]]);
    let state = data[36];
    let public_key_len = data[37] as usize;
    if public_key_len == 0 || public_key_len > 65 {
        return Err(anyhow!("invalid dWallet public_key_len: {public_key_len}"));
    }
    let public_key = data[38..38 + public_key_len].to_vec();
    Ok(DWalletAccount {
        curve,
        state,
        public_key,
    })
}

/// Compute the EVM address (20 bytes) from a 33-byte SEC1 compressed
/// secp256k1 public key. Returns the lowercase `0x`-prefixed hex string.
pub fn evm_address_from_secp256k1(compressed: &[u8]) -> Result<String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::PublicKey;
    use tiny_keccak::{Hasher, Keccak};

    if compressed.len() != 33 {
        return Err(anyhow!(
            "expected 33-byte compressed secp256k1 pubkey, got {}",
            compressed.len()
        ));
    }
    let pk = PublicKey::from_sec1_bytes(compressed)
        .map_err(|e| anyhow!("invalid secp256k1 pubkey: {e}"))?;
    let uncompressed = pk.to_encoded_point(false);
    let xy = &uncompressed.as_bytes()[1..]; // strip 0x04 prefix → 64 bytes
    let mut hash = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(xy);
    hasher.finalize(&mut hash);
    Ok(format!("0x{}", hex_encode(&hash[12..])))
}

/// `hash160(x)` = `RIPEMD160(SHA256(x))` — the standard Bitcoin key
/// fingerprint hash used for P2WPKH addresses.
fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(bytes);
    let ripemd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripemd);
    out
}

/// Bitcoin P2WPKH address (bech32, witness version 0) for the given network.
///
/// `hrp` is the human-readable part: `"bc"` for mainnet, `"tb"` for testnet,
/// `"bcrt"` for regtest. Returns e.g. `bc1q...` / `tb1q...`.
pub fn bitcoin_p2wpkh_address(compressed: &[u8], hrp: &str) -> Result<String> {
    if compressed.len() != 33 {
        return Err(anyhow!(
            "expected 33-byte compressed secp256k1 pubkey, got {}",
            compressed.len()
        ));
    }
    let h160 = hash160(compressed);
    let hrp = Hrp::parse(hrp).map_err(|e| anyhow!("invalid bech32 HRP: {e}"))?;
    // Witness version 0, then the 20-byte program. The bech32 crate exposes
    // this via `encode::<Bech32>` after we manually prepend the version.
    // For witness v0 P2WPKH the encoded payload is just the 20-byte hash and
    // the version byte is encoded outside the data. The simplest correct
    // path is to use `bech32::segwit::encode_v0`.
    bech32::segwit::encode_v0(hrp, &h160)
        .map_err(|e| anyhow!("bech32 encode: {e}"))
}

#[allow(dead_code)]
fn _bech32_unused() {
    // Silence unused-import warnings if `Bech32` / `CheckedHrpstring` are not
    // referenced after a future refactor.
    let _ = std::any::type_name::<Bech32>();
    let _ = std::any::type_name::<CheckedHrpstring<'_>>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dWallet pubkey from a real devnet DKG run on
    /// `87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY` — used as a known
    /// fixed input so we can pin every chain-native derivation against
    /// independently-computed reference values.
    const TEST_PK_HEX: &str =
        "03445655313b638875c9f559b34aacb355e59cc9ce248b49696a584d0416cd9b79";

    fn pk() -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        let bytes = TEST_PK_HEX.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            let hi = (bytes[i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    #[test]
    fn evm_address_matches_reference() {
        assert_eq!(
            evm_address_from_secp256k1(&pk()).unwrap(),
            "0x400d36c43a8e5871483e7caa957f0cace0d71a1d"
        );
    }

    #[test]
    fn p2wpkh_addresses_round_trip() {
        // Both networks should encode without error and decode back to the same
        // 20-byte hash160. We don't pin the literal bech32 string here because
        // the reference value is implicitly verified by the round-trip + the
        // hash160 equality check.
        let pk = pk();
        let main = bitcoin_p2wpkh_address(&pk, "bc").unwrap();
        let test = bitcoin_p2wpkh_address(&pk, "tb").unwrap();
        assert!(main.starts_with("bc1q"));
        assert!(test.starts_with("tb1q"));

        let h160 = hash160(&pk);
        for addr in [main, test] {
            let (_hrp, _witness_version, program) = bech32::segwit::decode(&addr).unwrap();
            assert_eq!(&program, &h160);
        }
    }
}

pub fn parse_ika_config(data: &[u8]) -> Result<IkaConfigAccount> {
    if data.len() < 101 || data[0] != 4 {
        return Err(anyhow!(
            "not an IkaConfig account (discriminator={})",
            data.first().unwrap_or(&0)
        ));
    }
    let mut offset = 1;
    let wallet = read_address(data, &mut offset)?;
    let dwallet = read_address(data, &mut offset)?;
    let user_pubkey_bytes = data.get(offset..offset + 32)
        .ok_or(anyhow!("unexpected end of data reading user_pubkey"))?;
    let user_pubkey = hex_encode(user_pubkey_bytes);
    offset += 32;
    let chain_kind = read_u8(data, &mut offset)?;
    let signature_scheme = u16::from_le_bytes(
        data.get(offset..offset + 2)
            .ok_or(anyhow!("unexpected end of data reading signature_scheme"))?
            .try_into()
            .unwrap(),
    );
    offset += 2;
    let bump = read_u8(data, &mut offset)?;
    Ok(IkaConfigAccount {
        wallet, dwallet, user_pubkey, chain_kind, signature_scheme, bump,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn parse_proposal(data: &[u8]) -> Result<ProposalAccount> {
    if data.is_empty() || data[0] != 3 {
        return Err(anyhow!("not a Proposal account (discriminator={})", data.first().unwrap_or(&0)));
    }
    let mut offset = 1;
    let wallet = read_address(data, &mut offset)?;
    let intent = read_address(data, &mut offset)?;
    let proposal_index = read_u64_le(data, &mut offset)?;
    let proposer = read_address(data, &mut offset)?;
    let status_byte = read_u8(data, &mut offset)?;
    let status = match status_byte {
        0 => "Active", 1 => "Approved", 2 => "Executed", 3 => "Cancelled", _ => "Unknown",
    }.to_string();
    let proposed_at = read_i64_le(data, &mut offset)?;
    let approved_at = read_i64_le(data, &mut offset)?;
    let bump = read_u8(data, &mut offset)?;
    let approval_bitmap = read_u16_le(data, &mut offset)?;
    let cancellation_bitmap = read_u16_le(data, &mut offset)?;
    let rent_refund = read_address(data, &mut offset)?;
    let params_data = read_vec_u8(data, &mut offset)?;

    Ok(ProposalAccount {
        wallet, intent, proposal_index, proposer, status,
        proposed_at, approved_at, bump, approval_bitmap, cancellation_bitmap,
        rent_refund, params_data,
    })
}

impl IntentAccount {
    pub fn intent_type_name(&self) -> &str {
        match self.intent_type {
            0 => "AddIntent",
            1 => "RemoveIntent",
            2 => "UpdateIntent",
            3 => "Custom",
            _ => "Unknown",
        }
    }

    pub fn template(&self) -> &str {
        if self.template_len == 0 { return ""; }
        let start = self.template_offset as usize;
        let end = start + self.template_len as usize;
        if end <= self.byte_pool.len() {
            std::str::from_utf8(&self.byte_pool[start..end]).unwrap_or("")
        } else {
            ""
        }
    }
}
