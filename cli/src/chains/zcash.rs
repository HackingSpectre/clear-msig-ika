//! Zcash transparent P2PKH transaction assembly + broadcast.
//!
//! Assembles a Sapling v4 transparent-only transaction from the dWallet
//! network's 64-byte ECDSA signature and broadcasts it via Zcash RPC
//! (`sendrawtransaction`).

use crate::error::*;
use super::BroadcastResult;

pub struct SpendInputs {
    pub header: u32,
    pub version_group_id: u32,
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub sender_pkh: [u8; 20],
    pub recipient_pkh: [u8; 20],
    pub send_amount_zat: u64,
    pub lock_time: u32,
    pub expiry_height: u32,
}

/// Assemble a signed Zcash Sapling v4 transparent P2PKH transaction and
/// broadcast it via the provided RPC URL.
pub fn assemble_and_broadcast(
    inputs: SpendInputs,
    r: &[u8; 32],
    s: &[u8; 32],
    pubkey_compressed: &[u8],
    rpc_url: &str,
) -> Result<BroadcastResult> {
    if pubkey_compressed.len() != 33 {
        return Err(anyhow!(
            "expected 33-byte compressed secp256k1 pubkey, got {}",
            pubkey_compressed.len()
        ));
    }

    // DER-encode the signature and append SIGHASH_ALL byte.
    let der_sig = der_encode_signature(r, s);
    let mut sig_with_hashtype = der_sig.clone();
    sig_with_hashtype.push(0x01); // SIGHASH_ALL

    // scriptSig for P2PKH: <sig_with_hashtype> <pubkey>
    let mut script_sig = Vec::new();
    script_sig.push(sig_with_hashtype.len() as u8);
    script_sig.extend_from_slice(&sig_with_hashtype);
    script_sig.push(pubkey_compressed.len() as u8);
    script_sig.extend_from_slice(pubkey_compressed);

    // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> <pkh> OP_EQUALVERIFY OP_CHECKSIG
    let mut output_script = Vec::with_capacity(25);
    output_script.push(0x76); // OP_DUP
    output_script.push(0xa9); // OP_HASH160
    output_script.push(0x14); // push 20
    output_script.extend_from_slice(&inputs.recipient_pkh);
    output_script.push(0x88); // OP_EQUALVERIFY
    output_script.push(0xac); // OP_CHECKSIG

    // Assemble the full Sapling v4 transparent-only transaction.
    let mut tx = Vec::with_capacity(256);

    // header (4 LE) — includes fOverwintered flag
    tx.extend_from_slice(&inputs.header.to_le_bytes());
    // nVersionGroupId (4 LE)
    tx.extend_from_slice(&inputs.version_group_id.to_le_bytes());

    // vin count (varint)
    tx.push(1);
    // vin[0]: outpoint
    tx.extend_from_slice(&inputs.prev_txid);
    tx.extend_from_slice(&inputs.prev_vout.to_le_bytes());
    // scriptSig
    push_varint(&mut tx, script_sig.len() as u64);
    tx.extend_from_slice(&script_sig);
    // sequence
    tx.extend_from_slice(&0xfffffffeu32.to_le_bytes());

    // vout count (varint)
    tx.push(1);
    // vout[0]: amount + scriptPubKey
    tx.extend_from_slice(&inputs.send_amount_zat.to_le_bytes());
    push_varint(&mut tx, output_script.len() as u64);
    tx.extend_from_slice(&output_script);

    // nLockTime (4 LE)
    tx.extend_from_slice(&inputs.lock_time.to_le_bytes());
    // nExpiryHeight (4 LE)
    tx.extend_from_slice(&inputs.expiry_height.to_le_bytes());
    // valueBalance (8 LE) = 0 (transparent-only)
    tx.extend_from_slice(&0i64.to_le_bytes());
    // vShieldedSpend count = 0
    tx.push(0);
    // vShieldedOutput count = 0
    tx.push(0);
    // vJoinSplit count = 0
    tx.push(0);

    let raw_hex = hex::encode(&tx);

    // Broadcast: detect Blockchair push API vs standard JSON-RPC.
    let client = reqwest::blocking::Client::new();
    let tx_id = if rpc_url.contains("blockchair") {
        // Blockchair push API: POST with form data.
        let resp: serde_json::Value = client
            .post(rpc_url)
            .form(&[("data", &raw_hex)])
            .send()
            .with_context(|| format!("POST to {rpc_url}"))?
            .json()
            .with_context(|| "parse Blockchair response")?;
        if let Some(err) = resp.get("context").and_then(|c| c.get("error")) {
            if !err.is_null() {
                return Err(anyhow!("Blockchair push failed: {err}"));
            }
        }
        resp["data"]
            .get("transaction_hash")
            .and_then(|h| h.as_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        // Standard zcashd JSON-RPC.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendrawtransaction",
            "params": [raw_hex],
        });
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&body)
            .send()
            .with_context(|| format!("POST to {rpc_url}"))?
            .json()
            .with_context(|| "parse JSON-RPC response")?;
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error");
            return Err(anyhow!(
                "sendrawtransaction failed (code {code}): {message}"
            ));
        }
        resp["result"].as_str().unwrap_or("unknown").to_string()
    };

    Ok(BroadcastResult {
        chain: "zcash_transparent",
        chain_kind: 3,
        tx_id,
        raw_tx_hex: format!("0x{raw_hex}"),
        recovery_v: None,
        explorer_url: None,
    })
}

/// DER-encode an ECDSA (r, s) pair.
fn der_encode_signature(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    fn encode_integer(val: &[u8]) -> Vec<u8> {
        let mut v = val.to_vec();
        // Strip leading zeros
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        // Add leading zero if high bit set (DER integer is signed)
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, v.len() as u8];
        out.extend_from_slice(&v);
        out
    }
    let r_der = encode_integer(r);
    let s_der = encode_integer(s);
    let total = r_der.len() + s_der.len();
    let mut sig = vec![0x30, total as u8];
    sig.extend_from_slice(&r_der);
    sig.extend_from_slice(&s_der);
    sig
}

fn push_varint(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}
