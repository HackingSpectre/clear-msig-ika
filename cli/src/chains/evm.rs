//! EVM signed-transaction assembly + broadcast.
//!
//! After `proposal execute --broadcast` finishes the on-chain `ika_sign` →
//! presign → sign roundtrip and gets a 64-byte ECDSA-secp256k1 signature
//! back from the dwallet network, we still need to:
//!
//!   1. **Recover `v`** (the 1-bit recovery parity). Ika returns only
//!      `(r, s)`; an Ethereum verifier needs `(r, s, v)` to ec_recover the
//!      sender. We try `v ∈ {0, 1}` and pick the one that recovers the
//!      dWallet's compressed secp256k1 pubkey.
//!   2. **Splice `(y_parity, r, s)` into the EIP-1559 RLP envelope.** The
//!      unsigned envelope is `0x02 || rlp([chain_id, nonce, max_priority,
//!      max_fee, gas, to, value, data, access_list])`. The signed envelope
//!      adds three fields at the end: `0x02 || rlp([..., y_parity, r, s])`.
//!   3. **Broadcast** via `eth_sendRawTransaction` to a JSON-RPC endpoint.
//!
//! All of this used to be a manual Node.js / curl ritual. The CLI now does
//! it inline so that `proposal execute --broadcast --rpc-url <URL>` takes a
//! pre-approved proposal all the way to a real on-chain transaction in one
//! shot.

use crate::chains::BroadcastResult;
use crate::error::*;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use serde::Deserialize;

/// Top-level entry point used by [`crate::chains::broadcast_signed_tx`] for
/// `chain_kind = 1` (`evm_1559`) and `chain_kind = 4` (`evm_1559_erc20`).
/// Both share the same EIP-1559 envelope; only the calldata differs, and
/// that's already baked into the `preimage` we receive here.
pub fn assemble_and_broadcast(
    preimage: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
    dwallet_pubkey_compressed: &[u8],
    rpc_url: &str,
) -> Result<BroadcastResult> {
    use tiny_keccak::{Hasher, Keccak};
    let mut digest = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(preimage);
    hasher.finalize(&mut digest);

    let v = recover_v(&digest, r, s, dwallet_pubkey_compressed)?;
    let raw_tx_hex = build_signed_eip1559(preimage, r, s, v)?;
    let tx_id = broadcast_eip1559(rpc_url, &raw_tx_hex)?;

    Ok(BroadcastResult {
        chain: "evm_1559",
        chain_kind: 1,
        tx_id,
        raw_tx_hex,
        recovery_v: Some(v),
        explorer_url: None,
    })
}

/// Try recovery `v ∈ {0, 1}` and return whichever value reconstructs
/// `expected_pubkey_compressed` (33 bytes, SEC1) from the message digest +
/// signature. Returns an error if neither parity works (which would mean
/// the signature was made over a different digest, or with a different
/// key — both are bugs in the upstream signing path).
pub fn recover_v(
    message_hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    expected_pubkey_compressed: &[u8],
) -> Result<u8> {
    use k256::ecdsa::RecoveryId;
    let sig = K256Signature::from_scalars(*r, *s)
        .map_err(|e| anyhow!("invalid (r,s): {e}"))?;
    for v in [0u8, 1u8] {
        let rec_id = RecoveryId::from_byte(v).expect("0/1 are valid recovery ids");
        let Ok(recovered) = K256VerifyingKey::recover_from_prehash(message_hash, &sig, rec_id)
        else {
            continue;
        };
        let recovered_compressed = recovered.to_encoded_point(true);
        if recovered_compressed.as_bytes() == expected_pubkey_compressed {
            return Ok(v);
        }
    }
    Err(anyhow!(
        "neither v=0 nor v=1 recovers the dwallet pubkey from the signed digest \
         — the signature is not over keccak256(preimage), or it was produced \
         by a different key"
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// Minimal RLP encoder
// ────────────────────────────────────────────────────────────────────────────
//
// We only need the subset that EIP-1559 envelopes use: byte strings + lists
// of byte strings. No nested lists beyond depth 1, no integers (we encode
// integers as their canonical big-endian byte string with leading zeros
// stripped, exactly like the on-chain RLP encoder in clear-wallet's
// `chains/evm.rs`).

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }
    if data.len() < 56 {
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(0x80 + data.len() as u8);
        out.extend_from_slice(data);
        return out;
    }
    let len_be = trim_leading_zeros(&data.len().to_be_bytes());
    let mut out = Vec::with_capacity(1 + len_be.len() + data.len());
    out.push(0xb7 + len_be.len() as u8);
    out.extend_from_slice(&len_be);
    out.extend_from_slice(data);
    out
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let inner: Vec<u8> = items.iter().flatten().copied().collect();
    if inner.len() < 56 {
        let mut out = Vec::with_capacity(1 + inner.len());
        out.push(0xc0 + inner.len() as u8);
        out.extend_from_slice(&inner);
        return out;
    }
    let len_be = trim_leading_zeros(&inner.len().to_be_bytes());
    let mut out = Vec::with_capacity(1 + len_be.len() + inner.len());
    out.push(0xf7 + len_be.len() as u8);
    out.extend_from_slice(&len_be);
    out.extend_from_slice(&inner);
    out
}

fn trim_leading_zeros(data: &[u8]) -> Vec<u8> {
    let first_nonzero = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    data[first_nonzero..].to_vec()
}

// ────────────────────────────────────────────────────────────────────────────
// RLP decoder (just enough to parse the unsigned EIP-1559 preimage so we can
// re-emit it with the signature appended)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct RlpItem<'a> {
    bytes: &'a [u8],
    next: usize,
}

fn rlp_read_list(buf: &[u8], off: usize) -> Result<(usize, usize)> {
    let b = *buf
        .get(off)
        .ok_or(anyhow!("rlp list header out of bounds"))?;
    if (0xc0..0xf8).contains(&b) {
        let len = (b - 0xc0) as usize;
        Ok((off + 1, len))
    } else if (0xf8..=0xff).contains(&b) {
        let llen = (b - 0xf7) as usize;
        let len_bytes = buf
            .get(off + 1..off + 1 + llen)
            .ok_or(anyhow!("rlp list length out of bounds"))?;
        let mut len: usize = 0;
        for &lb in len_bytes {
            len = (len << 8) | (lb as usize);
        }
        Ok((off + 1 + llen, len))
    } else {
        Err(anyhow!("expected rlp list header at offset {off}, got 0x{b:02x}"))
    }
}

fn rlp_read_item(buf: &[u8], off: usize) -> Result<RlpItem<'_>> {
    let b = *buf
        .get(off)
        .ok_or(anyhow!("rlp item header out of bounds"))?;
    if b < 0x80 {
        Ok(RlpItem {
            bytes: &buf[off..off + 1],
            next: off + 1,
        })
    } else if b < 0xb8 {
        let len = (b - 0x80) as usize;
        Ok(RlpItem {
            bytes: &buf[off + 1..off + 1 + len],
            next: off + 1 + len,
        })
    } else if b < 0xc0 {
        let llen = (b - 0xb7) as usize;
        let len_bytes = &buf[off + 1..off + 1 + llen];
        let mut len: usize = 0;
        for &lb in len_bytes {
            len = (len << 8) | (lb as usize);
        }
        let start = off + 1 + llen;
        Ok(RlpItem {
            bytes: &buf[start..start + len],
            next: start + len,
        })
    } else {
        Err(anyhow!(
            "expected rlp byte string at offset {off}, got 0x{b:02x} (list header)"
        ))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Signed-envelope assembly
// ────────────────────────────────────────────────────────────────────────────

/// Build the signed EIP-1559 RLP envelope from the unsigned preimage and the
/// recovered `(r, s, v)`. Returns the 0x-prefixed hex string ready to drop
/// into `eth_sendRawTransaction`.
pub fn build_signed_eip1559(preimage: &[u8], r: &[u8; 32], s: &[u8; 32], v: u8) -> Result<String> {
    if preimage.first() != Some(&0x02) {
        return Err(anyhow!("expected EIP-1559 type byte 0x02 at start of preimage"));
    }
    // Decode the inner list inside the preimage and re-emit it with three
    // extra fields appended (y_parity, r, s).
    let (list_payload_off, list_payload_len) = rlp_read_list(preimage, 1)?;
    let payload_end = list_payload_off + list_payload_len;
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(12);
    let mut off = list_payload_off;
    while off < payload_end {
        // Lists inside the inner list (e.g. the access_list at index 8) are
        // re-emitted verbatim, header + payload. An empty access_list is
        // just `0xc0`. Check the type byte first because `rlp_read_item`
        // errors on list headers.
        let b = preimage[off];
        if b >= 0xc0 {
            let (acl_off, acl_len) = rlp_read_list(preimage, off)?;
            let raw = preimage[off..acl_off + acl_len].to_vec();
            items.push(raw);
            off = acl_off + acl_len;
        } else {
            let item = rlp_read_item(preimage, off)?;
            items.push(rlp_encode_bytes(item.bytes));
            off = item.next;
        }
    }
    if items.len() != 9 {
        return Err(anyhow!(
            "expected 9 fields in unsigned EIP-1559 envelope, got {}",
            items.len()
        ));
    }

    // Append y_parity (RLP-encoded as either empty bytes for v=0 or 0x01 for v=1).
    let y_parity_bytes: &[u8] = if v == 0 { &[] } else { &[1u8] };
    items.push(rlp_encode_bytes(y_parity_bytes));
    items.push(rlp_encode_bytes(&trim_leading_zeros(r)));
    items.push(rlp_encode_bytes(&trim_leading_zeros(s)));

    let signed_list = rlp_encode_list(&items);
    let mut signed = Vec::with_capacity(1 + signed_list.len());
    signed.push(0x02);
    signed.extend_from_slice(&signed_list);

    let mut hex_out = String::with_capacity(2 + signed.len() * 2);
    hex_out.push_str("0x");
    for b in signed {
        hex_out.push_str(&format!("{b:02x}"));
    }
    Ok(hex_out)
}

// ────────────────────────────────────────────────────────────────────────────
// Broadcast via JSON-RPC `eth_sendRawTransaction`
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
}

/// Broadcast a signed EIP-1559 transaction (`raw_tx_hex` = `0x02...`) via the
/// given JSON-RPC URL using `eth_sendRawTransaction`. Returns the resulting
/// transaction hash on success.
pub fn broadcast_eip1559(rpc_url: &str, raw_tx_hex: &str) -> Result<String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [raw_tx_hex],
        "id": 1,
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .with_context(|| "build reqwest client")?;
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .with_context(|| format!("POST {rpc_url}"))?;
    let status = resp.status();
    let text = resp.text().with_context(|| "read RPC response body")?;
    if !status.is_success() {
        return Err(anyhow!("EVM RPC HTTP {status}: {text}"));
    }
    let parsed: JsonRpcResponse<String> = serde_json::from_str(&text)
        .with_context(|| format!("parse RPC response: {text}"))?;
    if let Some(err) = parsed.error {
        return Err(anyhow!(
            "eth_sendRawTransaction failed (code {}): {}{}",
            err.code,
            err.message,
            err.data
                .map(|d| format!(" — {d}"))
                .unwrap_or_default()
        ));
    }
    parsed
        .result
        .ok_or(anyhow!("RPC response had neither result nor error: {text}"))
}
