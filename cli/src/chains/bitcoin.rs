//! Bitcoin P2WPKH (BIP143) signed-transaction assembly + Esplora broadcast.
//!
//! Same shape as [`super::evm`], but the destination format is a serialized
//! Bitcoin segwit (witness) transaction broadcast via an Esplora REST
//! endpoint (`POST <base>/tx`).
//!
//! ## What this module does, end-to-end
//!
//! After `proposal execute --broadcast` finishes the on-chain `ika_sign` →
//! presign → sign roundtrip and the dwallet network returns a 64-byte
//! ECDSA-secp256k1 signature over the BIP143 sighash, this module:
//!
//!   1. **DER-encodes** `(r, s)` and appends `0x01` (`SIGHASH_ALL`). Bitcoin
//!      consensus rejects compact 64-byte sigs — segwit witness items must
//!      carry strict-DER encoded signatures.
//!   2. **Builds the segwit transaction body** for the single-input,
//!      single-output P2WPKH spend that matches the on-chain
//!      [`clear_wallet::chains::bitcoin::build_preimage`] layout. The body
//!      we emit is byte-for-byte the same transaction that the BIP143
//!      sighash committed to, only now with the witness filled in.
//!   3. **Attaches the witness** stack `[der_sig || sighash_type, pubkey]`
//!      so any verifier can re-run BIP143 on the same data and end up with
//!      the same sighash bytes the dwallet network signed.
//!   4. **Broadcasts** via Esplora `POST <base>/tx`, which takes a hex
//!      body and returns the txid as plain text on success.
//!
//! The serialized format is the standard Bitcoin segwit tx layout:
//! ```text
//! version              : 4 bytes  LE
//! marker               : 0x00            ← present iff this is segwit
//! flag                 : 0x01            ← present iff this is segwit
//! input_count          : varint
//!   prev_txid          : 32 bytes
//!   prev_vout          : 4 bytes  LE
//!   scriptSig_len      : varint = 0      ← P2WPKH has empty scriptSig
//!   sequence           : 4 bytes  LE
//! output_count         : varint
//!   value_sats         : 8 bytes  LE
//!   scriptPubKey_len   : varint = 22
//!   scriptPubKey       : OP_0 || 0x14 || 20-byte pkh   ← P2WPKH
//! witness_for_input_0:
//!   stack_count        : varint = 2
//!   item_0_len         : varint                          (DER + sighash byte)
//!   item_0             : DER(r, s) || 0x01
//!   item_1_len         : varint = 33
//!   item_1             : compressed pubkey
//! nLockTime            : 4 bytes  LE
//! ```
//!
//! Adding additional inputs/outputs is a matter of looping over more
//! `(prev_txid, vout, ...)` and `(value, scriptPubKey)` blocks; the witness
//! assembly stays one item per input. The current single-input,
//! single-output shape matches what
//! `clear_wallet::chains::bitcoin::build_preimage` understands and what
//! the on-chain BIP143 sighash commits to.

use crate::chains::BroadcastResult;
use crate::error::*;
use k256::ecdsa::Signature as K256Signature;
use serde::Deserialize;

/// Inputs needed to assemble the segwit transaction body. Anything not
/// recoverable from the BIP143 preimage hash tree (which commits to
/// outputs as a hash, not as the original values).
pub struct SpendInputs {
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub sequence: u32,
    pub recipient_pkh: [u8; 20],
    pub send_amount_sats: u64,
    pub lock_time: u32,
}

/// Top-level entry used by [`crate::chains::broadcast_signed_tx`] for
/// `chain_kind = 2` (`bitcoin_p2wpkh`). Returns the broadcast txid +
/// the raw signed tx hex on success.
pub fn assemble_and_broadcast(
    inputs: SpendInputs,
    r: &[u8; 32],
    s: &[u8; 32],
    dwallet_pubkey_compressed: &[u8],
    rpc_url: &str,
) -> Result<BroadcastResult> {
    if dwallet_pubkey_compressed.len() != 33 {
        return Err(anyhow!(
            "expected 33-byte SEC1 compressed secp256k1 pubkey, got {}",
            dwallet_pubkey_compressed.len()
        ));
    }
    let der_sig = der_encode_signature(r, s)?;
    let mut sig_with_hashtype = Vec::with_capacity(der_sig.len() + 1);
    sig_with_hashtype.extend_from_slice(&der_sig);
    sig_with_hashtype.push(SIGHASH_ALL);

    // We always emit version 2 because that's what the on-chain
    // `clear_wallet::chains::bitcoin` builder pins for the preimage. If
    // future templates expose a non-2 version, this should read it from
    // the same `tx_template` block the proposer signed off on.
    let raw_tx = build_segwit_tx(
        TX_VERSION,
        &inputs,
        &sig_with_hashtype,
        dwallet_pubkey_compressed,
    );
    let raw_tx_hex = hex_encode(&raw_tx);

    let tx_id = broadcast_via_esplora(rpc_url, &raw_tx_hex)?;
    let explorer_url = derive_explorer_url(rpc_url, &tx_id);

    Ok(BroadcastResult {
        chain: "bitcoin_p2wpkh",
        chain_kind: 2,
        tx_id,
        raw_tx_hex,
        recovery_v: None,
        explorer_url,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────────────

/// Bitcoin transaction version we emit. The on-chain BIP143 builder hard-codes
/// version 2 in its preimage; the broadcast tx must match.
const TX_VERSION: u32 = 2;

/// Sighash type byte appended to the DER signature inside the witness item.
/// `SIGHASH_ALL = 0x01` covers every input + output, which is what the on-chain
/// BIP143 preimage construction in `clear_wallet::chains::bitcoin` produces.
const SIGHASH_ALL: u8 = 0x01;

// ────────────────────────────────────────────────────────────────────────────
// DER signature encoding
// ────────────────────────────────────────────────────────────────────────────

/// Encode a `(r, s)` ECDSA signature as strict DER, the format Bitcoin
/// consensus expects in segwit witness items. We low-s normalize first
/// (BIP146) and then delegate the actual DER bytes to `k256`'s built-in
/// encoder so we don't reimplement the SEC1/DER serialization rules.
fn der_encode_signature(r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<u8>> {
    let sig = K256Signature::from_scalars(*r, *s)
        .map_err(|e| anyhow!("invalid (r, s) for DER encoding: {e}"))?;
    let normalized = sig.normalize_s().unwrap_or(sig);
    Ok(normalized.to_der().as_bytes().to_vec())
}

// ────────────────────────────────────────────────────────────────────────────
// Segwit transaction body assembly
// ────────────────────────────────────────────────────────────────────────────

fn build_segwit_tx(
    version: u32,
    inputs: &SpendInputs,
    sig_with_hashtype: &[u8],
    pubkey_compressed: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);

    // version + segwit marker/flag
    out.extend_from_slice(&version.to_le_bytes());
    out.push(0x00); // marker
    out.push(0x01); // flag

    // inputs (1)
    write_varint(&mut out, 1);
    out.extend_from_slice(&inputs.prev_txid);
    out.extend_from_slice(&inputs.prev_vout.to_le_bytes());
    write_varint(&mut out, 0); // empty scriptSig — P2WPKH spend
    out.extend_from_slice(&inputs.sequence.to_le_bytes());

    // outputs (1) — single P2WPKH output to recipient_pkh
    write_varint(&mut out, 1);
    out.extend_from_slice(&inputs.send_amount_sats.to_le_bytes());
    // P2WPKH scriptPubKey: OP_0 (0x00) + push20 (0x14) + 20-byte pkh = 22 bytes
    write_varint(&mut out, 22);
    out.push(0x00); // OP_0
    out.push(0x14); // OP_PUSHBYTES_20
    out.extend_from_slice(&inputs.recipient_pkh);

    // witness for input 0: stack of [sig||hashtype, compressed_pubkey]
    write_varint(&mut out, 2);
    write_varint(&mut out, sig_with_hashtype.len() as u64);
    out.extend_from_slice(sig_with_hashtype);
    write_varint(&mut out, pubkey_compressed.len() as u64);
    out.extend_from_slice(pubkey_compressed);

    // locktime
    out.extend_from_slice(&inputs.lock_time.to_le_bytes());

    out
}

/// Bitcoin variable-length integer (CompactSize) encoder. Used for input
/// counts, output counts, scriptPubKey lengths, and witness item counts.
fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ────────────────────────────────────────────────────────────────────────────
// Esplora REST broadcast
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum EsploraResponse {
    /// Some Esplora deployments return JSON like `{"txid": "..."}`.
    Json {
        txid: String,
    },
    /// Most return the txid as a plain text body.
    Text(String),
}

/// Broadcast a fully-signed Bitcoin tx via Esplora's REST endpoint.
///
/// Esplora is the API that runs behind block explorers like
/// blockstream.info and mempool.space. The relevant call is
/// `POST <base>/tx` with the hex-encoded raw tx as the request body
/// (no JSON wrapping). On success it returns the txid as a plain text
/// string in the response body. On failure it returns an HTTP 4xx with
/// the consensus error in the body (e.g. `bad-txns-inputs-missingorspent`).
fn broadcast_via_esplora(rpc_base: &str, raw_tx_hex: &str) -> Result<String> {
    let endpoint = format!("{}/tx", rpc_base.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .with_context(|| "build reqwest client")?;
    let resp = client
        .post(&endpoint)
        .header("Content-Type", "text/plain")
        .body(raw_tx_hex.to_string())
        .send()
        .with_context(|| format!("POST {endpoint}"))?;
    let status = resp.status();
    let text = resp.text().with_context(|| "read Esplora response body")?;
    if !status.is_success() {
        return Err(anyhow!(
            "Esplora broadcast failed (HTTP {status}): {}",
            text.trim()
        ));
    }
    let trimmed = text.trim();
    // Most Esplora deployments return the bare txid hex. Some return JSON.
    if trimmed.starts_with('{') {
        let parsed: EsploraResponse = serde_json::from_str(trimmed)
            .with_context(|| format!("parse Esplora JSON response: {trimmed}"))?;
        match parsed {
            EsploraResponse::Json { txid } => Ok(txid),
            EsploraResponse::Text(s) => Ok(s),
        }
    } else {
        Ok(trimmed.to_string())
    }
}

/// Best-effort explorer URL — recognises the public Esplora deployments
/// (blockstream.info and mempool.space) and emits a tx-page URL for them.
/// Returns `None` for any other base URL since we don't know the
/// corresponding explorer route.
fn derive_explorer_url(rpc_base: &str, txid: &str) -> Option<String> {
    if rpc_base.contains("blockstream.info/testnet") {
        Some(format!("https://blockstream.info/testnet/tx/{txid}"))
    } else if rpc_base.contains("blockstream.info") {
        Some(format!("https://blockstream.info/tx/{txid}"))
    } else if rpc_base.contains("mempool.space/testnet") {
        Some(format!("https://mempool.space/testnet/tx/{txid}"))
    } else if rpc_base.contains("mempool.space") {
        Some(format!("https://mempool.space/tx/{txid}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the segwit tx body byte layout against a known fixture so we
    /// don't accidentally regress the field order. The signature itself
    /// is opaque (any 64-byte value) — what we're checking is that the
    /// envelope is structured correctly so a Bitcoin verifier reading it
    /// can locate every field.
    #[test]
    fn segwit_tx_layout_is_well_formed() {
        let inputs = SpendInputs {
            prev_txid: [0xab; 32],
            prev_vout: 0,
            sequence: 0xffff_fffd, // RBF-enabled
            recipient_pkh: [0xcd; 20],
            send_amount_sats: 1_234,
            lock_time: 0,
        };
        // 64 dummy DER bytes + sighash byte (won't pass DER validation, but
        // we're only checking the *layout*, not signature legitimacy here).
        let sig_with_hashtype = vec![0x42u8; 65];
        let pubkey = [0x02u8; 33];

        let tx = build_segwit_tx(2, &inputs, &sig_with_hashtype, &pubkey);

        // Field-by-field cursor walk.
        let mut p = 0;
        // version (4)
        assert_eq!(&tx[p..p + 4], &2u32.to_le_bytes());
        p += 4;
        // marker + flag
        assert_eq!(tx[p], 0x00);
        assert_eq!(tx[p + 1], 0x01);
        p += 2;
        // input_count varint = 1
        assert_eq!(tx[p], 1);
        p += 1;
        // prev_txid (32)
        assert_eq!(&tx[p..p + 32], &[0xab; 32]);
        p += 32;
        // prev_vout (4) = 0
        assert_eq!(&tx[p..p + 4], &0u32.to_le_bytes());
        p += 4;
        // scriptSig_len varint = 0
        assert_eq!(tx[p], 0);
        p += 1;
        // sequence (4)
        assert_eq!(&tx[p..p + 4], &0xffff_fffdu32.to_le_bytes());
        p += 4;
        // output_count varint = 1
        assert_eq!(tx[p], 1);
        p += 1;
        // value_sats (8) = 1_234
        assert_eq!(&tx[p..p + 8], &1_234u64.to_le_bytes());
        p += 8;
        // scriptPubKey_len varint = 22
        assert_eq!(tx[p], 22);
        p += 1;
        // scriptPubKey: OP_0 + 0x14 + 20-byte pkh
        assert_eq!(tx[p], 0x00);
        assert_eq!(tx[p + 1], 0x14);
        assert_eq!(&tx[p + 2..p + 22], &[0xcd; 20]);
        p += 22;
        // witness stack_count varint = 2
        assert_eq!(tx[p], 2);
        p += 1;
        // witness item 0: sig + sighash
        assert_eq!(tx[p], 65);
        p += 1;
        assert_eq!(&tx[p..p + 65], &vec![0x42u8; 65][..]);
        p += 65;
        // witness item 1: compressed pubkey (33 bytes)
        assert_eq!(tx[p], 33);
        p += 1;
        assert_eq!(&tx[p..p + 33], &[0x02u8; 33]);
        p += 33;
        // locktime (4) = 0
        assert_eq!(&tx[p..p + 4], &0u32.to_le_bytes());
        p += 4;
        assert_eq!(p, tx.len(), "every byte accounted for");
    }

    /// Variable-int encoder pin: small values use 1 byte, threshold values
    /// switch to the longer encodings. Bitcoin consensus is strict about
    /// minimal CompactSize encoding so this matters.
    #[test]
    fn varint_encoding_matches_bitcoin_compactsize() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (252, &[0xfc]),
            (253, &[0xfd, 0xfd, 0x00]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x10000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (0xffff_ffff, &[0xfe, 0xff, 0xff, 0xff, 0xff]),
            (0x1_0000_0000, &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        ];
        for &(n, want) in cases {
            let mut out = Vec::new();
            write_varint(&mut out, n);
            assert_eq!(&out, want, "varint({n})");
        }
    }

    /// DER encoding round-trip: we encode an arbitrary `(r, s)` and then
    /// re-parse it via `k256` to make sure the result is a structurally
    /// valid Bitcoin-compatible DER signature (low-s, no extra bytes).
    #[test]
    fn der_signature_is_strict() {
        // Use a known canonical (r, s) — both well below the curve order
        // and both with their high bit clear, so DER doesn't need to pad.
        let r = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
        ];
        let s = [
            0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65,
            0x43, 0x21, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x0f, 0xed, 0xcb, 0xa9,
            0x87, 0x65, 0x43, 0x21,
        ];
        let der = der_encode_signature(&r, &s).unwrap();
        // DER prefix
        assert_eq!(der[0], 0x30, "DER tag");
        // total length byte = bytes after the length itself
        assert_eq!(der[1] as usize, der.len() - 2);
        // first INTEGER tag
        assert_eq!(der[2], 0x02);
        // round-trip parse via k256 to confirm strict DER
        let parsed = K256Signature::from_der(&der);
        assert!(parsed.is_ok(), "k256 must round-trip the DER we emit");
    }
}
