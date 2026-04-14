//! Ika dWallet integration helpers used by `wallet add-chain` and the
//! chain-aware `proposal execute`.
//!
//! This module hides the gRPC roundtrip, the dWallet program PDA derivations,
//! and the BCS request shaping. Everything synchronous-callable; the few
//! async pieces (gRPC roundtrips) spin a localized tokio runtime so the
//! rest of the CLI stays sync.

use crate::config::RuntimeConfig;
use crate::error::*;
use crate::rpc;
use ika_dwallet_types::*;
use ika_grpc::d_wallet_service_client::DWalletServiceClient;
use ika_grpc::UserSignedRequest;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer as _;
use std::time::{Duration, Instant};

/// Default Ika pre-alpha gRPC endpoint.
pub const DEFAULT_GRPC_URL: &str = "https://pre-alpha-dev-1.ika.ika-network.net:443";

// ── dWallet program constants (mirror upstream e2e examples) ──

pub const SEED_DWALLET_COORDINATOR: &[u8] = b"dwallet_coordinator";
pub const SEED_DWALLET: &[u8] = b"dwallet";
pub const SEED_MESSAGE_APPROVAL: &[u8] = b"message_approval";
pub const SEED_CPI_AUTHORITY: &[u8] = b"__ika_cpi_authority";

pub const DISC_COORDINATOR: u8 = 1;
pub const DISC_NEK: u8 = 3;
pub const DISC_MESSAGE_APPROVAL: u8 = 14;

pub const COORDINATOR_LEN: usize = 116;
pub const NEK_LEN: usize = 164;

// MessageApproval layout offsets (updated for new pre-alpha).
pub const MA_STATUS: usize = 172;
pub const MA_STATUS_SIGNED: u8 = 1;
pub const MA_SIGNATURE_LEN: usize = 173;
pub const MA_SIGNATURE: usize = 175;

// Curve discriminants — match `DWalletCurve` repr in `ika-dwallet-types`.
pub const CURVE_SECP256K1: u16 = 0;
pub const CURVE_SECP256R1: u16 = 1;
pub const CURVE_CURVE25519: u16 = 2;

/// Map a `DWalletCurve` to its on-chain u16 discriminant (used in dWallet
/// PDA derivation `["dwallet", chunks(curve_u16_le || pubkey)]`).
pub fn curve_u16(curve: DWalletCurve) -> u16 {
    match curve {
        DWalletCurve::Secp256k1 => CURVE_SECP256K1,
        DWalletCurve::Secp256r1 => CURVE_SECP256R1,
        DWalletCurve::Curve25519 => CURVE_CURVE25519,
        DWalletCurve::Ristretto => 3,
    }
}

/// Backwards-compat alias used by the `curve_byte` call sites that haven't
/// been migrated to `curve_u16` yet (e.g. the old u8 code paths).
pub fn curve_byte(curve: DWalletCurve) -> u8 {
    curve_u16(curve) as u8
}

// ── PDA helpers ──

/// Program-wide CPI authority PDA — `[SEED_CPI_AUTHORITY]`.
pub fn cpi_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_CPI_AUTHORITY], program_id)
}

/// Per-dWallet ownership lock PDA — `["dwallet_owner", dwallet]`.
pub fn dwallet_ownership_pda(program_id: &Pubkey, dwallet: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"dwallet_owner", dwallet.as_ref()], program_id)
}

/// Derive a dWallet PDA from `(curve, public_key)`.
///
/// Mirrors the upstream `DWalletPdaSeeds::new`: concatenates `curve_u16_le ||
/// public_key` into a single buffer and splits it into 32-byte chunks
/// (Solana's `MAX_SEED_LEN`), passing each chunk as its own PDA seed.
pub fn dwallet_pda(dwallet_program: &Pubkey, curve: u16, public_key: &[u8]) -> (Pubkey, u8) {
    let payload = pack_dwallet_seed_payload(curve, public_key);
    let mut seeds: Vec<&[u8]> = Vec::with_capacity(4);
    seeds.push(SEED_DWALLET);
    for chunk in payload.chunks(32) {
        seeds.push(chunk);
    }
    Pubkey::find_program_address(&seeds, dwallet_program)
}

/// Pack `curve_u16_le || public_key` for PDA seed chunking.
fn pack_dwallet_seed_payload(curve: u16, public_key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + public_key.len());
    buf.extend_from_slice(&curve.to_le_bytes());
    buf.extend_from_slice(public_key);
    buf
}

/// MessageApproval PDA — hierarchical seeds under the dWallet:
/// `["dwallet", chunks(curve_u16_le || pk), "message_approval", &scheme_u16_le, &message_digest]`
pub fn message_approval_pda(
    dwallet_program: &Pubkey,
    curve: u16,
    public_key: &[u8],
    signature_scheme: u16,
    message_digest: &[u8; 32],
) -> (Pubkey, u8) {
    let payload = pack_dwallet_seed_payload(curve, public_key);
    let scheme_bytes = signature_scheme.to_le_bytes();
    let mut seeds: Vec<&[u8]> = Vec::with_capacity(6);
    seeds.push(b"dwallet");
    for chunk in payload.chunks(32) {
        seeds.push(chunk);
    }
    seeds.push(SEED_MESSAGE_APPROVAL);
    seeds.push(&scheme_bytes);
    seeds.push(message_digest);
    Pubkey::find_program_address(&seeds, dwallet_program)
}

/// DWalletCoordinator PDA.
pub fn coordinator_pda(dwallet_program: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_DWALLET_COORDINATOR], dwallet_program)
}

/// `["ika_config", wallet, &[chain_kind]]` under clear-wallet's program.
pub fn ika_config_pda(
    clear_wallet_program: &Pubkey,
    wallet: &Pubkey,
    chain_kind: u8,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"ika_config", wallet.as_ref(), &[chain_kind]],
        clear_wallet_program,
    )
}

// ── Attestation persistence ──

/// Directory for storing DKG attestations.
fn attestation_dir() -> std::path::PathBuf {
    let home = dirs::home_dir().unwrap_or_default();
    home.join(".config/clear-msig/attestations")
}

/// Save a DKG attestation to disk keyed by wallet name.
pub fn save_attestation(
    wallet_name: &str,
    attestation: &NetworkSignedAttestation,
) -> Result<()> {
    let dir = attestation_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{wallet_name}.json"));
    let json = serde_json::json!({
        "attestation_data": hex_encode_bytes(&attestation.attestation_data),
        "network_signature": hex_encode_bytes(&attestation.network_signature),
        "network_pubkey": hex_encode_bytes(&attestation.network_pubkey),
        "epoch": attestation.epoch,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

/// Load a previously saved DKG attestation for a wallet.
pub fn load_attestation(wallet_name: &str) -> Result<NetworkSignedAttestation> {
    let path = attestation_dir().join(format!("{wallet_name}.json"));
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!(
            "no saved attestation for wallet '{wallet_name}' at {}; \
             re-run `wallet add-chain` to generate one",
            path.display()
        ))?;
    let json: serde_json::Value = serde_json::from_str(&data)?;
    Ok(NetworkSignedAttestation {
        attestation_data: hex_decode_field(&json, "attestation_data")?,
        network_signature: hex_decode_field(&json, "network_signature")?,
        network_pubkey: hex_decode_field(&json, "network_pubkey")?,
        epoch: json["epoch"].as_u64().unwrap_or(1),
    })
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_field(json: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let s = json[field].as_str().unwrap_or("");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow!("{e}")))
        .collect()
}

// ── Setup probes ──

/// Wait for the dWallet program's coordinator PDA to be initialized.
pub fn wait_for_coordinator(
    client: &solana_client::rpc_client::RpcClient,
    dwallet_program: &Pubkey,
    timeout: Duration,
) -> Result<()> {
    let (coord, _) = coordinator_pda(dwallet_program);
    poll_until(client, &coord, |d| d.len() >= COORDINATOR_LEN && d[0] == DISC_COORDINATOR, timeout)?;
    Ok(())
}

// ── gRPC dance ──

/// DKG result — carries both the dWallet address and the attestation needed
/// for later Sign requests.
pub struct DkgResult {
    pub dwallet_addr: [u8; 32],
    pub public_key: Vec<u8>,
    pub attestation: NetworkSignedAttestation,
}

/// Run a DKG via Ika gRPC. Returns the full DKG result including the
/// attestation needed by subsequent Sign calls.
pub fn dkg(
    config: &RuntimeConfig,
    grpc_url: &str,
    curve: DWalletCurve,
) -> Result<DkgResult> {
    let payer_pubkey = config.payer.pubkey();
    let request = SignedRequestData {
        session_identifier_preimage: [0u8; 32],
        epoch: 1,
        chain_id: ChainId::Solana,
        intended_chain_sender: payer_pubkey.to_bytes().to_vec(),
        request: DWalletRequest::DKG {
            dwallet_network_encryption_public_key: vec![0u8; 32],
            curve,
            centralized_public_key_share_and_proof: vec![0u8; 32],
            user_secret_key_share: UserSecretKeyShare::Encrypted {
                encrypted_centralized_secret_share_and_proof: vec![0u8; 32],
                encryption_key: vec![0u8; 32],
                signer_public_key: payer_pubkey.to_bytes().to_vec(),
            },
            user_public_output: vec![0u8; 32],
            sign_during_dkg_request: None,
        },
    };

    let response = grpc_call(grpc_url, build_signed_request(&payer_pubkey, request))?;
    match response {
        TransactionResponseData::Attestation(attestation) => {
            let versioned: VersionedDWalletDataAttestation =
                bcs::from_bytes(&attestation.attestation_data)
                    .with_context(|| "failed to decode DKG attestation")?;
            let VersionedDWalletDataAttestation::V1(data) = versioned;
            Ok(DkgResult {
                dwallet_addr: data.session_identifier,
                public_key: data.public_key,
                attestation,
            })
        }
        TransactionResponseData::Error { message } => Err(anyhow!("gRPC DKG failed: {message}")),
        other => Err(anyhow!("unexpected DKG response: {other:?}")),
    }
}

/// Allocate a presign for the given dWallet via Ika gRPC.
/// Returns `(presign_session_identifier, presign_data)`.
pub fn presign(
    config: &RuntimeConfig,
    grpc_url: &str,
    dwallet_addr: [u8; 32],
    curve: DWalletCurve,
    algo: DWalletSignatureAlgorithm,
) -> Result<Vec<u8>> {
    let payer_pubkey = config.payer.pubkey();
    let request = SignedRequestData {
        session_identifier_preimage: dwallet_addr,
        epoch: 1,
        chain_id: ChainId::Solana,
        intended_chain_sender: payer_pubkey.to_bytes().to_vec(),
        request: DWalletRequest::Presign {
            dwallet_network_encryption_public_key: vec![0u8; 32],
            curve,
            signature_algorithm: algo,
        },
    };

    let response = grpc_call(grpc_url, build_signed_request(&payer_pubkey, request))?;
    match response {
        TransactionResponseData::Attestation(att) => {
            let versioned: VersionedPresignDataAttestation =
                bcs::from_bytes(&att.attestation_data)
                    .with_context(|| "failed to decode presign attestation")?;
            let VersionedPresignDataAttestation::V1(data) = versioned;
            Ok(data.presign_session_identifier)
        }
        TransactionResponseData::Error { message } => {
            Err(anyhow!("gRPC presign failed: {message}"))
        }
        other => Err(anyhow!("unexpected presign response: {other:?}")),
    }
}

/// Send a Sign request to Ika gRPC. Returns the produced signature bytes.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    config: &RuntimeConfig,
    grpc_url: &str,
    dwallet_addr: [u8; 32],
    dwallet_attestation: NetworkSignedAttestation,
    presign_session_identifier: Vec<u8>,
    message: Vec<u8>,
    message_metadata: Vec<u8>,
    quorum_tx_signature: Vec<u8>,
) -> Result<Vec<u8>> {
    let payer_pubkey = config.payer.pubkey();
    let request = SignedRequestData {
        session_identifier_preimage: dwallet_addr,
        epoch: 1,
        chain_id: ChainId::Solana,
        intended_chain_sender: payer_pubkey.to_bytes().to_vec(),
        request: DWalletRequest::Sign {
            message,
            message_metadata,
            presign_session_identifier,
            message_centralized_signature: vec![0u8; 64],
            dwallet_attestation,
            approval_proof: ApprovalProof::Solana {
                transaction_signature: quorum_tx_signature,
                slot: 0,
            },
        },
    };

    let response = grpc_call(grpc_url, build_signed_request(&payer_pubkey, request))?;
    match response {
        TransactionResponseData::Signature { signature } => Ok(signature),
        TransactionResponseData::Error { message } => Err(anyhow!("gRPC sign failed: {message}")),
        other => Err(anyhow!("unexpected sign response: {other:?}")),
    }
}

// ── Plumbing ──

fn build_signed_request(payer: &Pubkey, request: SignedRequestData) -> UserSignedRequest {
    let signed_data = bcs::to_bytes(&request).expect("BCS serialize");
    let user_sig = UserSignature::Ed25519 {
        signature: vec![0u8; 64],
        public_key: payer.to_bytes().to_vec(),
    };
    UserSignedRequest {
        user_signature: bcs::to_bytes(&user_sig).expect("BCS serialize sig"),
        signed_request_data: signed_data,
    }
}

/// Run a single gRPC submit_transaction call against the Ika dWallet service.
/// Spins a localized tokio runtime so callers can stay sync.
fn grpc_call(grpc_url: &str, request: UserSignedRequest) -> Result<TransactionResponseData> {
    // DEBUG: dump the protobuf-framed body so we can replay via curl.
    if std::env::var("CLEAR_MSIG_DEBUG_GRPC").is_ok() {
        use prost::Message;
        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();
        let mut framed = Vec::with_capacity(5 + buf.len());
        framed.push(0u8);
        framed.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        framed.extend_from_slice(&buf);
        let path = "/tmp/clear-msig-grpc-request.bin";
        std::fs::write(path, &framed).ok();
        eprintln!("[DEBUG] dumped {} bytes of gRPC body to {path}", framed.len());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .with_context(|| "tokio runtime build failed")?;
    runtime.block_on(async move {
        let mut client = if grpc_url.starts_with("https") {
            let tls = tonic::transport::ClientTlsConfig::new().with_native_roots();
            let channel = tonic::transport::Channel::from_shared(grpc_url.to_string())
                .with_context(|| "invalid gRPC URL")?
                .tls_config(tls)
                .with_context(|| "TLS config failed")?
                .connect()
                .await
                .with_context(|| format!("failed to connect to gRPC at {grpc_url}"))?;
            DWalletServiceClient::new(channel)
        } else {
            DWalletServiceClient::connect(grpc_url.to_string())
                .await
                .with_context(|| format!("failed to connect to gRPC at {grpc_url}"))?
        };
        let response = client
            .submit_transaction(request)
            .await
            .with_context(|| "gRPC submit_transaction failed")?;
        let response_data: TransactionResponseData =
            bcs::from_bytes(&response.into_inner().response_data)
                .with_context(|| "BCS deserialize response")?;
        Ok(response_data)
    })
}

// ── On-chain polling ──

/// Block until `account` exists and `check(data)` returns true, or `timeout`.
pub fn poll_until(
    client: &solana_client::rpc_client::RpcClient,
    account: &Pubkey,
    check: impl Fn(&[u8]) -> bool,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("timeout waiting for account {account}"));
        }
        if let Some(data) = rpc::fetch_account_optional(client, account)? {
            if check(&data) {
                return Ok(data);
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ── Off-chain preimage builders (mirror on-chain `dispatch_sighash`) ──

use crate::accounts::IntentAccount;

/// Build the destination-chain preimage for an intent.
pub fn build_chain_preimage(intent: &IntentAccount, params_data: &[u8]) -> Result<Vec<u8>> {
    let tx_template = read_tx_template(intent)?;
    match intent.chain_kind {
        1 => evm_native_preimage(intent, params_data, tx_template),
        4 => evm_erc20_preimage(intent, params_data, tx_template),
        2 => bitcoin_p2wpkh_preimage(intent, params_data, tx_template),
        0 => Err(anyhow!("solana intents are executed locally, not via Ika")),
        n => Err(anyhow!("unknown chain_kind {n}")),
    }
}

fn read_tx_template(intent: &IntentAccount) -> Result<&[u8]> {
    let off = intent.tx_template_offset as usize;
    let len = intent.tx_template_len as usize;
    if len == 0 {
        return Ok(&[]);
    }
    intent
        .byte_pool
        .get(off..off + len)
        .ok_or(anyhow!("tx_template offset/len out of bounds"))
}

// EVM 1559 native — see programs/clear-wallet/src/chains/evm.rs::build_sighash
fn evm_native_preimage(intent: &IntentAccount, params_data: &[u8], tx_template: &[u8]) -> Result<Vec<u8>> {
    use clear_wallet_client::chains::evm::Tx1559;
    if tx_template.len() != 32 {
        return Err(anyhow!("evm_1559 tx_template must be 32 bytes, got {}", tx_template.len()));
    }
    let chain_id = u64::from_le_bytes(tx_template[0..8].try_into().unwrap());
    let gas_limit = u64::from_le_bytes(tx_template[8..16].try_into().unwrap());
    let max_priority_fee_per_gas = u64::from_le_bytes(tx_template[16..24].try_into().unwrap());
    let max_fee_per_gas = u64::from_le_bytes(tx_template[24..32].try_into().unwrap());

    let nonce = read_param_u64(intent, params_data, 0)?;
    let to = read_param_bytes20(intent, params_data, 1)?;
    let value = read_param_u64(intent, params_data, 2)?;
    let data_param = read_param_raw(intent, params_data, 3)?;
    let data = if data_param.is_empty() {
        Vec::new()
    } else {
        let len = data_param[0] as usize;
        data_param[1..1 + len].to_vec()
    };

    let tx = Tx1559 {
        chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
        to, value, data,
    };
    Ok(tx.rlp_preimage())
}

fn evm_erc20_preimage(intent: &IntentAccount, params_data: &[u8], tx_template: &[u8]) -> Result<Vec<u8>> {
    use clear_wallet_client::chains::evm::Erc20Transfer;
    if tx_template.len() != 32 {
        return Err(anyhow!("evm_1559_erc20 tx_template must be 32 bytes"));
    }
    let chain_id = u64::from_le_bytes(tx_template[0..8].try_into().unwrap());
    let gas_limit = u64::from_le_bytes(tx_template[8..16].try_into().unwrap());
    let max_priority_fee_per_gas = u64::from_le_bytes(tx_template[16..24].try_into().unwrap());
    let max_fee_per_gas = u64::from_le_bytes(tx_template[24..32].try_into().unwrap());

    let nonce = read_param_u64(intent, params_data, 0)?;
    let token_contract = read_param_bytes20(intent, params_data, 1)?;
    let recipient = read_param_bytes20(intent, params_data, 2)?;
    let amount = read_param_u128(intent, params_data, 3)?;

    let tx = Erc20Transfer {
        chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
        token_contract, recipient, amount,
    };
    Ok(tx.rlp_preimage())
}

fn bitcoin_p2wpkh_preimage(intent: &IntentAccount, params_data: &[u8], tx_template: &[u8]) -> Result<Vec<u8>> {
    use clear_wallet_client::chains::bitcoin::P2wpkhSpend;
    if tx_template.len() != 16 {
        return Err(anyhow!("bitcoin_p2wpkh tx_template must be 16 bytes"));
    }
    let version = u32::from_le_bytes(tx_template[0..4].try_into().unwrap());
    let lock_time = u32::from_le_bytes(tx_template[4..8].try_into().unwrap());
    let sequence = u32::from_le_bytes(tx_template[8..12].try_into().unwrap());
    let sighash_type = u32::from_le_bytes(tx_template[12..16].try_into().unwrap());

    let prev_txid = read_param_bytes32(intent, params_data, 0)?;
    let prev_vout = read_param_u64(intent, params_data, 1)? as u32;
    let prev_amount_sats = read_param_u64(intent, params_data, 2)?;
    let sender_pkh = read_param_bytes20(intent, params_data, 3)?;
    let recipient_pkh = read_param_bytes20(intent, params_data, 4)?;
    let send_amount_sats = read_param_u64(intent, params_data, 5)?;

    let spend = P2wpkhSpend {
        version, lock_time, sequence, sighash_type,
        prev_txid, prev_vout, prev_amount_sats,
        sender_pkh, recipient_pkh, send_amount_sats,
    };
    Ok(spend.bip143_preimage())
}

// ── Param readers (mirror programs/clear-wallet/src/chains/mod.rs) ──

fn param_offset(intent: &IntentAccount, params_data: &[u8], target: u8) -> Result<usize> {
    let mut off = 0usize;
    for i in 0..target as usize {
        let p = intent.params.get(i).ok_or(anyhow!("param index out of bounds"))?;
        off += param_byte_size_at(p.param_type, params_data, off)?;
    }
    Ok(off)
}

fn param_byte_size_at(
    param_type: clear_wallet::utils::definition::ParamType,
    params_data: &[u8],
    offset: usize,
) -> Result<usize> {
    use clear_wallet::utils::definition::ParamType;
    Ok(match param_type {
        ParamType::Address | ParamType::Bytes32 => 32,
        ParamType::U64 | ParamType::I64 => 8,
        ParamType::Bytes20 => 20,
        ParamType::String => {
            let len = *params_data
                .get(offset)
                .ok_or(anyhow!("string length OOB"))? as usize;
            1 + len
        }
        ParamType::Bool | ParamType::U8 => 1,
        ParamType::U16 => 2,
        ParamType::U32 => 4,
        ParamType::U128 => 16,
    })
}

pub(crate) fn read_param_raw<'a>(intent: &IntentAccount, params_data: &'a [u8], idx: u8) -> Result<&'a [u8]> {
    let off = param_offset(intent, params_data, idx)?;
    let p = intent.params.get(idx as usize).ok_or(anyhow!("param idx OOB"))?;
    let size = param_byte_size_at(p.param_type, params_data, off)?;
    params_data.get(off..off + size).ok_or(anyhow!("param slice OOB")).map(|s| s)
}

pub(crate) fn read_param_u64(intent: &IntentAccount, params_data: &[u8], idx: u8) -> Result<u64> {
    let bytes = read_param_raw(intent, params_data, idx)?;
    if bytes.len() < 8 { return Err(anyhow!("expected u64")); }
    Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
}

pub(crate) fn read_param_u128(intent: &IntentAccount, params_data: &[u8], idx: u8) -> Result<u128> {
    let bytes = read_param_raw(intent, params_data, idx)?;
    if bytes.len() < 16 { return Err(anyhow!("expected u128")); }
    Ok(u128::from_le_bytes(bytes[..16].try_into().unwrap()))
}

pub(crate) fn read_param_bytes20(intent: &IntentAccount, params_data: &[u8], idx: u8) -> Result<[u8; 20]> {
    let bytes = read_param_raw(intent, params_data, idx)?;
    if bytes.len() < 20 { return Err(anyhow!("expected bytes20")); }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes[..20]);
    Ok(out)
}

pub(crate) fn read_param_bytes32(intent: &IntentAccount, params_data: &[u8], idx: u8) -> Result<[u8; 32]> {
    let bytes = read_param_raw(intent, params_data, idx)?;
    if bytes.len() < 32 { return Err(anyhow!("expected bytes32")); }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Ok(out)
}

/// Keccak256 of a byte slice.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// sha256(sha256(data)) — Bitcoin's hash for BIP143 sighashes.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Compute the on-chain `MessageApproval.message_digest` for a preimage.
///
/// Always `keccak256(preimage)` regardless of `chain_kind`. The chain-specific
/// signing digest (e.g. `sha256d` for Bitcoin BIP143) is computed by the
/// dwallet network off-chain via the `DWalletSignatureScheme` on the gRPC
/// `Sign` request.
pub fn hash_preimage(_chain_kind: u8, preimage: &[u8]) -> [u8; 32] {
    keccak256(preimage)
}

// ── Curve / scheme defaults per chain_kind ──

/// Returns the curve and combined signature scheme that match the destination
/// chain. The `DWalletSignatureScheme` replaces the old separate
/// `(DWalletSignatureAlgorithm, DWalletHashScheme)` tuple.
pub fn signing_params(
    chain_kind: u8,
    force_curve25519: bool,
) -> (DWalletCurve, DWalletSignatureAlgorithm, DWalletSignatureScheme) {
    if force_curve25519 {
        return (
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
            DWalletSignatureScheme::EddsaSha512,
        );
    }
    match chain_kind {
        // Evm1559 (1) / Evm1559Erc20 (4) — keccak256 of RLP, secp256k1 ECDSA.
        1 | 4 => (
            DWalletCurve::Secp256k1,
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            DWalletSignatureScheme::EcdsaKeccak256,
        ),
        // BitcoinP2wpkh (2) — sha256d of BIP143 preimage, secp256k1 ECDSA.
        2 => (
            DWalletCurve::Secp256k1,
            DWalletSignatureAlgorithm::ECDSASecp256k1,
            DWalletSignatureScheme::EcdsaDoubleSha256,
        ),
        // Default: Ed25519 + SHA512.
        _ => (
            DWalletCurve::Curve25519,
            DWalletSignatureAlgorithm::EdDSA,
            DWalletSignatureScheme::EddsaSha512,
        ),
    }
}
