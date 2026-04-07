// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Clear-msig + Ika E2E Demo (EVM signing).
//!
//! End-to-end flow against Solana devnet and the Ika pre-alpha gRPC service.
//! Drives a 2-of-2 clear-msig wallet through approving an EIP-1559 ETH
//! transfer and getting it signed by an Ika dWallet.
//!
//! ## Steps
//!
//! 1. Wait for the dWallet program's coordinator + NEK to initialize.
//! 2. Request a DKG via gRPC. The mock signer commits the dWallet on-chain
//!    and transfers ownership to the payer.
//! 3. Off-chain `transfer_ownership` from payer → clear-wallet's CPI authority PDA.
//! 4. `create_wallet` (clear-msig wallet with proposer + 2 approvers).
//! 5. `add_intent` flow:
//!     - Build an EVM EIP-1559 intent body using `clear-wallet-client::IntentBuilder`
//!       (loads `examples/intents/evm_transfer.json`).
//!     - Propose AddIntent (proposer signs the wrapped offchain message).
//!     - Approve.
//!     - Execute (writes the new intent on-chain at index 3).
//! 6. `bind_dwallet` — creates the IkaConfig PDA and re-asserts the dWallet binding.
//! 7. Propose a Custom EVM intent with concrete params (nonce, to, value, empty data).
//! 8. Approver1 + Approver2 approve.
//! 9. `ika_sign` — clear-wallet builds the EVM RLP sighash and CPIs `approve_message`.
//! 10. Verify `MessageApproval` PDA exists with status=Pending.
//! 11. gRPC `Presign` then `Sign` with the same RLP-encoded message.
//! 12. Verify the Ika network commits the signature back into MessageApproval (status=Signed).
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p e2e-clear-msig-ika -- <DWALLET_PROGRAM_ID> [CLEAR_WALLET_PROGRAM_ID]
//! ```
//!
//! `CLEAR_WALLET_PROGRAM_ID` defaults to `clear-wallet-client::ID`. Override
//! the RPC and gRPC endpoints with `RPC_URL` and `GRPC_URL`.
//!
//! ## Pre-conditions
//!
//! - `~/.config/solana/devnet-admin.json` is a funded devnet keypair (override
//!   with `PAYER_KEYPAIR`).
//! - `clear_wallet.so` is deployed to devnet at the program ID you pass.
//! - The dWallet program is deployed to the same devnet at the program ID you pass.

use std::env;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::Signer as DalekSigner;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer as SolanaSigner;
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::transaction::Transaction;

use ika_dwallet_types::*;
use ika_grpc::d_wallet_service_client::DWalletServiceClient;
use ika_grpc::UserSignedRequest;

use clear_wallet_client::chains::evm::Tx1559;
use clear_wallet_client::intent_json::{IntentTransactionJson, IntentDefinitionJson};
use clear_wallet_client::pda::{
    compute_name_hash, find_ika_config_address, find_intent_address,
    find_proposal_address, find_vault_address, find_wallet_address,
};

// ======================================================================
// Output formatting
// ======================================================================

const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";

fn log(step: &str, msg: &str) {
    println!("{CYAN}[{step}]{RESET} {msg}");
}
fn ok(msg: &str) {
    println!("{GREEN}  \u{2713}{RESET} {msg}");
}
fn val(label: &str, v: impl std::fmt::Display) {
    println!("{YELLOW}  \u{2192}{RESET} {label}: {v}");
}

// ======================================================================
// dWallet program constants (mirrors voting/multisig e2e)
// ======================================================================

const IX_TRANSFER_OWNERSHIP: u8 = 24;

const DISC_COORDINATOR: u8 = 1;
const DISC_NEK: u8 = 3;
const DISC_MESSAGE_APPROVAL: u8 = 14;

const COORDINATOR_LEN: usize = 116;
const NEK_LEN: usize = 164;

const MA_STATUS: usize = 139;
const MA_STATUS_SIGNED: u8 = 1;
const MA_SIGNATURE_LEN: usize = 140;
const MA_SIGNATURE: usize = 142;

const SEED_DWALLET_COORDINATOR: &[u8] = b"dwallet_coordinator";
const SEED_DWALLET: &[u8] = b"dwallet";
const SEED_MESSAGE_APPROVAL: &[u8] = b"message_approval";
const SEED_CPI_AUTHORITY: &[u8] = b"__ika_cpi_authority";

// Pre-alpha mock signer only handles Curve25519 + EdDSA. We still drive the
// EVM RLP code path (the on-chain `ika_sign` builds the EIP-1559 sighash and
// hands it to `approve_message`) but ask the network to sign it as an
// arbitrary blob. The resulting signature is Ed25519, not real ECDSA — for
// production EVM you need Ika to actually support Secp256k1.
const CURVE_CURVE25519: u8 = 2;

// ======================================================================
// Clear-wallet instruction discriminators
// ======================================================================

const IX_CREATE_WALLET: u8 = 0;
const IX_PROPOSE: u8 = 1;
const IX_APPROVE: u8 = 2;
const IX_EXECUTE: u8 = 4;
const IX_BIND_DWALLET: u8 = 6;
const IX_IKA_SIGN: u8 = 7;

// Intent type discriminants on-chain.
const INTENT_TYPE_ADD_INTENT: u8 = 0;
const INTENT_TYPE_CUSTOM: u8 = 3;

// Chain kind for EVM.
const CHAIN_KIND_EVM: u8 = 1;

// Default expiry: ~year 2030.
const DEFAULT_EXPIRY: i64 = 1_900_000_000;

// ======================================================================
// Solana / Ika helpers
// ======================================================================

fn load_payer() -> Keypair {
    let path = env::var("PAYER_KEYPAIR").unwrap_or_else(|_| {
        format!("{}/.config/solana/devnet-admin.json", env::var("HOME").unwrap_or_default())
    });
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Cannot read keypair at {path}"));
    let bytes: Vec<u8> = {
        let s = data.trim();
        s[1..s.len() - 1]
            .split(',')
            .map(|v| v.trim().parse::<u8>().unwrap())
            .collect()
    };
    #[allow(deprecated)]
    Keypair::from_bytes(&bytes).expect("valid keypair")
}

fn send_tx(
    client: &RpcClient,
    payer: &Keypair,
    ixs: Vec<Instruction>,
    extra: &[&Keypair],
) -> solana_sdk::signature::Signature {
    let blockhash = client.get_latest_blockhash().expect("blockhash");
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &signers, blockhash);
    client.send_and_confirm_transaction(&tx).expect("send_and_confirm")
}

fn poll_until(
    client: &RpcClient,
    account: &Pubkey,
    check: impl Fn(&[u8]) -> bool,
    timeout: Duration,
) -> Vec<u8> {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            panic!("timeout waiting for account {account}");
        }
        if let Ok(acct) = client.get_account(account) {
            if check(&acct.data) {
                return acct.data;
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn build_grpc_request(payer: &Keypair, request: SignedRequestData) -> UserSignedRequest {
    let signed_data = bcs::to_bytes(&request).expect("BCS serialize");
    let user_sig = UserSignature::Ed25519 {
        signature: vec![0u8; 64],
        public_key: payer.pubkey().to_bytes().to_vec(),
    };
    UserSignedRequest {
        user_signature: bcs::to_bytes(&user_sig).expect("BCS serialize sig"),
        signed_request_data: signed_data,
    }
}

// ======================================================================
// Offchain message wrapping (matches the on-chain MessageBuilder)
// ======================================================================

const OFFCHAIN_DOMAIN: &[u8] = b"\xffsolana offchain";

fn wrap_offchain(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(OFFCHAIN_DOMAIN); // 16
    out.push(0); // version
    out.push(0); // format
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn sign_dalek(key: &ed25519_dalek::SigningKey, body: &[u8]) -> [u8; 64] {
    key.sign(&wrap_offchain(body)).to_bytes()
}

fn format_timestamp(ts: i64) -> String {
    // Yyyy-mm-dd HH:MM:SS — matches on-chain `format_timestamp` in `utils/datetime.rs`
    let secs_per_day: i64 = 86400;
    let mut days = ts / secs_per_day;
    let day_secs = ((ts % secs_per_day) + secs_per_day) % secs_per_day;
    if ts < 0 && day_secs > 0 { days -= 1; }
    let (hour, min, sec) = (day_secs / 3600, (day_secs % 3600) / 60, day_secs % 60);
    let adj = days + 719468;
    let era = if adj >= 0 { adj } else { adj - 146096 } / 146097;
    let doe = adj - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} {hour:02}:{min:02}:{sec:02}")
}

fn hex_lower(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Build the same message body the on-chain code computes for an AddIntent
/// proposal/approval. Format:
/// `expires <ts>: <action> add intent definition_hash: <hex> | wallet: <name> proposal: <index>`
fn add_intent_msg(action: &str, expiry: i64, wallet_name: &str, proposal_index: u64, body: &[u8]) -> Vec<u8> {
    format!(
        "expires {}: {action} add intent definition_hash: {} | wallet: {wallet_name} proposal: {proposal_index}",
        format_timestamp(expiry),
        hex_lower(&sha256_hash(body)),
    ).into_bytes()
}

/// Build the message body for a Custom intent proposal/approval. The on-chain
/// `render_template` substitutes `{N}` with the rendered param at index N. We
/// hard-code the format here for the EVM transfer template
/// `"send {2} wei to 0x{1} (nonce {0})"`.
fn custom_evm_msg(
    action: &str,
    expiry: i64,
    wallet_name: &str,
    proposal_index: u64,
    nonce: u64,
    to: &[u8; 20],
    value: u64,
) -> Vec<u8> {
    format!(
        "expires {}: {action} send {value} wei to 0x{} (nonce {nonce}) | wallet: {wallet_name} proposal: {proposal_index}",
        format_timestamp(expiry),
        hex_lower(to),
    ).into_bytes()
}

// ======================================================================
// Convert solana_sdk::Pubkey ↔ solana_address::Address (different crates)
// ======================================================================

fn pk_to_addr(p: Pubkey) -> solana_address::Address {
    solana_address::Address::new_from_array(p.to_bytes())
}

fn addr_to_pk(a: solana_address::Address) -> Pubkey {
    Pubkey::new_from_array(a.to_bytes())
}

// ======================================================================
// Main
// ======================================================================

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: e2e-clear-msig-ika <DWALLET_PROGRAM_ID> [CLEAR_WALLET_PROGRAM_ID]");
        eprintln!();
        eprintln!("Defaults to Solana devnet and pre-alpha gRPC. Override with:");
        eprintln!("  RPC_URL=<solana_rpc> GRPC_URL=<grpc_url> PAYER_KEYPAIR=<path>");
        std::process::exit(1);
    }

    let dwallet_program_id = Pubkey::from_str(&args[1]).expect("invalid dWallet program ID");
    let clear_wallet_program_id = if args.len() >= 3 {
        Pubkey::from_str(&args[2]).expect("invalid clear-wallet program ID")
    } else {
        addr_to_pk(clear_wallet_client::ID)
    };
    let grpc_url = env::var("GRPC_URL")
        .unwrap_or_else(|_| "https://pre-alpha-dev-1.ika.ika-network.net:443".to_string());

    let client = RpcClient::new_with_commitment(
        env::var("RPC_URL").unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
        CommitmentConfig::confirmed(),
    );

    println!();
    println!("{BOLD}\u{2550}\u{2550}\u{2550} clear-msig × Ika E2E Demo (EVM) \u{2550}\u{2550}\u{2550}{RESET}");
    println!();
    val("dWallet program", dwallet_program_id);
    val("clear-wallet program", clear_wallet_program_id);
    val("gRPC endpoint", &grpc_url);
    println!();

    // ---------------------------------------------------------------
    // Setup
    // ---------------------------------------------------------------
    log("Setup", "Loading payer + waiting for dWallet program init...");
    let payer = load_payer();
    let balance = client.get_balance(&payer.pubkey()).unwrap_or(0);
    ok(&format!("Payer: {} ({:.3} SOL)", payer.pubkey(), balance as f64 / 1e9));
    if balance < 100_000_000 {
        panic!("payer needs at least 0.1 SOL on devnet");
    }

    let (coordinator_pda, _) =
        Pubkey::find_program_address(&[SEED_DWALLET_COORDINATOR], &dwallet_program_id);
    poll_until(
        &client,
        &coordinator_pda,
        |d| d.len() >= COORDINATOR_LEN && d[0] == DISC_COORDINATOR,
        Duration::from_secs(30),
    );
    ok(&format!("DWalletCoordinator: {coordinator_pda}"));

    use solana_sdk::account::Account;
    let nek_accounts: Vec<(Pubkey, Account)> = {
        let start = Instant::now();
        loop {
            let accs = client.get_program_accounts(&dwallet_program_id).unwrap_or_default();
            let neks: Vec<_> = accs.into_iter()
                .filter(|(_, a)| a.data.len() >= NEK_LEN && a.data[0] == DISC_NEK)
                .collect();
            if !neks.is_empty() {
                break neks;
            }
            if start.elapsed() > Duration::from_secs(30) {
                panic!("timeout waiting for NEK account");
            }
            thread::sleep(Duration::from_millis(500));
        }
    };
    let (nek_pda, _) = &nek_accounts[0];
    ok(&format!("NetworkEncryptionKey: {nek_pda}"));
    println!();

    // ---------------------------------------------------------------
    // 1. gRPC DKG → dWallet on-chain
    // ---------------------------------------------------------------
    log("1/12", "Requesting DKG via gRPC (Curve25519 — pre-alpha mock limitation)...");

    let mut grpc_client = if grpc_url.starts_with("https") {
        let tls = tonic::transport::ClientTlsConfig::new().with_native_roots();
        let channel = tonic::transport::Channel::from_shared(grpc_url.clone())
            .expect("valid URL").tls_config(tls).expect("tls")
            .connect().await.expect("connect to gRPC");
        DWalletServiceClient::new(channel)
    } else {
        DWalletServiceClient::connect(grpc_url.clone()).await.expect("connect to gRPC")
    };

    let dkg_request = build_grpc_request(&payer, SignedRequestData {
        session_identifier_preimage: [0u8; 32],
        epoch: 1,
        chain_id: ChainId::Solana,
        intended_chain_sender: payer.pubkey().to_bytes().to_vec(),
        request: DWalletRequest::DKG {
            dwallet_network_encryption_public_key: vec![0u8; 32],
            curve: DWalletCurve::Curve25519,
            centralized_public_key_share_and_proof: vec![0u8; 32],
            encrypted_centralized_secret_share_and_proof: vec![0u8; 32],
            encryption_key: vec![0u8; 32],
            user_public_output: vec![0u8; 32],
            signer_public_key: payer.pubkey().to_bytes().to_vec(),
        },
    });

    // DEBUG: dump the protobuf-encoded request body so we can replay via curl
    // and inspect the raw upstream response (tonic eats the HTML body that
    // nginx returns on 502).
    {
        use prost::Message;
        let mut buf = Vec::new();
        dkg_request.encode(&mut buf).unwrap();
        let mut framed = Vec::with_capacity(5 + buf.len());
        framed.push(0u8); // compression flag
        framed.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        framed.extend_from_slice(&buf);
        std::fs::write("/tmp/dkg-request.bin", &framed).unwrap();
        eprintln!("[DEBUG] dumped {} bytes of framed gRPC body to /tmp/dkg-request.bin", framed.len());
    }

    let response = grpc_client.submit_transaction(dkg_request).await.expect("gRPC DKG");
    let response_data: TransactionResponseData =
        bcs::from_bytes(&response.into_inner().response_data).expect("BCS deserialize");

    let attestation_data = match response_data {
        TransactionResponseData::Attestation { attestation_data, .. } => attestation_data,
        TransactionResponseData::Error { message } => panic!("gRPC DKG failed: {message}"),
        other => panic!("unexpected DKG response: {other:?}"),
    };
    ok("DKG attestation received");

    let dwallet_addr: [u8; 32] = attestation_data[0..32].try_into().unwrap();
    let pk_len = attestation_data[32] as usize;
    let dwallet_public_key = attestation_data[33..33 + pk_len].to_vec();

    val("dWallet address", hex::encode(dwallet_addr));
    val("dWallet pubkey", hex::encode(&dwallet_public_key));

    let (dwallet_pda, _) = Pubkey::find_program_address(
        &[SEED_DWALLET, &[CURVE_CURVE25519], &dwallet_public_key],
        &dwallet_program_id,
    );
    poll_until(
        &client,
        &dwallet_pda,
        |d| d.len() > 2 && d[0] == 2,
        Duration::from_secs(15),
    );
    ok(&format!("dWallet on-chain: {dwallet_pda}"));
    println!();

    // ---------------------------------------------------------------
    // 2. Transfer dWallet authority → clear-wallet's CPI authority PDA
    // ---------------------------------------------------------------
    log("2/12", "Transferring dWallet authority to clear-wallet CPI PDA...");

    let (cpi_authority_pk, cpi_authority_bump) =
        Pubkey::find_program_address(&[SEED_CPI_AUTHORITY], &clear_wallet_program_id);

    let mut transfer_data = Vec::with_capacity(33);
    transfer_data.push(IX_TRANSFER_OWNERSHIP);
    transfer_data.extend_from_slice(cpi_authority_pk.as_ref());

    send_tx(&client, &payer, vec![Instruction::new_with_bytes(
        dwallet_program_id,
        &transfer_data,
        vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(dwallet_pda, false),
        ],
    )], &[]);
    ok(&format!("Authority → {cpi_authority_pk}"));
    println!();

    // ---------------------------------------------------------------
    // 3. Create clear-msig wallet (1 proposer, 2 approvers, 2-of-2)
    // ---------------------------------------------------------------
    log("3/12", "Creating clear-msig wallet (2-of-2)...");

    let proposer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let approver1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let approver2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

    let proposer_pk = Pubkey::new_from_array(proposer.verifying_key().to_bytes());
    let approver1_pk = Pubkey::new_from_array(approver1.verifying_key().to_bytes());
    let approver2_pk = Pubkey::new_from_array(approver2.verifying_key().to_bytes());

    let wallet_name = format!("e2e-{}", &hex_lower(&rand::random::<[u8; 4]>()));
    let name_hash = compute_name_hash(&wallet_name);
    let name_hash_pk = Pubkey::new_from_array(name_hash);
    let (wallet_pk_addr, _) = find_wallet_address(&wallet_name, &pk_to_addr(clear_wallet_program_id));
    let wallet_pk = addr_to_pk(wallet_pk_addr);
    let (vault_addr, _) = find_vault_address(&wallet_pk_addr, &pk_to_addr(clear_wallet_program_id));
    let vault_pk = addr_to_pk(vault_addr);

    let (add_intent_addr, _) = find_intent_address(&wallet_pk_addr, 0, &pk_to_addr(clear_wallet_program_id));
    let (remove_intent_addr, _) = find_intent_address(&wallet_pk_addr, 1, &pk_to_addr(clear_wallet_program_id));
    let (update_intent_addr, _) = find_intent_address(&wallet_pk_addr, 2, &pk_to_addr(clear_wallet_program_id));
    let add_intent_pk = addr_to_pk(add_intent_addr);
    let remove_intent_pk = addr_to_pk(remove_intent_addr);
    let update_intent_pk = addr_to_pk(update_intent_addr);

    // create_wallet args: name (String<64>), thresholds, num_proposers
    // Wire: disc(1) + approval_threshold(1) + cancellation_threshold(1)
    //       + timelock_seconds(4 LE) + num_proposers(1) + name_len(1) + name
    let mut cw_data = Vec::new();
    cw_data.push(IX_CREATE_WALLET);
    cw_data.push(2u8); // approval_threshold
    cw_data.push(1u8); // cancellation_threshold
    cw_data.extend_from_slice(&0u32.to_le_bytes()); // timelock_seconds
    cw_data.push(1u8); // num_proposers
    cw_data.push(wallet_name.len() as u8);
    cw_data.extend_from_slice(wallet_name.as_bytes());

    let cw_ix = Instruction::new_with_bytes(
        clear_wallet_program_id,
        &cw_data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(name_hash_pk, false),
            AccountMeta::new(wallet_pk, false),
            AccountMeta::new(add_intent_pk, false),
            AccountMeta::new(remove_intent_pk, false),
            AccountMeta::new(update_intent_pk, false),
            AccountMeta::new_readonly(system_program::id(), false),
            // Remaining accounts: proposers then approvers
            AccountMeta::new_readonly(proposer_pk, false),
            AccountMeta::new_readonly(approver1_pk, false),
            AccountMeta::new_readonly(approver2_pk, false),
        ],
    );
    send_tx(&client, &payer, vec![cw_ix], &[]);
    ok(&format!("Wallet: {wallet_pk}"));
    val("Vault", vault_pk);
    val("Proposer", proposer_pk);
    val("Approver 1", approver1_pk);
    val("Approver 2", approver2_pk);
    println!();

    // ---------------------------------------------------------------
    // 4. Build the EVM intent body via the JSON example
    // ---------------------------------------------------------------
    log("4/12", "Loading and building EVM intent definition from JSON...");

    let json = std::fs::read_to_string("examples/intents/evm_transfer.json")
        .expect("read evm_transfer.json (run from repo root)");
    let tx_def: IntentTransactionJson = serde_json::from_str(&json).expect("parse evm_transfer.json");
    let def: IntentDefinitionJson = tx_def.with_governance(
        vec![bs58::encode(proposer_pk.as_ref()).into_string()],
        vec![
            bs58::encode(approver1_pk.as_ref()).into_string(),
            bs58::encode(approver2_pk.as_ref()).into_string(),
        ],
        2, // approval_threshold
        1, // cancellation_threshold
        0, // timelock
    );
    let built = def.to_built().expect("build intent");
    val("chain_kind", built.chain_kind);
    val("tx_template_len", built.tx_template_len);
    val("params", built.params.len());

    // Serialize the intent body that will become params_data of the AddIntent proposal.
    let intent_body = built.serialize_body(&wallet_pk_addr, /*bump=*/ 0, /*intent_index=*/ 3, INTENT_TYPE_CUSTOM);
    println!();

    // ---------------------------------------------------------------
    // 5. Propose AddIntent
    // ---------------------------------------------------------------
    log("5/12", "Proposing AddIntent (EVM transfer template)...");

    let proposal_index_add: u64 = 0;
    let (proposal_add_addr, _) = find_proposal_address(&add_intent_addr, proposal_index_add, &pk_to_addr(clear_wallet_program_id));
    let proposal_add_pk = addr_to_pk(proposal_add_addr);

    let propose_msg = add_intent_msg("propose", DEFAULT_EXPIRY, &wallet_name, proposal_index_add, &intent_body);
    let proposer_sig = sign_dalek(&proposer, &propose_msg);

    // Wire layout for `propose` (disc 1):
    //   disc(1) + expiry(8 LE i64) + proposer_pubkey(32) + signature(64) + params_data
    // params_data is the trailing bytes; quasar `&[u8]` reads to end-of-data.
    let mut prop_data = Vec::with_capacity(1 + 8 + 32 + 64 + intent_body.len());
    prop_data.push(IX_PROPOSE);
    prop_data.extend_from_slice(&DEFAULT_EXPIRY.to_le_bytes());
    prop_data.extend_from_slice(&proposer.verifying_key().to_bytes());
    prop_data.extend_from_slice(&proposer_sig);
    prop_data.extend_from_slice(&intent_body);

    let propose_ix = Instruction::new_with_bytes(
        clear_wallet_program_id,
        &prop_data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(wallet_pk, false),
            AccountMeta::new(add_intent_pk, false),
            AccountMeta::new(proposal_add_pk, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    );
    send_tx(&client, &payer, vec![propose_ix], &[]);
    ok(&format!("AddIntent proposal: {proposal_add_pk}"));

    // ---------------------------------------------------------------
    // 6. Approve AddIntent (2 approvers)
    // ---------------------------------------------------------------
    log("6/12", "Approving AddIntent (2/2)...");

    let approve_msg = add_intent_msg("approve", DEFAULT_EXPIRY, &wallet_name, proposal_index_add, &intent_body);
    for (idx, approver) in [(0u8, &approver1), (1u8, &approver2)] {
        let sig = sign_dalek(approver, &approve_msg);
        let mut data = Vec::with_capacity(1 + 8 + 1 + 64);
        data.push(IX_APPROVE);
        data.extend_from_slice(&DEFAULT_EXPIRY.to_le_bytes());
        data.push(idx);
        data.extend_from_slice(&sig);

        let ix = Instruction::new_with_bytes(
            clear_wallet_program_id,
            &data,
            vec![
                AccountMeta::new_readonly(wallet_pk, false),
                AccountMeta::new(add_intent_pk, false),
                AccountMeta::new(proposal_add_pk, false),
            ],
        );
        send_tx(&client, &payer, vec![ix], &[]);
    }
    ok("AddIntent approved");

    // ---------------------------------------------------------------
    // 7. Execute AddIntent — writes the new intent at index 3
    // ---------------------------------------------------------------
    log("7/12", "Executing AddIntent → writes EVM intent at index 3...");

    let (custom_intent_addr, _) = find_intent_address(&wallet_pk_addr, 3, &pk_to_addr(clear_wallet_program_id));
    let custom_intent_pk = addr_to_pk(custom_intent_addr);

    let exec_data = vec![IX_EXECUTE];
    let exec_ix = Instruction::new_with_bytes(
        clear_wallet_program_id,
        &exec_data,
        vec![
            AccountMeta::new(wallet_pk, false),
            AccountMeta::new(vault_pk, false),
            AccountMeta::new(add_intent_pk, false),
            AccountMeta::new(proposal_add_pk, false),
            AccountMeta::new_readonly(system_program::id(), false),
            // Remaining: payer (for new intent rent), new intent PDA
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(custom_intent_pk, false),
        ],
    );
    send_tx(&client, &payer, vec![exec_ix], &[]);
    ok(&format!("Custom EVM intent at index 3: {custom_intent_pk}"));
    println!();

    // ---------------------------------------------------------------
    // 8. Bind dWallet
    // ---------------------------------------------------------------
    log("8/12", "Binding dWallet to clear-msig wallet (chain=evm_1559)...");

    let (ika_config_addr, _) = find_ika_config_address(
        &wallet_pk_addr,
        CHAIN_KIND_EVM,
        &pk_to_addr(clear_wallet_program_id),
    );
    let ika_config_pk = addr_to_pk(ika_config_addr);

    // user_pubkey is the dWallet's secp256k1 public key. Pad/truncate to 32 bytes
    // for the on-chain field — pre-alpha mock doesn't validate this. In a real
    // deployment this is the compressed secp256k1 pubkey.
    let mut user_pubkey = [0u8; 32];
    let copy_len = dwallet_public_key.len().min(32);
    user_pubkey[..copy_len].copy_from_slice(&dwallet_public_key[..copy_len]);

    // bind_dwallet args: chain_kind(1) + user_pubkey(32) + signature_scheme(1) + cpi_authority_bump(1)
    let mut bind_data = Vec::with_capacity(1 + 1 + 32 + 1 + 1);
    bind_data.push(IX_BIND_DWALLET);
    bind_data.push(CHAIN_KIND_EVM);
    bind_data.extend_from_slice(&user_pubkey);
    bind_data.push(0); // signature_scheme = ECDSA secp256k1 in our convention
    bind_data.push(cpi_authority_bump);

    let clear_wallet_program_acct = AccountMeta::new_readonly(clear_wallet_program_id, false);
    let bind_ix = Instruction::new_with_bytes(
        clear_wallet_program_id,
        &bind_data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(wallet_pk, false),
            AccountMeta::new(ika_config_pk, false),
            AccountMeta::new(dwallet_pda, false),
            AccountMeta::new_readonly(cpi_authority_pk, false),
            clear_wallet_program_acct.clone(),
            AccountMeta::new_readonly(dwallet_program_id, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    );
    send_tx(&client, &payer, vec![bind_ix], &[]);
    ok(&format!("IkaConfig: {ika_config_pk}"));
    println!();

    // ---------------------------------------------------------------
    // 9. Propose a Custom EVM intent — transfer 1 Gwei to 0x42..42
    // ---------------------------------------------------------------
    log("9/12", "Proposing Custom EVM transfer...");

    let evm_nonce: u64 = 0;
    let evm_to: [u8; 20] = [0x42; 20];
    let evm_value: u64 = 1_000_000_000; // 1 Gwei in wei
    let evm_data: Vec<u8> = vec![];

    // params_data wire layout matches param order in evm_transfer.json:
    //   nonce (u64 LE) + to (Bytes20) + value (u64 LE) + data (string: u8 len + bytes)
    let mut evm_params = Vec::new();
    evm_params.extend_from_slice(&evm_nonce.to_le_bytes());
    evm_params.extend_from_slice(&evm_to);
    evm_params.extend_from_slice(&evm_value.to_le_bytes());
    evm_params.push(evm_data.len() as u8);
    evm_params.extend_from_slice(&evm_data);

    let proposal_index_custom: u64 = 1;
    let (proposal_custom_addr, _) = find_proposal_address(
        &custom_intent_addr,
        proposal_index_custom,
        &pk_to_addr(clear_wallet_program_id),
    );
    let proposal_custom_pk = addr_to_pk(proposal_custom_addr);

    let custom_msg = custom_evm_msg("propose", DEFAULT_EXPIRY, &wallet_name, proposal_index_custom, evm_nonce, &evm_to, evm_value);
    let custom_sig = sign_dalek(&proposer, &custom_msg);

    let mut prop2 = Vec::new();
    prop2.push(IX_PROPOSE);
    prop2.extend_from_slice(&DEFAULT_EXPIRY.to_le_bytes());
    prop2.extend_from_slice(&proposer.verifying_key().to_bytes());
    prop2.extend_from_slice(&custom_sig);
    prop2.extend_from_slice(&evm_params);

    let prop2_ix = Instruction::new_with_bytes(
        clear_wallet_program_id,
        &prop2,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(wallet_pk, false),
            AccountMeta::new(custom_intent_pk, false),
            AccountMeta::new(proposal_custom_pk, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    );
    send_tx(&client, &payer, vec![prop2_ix], &[]);
    ok(&format!("EVM transfer proposal: {proposal_custom_pk}"));

    log("10/12", "Approving EVM transfer (2/2)...");

    let approve2_msg = custom_evm_msg("approve", DEFAULT_EXPIRY, &wallet_name, proposal_index_custom, evm_nonce, &evm_to, evm_value);
    for (idx, approver) in [(0u8, &approver1), (1u8, &approver2)] {
        let sig = sign_dalek(approver, &approve2_msg);
        let mut data = Vec::with_capacity(1 + 8 + 1 + 64);
        data.push(IX_APPROVE);
        data.extend_from_slice(&DEFAULT_EXPIRY.to_le_bytes());
        data.push(idx);
        data.extend_from_slice(&sig);

        let ix = Instruction::new_with_bytes(
            clear_wallet_program_id,
            &data,
            vec![
                AccountMeta::new_readonly(wallet_pk, false),
                AccountMeta::new(custom_intent_pk, false),
                AccountMeta::new(proposal_custom_pk, false),
            ],
        );
        send_tx(&client, &payer, vec![ix], &[]);
    }
    ok("EVM transfer approved");
    println!();

    // ---------------------------------------------------------------
    // 11. ika_sign — clear-wallet builds the EVM RLP sighash and CPIs approve_message
    // ---------------------------------------------------------------
    log("11/12", "ika_sign → builds EIP-1559 RLP sighash + CPIs approve_message...");

    // Compute the same RLP preimage off-chain so we can pass it to the gRPC Sign request.
    let evm_tx = Tx1559 {
        chain_id: 1,
        nonce: evm_nonce,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 21_000,
        to: evm_to,
        value: evm_value,
        data: evm_data.clone(),
    };
    let rlp_preimage = evm_tx.rlp_preimage();

    // Compute keccak256 of the preimage to derive the MessageApproval PDA.
    let message_hash = {
        use tiny_keccak::{Hasher, Keccak};
        let mut h = Keccak::v256();
        h.update(&rlp_preimage);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        out
    };

    let (message_approval_pda, message_approval_bump) = Pubkey::find_program_address(
        &[SEED_MESSAGE_APPROVAL, dwallet_pda.as_ref(), &message_hash],
        &dwallet_program_id,
    );

    let mut sign_data = Vec::with_capacity(1 + 1 + 1);
    sign_data.push(IX_IKA_SIGN);
    sign_data.push(message_approval_bump);
    sign_data.push(cpi_authority_bump);

    let sign_ix = Instruction::new_with_bytes(
        clear_wallet_program_id,
        &sign_data,
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(wallet_pk, false),
            AccountMeta::new(custom_intent_pk, false),
            AccountMeta::new(proposal_custom_pk, false),
            AccountMeta::new_readonly(ika_config_pk, false),
            AccountMeta::new(dwallet_pda, false),
            AccountMeta::new(message_approval_pda, false),
            AccountMeta::new_readonly(cpi_authority_pk, false),
            AccountMeta::new_readonly(clear_wallet_program_id, false),
            AccountMeta::new_readonly(dwallet_program_id, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
    );
    let quorum_tx_sig = send_tx(&client, &payer, vec![sign_ix], &[]);
    ok(&format!("ika_sign tx: {quorum_tx_sig}"));

    let ma_data = poll_until(
        &client,
        &message_approval_pda,
        |d| d.len() > MA_STATUS && d[0] == DISC_MESSAGE_APPROVAL,
        Duration::from_secs(15),
    );
    assert_eq!(ma_data[MA_STATUS], 0);
    ok(&format!("MessageApproval: {message_approval_pda}"));
    val("Status", "Pending");
    val("RLP length", rlp_preimage.len());
    val("Message hash", hex::encode(message_hash));
    println!();

    // ---------------------------------------------------------------
    // 12. gRPC Presign + Sign + verify
    // ---------------------------------------------------------------
    log("12/12", "Allocating presign + signing via gRPC...");

    let presign_request = build_grpc_request(&payer, SignedRequestData {
        session_identifier_preimage: dwallet_addr,
        epoch: 1,
        chain_id: ChainId::Solana,
        intended_chain_sender: payer.pubkey().to_bytes().to_vec(),
        request: DWalletRequest::PresignForDWallet {
            dwallet_id: dwallet_addr.to_vec(),
            curve: DWalletCurve::Curve25519,
            signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
        },
    });
    let presign_response = grpc_client.submit_transaction(presign_request).await.expect("presign");
    let presign_data: TransactionResponseData =
        bcs::from_bytes(&presign_response.into_inner().response_data).expect("BCS");
    let presign_id = match presign_data {
        TransactionResponseData::Presign { presign_id, .. } => presign_id,
        TransactionResponseData::Error { message } => panic!("presign failed: {message}"),
        other => panic!("unexpected presign response: {other:?}"),
    };
    ok("Presign allocated");
    val("Presign ID", hex::encode(&presign_id));

    let sign_request = build_grpc_request(&payer, SignedRequestData {
        session_identifier_preimage: dwallet_addr,
        epoch: 1,
        chain_id: ChainId::Solana,
        intended_chain_sender: payer.pubkey().to_bytes().to_vec(),
        request: DWalletRequest::Sign {
            message: rlp_preimage.clone(),
            curve: DWalletCurve::Curve25519,
            signature_algorithm: DWalletSignatureAlgorithm::EdDSA,
            hash_scheme: DWalletHashScheme::Keccak256,
            presign_id,
            message_centralized_signature: vec![0u8; 64],
            approval_proof: ApprovalProof::Solana {
                transaction_signature: quorum_tx_sig.as_ref().to_vec(),
                slot: 0,
            },
        },
    });
    let sign_response = grpc_client.submit_transaction(sign_request).await.expect("sign");
    let sign_data: TransactionResponseData =
        bcs::from_bytes(&sign_response.into_inner().response_data).expect("BCS");
    let grpc_signature = match sign_data {
        TransactionResponseData::Signature { signature } => signature,
        TransactionResponseData::Error { message } => panic!("sign failed: {message}"),
        other => panic!("unexpected sign response: {other:?}"),
    };
    ok("Signature received from gRPC");
    val("Signature", hex::encode(&grpc_signature));

    // Wait for the network to commit the signature back into MessageApproval.
    let ma_signed = poll_until(
        &client,
        &message_approval_pda,
        |d| d.len() > MA_STATUS && d[MA_STATUS] == MA_STATUS_SIGNED,
        Duration::from_secs(15),
    );
    let onchain_sig_len = read_u16_le(&ma_signed, MA_SIGNATURE_LEN) as usize;
    let onchain_signature = &ma_signed[MA_SIGNATURE..MA_SIGNATURE + onchain_sig_len];
    assert_eq!(onchain_signature, grpc_signature.as_slice());
    ok("Signature committed on-chain");

    println!();
    println!("{BOLD}{GREEN}\u{2550}\u{2550}\u{2550} E2E PASSED \u{2550}\u{2550}\u{2550}{RESET}");
    println!();
    val("clear-msig wallet", wallet_pk);
    val("Bound dWallet",     dwallet_pda);
    val("EVM tx (RLP)",      hex::encode(&rlp_preimage));
    val("Final signature",   hex::encode(onchain_signature));
    println!();
}
