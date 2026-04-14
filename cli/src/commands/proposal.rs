use crate::config::RuntimeConfig;
use crate::error::*;
use crate::output::print_json;
use crate::{accounts, message, params, resolve, rpc};
use clap::Subcommand;
use solana_sdk::pubkey::Pubkey;

#[derive(Subcommand)]
pub enum ProposalAction {
    /// Create a new proposal for a custom intent
    Create {
        #[arg(long)]
        wallet: String,
        /// Intent index to propose against
        #[arg(long)]
        intent_index: u8,
        /// Parameters as key=value pairs
        #[arg(long = "param")]
        params: Vec<String>,
        /// Message expiry (YYYY-MM-DD HH:MM:SS). Defaults to now + configured expiry_seconds.
        #[arg(long)]
        expiry: Option<String>,
    },
    /// Approve an existing proposal
    Approve {
        #[arg(long)]
        wallet: String,
        /// Proposal account address
        #[arg(long)]
        proposal: String,
        /// Message expiry (YYYY-MM-DD HH:MM:SS). Defaults to now + configured expiry_seconds.
        #[arg(long)]
        expiry: Option<String>,
    },
    /// Cancel / reject a proposal
    Cancel {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        proposal: String,
        /// Message expiry (YYYY-MM-DD HH:MM:SS). Defaults to now + configured expiry_seconds.
        #[arg(long)]
        expiry: Option<String>,
    },
    /// Execute an approved proposal.
    ///
    /// Chain-aware: for `chain = solana` intents, runs the local CPI executor
    /// (vault PDA signs). For any remote chain (EVM, BTC, ZEC, ERC-20),
    /// drives the on-chain `ika_sign` instruction and then completes the
    /// gRPC presign+sign roundtrip with the bound dWallet.
    Execute {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        proposal: String,
        /// Required for remote-chain execution: the dWallet program ID on
        /// the current cluster. Ignored for local Solana intents.
        #[arg(long)]
        dwallet_program: Option<String>,
        /// Ika gRPC endpoint (default: pre-alpha-dev-1).
        #[arg(long, default_value = crate::ika::DEFAULT_GRPC_URL)]
        grpc_url: String,
        /// Debug escape hatch: force Curve25519+EdDSA even if the chain
        /// natively wants secp256k1. Default false — Ika pre-alpha supports
        /// both curves so each chain uses its native one.
        #[arg(long, default_value = "false")]
        force_curve25519: bool,
        /// Destination-chain RPC URL. If set together with `--broadcast`,
        /// the CLI assembles the chain-native signed transaction (recovers
        /// `v`, splices the signature into the EIP-1559 RLP envelope for
        /// EVM, builds the witness for Bitcoin, etc.) and broadcasts it
        /// via this endpoint after the dwallet network returns the
        /// signature. Chain-native protocol is selected automatically from
        /// the intent's `chain_kind` — JSON-RPC `eth_sendRawTransaction`
        /// for EVM, Bitcoin Core RPC `sendrawtransaction` / Esplora REST
        /// `POST /tx` for BTC, etc.
        ///
        /// Examples:
        ///   - Sepolia (public):           `https://ethereum-sepolia-rpc.publicnode.com`
        ///   - Ethereum mainnet (Alchemy): `https://eth-mainnet.g.alchemy.com/v2/<key>`
        ///   - Base mainnet:               `https://mainnet.base.org`
        ///   - Bitcoin testnet (Esplora):  `https://blockstream.info/testnet/api`
        #[arg(long)]
        rpc_url: Option<String>,
        /// Broadcast the signed transaction to the chain after signing.
        /// Requires `--rpc-url <URL>`. Without this flag the CLI just
        /// returns the raw signed bytes in the JSON output and the caller
        /// is responsible for broadcasting them.
        #[arg(long, default_value = "false")]
        broadcast: bool,
    },
    /// List proposals for a wallet
    List {
        #[arg(long)]
        wallet: String,
    },
    /// Show details of a specific proposal
    Show {
        /// Proposal account address
        #[arg(long)]
        proposal: String,
    },
    /// Close an executed/cancelled proposal and reclaim rent
    Cleanup {
        #[arg(long)]
        proposal: String,
    },
}

pub fn handle(action: ProposalAction, config: &RuntimeConfig) -> Result<()> {
    match action {
        ProposalAction::Create {
            wallet: wallet_name,
            intent_index,
            params: raw_params,
            expiry,
        } => {
            let expiry_ts = message::resolve_expiry(&expiry, config)?;
            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());

            let (wallet_addr, _) =
                clear_wallet_client::pda::find_wallet_address(&wallet_name, &pid);
            let wallet_pubkey = Pubkey::new_from_array(wallet_addr.to_bytes());

            let client = rpc::client(config);
            let wallet_data = rpc::fetch_account(&client, &wallet_pubkey)?;
            let wallet_account = accounts::parse_wallet(&wallet_data)?;

            let (intent_addr, _) = clear_wallet_client::pda::find_intent_address(
                &wallet_addr,
                intent_index,
                &pid,
            );
            let intent_pubkey = Pubkey::new_from_array(intent_addr.to_bytes());
            let intent_data = rpc::fetch_account(&client, &intent_pubkey)?;
            let intent_account = accounts::parse_intent(&intent_data)?;

            if !intent_account.approved {
                return Err(anyhow!("intent {} is not approved", intent_index));
            }

            // Check signer is a proposer
            let signer_pubkey_b58 = bs58::encode(config.signer.pubkey()).into_string();
            if !intent_account.proposers.contains(&signer_pubkey_b58) {
                return Err(anyhow!(
                    "signer {} is not a proposer on intent {}",
                    signer_pubkey_b58,
                    intent_index
                ));
            }

            let params_data = params::encode_params(&intent_account, &raw_params)?;

            let proposal_index = wallet_account.proposal_index;
            let msg = message::build_message(
                "propose",
                expiry_ts,
                &wallet_account.name,
                proposal_index,
                &intent_account,
                &params_data,
            )?;

            eprintln!("Signing message:\n{}", String::from_utf8_lossy(&msg[20..]));
            let signature = config.signer.sign_message(&msg)?;
            let proposer_pubkey = config.signer.pubkey();

            let (proposal_addr, _) = clear_wallet_client::pda::find_proposal_address(
                &intent_addr,
                proposal_index,
                &pid,
            );

            let payer_pubkey = solana_sdk::signer::Signer::pubkey(&config.payer);
            let ix = crate::instructions::propose(crate::instructions::ProposeArgs {
                payer: payer_pubkey,
                wallet: wallet_pubkey,
                intent: intent_pubkey,
                proposal: Pubkey::new_from_array(proposal_addr.to_bytes()),
                proposal_index,
                expiry: expiry_ts,
                proposer_pubkey,
                signature,
                params_data: &params_data,
            });

            let sig = rpc::send_instruction(&client, config, ix)?;

            print_json(&serde_json::json!({
                "txid": sig.to_string(),
                "proposal": Pubkey::new_from_array(proposal_addr.to_bytes()).to_string(),
                "proposal_index": proposal_index,
            }));
        }

        ProposalAction::Approve {
            wallet: wallet_name,
            proposal: proposal_addr_str,
            expiry,
        } => {
            approve_or_cancel(config, &wallet_name, &proposal_addr_str, &expiry, true)?;
        }

        ProposalAction::Cancel {
            wallet: wallet_name,
            proposal: proposal_addr_str,
            expiry,
        } => {
            approve_or_cancel(config, &wallet_name, &proposal_addr_str, &expiry, false)?;
        }

        ProposalAction::Execute {
            wallet: wallet_name,
            proposal: proposal_addr_str,
            dwallet_program,
            grpc_url,
            force_curve25519,
            rpc_url,
            broadcast,
        } => {
            if broadcast && rpc_url.is_none() {
                return Err(anyhow!(
                    "--broadcast requires --rpc-url <URL> for the destination chain"
                ));
            }
            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());

            let (wallet_addr, _) =
                clear_wallet_client::pda::find_wallet_address(&wallet_name, &pid);
            let wallet_pubkey = Pubkey::new_from_array(wallet_addr.to_bytes());

            let (vault_addr, _) =
                clear_wallet_client::pda::find_vault_address(&wallet_addr, &pid);
            let vault_pubkey = Pubkey::new_from_array(vault_addr.to_bytes());

            let proposal_pubkey: Pubkey = proposal_addr_str
                .parse()
                .with_context(|| "invalid proposal address")?;

            let client = rpc::client(config);
            let proposal_data = rpc::fetch_account(&client, &proposal_pubkey)?;
            let proposal_account = accounts::parse_proposal(&proposal_data)?;

            if proposal_account.status != "Approved" {
                return Err(anyhow!(
                    "proposal status is '{}', must be 'Approved' to execute",
                    proposal_account.status
                ));
            }

            let intent_pubkey: Pubkey = proposal_account
                .intent
                .parse()
                .with_context(|| "invalid intent address in proposal")?;
            let intent_data = rpc::fetch_account(&client, &intent_pubkey)?;
            let intent_account = accounts::parse_intent(&intent_data)?;

            // Meta-intents (AddIntent=0, RemoveIntent=1, UpdateIntent=2) use
            // the local execute instruction. Custom intents (3) go through
            // Ika dWallet signing for all chains.
            if intent_account.intent_type <= 2 {
                let payer_pubkey = solana_sdk::signer::Signer::pubkey(&config.payer);
                let remaining = resolve::resolve_remaining_accounts(
                    &client,
                    &intent_account,
                    &wallet_pubkey,
                    &vault_pubkey,
                    &proposal_account.params_data,
                    &payer_pubkey,
                )?;
                let ix = crate::instructions::execute(
                    wallet_pubkey,
                    vault_pubkey,
                    intent_pubkey,
                    proposal_pubkey,
                    remaining,
                );
                let sig = rpc::send_instruction(&client, config, ix)?;
                print_json(&serde_json::json!({
                    "txid": sig.to_string(),
                    "path": "meta-intent",
                    "status": "executed",
                }));
            } else {
                let dwallet_program_pk: Pubkey = dwallet_program
                    .ok_or(anyhow!(
                        "proposal execution requires --dwallet-program",
                    ))?
                    .parse()
                    .with_context(|| "invalid dWallet program ID")?;

                execute_via_ika(
                    config,
                    &client,
                    &wallet_name,
                    wallet_pubkey,
                    intent_pubkey,
                    &intent_account,
                    proposal_pubkey,
                    &proposal_account,
                    dwallet_program_pk,
                    &grpc_url,
                    force_curve25519,
                    rpc_url.as_deref(),
                    broadcast,
                )?;
            }
        }

        ProposalAction::List {
            wallet: wallet_name,
        } => {
            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());

            let (wallet_addr, _) =
                clear_wallet_client::pda::find_wallet_address(&wallet_name, &pid);
            let wallet_pubkey = Pubkey::new_from_array(wallet_addr.to_bytes());

            let client = rpc::client(config);
            let wallet_data = rpc::fetch_account(&client, &wallet_pubkey)?;
            let wallet_account = accounts::parse_wallet(&wallet_data)?;

            // Iterate all intents, then all proposals for each
            let mut proposals = Vec::new();
            for intent_idx in 0..=wallet_account.intent_index {
                let (intent_addr, _) = clear_wallet_client::pda::find_intent_address(
                    &wallet_addr,
                    intent_idx,
                    &pid,
                );

                // Try fetching proposals for this intent
                // We don't know the exact count, so scan from 0 up to wallet.proposal_index
                for prop_idx in 0..wallet_account.proposal_index {
                    let (proposal_addr, _) = clear_wallet_client::pda::find_proposal_address(
                        &intent_addr,
                        prop_idx,
                        &pid,
                    );
                    let proposal_pubkey = Pubkey::new_from_array(proposal_addr.to_bytes());
                    if let Some(data) = rpc::fetch_account_optional(&client, &proposal_pubkey)? {
                        if let Ok(p) = accounts::parse_proposal(&data) {
                            proposals.push(serde_json::json!({
                                "address": proposal_pubkey.to_string(),
                                "intent_index": intent_idx,
                                "proposal_index": p.proposal_index,
                                "proposer": p.proposer,
                                "status": p.status,
                                "proposed_at": p.proposed_at,
                                "approved_at": p.approved_at,
                                "approval_bitmap": p.approval_bitmap,
                                "cancellation_bitmap": p.cancellation_bitmap,
                            }));
                        }
                    }
                }
            }

            print_json(&proposals);
        }

        ProposalAction::Show {
            proposal: proposal_addr_str,
        } => {
            let proposal_pubkey: Pubkey = proposal_addr_str
                .parse()
                .with_context(|| "invalid proposal address")?;

            let client = rpc::client(config);
            let data = rpc::fetch_account(&client, &proposal_pubkey)?;
            let proposal = accounts::parse_proposal(&data)?;

            print_json(&serde_json::json!({
                "address": proposal_pubkey.to_string(),
                "wallet": proposal.wallet,
                "intent": proposal.intent,
                "proposal_index": proposal.proposal_index,
                "proposer": proposal.proposer,
                "status": proposal.status,
                "proposed_at": proposal.proposed_at,
                "approved_at": proposal.approved_at,
                "approval_bitmap": proposal.approval_bitmap,
                "cancellation_bitmap": proposal.cancellation_bitmap,
                "rent_refund": proposal.rent_refund,
                "params_data": bs58::encode(&proposal.params_data).into_string(),
            }));
        }

        ProposalAction::Cleanup {
            proposal: proposal_addr_str,
        } => {
            let proposal_pubkey: Pubkey = proposal_addr_str
                .parse()
                .with_context(|| "invalid proposal address")?;

            let client = rpc::client(config);
            let data = rpc::fetch_account(&client, &proposal_pubkey)?;
            let proposal = accounts::parse_proposal(&data)?;
            let rent_refund: Pubkey = proposal.rent_refund
                .parse()
                .with_context(|| "invalid rent_refund address in proposal")?;

            let ix = crate::instructions::cleanup(proposal_pubkey, rent_refund);
            let sig = rpc::send_instruction(&client, config, ix)?;

            print_json(&serde_json::json!({
                "txid": sig.to_string(),
                "status": "cleaned up",
            }));
        }
    }
    Ok(())
}

/// Drive a remote-chain proposal through Ika: build the destination-chain
/// preimage off-chain, send the on-chain `ika_sign` ix, then run the gRPC
/// presign + sign roundtrip and verify the signature lands in the
/// `MessageApproval` PDA. If `broadcast` is set, also assemble the
/// chain-native signed transaction and push it to `rpc_url`.
#[allow(clippy::too_many_arguments)]
fn execute_via_ika(
    config: &RuntimeConfig,
    client: &solana_client::rpc_client::RpcClient,
    _wallet_name: &str,
    wallet_pubkey: Pubkey,
    intent_pubkey: Pubkey,
    intent_account: &accounts::IntentAccount,
    proposal_pubkey: Pubkey,
    proposal_account: &accounts::ProposalAccount,
    dwallet_program: Pubkey,
    grpc_url: &str,
    force_curve25519: bool,
    rpc_url: Option<&str>,
    broadcast: bool,
) -> Result<()> {
    use crate::ika;
    use ika_dwallet_types::VersionedDWalletDataAttestation;
    use std::time::Duration;

    let chain_kind = intent_account.chain_kind;
    eprintln!(
        "→ Remote-chain execution (chain_kind={chain_kind}) via Ika dWallet"
    );

    let program_id = crate::instructions::program_id();

    // 1. Locate the IkaConfig binding for (wallet, chain_kind).
    let (ika_config_pk, _) = ika::ika_config_pda(&program_id, &wallet_pubkey, chain_kind);
    let cfg_data = rpc::fetch_account(client, &ika_config_pk).with_context(|| {
        format!(
            "wallet has no binding for chain_kind={chain_kind}; \
             run `clear-msig wallet add-chain --wallet <name> --chain <name>` first"
        )
    })?;
    let cfg = accounts::parse_ika_config(&cfg_data)?;
    let dwallet_pk: Pubkey = cfg.dwallet.parse().context("invalid dwallet in IkaConfig")?;
    eprintln!("✓ IkaConfig: {ika_config_pk} → dWallet {dwallet_pk}");

    // 2. Resolve signing params and fetch the dWallet pubkey.
    let (curve, algo, scheme) = ika::signing_params(chain_kind, force_curve25519);
    let curve_u16 = ika::curve_u16(curve);
    let scheme_u16 = scheme as u16;

    let dwallet_data = rpc::fetch_account(client, &dwallet_pk).with_context(|| {
        format!("failed to fetch dwallet account {dwallet_pk}")
    })?;
    let dwallet_account = accounts::parse_dwallet(&dwallet_data)?;

    // 3. Build the off-chain preimage and derive the message hash.
    //    For Solana: full tx message (needs dWallet pubkey).
    //    For Zcash: full ZIP-243 preimage.
    //    For others: chain-native preimage.
    let preimage = match chain_kind {
        0 => {
            let dest = ika::read_param_bytes32(intent_account, &proposal_account.params_data, 0)?;
            let amt = ika::read_param_u64(intent_account, &proposal_account.params_data, 1)?;
            let nonce_val = ika::read_param_bytes32(intent_account, &proposal_account.params_data, 2)?;
            let off = intent_account.tx_template_offset as usize;
            let nonce_acct: [u8; 32] = intent_account.byte_pool[off..off + 32]
                .try_into().map_err(|_| anyhow!("nonce_account read failed"))?;
            ika::build_solana_tx_message(
                &dwallet_account.public_key[..32].try_into().unwrap(),
                &dest, amt, &nonce_acct, &nonce_val,
            )
        }
        3 => ika::build_zcash_zip243_preimage(intent_account, &proposal_account.params_data)?,
        _ => ika::build_chain_preimage(intent_account, &proposal_account.params_data)?,
    };
    let message_hash = ika::hash_preimage(chain_kind, &preimage);
    eprintln!(
        "✓ Built {}-byte preimage, hash {}",
        preimage.len(),
        hex_lower(&message_hash)
    );

    // 4. Resolve the MessageApproval PDA + bump using hierarchical seeds.
    let tt_off = intent_account.tx_template_offset as usize;
    let tt_len = intent_account.tx_template_len as usize;
    let tx_template = &intent_account.byte_pool[tt_off..tt_off + tt_len];
    let meta_digest = ika::metadata_digest(intent_account.chain_kind, tx_template);
    let (message_approval_pk, message_approval_bump) =
        ika::message_approval_pda(&dwallet_program, curve_u16, &dwallet_account.public_key, scheme_u16, &message_hash, &meta_digest);
    let (coordinator_pk, _) = ika::coordinator_pda(&dwallet_program);
    let (cpi_authority_pk, cpi_authority_bump) = ika::cpi_authority_pda(&program_id);
    let (dwallet_ownership_pk, _) = ika::dwallet_ownership_pda(&program_id, &dwallet_pk);

    // 5. For Zcash, compute the BLAKE2b sub-hashes so the on-chain program
    //    can build the full ZIP-243 preimage for the MA PDA.
    let blake2b_hashes = if chain_kind == 3 {
        ika::compute_zcash_blake2b_hashes(intent_account, &proposal_account.params_data)?
    } else {
        [0u8; 96]
    };

    let payer_pubkey = solana_sdk::signer::Signer::pubkey(&config.payer);
    let ix = crate::instructions::ika_sign(
        payer_pubkey,
        wallet_pubkey,
        intent_pubkey,
        proposal_pubkey,
        ika_config_pk,
        dwallet_ownership_pk,
        dwallet_pk,
        message_approval_pk,
        coordinator_pk,
        cpi_authority_pk,
        dwallet_program,
        message_approval_bump,
        cpi_authority_bump,
        blake2b_hashes,
    );
    let quorum_tx_sig = rpc::send_instruction(client, config, ix)
        .with_context(|| "ika_sign failed")?;
    eprintln!("✓ ika_sign tx: {quorum_tx_sig}");

    // 6. Wait for the MessageApproval PDA to materialize on-chain.
    ika::poll_until(
        client,
        &message_approval_pk,
        |d| d.len() > ika::MA_STATUS && d[0] == ika::DISC_MESSAGE_APPROVAL,
        Duration::from_secs(15),
    )
    .with_context(|| "MessageApproval PDA never appeared after ika_sign")?;
    eprintln!("✓ MessageApproval pending: {message_approval_pk}");

    // 7. gRPC: presign then sign.
    // Load the DKG attestation saved during `wallet add-chain` and use its
    // session_identifier as the dwallet_addr — this must match the value
    // the mock stored the key under during DKG.
    let dwallet_attestation = ika::load_attestation(_wallet_name)
        .with_context(|| "failed to load dWallet attestation")?;
    let dwallet_addr_bytes = {
        let versioned: VersionedDWalletDataAttestation =
            bcs::from_bytes(&dwallet_attestation.attestation_data)
                .with_context(|| "failed to decode dWallet attestation for session_identifier")?;
        let VersionedDWalletDataAttestation::V1(data) = versioned;
        data.session_identifier
    };

    let presign_id = ika::presign(config, grpc_url, dwallet_addr_bytes, curve, algo)?;
    eprintln!("✓ Presign allocated ({} bytes)", presign_id.len());

    // Build the chain-specific message for the Sign request.
    // For Solana: full tx message with durable nonce (what Ed25519 signs).
    // For Zcash: full ZIP-243 preimage + BLAKE2b metadata.
    // For EVM/BTC: the preimage itself.
    let (sign_message, message_metadata) = match chain_kind {
        0 => {
            // Solana: build the actual transaction message.
            let destination = ika::read_param_bytes32(intent_account, &proposal_account.params_data, 0)?;
            let amount = ika::read_param_u64(intent_account, &proposal_account.params_data, 1)?;
            let nonce_value = ika::read_param_bytes32(intent_account, &proposal_account.params_data, 2)?;
            let off = intent_account.tx_template_offset as usize;
            let nonce_account: [u8; 32] = intent_account.byte_pool[off..off + 32]
                .try_into().map_err(|_| anyhow!("nonce_account read failed"))?;
            let tx_msg = ika::build_solana_tx_message(
                &dwallet_account.public_key[..32].try_into().unwrap(),
                &destination, amount, &nonce_account, &nonce_value,
            );
            (tx_msg, vec![])
        }
        3 => {
            let zip243 = ika::build_zcash_zip243_preimage(intent_account, &proposal_account.params_data)?;
            let off = intent_account.tx_template_offset as usize;
            let branch_id = u32::from_le_bytes(
                intent_account.byte_pool[off + 16..off + 20].try_into().unwrap()
            );
            let personal = ika::zcash_sighash_personal(branch_id);
            let metadata = ika_dwallet_types::Blake2bMessageMetadata {
                personal,
                salt: vec![],
            };
            (zip243, bcs::to_bytes(&metadata).unwrap_or_default())
        }
        _ => (preimage.clone(), vec![]),
    };
    let sign_message_for_broadcast = sign_message.clone();

    let signature = ika::sign(
        config,
        grpc_url,
        dwallet_addr_bytes,
        dwallet_attestation,
        presign_id,
        sign_message,
        message_metadata,
        quorum_tx_sig.as_ref().to_vec(),
    )?;
    eprintln!("✓ Signature received from Ika ({} bytes)", signature.len());

    // 8. Poll MessageApproval until the network commits the signature.
    let ma_signed = ika::poll_until(
        client,
        &message_approval_pk,
        |d| d.len() > ika::MA_STATUS && d[ika::MA_STATUS] == ika::MA_STATUS_SIGNED,
        Duration::from_secs(15),
    )
    .with_context(|| "MessageApproval signature not committed on-chain")?;
    let onchain_sig_len = u16::from_le_bytes(
        ma_signed[ika::MA_SIGNATURE_LEN..ika::MA_SIGNATURE_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let onchain_sig = &ma_signed[ika::MA_SIGNATURE..ika::MA_SIGNATURE + onchain_sig_len];

    let mut output = serde_json::json!({
        "txid":             quorum_tx_sig.to_string(),
        "path":             "ika-dwallet",
        "status":           "signed",
        "chain_kind":       chain_kind,
        "preimage_hex":     hex_lower(&preimage),
        "message_hash_hex": hex_lower(&message_hash),
        "signature_hex":    hex_lower(onchain_sig),
        "message_approval": message_approval_pk.to_string(),
    });

    // 9. Optional: assemble the chain-native signed transaction and broadcast.
    if broadcast {
        let rpc_url = rpc_url.expect("--broadcast already validated to require --rpc-url");

        if chain_kind == 0 {
            // Solana: assemble wire tx from sign_message + signature directly.
            // Wire format: [1 (num_sigs compact-u16)] [64-byte sig] [message_bytes]
            let mut wire_tx = Vec::with_capacity(1 + 64 + sign_message_for_broadcast.len());
            wire_tx.push(1); // 1 signature (compact-u16)
            wire_tx.extend_from_slice(&signature);
            wire_tx.extend_from_slice(&sign_message_for_broadcast);

            let sol_client = solana_client::rpc_client::RpcClient::new(rpc_url.to_string());
            let tx: solana_sdk::transaction::Transaction =
                bincode::deserialize(&wire_tx)
                    .with_context(|| "failed to deserialize Solana transaction")?;
            let tx_sig = sol_client
                .send_and_confirm_transaction(&tx)
                .with_context(|| "failed to send Solana transaction")?;
            eprintln!("✓ Broadcast solana: {tx_sig}");
            output["broadcast"] = serde_json::json!({
                "chain": "solana",
                "chain_kind": 0,
                "tx_id": tx_sig.to_string(),
                "raw_tx_hex": format!("0x{}", hex_lower(&wire_tx)),
            });
        } else {
            let inputs = build_broadcast_inputs(
                chain_kind,
                intent_account,
                &proposal_account.params_data,
            )?;

            let result = crate::chains::broadcast_signed_tx(
                chain_kind,
                inputs,
                &preimage,
                onchain_sig,
                &dwallet_account.public_key,
                rpc_url,
            )
            .with_context(|| format!("broadcast to {rpc_url} failed"))?;
            eprintln!("✓ Broadcast {}: {}", result.chain, result.tx_id);
            if let Some(url) = &result.explorer_url {
                eprintln!("  → {url}");
            }
            output["broadcast"] = serde_json::to_value(&result)?;
        }
    }

    print_json(&output);
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the chain-specific [`crate::chains::BroadcastInputs`] payload from
/// the intent's params + tx_template. EVM doesn't need any extras (the
/// EIP-1559 RLP is fully self-describing), so chains 1 and 4 short-circuit
/// to `BroadcastInputs::Evm`. Bitcoin BIP143 commits to its outputs as a
/// hash, so we have to plumb the originals through.
fn build_broadcast_inputs(
    chain_kind: u8,
    intent: &accounts::IntentAccount,
    params_data: &[u8],
) -> Result<crate::chains::BroadcastInputs> {
    use crate::chains::BroadcastInputs;
    use crate::ika;

    match chain_kind {
        0 => {
            let destination = ika::read_param_bytes32(intent, params_data, 0)?;
            let amount_lamports = ika::read_param_u64(intent, params_data, 1)?;
            Ok(BroadcastInputs::Solana { destination, amount_lamports })
        }
        1 | 4 => Ok(BroadcastInputs::Evm),
        2 => {
            // Param schema (must match `clear_wallet::chains::bitcoin`):
            //   [0] prev_txid       : Bytes32
            //   [1] prev_vout       : U64 (we use the low 32 bits)
            //   [2] prev_amount     : U64  (committed via BIP143 amount field)
            //   [3] sender_pkh      : Bytes20 (committed via scriptCode)
            //   [4] recipient_pkh   : Bytes20 ← needed for output assembly
            //   [5] send_amount_sats: U64    ← needed for output assembly
            let prev_txid = ika::read_param_bytes32(intent, params_data, 0)?;
            let prev_vout = ika::read_param_u64(intent, params_data, 1)? as u32;
            // Skip prev_amount (committed via the BIP143 preimage) and
            // sender_pkh (committed via scriptCode); we don't need them
            // again for the witness tx body.
            let recipient_pkh = ika::read_param_bytes20(intent, params_data, 4)?;
            let send_amount_sats = ika::read_param_u64(intent, params_data, 5)?;

            // tx_template layout (16 bytes):
            //   version(4) || lock_time(4) || sequence(4) || sighash_type(4)
            // Pull out sequence + lock_time so the broadcast tx body matches
            // the BIP143 preimage byte-for-byte.
            let off = intent.tx_template_offset as usize;
            let len = intent.tx_template_len as usize;
            if len != 16 {
                return Err(anyhow!(
                    "bitcoin_p2wpkh tx_template must be 16 bytes, got {len}"
                ));
            }
            let tt = intent
                .byte_pool
                .get(off..off + len)
                .ok_or(anyhow!("tx_template OOB"))?;
            let lock_time = u32::from_le_bytes(tt[4..8].try_into().unwrap());
            let sequence = u32::from_le_bytes(tt[8..12].try_into().unwrap());

            Ok(BroadcastInputs::BitcoinP2wpkh {
                prev_txid,
                prev_vout,
                sequence,
                recipient_pkh,
                send_amount_sats,
                lock_time,
            })
        }
        3 => {
            let prev_txid = ika::read_param_bytes32(intent, params_data, 0)?;
            let prev_vout = ika::read_param_u64(intent, params_data, 1)? as u32;
            let sender_pkh = ika::read_param_bytes20(intent, params_data, 3)?;
            let recipient_pkh = ika::read_param_bytes20(intent, params_data, 4)?;
            let send_amount_zat = ika::read_param_u64(intent, params_data, 5)?;

            let off = intent.tx_template_offset as usize;
            let len = intent.tx_template_len as usize;
            if len != 20 {
                return Err(anyhow!(
                    "zcash_transparent tx_template must be 20 bytes, got {len}"
                ));
            }
            let tt = intent
                .byte_pool
                .get(off..off + len)
                .ok_or(anyhow!("tx_template OOB"))?;
            let header = u32::from_le_bytes(tt[0..4].try_into().unwrap());
            let version_group_id = u32::from_le_bytes(tt[4..8].try_into().unwrap());
            let lock_time = u32::from_le_bytes(tt[8..12].try_into().unwrap());
            let expiry_height = u32::from_le_bytes(tt[12..16].try_into().unwrap());

            Ok(BroadcastInputs::ZcashTransparent {
                header,
                version_group_id,
                prev_txid,
                prev_vout,
                sender_pkh,
                recipient_pkh,
                send_amount_zat,
                lock_time,
                expiry_height,
            })
        }
        n => Err(anyhow!(
            "broadcast not supported for chain_kind {n}"
        )),
    }
}

fn parse_hex_local(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex string has odd length"));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow!("invalid hex: {e}")))
        .collect()
}

/// Shared logic for approve and cancel.
fn approve_or_cancel(
    config: &RuntimeConfig,
    wallet_name: &str,
    proposal_addr_str: &str,
    expiry: &Option<String>,
    is_approve: bool,
) -> Result<()> {
    let expiry_ts = message::resolve_expiry(expiry, config)?;
    let program_id = crate::instructions::program_id();
    let pid = solana_address::Address::new_from_array(program_id.to_bytes());

    let (wallet_addr, _) = clear_wallet_client::pda::find_wallet_address(wallet_name, &pid);
    let wallet_pubkey = Pubkey::new_from_array(wallet_addr.to_bytes());

    let client = rpc::client(config);
    let wallet_data = rpc::fetch_account(&client, &wallet_pubkey)?;
    let wallet_account = accounts::parse_wallet(&wallet_data)?;

    let proposal_pubkey: Pubkey = proposal_addr_str
        .parse()
        .with_context(|| "invalid proposal address")?;
    let proposal_data = rpc::fetch_account(&client, &proposal_pubkey)?;
    let proposal_account = accounts::parse_proposal(&proposal_data)?;

    let intent_pubkey: Pubkey = proposal_account
        .intent
        .parse()
        .with_context(|| "invalid intent address in proposal")?;
    let intent_data = rpc::fetch_account(&client, &intent_pubkey)?;
    let intent_account = accounts::parse_intent(&intent_data)?;

    // Find our index in the approvers list
    let signer_pubkey_b58 = bs58::encode(config.signer.pubkey()).into_string();
    let approver_index = intent_account
        .approvers
        .iter()
        .position(|a| a == &signer_pubkey_b58)
        .ok_or(anyhow!(
            "signer {} is not an approver on this intent",
            signer_pubkey_b58
        ))? as u8;

    let action = if is_approve { "approve" } else { "cancel" };
    let msg = message::build_message(
        action,
        expiry_ts,
        &wallet_account.name,
        proposal_account.proposal_index,
        &intent_account,
        &proposal_account.params_data,
    )?;

    eprintln!("Signing message:\n{}", String::from_utf8_lossy(&msg[20..]));
    let signature = config.signer.sign_message(&msg)?;

    let ix = if is_approve {
        crate::instructions::approve(
            wallet_pubkey,
            intent_pubkey,
            proposal_pubkey,
            expiry_ts,
            approver_index,
            signature,
        )
    } else {
        crate::instructions::cancel(
            wallet_pubkey,
            intent_pubkey,
            proposal_pubkey,
            expiry_ts,
            approver_index,
            signature,
        )
    };

    let sig = rpc::send_instruction(&client, config, ix)?;

    print_json(&serde_json::json!({
        "txid": sig.to_string(),
        "action": action,
        "approver_index": approver_index,
    }));

    Ok(())
}
