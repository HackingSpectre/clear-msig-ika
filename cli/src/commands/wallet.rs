use crate::accounts;
use crate::config::RuntimeConfig;
use crate::error::*;
use crate::ika;
use crate::output::print_json;
use crate::rpc;
use clap::Subcommand;
use solana_sdk::pubkey::Pubkey;
use std::time::Duration;

#[derive(Subcommand)]
pub enum WalletAction {
    /// Create a new multisig wallet
    Create {
        /// Wallet name (used to derive PDA)
        #[arg(long)]
        name: String,
        /// Comma-separated proposer addresses
        #[arg(long, value_delimiter = ',')]
        proposers: Vec<String>,
        /// Comma-separated approver addresses
        #[arg(long, value_delimiter = ',')]
        approvers: Vec<String>,
        /// Approval threshold
        #[arg(long)]
        threshold: u8,
        /// Cancellation threshold
        #[arg(long, default_value = "1")]
        cancellation_threshold: u8,
        /// Timelock in seconds
        #[arg(long, default_value = "0")]
        timelock: u32,
    },
    /// Show wallet details
    Show {
        /// Wallet name
        #[arg(long)]
        name: String,
    },
    /// Give the wallet an identity on a remote chain via Ika dWallet.
    ///
    /// Performs the full DKG → transfer-authority → bind sequence in one
    /// command. After this, intents declared with `chain = <chain>` can be
    /// signed via `proposal execute` for the same wallet.
    AddChain {
        /// Wallet name
        #[arg(long)]
        wallet: String,
        /// Destination chain (matches `chain` field in intent JSON files):
        /// `evm_1559`, `evm_1559_erc20`, `bitcoin_p2wpkh`.
        #[arg(long)]
        chain: String,
        /// dWallet program ID on the current cluster.
        #[arg(long)]
        dwallet_program: String,
        /// Ika gRPC endpoint (default: pre-alpha-dev-1).
        #[arg(long, default_value = ika::DEFAULT_GRPC_URL)]
        grpc_url: String,
        /// Skip DKG and bind an existing dWallet by address. Pass the
        /// dWallet's curve-native public key as hex (32 bytes for Curve25519
        /// or 33 bytes for compressed secp256k1).
        #[arg(long)]
        existing_dwallet_pubkey: Option<String>,
        /// 32-byte Ika session identifier for the existing dWallet, as hex.
        /// Required only when `--existing-dwallet-pubkey` is set AND no
        /// other `IkaConfig` on this wallet already binds the same dWallet —
        /// in that case the CLI can't auto-recover the session id from a
        /// sibling binding and you have to pass it. Read it out of any
        /// other clear-msig wallet's `wallet chains` JSON, where it appears
        /// as `user_pubkey_hex` for the same dWallet.
        #[arg(long)]
        existing_dwallet_addr: Option<String>,
        /// Debug escape hatch: force Curve25519+EdDSA even if the chain
        /// natively wants secp256k1. Default false — secp256k1 is supported
        /// by Ika pre-alpha for both DKG and Sign per the docs.
        #[arg(long, default_value = "false")]
        force_curve25519: bool,
    },
    /// List chains the wallet has been added to (i.e., which IkaConfig PDAs exist).
    Chains {
        /// Wallet name
        #[arg(long)]
        wallet: String,
        /// dWallet program ID (only used to display the dWallet account, optional).
        #[arg(long)]
        dwallet_program: Option<String>,
    },
}

/// Map a CLI `--chain` string to its on-chain `ChainKind` discriminant.
fn parse_chain_kind(chain: &str) -> Result<u8> {
    match chain {
        "solana"              => Ok(0),
        "evm_1559"            => Ok(1),
        "bitcoin_p2wpkh"      => Ok(2),
        "zcash_transparent"   => Ok(3),
        "evm_1559_erc20"      => Ok(4),
        other => Err(anyhow!(
            "unknown chain '{other}' (expected one of: solana, evm_1559, evm_1559_erc20, bitcoin_p2wpkh, zcash_transparent, solana_dwallet)"
        )),
    }
}

fn chain_kind_name(k: u8) -> &'static str {
    match k {
        0 => "solana",
        1 => "evm_1559",
        2 => "bitcoin_p2wpkh",
        3 => "zcash_transparent",
        4 => "evm_1559_erc20",
        _ => "unknown",
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex string has odd length"));
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow!("invalid hex: {e}")))
        .collect()
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

pub fn handle(action: WalletAction, config: &RuntimeConfig) -> Result<()> {
    match action {
        WalletAction::Create {
            name,
            proposers,
            approvers,
            threshold,
            cancellation_threshold,
            timelock,
        } => {
            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());

            let (wallet_addr, _) = clear_wallet_client::pda::find_wallet_address(&name, &pid);
            let wallet = Pubkey::new_from_array(wallet_addr.to_bytes());

            let (vault_addr, _) = clear_wallet_client::pda::find_vault_address(&wallet_addr, &pid);
            let vault = Pubkey::new_from_array(vault_addr.to_bytes());

            let name_hash = clear_wallet_client::pda::compute_name_hash(&name);
            let name_hash_pubkey = Pubkey::new_from_array(name_hash);

            // Derive PDAs for the 3 default meta-intents
            let (add_intent_addr, _) =
                clear_wallet_client::pda::find_intent_address(&wallet_addr, 0, &pid);
            let (remove_intent_addr, _) =
                clear_wallet_client::pda::find_intent_address(&wallet_addr, 1, &pid);
            let (update_intent_addr, _) =
                clear_wallet_client::pda::find_intent_address(&wallet_addr, 2, &pid);

            let proposer_pubkeys: Vec<Pubkey> = proposers
                .iter()
                .map(|s| s.parse().with_context(|| format!("invalid proposer address: {s}")))
                .collect::<Result<_>>()?;
            let approver_pubkeys: Vec<Pubkey> = approvers
                .iter()
                .map(|s| s.parse().with_context(|| format!("invalid approver address: {s}")))
                .collect::<Result<_>>()?;

            let payer_pubkey = solana_sdk::signer::Signer::pubkey(&config.payer);
            let ix = crate::instructions::create_wallet(crate::instructions::CreateWalletArgs {
                payer: payer_pubkey,
                name_hash: name_hash_pubkey,
                wallet,
                add_intent: Pubkey::new_from_array(add_intent_addr.to_bytes()),
                remove_intent: Pubkey::new_from_array(remove_intent_addr.to_bytes()),
                update_intent: Pubkey::new_from_array(update_intent_addr.to_bytes()),
                name: &name,
                threshold,
                cancel_threshold: cancellation_threshold,
                timelock,
                proposers: &proposer_pubkeys,
                approvers: &approver_pubkeys,
            });

            let client = rpc::client(config);
            let sig = rpc::send_instruction(&client, config, ix)?;

            print_json(&serde_json::json!({
                "txid": sig.to_string(),
                "wallet": wallet.to_string(),
                "vault": vault.to_string(),
            }));
        }
        WalletAction::AddChain {
            wallet: wallet_name,
            chain,
            dwallet_program,
            grpc_url,
            existing_dwallet_pubkey,
            existing_dwallet_addr,
            force_curve25519,
        } => {
            let chain_kind = parse_chain_kind(&chain)?;
            let dwallet_program_pk: Pubkey = dwallet_program
                .parse()
                .with_context(|| format!("invalid dWallet program ID: {dwallet_program}"))?;

            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());
            let (wallet_addr, _) = clear_wallet_client::pda::find_wallet_address(&wallet_name, &pid);
            let wallet_pubkey = Pubkey::new_from_array(wallet_addr.to_bytes());

            // Verify the wallet exists before doing anything Ika-side.
            let client = rpc::client(config);
            let _wallet_data = rpc::fetch_account(&client, &wallet_pubkey)
                .with_context(|| format!("wallet `{wallet_name}` not found on-chain"))?;

            // Wait for the dWallet program's coordinator (mock auto-init).
            ika::wait_for_coordinator(&client, &dwallet_program_pk, Duration::from_secs(30))
                .with_context(|| "dWallet program coordinator not initialized")?;
            eprintln!("✓ dWallet program ready");

            let (curve, _algo, scheme) = ika::signing_params(chain_kind, force_curve25519);
            let curve_val = ika::curve_u16(curve);
            let scheme_u16 = scheme as u16;
            eprintln!("→ Using curve: {curve:?} (u16={curve_val})");

            // 1. DKG (or skip if BYO dWallet).
            //
            // The "dwallet address" returned by DKG is a 32-byte session
            // identifier the Ika network uses to look up the dWallet's
            // key material in its internal store — it's NOT a hash of the
            // pubkey, and we cannot reconstruct it from the pubkey alone.
            // For the BYO path we recover it by reading any existing
            // `IkaConfig` PDA on this wallet that already references the
            // same dWallet PDA, and copying its `user_pubkey` field
            // (which the prior `add-chain` populated with the real
            // session identifier from the original DKG).
            let (dwallet_addr_bytes, dwallet_public_key) = if let Some(hex_pk) = existing_dwallet_pubkey {
                let pk = parse_hex(&hex_pk)?;
                eprintln!("→ Using existing dWallet pubkey ({} bytes)", pk.len());
                let (target_dwallet_pda, _) =
                    ika::dwallet_pda(&dwallet_program_pk, curve_val, &pk);

                // Resolve the 32-byte Ika session id. Prefer the explicit
                // `--existing-dwallet-addr` if provided; otherwise scan the
                // current wallet's other IkaConfigs for one that already
                // binds this dWallet and copy its `user_pubkey` field.
                let addr = if let Some(addr_hex) = existing_dwallet_addr {
                    let bytes = parse_hex(&addr_hex)?;
                    if bytes.len() != 32 {
                        return Err(anyhow!(
                            "--existing-dwallet-addr must be exactly 32 bytes (64 hex chars), got {}",
                            bytes.len()
                        ));
                    }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&bytes);
                    eprintln!("  ↳ session id from --existing-dwallet-addr: {}", hex_encode(&a));
                    a
                } else {
                    let mut found: Option<[u8; 32]> = None;
                    for probe_kind in 1u8..=4 {
                        if probe_kind == chain_kind {
                            continue;
                        }
                        let (cfg_pk, _) =
                            ika::ika_config_pda(&program_id, &wallet_pubkey, probe_kind);
                        let Some(cfg_data) = rpc::fetch_account_optional(&client, &cfg_pk)? else {
                            continue;
                        };
                        let Ok(cfg) = accounts::parse_ika_config(&cfg_data) else {
                            continue;
                        };
                        if cfg.dwallet != target_dwallet_pda.to_string() {
                            continue;
                        }
                        let prior_addr = parse_hex(&cfg.user_pubkey)?;
                        if prior_addr.len() != 32 {
                            continue;
                        }
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&prior_addr);
                        eprintln!(
                            "  ↳ recovered session id from chain_kind={probe_kind} binding: {}",
                            hex_encode(&a)
                        );
                        found = Some(a);
                        break;
                    }
                    found.ok_or(anyhow!(
                        "no existing IkaConfig binds wallet `{wallet_name}` to dWallet \
                         {target_dwallet_pda} — cannot recover the Ika session identifier. \
                         Either run `wallet add-chain` for at least one chain_kind via DKG \
                         first, or pass `--existing-dwallet-addr <hex>` explicitly (read it \
                         from another wallet's `wallet chains` JSON)."
                    ))?
                };
                (addr, pk)
            } else {
                eprintln!("→ Running DKG via gRPC ({grpc_url})...");
                let dkg_result = ika::dkg(config, &grpc_url, curve)
                    .with_context(|| "Ika DKG failed")?;
                eprintln!("✓ DKG complete");
                eprintln!("  → dWallet address: {}", hex_encode(&dkg_result.dwallet_addr));
                eprintln!("  → dWallet pubkey:  {}", hex_encode(&dkg_result.public_key));

                // Persist the DKG attestation so `proposal execute` can use it
                // for the gRPC Sign request later.
                ika::save_attestation(
                    &wallet_name,
                    &dkg_result.attestation,
                )?;
                eprintln!("✓ Attestation saved");

                (dkg_result.dwallet_addr, dkg_result.public_key)
            };

            // 2. Resolve the dWallet PDA on-chain (mock auto-commits within ~5s).
            let (dwallet_pda, _) = ika::dwallet_pda(&dwallet_program_pk, curve_val, &dwallet_public_key);
            ika::poll_until(
                &client,
                &dwallet_pda,
                |d| d.len() > 2 && d[0] == 2,
                Duration::from_secs(20),
            )
            .with_context(|| "dWallet PDA never appeared on-chain after DKG")?;
            eprintln!("✓ dWallet on-chain: {dwallet_pda}");

            // 3. Transfer authority → clear-wallet's CPI authority PDA, but
            //    only if it isn't already there. Re-binding an existing
            //    dWallet to a *second* chain_kind (e.g. evm_1559_erc20 after
            //    evm_1559) hits this path with a dWallet whose authority has
            //    already been moved by a prior `add-chain` call — calling
            //    `transfer_ownership` again would fail with "missing required
            //    signature for instruction" because the payer is no longer
            //    the authority.
            let (cpi_auth_pk, cpi_auth_bump) = ika::cpi_authority_pda(&program_id);
            let (dwallet_ownership_pk, _) = ika::dwallet_ownership_pda(&program_id, &dwallet_pda);
            let payer_pubkey = solana_sdk::signer::Signer::pubkey(&config.payer);
            let dwallet_data = rpc::fetch_account(&client, &dwallet_pda)
                .with_context(|| "fetch dWallet account before transfer")?;
            let current_authority = accounts::parse_dwallet_authority(&dwallet_data)?;
            if current_authority == cpi_auth_pk {
                eprintln!("✓ Authority already → clear-wallet CPI PDA ({cpi_auth_pk}) — skipping transfer");
            } else if current_authority == payer_pubkey {
                let xfer_ix = crate::instructions::ika_transfer_ownership(
                    dwallet_program_pk,
                    payer_pubkey,
                    dwallet_pda,
                    cpi_auth_pk,
                );
                rpc::send_instruction(&client, config, xfer_ix)
                    .with_context(|| "transfer_ownership failed")?;
                eprintln!("✓ Authority → clear-wallet CPI PDA ({cpi_auth_pk})");
            } else {
                return Err(anyhow!(
                    "dWallet {dwallet_pda} is owned by {current_authority}, neither the payer \
                     ({payer_pubkey}) nor the clear-wallet CPI authority ({cpi_auth_pk}). \
                     This wallet was bound by someone else; cannot rebind."
                ));
            }

            // 4. On-chain bind_dwallet → creates the IkaConfig PDA.
            let (ika_config_pk, _) = ika::ika_config_pda(&program_id, &wallet_pubkey, chain_kind);
            // We store the dWallet's *DKG address* (not the curve public key)
            // in the IkaConfig.user_pubkey slot. Ika's `approve_message` treats
            // this field as an opaque 32-byte identifier (in upstream tests
            // it's literally `[0xCC; 32]`), and `proposal execute` later
            // needs it as `session_identifier_preimage` for the gRPC sign
            // request — which is the actual DKG address, not the pubkey.
            let user_pubkey = dwallet_addr_bytes;

            let bind_ix = crate::instructions::bind_dwallet(
                payer_pubkey,
                wallet_pubkey,
                ika_config_pk,
                dwallet_ownership_pk,
                dwallet_pda,
                cpi_auth_pk,
                dwallet_program_pk,
                chain_kind,
                user_pubkey,
                scheme_u16,
                cpi_auth_bump,
            );
            let bind_sig = rpc::send_instruction(&client, config, bind_ix)
                .with_context(|| "bind_dwallet failed")?;
            eprintln!("✓ IkaConfig: {ika_config_pk}");

            print_json(&serde_json::json!({
                "txid": bind_sig.to_string(),
                "wallet": wallet_pubkey.to_string(),
                "chain": chain,
                "chain_kind": chain_kind,
                "dwallet": dwallet_pda.to_string(),
                "dwallet_pubkey_hex": hex_encode(&dwallet_public_key),
                "ika_config": ika_config_pk.to_string(),
                "cpi_authority": cpi_auth_pk.to_string(),
            }));
        }

        WalletAction::Chains {
            wallet: wallet_name,
            dwallet_program: _,
        } => {
            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());
            let (wallet_addr, _) = clear_wallet_client::pda::find_wallet_address(&wallet_name, &pid);
            let wallet_pubkey = Pubkey::new_from_array(wallet_addr.to_bytes());

            let client = rpc::client(config);
            // Verify the wallet exists.
            let _wallet_data = rpc::fetch_account(&client, &wallet_pubkey)
                .with_context(|| format!("wallet `{wallet_name}` not found"))?;

            // Probe each known chain_kind for an IkaConfig PDA.
            let mut chains = Vec::new();
            for chain_kind in 0u8..=4 {
                let (cfg_pk, _) = ika::ika_config_pda(&program_id, &wallet_pubkey, chain_kind);
                if let Some(data) = rpc::fetch_account_optional(&client, &cfg_pk)? {
                    if let Ok(cfg) = accounts::parse_ika_config(&data) {
                        // Read the underlying DWallet account so we can show the
                        // real curve-native pubkey (33 bytes for secp256k1) and
                        // derive a chain-native sender address (e.g. EVM 0x...).
                        let dwallet_pk = cfg
                            .dwallet
                            .parse::<Pubkey>()
                            .with_context(|| "ika_config.dwallet is not a valid pubkey")?;
                        let mut entry = serde_json::json!({
                            "chain":            chain_kind_name(chain_kind),
                            "chain_kind":       chain_kind,
                            "ika_config":       cfg_pk.to_string(),
                            "dwallet":          cfg.dwallet,
                            "user_pubkey_hex":  cfg.user_pubkey,
                            "signature_scheme": cfg.signature_scheme,
                        });
                        if let Some(dw_data) =
                            rpc::fetch_account_optional(&client, &dwallet_pk)?
                        {
                            if let Ok(dw) = accounts::parse_dwallet(&dw_data) {
                                let pk_hex = dw
                                    .public_key
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<String>();
                                entry["secp256k1_pubkey_hex"] =
                                    serde_json::Value::String(pk_hex);
                                // Solana dWallet: 32-byte Ed25519 pubkey IS the Solana address.
                                if chain_kind == 0 && dw.public_key.len() == 32 {
                                    let sol_addr = solana_sdk::pubkey::Pubkey::new_from_array(
                                        dw.public_key[..32].try_into().unwrap()
                                    );
                                    entry["solana_address"] =
                                        serde_json::Value::String(sol_addr.to_string());
                                }
                                if dw.public_key.len() == 33 {
                                    match chain_kind {
                                        // 1 = evm_1559, 4 = evm_1559_erc20 — both use the
                                        // standard EOA derivation `keccak256(uncompressed)[12..]`.
                                        1 | 4 => {
                                            if let Ok(addr) = accounts::evm_address_from_secp256k1(
                                                &dw.public_key,
                                            ) {
                                                entry["evm_address"] =
                                                    serde_json::Value::String(addr);
                                            }
                                        }
                                        // 2 = bitcoin_p2wpkh — emit both mainnet (`bc1q...`)
                                        // and testnet (`tb1q...`) addresses since the on-chain
                                        // dWallet itself is network-agnostic; the per-tx network
                                        // is selected at signing time via the intent template.
                                        2 => {
                                            if let Ok(addr) = accounts::bitcoin_p2wpkh_address(
                                                &dw.public_key,
                                                "bc",
                                            ) {
                                                entry["btc_p2wpkh_mainnet"] =
                                                    serde_json::Value::String(addr);
                                            }
                                            if let Ok(addr) = accounts::bitcoin_p2wpkh_address(
                                                &dw.public_key,
                                                "tb",
                                            ) {
                                                entry["btc_p2wpkh_testnet"] =
                                                    serde_json::Value::String(addr);
                                            }
                                        }
                                        // 3 = zcash_transparent
                                        3 => {
                                            if let Ok(addr) = accounts::zcash_transparent_address(
                                                &dw.public_key,
                                                true,
                                            ) {
                                                entry["zcash_t_addr_mainnet"] =
                                                    serde_json::Value::String(addr);
                                            }
                                            if let Ok(addr) = accounts::zcash_transparent_address(
                                                &dw.public_key,
                                                false,
                                            ) {
                                                entry["zcash_t_addr_testnet"] =
                                                    serde_json::Value::String(addr);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        chains.push(entry);
                    }
                }
            }
            print_json(&serde_json::json!({
                "wallet": wallet_pubkey.to_string(),
                "chains": chains,
            }));
        }

        WalletAction::Show { name } => {
            let program_id = crate::instructions::program_id();
            let pid = solana_address::Address::new_from_array(program_id.to_bytes());
            let (wallet_addr, _) = clear_wallet_client::pda::find_wallet_address(&name, &pid);
            let wallet = Pubkey::new_from_array(wallet_addr.to_bytes());

            let client = rpc::client(config);
            let data = rpc::fetch_account(&client, &wallet)?;
            let account = crate::accounts::parse_wallet(&data)?;

            let (vault_addr, _) = clear_wallet_client::pda::find_vault_address(&wallet_addr, &pid);

            print_json(&serde_json::json!({
                "address": wallet.to_string(),
                "vault": Pubkey::new_from_array(vault_addr.to_bytes()).to_string(),
                "name": account.name,
                "proposal_index": account.proposal_index,
                "intent_index": account.intent_index,
            }));
        }
    }
    Ok(())
}
