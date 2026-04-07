use crate::config::{PersistedConfig, config_path};
use crate::error::*;
use crate::signing::MessageSigner;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Set a configuration value
    Set {
        /// RPC URL
        #[arg(long)]
        url: Option<String>,
        /// Path to payer keypair
        #[arg(long)]
        payer: Option<String>,
        /// Path to signer keypair
        #[arg(long)]
        signer: Option<String>,
        /// Use Ledger as signer
        #[arg(long)]
        signer_ledger: bool,
        /// Default message expiry in seconds from now (default: 300 = 5 minutes)
        #[arg(long)]
        expiry_seconds: Option<u64>,
        /// Ledger derivation account index (e.g. 10 for m/44'/501'/10')
        #[arg(long)]
        ledger_account: Option<u32>,
    },
    /// Show current configuration
    Show,
}

pub fn handle(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Set { url, payer, signer, signer_ledger, expiry_seconds, ledger_account } => {
            let mut config = PersistedConfig::load();
            if let Some(url) = url { config.rpc_url = url; }
            if let Some(payer) = payer { config.payer = payer; }
            if let Some(signer) = signer {
                config.signer = signer;
                config.signer_type = crate::config::SignerType::Keypair;
            }
            if signer_ledger {
                config.signer_type = crate::config::SignerType::Ledger;
            }
            if let Some(seconds) = expiry_seconds {
                config.expiry_seconds = seconds;
            }
            if let Some(account) = ledger_account {
                config.ledger_account = Some(account);
            }
            config.save()?;
            let json = serde_json::to_string_pretty(&config)?;
            println!("{json}");
        }
        ConfigAction::Show => {
            let config = PersistedConfig::load();
            let mut output = serde_json::to_value(&config)?;
            output["config_path"] = serde_json::Value::String(config_path().to_string_lossy().to_string());

            // Resolve and display payer pubkey
            if let Ok(payer) = crate::config::load_keypair_public(&config.payer) {
                output["payer_pubkey"] = serde_json::Value::String(payer);
            }

            // Resolve and display signer pubkey (keypair only; ledger requires device)
            match config.signer_type {
                crate::config::SignerType::Keypair => {
                    if let Ok(signer) = crate::config::load_keypair_public(&config.signer) {
                        output["signer_pubkey"] = serde_json::Value::String(signer);
                    }
                }
                crate::config::SignerType::Ledger => {
                    match crate::signing::LedgerMessageSigner::new(config.ledger_account) {
                        Ok(signer) => {
                            output["signer_pubkey"] = serde_json::Value::String(
                                bs58::encode(signer.pubkey()).into_string(),
                            );
                        }
                        Err(_) => {
                            output["signer_pubkey"] = serde_json::Value::String(
                                "(ledger not available — connect device to resolve)".into(),
                            );
                        }
                    }
                }
            }

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    Ok(())
}
