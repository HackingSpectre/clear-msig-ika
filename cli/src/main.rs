mod commands;
mod config;
mod error;
mod signing;
mod accounts;
mod chains;
mod ika;
mod message;
mod params;
mod resolve;
mod instructions;
mod output;
mod quasar_client;
mod rpc;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "clear-msig", about = "Clear-sign multisig wallet CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// RPC URL (overrides config)
    #[arg(long, global = true)]
    url: Option<String>,

    /// Path to payer keypair (overrides config)
    #[arg(long, global = true)]
    keypair: Option<String>,

    /// Path to signer keypair for multisig messages (overrides config)
    #[arg(long, global = true)]
    signer: Option<String>,

    /// Use Ledger as signer (overrides config)
    #[arg(long, global = true)]
    signer_ledger: bool,

    /// Ledger derivation account index (overrides config, e.g. 10 for m/44'/501'/10')
    #[arg(long, global = true)]
    ledger_account: Option<u32>,
}

#[derive(Subcommand)]
enum Command {
    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        action: commands::config::ConfigAction,
    },
    /// Manage multisig wallets
    Wallet {
        #[command(subcommand)]
        action: commands::wallet::WalletAction,
    },
    /// Manage intents on a wallet
    Intent {
        #[command(subcommand)]
        action: commands::intent::IntentAction,
    },
    /// Manage proposals
    Proposal {
        #[command(subcommand)]
        action: commands::proposal::ProposalAction,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Config { action } => commands::config::handle(action),
        Command::Wallet { action } => {
            let cfg = config::load_config(&cli.url, &cli.keypair, &cli.signer, cli.signer_ledger, cli.ledger_account);
            commands::wallet::handle(action, &cfg)
        }
        Command::Intent { action } => {
            let cfg = config::load_config(&cli.url, &cli.keypair, &cli.signer, cli.signer_ledger, cli.ledger_account);
            commands::intent::handle(action, &cfg)
        }
        Command::Proposal { action } => {
            let cfg = config::load_config(&cli.url, &cli.keypair, &cli.signer, cli.signer_ledger, cli.ledger_account);
            commands::proposal::handle(action, &cfg)
        }
    };

    if let Err(err) = result {
        eprintln!("{{\n  \"error\": \"{err:?}\"\n}}");
        std::process::exit(1);
    }
}
