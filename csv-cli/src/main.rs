//! CSV Adapter CLI — Cross-Chain Sanads, Proofs, Wallets, and End-to-End Testing
//!
//! ```bash
//! # Chain management
//! csv chain list
//! csv chain status --chain bitcoin
//! csv chain config --chain ethereum
//!
//! # Wallet operations (encrypted mnemonics)
//! csv wallet init
//! csv wallet generate --chain bitcoin --network signet
//! csv wallet balance --chain bitcoin
//!
//! # Sanad operations
//! csv sanad create --chain bitcoin --value 100000

#![allow(deprecated)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::type_complexity)]
#![allow(clippy::bind_instead_of_map)]
#![allow(clippy::useless_format)]
#![allow(clippy::match_result_ok)]
//! csv sanad transfer --chain bitcoin --sanad-id 0x... --to bcrt1...
//! csv sanad consume --chain bitcoin --sanad-id 0x...
//! csv sanad list --chain bitcoin
//!
//! # Proof operations
//! csv proof generate --chain bitcoin --sanad-id 0x...
//! csv proof verify --chain sui --proof-file proof.json
//!
//! # Cross-chain transfers (pick a mode explicitly)
//! csv cross-chain materialize --from bitcoin --to sui --sanad-id 0x...   # on-chain mint
//! csv cross-chain send --from bitcoin --sanad-id 0x... --invoice <blob>  # interactive off-chain
//! csv cross-chain status --transfer-id 0x...
//!
//! # Contract deployment
//! csv contract deploy --chain sui --network testnet
//! csv contract status --chain ethereum
//!
//! # End-to-end tests
//! csv test run --chain-pair bitcoin:sui
//! csv test run-all
//! ```

use clap::{Parser, Subcommand};

mod commands;
mod config;
mod output;
mod state;
mod wallet_identity;

use commands::*;
use config::Config;
use state::UnifiedStateManager;

// Import chain management commands
use commands::chain_management::ChainCommands;

/// CLI version from Cargo.toml - single source of truth
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "csv",
    about = "CSV Adapter CLI — Cross-Chain Sanads, Proofs, and Transfers",
    version = VERSION,
    long_about = None
)]
struct Cli {
    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Emit canonical CBOR (hex) instead of pretty JSON where applicable
    #[arg(long, global = true)]
    canonical: bool,

    /// Emit proof DAG / Merkle tree structure for proof commands
    #[arg(long, global = true)]
    proof_tree: bool,

    /// Configuration file path
    #[arg(short = 'C', long, global = true, default_value = "~/.csv/config.toml")]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ─── Chain Management ───
    /// List all supported chains
    Chain {
        #[command(subcommand)]
        action: ChainAction,
    },
    /// Chain discovery and configuration management
    ChainManagement {
        #[command(subcommand)]
        action: ChainCommands,
    },

    // ─── Wallet Operations ───
    /// Wallet management (encrypted mnemonic generation and balance)
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    // ─── Sanad Operations ───
    /// Sanad lifecycle (create, transfer, consume, list, show)
    Sanad {
        #[command(subcommand)]
        action: SanadAction,
    },

    // ─── Proof Operations ───
    /// Proof generation and verification
    Proof {
        #[command(subcommand)]
        action: ProofAction,
    },

    // ─── Cross-Chain Transfers ───
    /// Cross-chain Sanad transfers
    #[command(name = "cross-chain")]
    CrossChain {
        #[command(subcommand)]
        action: CrossChainAction,
    },

    // ─── Contract Deployment ───
    /// Contract deployment and management
    Contract {
        #[command(subcommand)]
        action: ContractAction,
    },

    // ─── Seal Operations ───
    /// Seal management (create, consume, verify)
    Seal {
        #[command(subcommand)]
        action: SealAction,
    },

    // ─── End-to-End Testing ───
    /// Run end-to-end tests
    Test {
        #[command(subcommand)]
        action: TestAction,
    },

    // ─── Validation ───
    /// Validate consignments and proofs
    Validate {
        #[command(subcommand)]
        action: ValidateAction,
    },

    /// Protocol inspection (replay registry, Merkle proofs)
    Inspect {
        #[command(subcommand)]
        action: commands::inspect::InspectAction,
    },

    /// Schema registry tooling
    Schema {
        #[command(subcommand)]
        action: commands::schema_cmd::SchemaAction,
    },

    // ─── Content Management ───
    /// Content tree management and selective disclosure
    Content {
        #[command(subcommand)]
        action: commands::content::ContentAction,
    },

    // ─── Runtime Monitoring ───
    /// Runtime monitoring and diagnostics
    Runtime {
        #[command(subcommand)]
        action: commands::runtime::RuntimeAction,
    },

    // ─── Trust Management ───
    /// Trust anchor and trust package management
    Trust {
        #[command(subcommand)]
        action: commands::trust::TrustAction,
    },
}

use commands::chain::ChainAction;
use commands::contracts::ContractAction;
use commands::cross_chain::CrossChainAction;
use commands::proofs::ProofAction;
use commands::sanads::SanadAction;
use commands::seals::SealAction;
use commands::tests::TestAction;
use commands::validate::ValidateAction;
use commands::wallet::WalletAction;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "warn" };
    unsafe { std::env::set_var("RUST_LOG", log_level) };
    env_logger::init();

    // Load configuration
    let config = Config::load(cli.config.as_deref())?;
    // Commands that do not read wallet/display state must remain non-interactive
    // and must not rewrite the encrypted state file. This is important for
    // monitoring/automation and avoids turning a read-only chain query into an
    // unrelated passphrase/state-write failure.
    let needs_state = matches!(
        &cli.command,
        Commands::Wallet { .. }
            | Commands::Sanad { .. }
            | Commands::Proof { .. }
            | Commands::CrossChain { .. }
            | Commands::Contract { .. }
            | Commands::Seal { .. }
            | Commands::Test { .. }
            | Commands::Validate { .. }
    );
    let mut state = if needs_state {
        let passphrase = UnifiedStateManager::prompt_passphrase()?;
        Some(UnifiedStateManager::load(&passphrase)?)
    } else {
        None
    };

    // Dispatch commands
    let result = match cli.command {
        Commands::Chain { action } => chain::execute(action, &config).await,
        Commands::ChainManagement { action } => chain_management::ChainCommands::execute(&action)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e)),
        Commands::Wallet { action } => {
            wallet::execute(action, &config, required_state_mut(&mut state)?).await
        }
        Commands::Sanad { action } => {
            sanads::execute(
                action,
                &config,
                required_state_mut(&mut state)?,
                cli.canonical,
            )
            .await
        }
        Commands::Proof { action } => {
            proofs::execute(
                action,
                &config,
                required_state(&state)?,
                cli.canonical,
                cli.proof_tree,
            )
            .await
        }
        Commands::CrossChain { action } => {
            cross_chain::execute(action, &config, required_state_mut(&mut state)?).await
        }
        Commands::Contract { action } => {
            contracts::execute(action, &config, required_state_mut(&mut state)?)
        }
        Commands::Seal { action } => {
            seals::execute(action, &config, required_state_mut(&mut state)?).await
        }
        Commands::Test { action } => tests::execute(action, &config, required_state(&state)?),
        Commands::Validate { action } => {
            validate::execute(action, &config, required_state(&state)?)
        }
        Commands::Inspect { action } => commands::inspect::execute(action),
        Commands::Schema { action } => commands::schema_cmd::execute(action),
        Commands::Content { action } => commands::content::execute(action, &config),
        Commands::Runtime { action } => commands::runtime::execute(action, &config),
        Commands::Trust { action } => commands::trust::execute(action, &config),
    };

    if let Some(state) = state {
        state.save()?;
    }

    result
}

fn required_state(state: &Option<UnifiedStateManager>) -> anyhow::Result<&UnifiedStateManager> {
    state
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("internal error: command requires CLI state"))
}

fn required_state_mut(
    state: &mut Option<UnifiedStateManager>,
) -> anyhow::Result<&mut UnifiedStateManager> {
    state
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("internal error: command requires CLI state"))
}
