//! Wallet management commands — encrypted mnemonic management only.

pub mod balance;
pub mod export;
pub mod generate;
pub mod import;
pub mod portable;
pub mod private_key;
pub mod types;

pub use types::WalletAction;

use crate::config::Config;
use crate::output;
use crate::state::UnifiedStateManager;
use crate::wallet_identity::WalletIdentity;
use anyhow::Result;

/// Execute wallet command.
pub async fn execute(
    action: WalletAction,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match action {
        WalletAction::Init {
            network,
            words,
            account,
        } => generate::cmd_init(network, words, account, config, state),
        WalletAction::Import {
            file,
            mode,
            account,
            force,
        } => import::cmd_import(&file, mode, account, force, config, state),
        WalletAction::ImportMnemonic { account, force } => {
            import::cmd_import_mnemonic(account, force, config, state)
        }
        WalletAction::Export { out, force } => export::cmd_export(&out, force, config, state),
        WalletAction::Generate { chain, network } => {
            generate::cmd_generate(chain, network, config, state)
        }
        WalletAction::Balance {
            chain,
            address,
            account,
            index,
        } => balance::cmd_balance(chain, address, account, index, config, state).await,
        WalletAction::List {
            chain,
            account,
            index,
        } => balance::cmd_list(chain, account, index, config, state),
        WalletAction::PrivateKey { chain } => private_key::cmd_private_key(chain, config, state),
        WalletAction::Address {
            chain,
            account,
            index,
        } => cmd_address(chain, account, index, config, state).await,
        WalletAction::Scan {
            chain,
            account,
            gap_limit,
        } => cmd_scan(chain, account, gap_limit, config, state).await,
    }
}

async fn cmd_address(
    chain: crate::config::Chain,
    account: u32,
    index: u32,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Funding Address for {}", chain));

    let identity = WalletIdentity::from_state(state)?;
    let address = identity.address(&chain, account, index)?;

    output::kv("Address", &address);
    output::kv("Account", &account.to_string());
    output::kv("Index", &index.to_string());

    // Show derivation path based on chain
    let derivation_path = match chain.as_str() {
        "bitcoin" => format!("m/86'/1'/{}'/0/{}", account, index),
        "ethereum" => format!("m/44'/60'/{}'/0/{}", account, index),
        "sui" => format!("m/44'/784'/{}'/0/{}", account, index),
        "aptos" => format!("m/44'/637'/{}'/0/{}", account, index),
        "solana" => format!("m/44'/501'/{}'/0/{}", account, index),
        _ => format!("m/44'/0'/{}'/0/{}", account, index),
    };
    output::kv("Derivation Path", &derivation_path);

    if chain.as_str() == "bitcoin" {
        output::info(
            "Send Bitcoin to this address, then run 'csv wallet scan --chain bitcoin' to discover UTXOs.",
        );
    }

    Ok(())
}

async fn cmd_scan(
    chain: crate::config::Chain,
    _account: u32,
    _gap_limit: usize,
    _config: &Config,
    _state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Scanning Wallet for UTXOs on {}", chain));

    // Chain-specific wallet operations should use csv-sdk, not direct adapter access
    output::error("Chain-specific wallet scanning is not available in csv-cli.");
    output::info("Use csv-sdk for chain-specific wallet operations:");
    output::info("  ```rust");
    output::info("  use csv_sdk::prelude::*;");
    output::info("  ");
    output::info(&format!(
        "  let client = CsvClient::builder().with_chain(\"{}\").build()?;",
        chain
    ));
    output::info("  ");
    output::info("  // Use client.wallet() for chain-specific operations");
    output::info("  ```");

    Ok(())
}
