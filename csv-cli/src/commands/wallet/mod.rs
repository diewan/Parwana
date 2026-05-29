//! Wallet management commands — encrypted mnemonic management only.

pub mod balance;
pub mod export;
pub mod generate;
pub mod import;
pub mod private_key;
pub mod types;

pub use types::WalletAction;

use crate::config::Config;
use crate::output;
use crate::state::UnifiedStateManager;
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
            phrase,
            network,
            account,
        } => import::cmd_import(&phrase, network, account, config, state),
        WalletAction::Export => export::cmd_export(config, state),
        WalletAction::Generate { chain, network } => {
            generate::cmd_generate(chain, network, config, state)
        }
        WalletAction::Balance { chain, address } => {
            balance::cmd_balance(chain, address, config, state).await
        }
        WalletAction::List { chain, account, index } => {
            balance::cmd_list(chain, account, index, config, state)
        }
        WalletAction::PrivateKey { chain } => private_key::cmd_private_key(chain, config, state),
        WalletAction::Address { chain, account, index } => {
            cmd_address(chain, account, index, config, state).await
        }
        WalletAction::Scan { chain, account, gap_limit } => {
            cmd_scan(chain, account, gap_limit, config, state).await
        }
    }
}

async fn cmd_address(
    chain: crate::config::Chain,
    account: u32,
    index: u32,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Funding Address for {}", chain));

    // Derive seed from wallet mnemonic
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
    })?;

    let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
        .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(None);
    let seed_array = *seed.as_bytes();

    match chain.as_str() {
        "bitcoin" => {
            // Use csv-coordinator for wallet operations (architecture compliant)
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::bitcoin::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::bitcoin::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::bitcoin::Network::Dev,
            };
            let address = csv_coordinator::wallet::bitcoin::derive_funding_address(
                &seed_array,
                network,
                account,
                index,
            ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

            output::kv("Address", &address);
            output::kv("Account", &account.to_string());
            output::kv("Index", &index.to_string());
            output::kv("Derivation Path", &format!("m/86'/1'/{}'/0/{}", account, index));
            output::info("Send Bitcoin to this address, then run 'csv wallet scan --chain bitcoin' to discover UTXOs.");
        }
        "ethereum" => {
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::ethereum::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::ethereum::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::ethereum::Network::Dev,
            };
            let address = csv_coordinator::wallet::ethereum::derive_funding_address(
                &seed_array,
                network,
                account,
                index,
            ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

            output::kv("Address", &address);
            output::kv("Account", &account.to_string());
            output::kv("Index", &index.to_string());
            output::kv("Derivation Path", &format!("m/44'/60'/{}'/0/{}", account, index));
        }
        "sui" => {
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::sui::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::sui::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::sui::Network::Dev,
            };
            let address = csv_coordinator::wallet::sui::derive_funding_address(
                &seed_array,
                network,
                account,
                index,
            ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

            output::kv("Address", &address);
            output::kv("Account", &account.to_string());
            output::kv("Index", &index.to_string());
            output::kv("Derivation Path", &format!("m/44'/784'/{}'/0/{}", account, index));
        }
        "aptos" => {
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::aptos::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::aptos::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::aptos::Network::Dev,
            };
            let address = csv_coordinator::wallet::aptos::derive_funding_address(
                &seed_array,
                network,
                account,
                index,
            ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

            output::kv("Address", &address);
            output::kv("Account", &account.to_string());
            output::kv("Index", &index.to_string());
            output::kv("Derivation Path", &format!("m/44'/637'/{}'/0/{}", account, index));
        }
        "solana" => {
            let network = match config.chain(&chain)?.network {
                crate::config::Network::Main => csv_coordinator::wallet::solana::Network::Main,
                crate::config::Network::Test => csv_coordinator::wallet::solana::Network::Test,
                crate::config::Network::Dev => csv_coordinator::wallet::solana::Network::Dev,
            };
            let address = csv_coordinator::wallet::solana::derive_funding_address(
                &seed_array,
                network,
                account,
                index,
            ).map_err(|e| anyhow::anyhow!("Failed to derive address: {}", e))?;

            output::kv("Address", &address);
            output::kv("Account", &account.to_string());
            output::kv("Index", &index.to_string());
            output::kv("Derivation Path", &format!("m/44'/501'/{}'/0/{}", account, index));
        }
        _ => {
            output::info(&format!("Funding address for {} is not yet implemented.", chain));
        }
    }

    Ok(())
}

async fn cmd_scan(
    chain: crate::config::Chain,
    account: u32,
    gap_limit: usize,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header(&format!("Scanning Wallet for UTXOs on {}", chain));

    if chain.as_str() == "bitcoin" {
        output::info("Scanning Bitcoin wallet for UTXOs...");
        output::kv("Account", &account.to_string());
        output::kv("Gap limit", &gap_limit.to_string());

        // Derive seed from wallet mnemonic
        let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
            anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
        })?;

        let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
            .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
        let seed = mnemonic.to_seed(None);
        let seed_array = *seed.as_bytes();

        // Get RPC URL
        let rpc_url = config.chain(&chain)?.rpc_url.clone();

        // Use csv-coordinator for wallet operations (architecture compliant)
        let network = match config.chain(&chain)?.network {
            crate::config::Network::Main => csv_coordinator::wallet::bitcoin::Network::Main,
            crate::config::Network::Test => csv_coordinator::wallet::bitcoin::Network::Test,
            crate::config::Network::Dev => csv_coordinator::wallet::bitcoin::Network::Dev,
        };
        let (_wallet, wallet_utxos) = csv_coordinator::wallet::bitcoin::scan_utxos_with_wallet(
            &seed_array,
            network,
            account,
            gap_limit,
            &rpc_url,
        ).await.map_err(|e| anyhow::anyhow!("Failed to scan UTXOs: {}", e))?;

        // Clear old UTXOs for this account before adding new ones
        state.storage.wallet.utxos.retain(|u| u.account != account);

        let mut total_utxos = 0;
        let mut total_value = 0u64;

        for utxo in wallet_utxos {
            output::kv(&format!("  UTXO {}:{} ({} sats)", &utxo.txid[..16], utxo.vout, utxo.value), "");

            // Add UTXO to unified state for persistence with script_pubkey
            let utxo_record = csv_store::state::wallet::UtxoRecord {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                value: utxo.value,
                account,
                index: 0, // TODO: track actual index from derivation_path
                derivation_path: format!("m/86'/1'/{}'/0/0", account),
                script_pubkey: utxo.scriptpubkey_hex,
            };
            state.storage.wallet.utxos.push(utxo_record);

            total_utxos += 1;
            total_value += utxo.value;
        }

        state.save()?;

        output::kv("Total UTXOs found", &total_utxos.to_string());
        output::kv("Total value", &format!("{} sats", total_value));

        if total_utxos > 0 {
            output::success("Wallet has UTXOs. You can now create a Sanad using 'csv sanad create --chain bitcoin'.");
        } else {
            output::info("No UTXOs found. Send Bitcoin to a wallet address first.");
        }
    } else {
        output::info(&format!("Wallet scanning for {} is not yet implemented.", chain));
    }

    Ok(())
}
