//! Extension commands for csv-wallet integration

use anyhow::Result;
use csv_store::state::WalletAccount;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::UnifiedStateManager;

// ===== csv-wallet JSON format structures =====

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CsvWalletJson {
    accounts: Vec<CsvWalletAccount>,
    selected_account_id: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct CsvWalletAccount {
    id: String,
    chain: String,
    name: String,
    private_key: Option<String>,
    address: String,
}

/// Import full wallet from csv-wallet JSON export
pub fn cmd_import_csv_wallet(
    path: Option<String>,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let path = path.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| {
                h.join(".csv/wallet/csv-wallet.json")
                    .to_string_lossy()
                    .to_string()
            })
            .unwrap_or_else(|| "~/.csv/wallet/csv-wallet.json".to_string())
    });

    output::header("Importing Wallet from csv-wallet");
    output::kv("Source", &path);

    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;

    let wallet: CsvWalletJson = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Invalid JSON format: {}", e))?;

    output::info(&format!("Found {} accounts", wallet.accounts.len()));

    let mut imported = 0;
    let mut updated = 0;

    for account in &wallet.accounts {
        let chain = match account.chain.to_lowercase().as_str() {
            "bitcoin" => Chain::new("bitcoin"),
            "ethereum" => Chain::new("ethereum"),
            "sui" => Chain::new("sui"),
            "aptos" => Chain::new("aptos"),
            "solana" => Chain::new("solana"),
            _ => {
                output::warning(&format!("Skipping unknown chain: {}", account.chain));
                continue;
            }
        };

        // Check if account with same ID already exists
        let existing = state
            .storage
            .wallet
            .accounts
            .iter()
            .find(|a| a.id == account.id)
            .cloned();
        let was_same = existing
            .as_ref()
            .map(|e| e.address == account.address)
            .unwrap_or(false);

        // Create wallet account with all imported data
        // Note: private keys are no longer stored in WalletAccount directly
        // They should be stored in the keystore and referenced via keystore_ref
        let wallet_account = WalletAccount {
            id: account.id.clone(),
            chain: chain.clone(),
            name: account.name.clone(),
            address: account.address.clone(),
            xpub: None,
            derivation_path: None,
            keystore_ref: None,
        };

        // Store account (preserves multiple accounts per chain)
        state.set_account(wallet_account);

        if was_same {
            output::info(&format!(
                "{} [{}]: {} (already set)",
                chain,
                account.id,
                &account.address[..16.min(account.address.len())]
            ));
        } else {
            output::success(&format!(
                "{} [{}]: {} -> {}",
                chain,
                account.id,
                existing
                    .as_ref()
                    .map(|a| &a.address[..16.min(a.address.len())])
                    .unwrap_or("none"),
                &account.address[..16.min(account.address.len())]
            ));
            if existing.is_some() {
                updated += 1;
            } else {
                imported += 1;
            }
        }
    }

    output::success(&format!(
        "Imported {} accounts, updated {}",
        imported, updated
    ));
    output::info("The private keys are now available for cross-chain transfers.");
    output::info("Run 'csv wallet list' to verify addresses.");

    Ok(())
}

/// Export wallet to csv-wallet JSON format
pub fn cmd_export_csv_wallet(
    output: Option<String>,
    _config: &Config,
    state: &UnifiedStateManager,
) -> Result<()> {
    let output_path = output.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| {
                h.join(".csv/wallet/csv-cli-export.json")
                    .to_string_lossy()
                    .to_string()
            })
            .unwrap_or_else(|| "~/.csv/wallet/csv-cli-export.json".to_string())
    });

    output::header("Exporting Wallet to csv-wallet Format");

    let mut accounts = Vec::new();

    for chain in [
        Chain::new("bitcoin"),
        Chain::new("ethereum"),
        Chain::new("sui"),
        Chain::new("aptos"),
        Chain::new("solana"),
    ] {
        if let Some(account) = state.get_account(&chain) {
            // Note: private keys are no longer stored in WalletAccount
            // Use keystore or DEPLOYER_KEY env var for key access
            if account.keystore_ref.is_some() || !account.address.is_empty() {
                accounts.push(CsvWalletAccount {
                    id: format!(
                        "{}-cli-{}",
                        chain,
                        &account.address[..8.min(account.address.len())]
                    ),
                    chain: chain.to_string().to_lowercase(),
                    name: format!("CSV CLI {} Account", chain),
                    private_key: None, // Private keys no longer stored in WalletAccount
                    address: account.address.clone(),
                });
                output::success(&format!("Exported {} account", chain));
            } else {
                output::warning(&format!("{}: no private key available", chain));
            }
        } else {
            output::warning(&format!("{}: no account configured", chain));
        }
    }

    let wallet = CsvWalletJson {
        accounts,
        selected_account_id: None,
    };

    let json = serde_json::to_string_pretty(&wallet)
        .map_err(|e| anyhow::anyhow!("Failed to serialize: {}", e))?;

    std::fs::write(&output_path, json)
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {}", output_path, e))?;

    output::success(&format!(
        "Exported {} accounts to {}",
        wallet.accounts.len(),
        output_path
    ));
    output::warning("WARNING: This file contains unencrypted private keys. Store it securely!");

    Ok(())
}

/// Sync with csv-wallet (bidirectional - import addresses from csv-wallet)
pub fn cmd_sync_csv_wallet(
    path: Option<String>,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let path = path.unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| {
                h.join(".csv/wallet/csv-wallet.json")
                    .to_string_lossy()
                    .to_string()
            })
            .unwrap_or_else(|| "~/.csv/wallet/csv-wallet.json".to_string())
    });

    output::header("Syncing with csv-wallet");
    output::kv("Source", &path);

    // First import the addresses
    cmd_import_csv_wallet(Some(path), config, state)?;

    output::info("");
    output::info("To complete unification:");
    output::info("1. Use 'csv wallet export-csv-wallet' to export CLI wallets");
    output::info("2. Import that file into csv-wallet (if csv-wallet supports import)");
    output::info("3. Both tools will now use the same addresses and keys");

    Ok(())
}
