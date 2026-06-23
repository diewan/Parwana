//! Wallet generation for all chains (Phase 5 Compliant).
//!
//! Uses csv-wallet for unified wallet abstraction.
//! Mnemonics and private keys are encrypted with user passphrase.

//! To add a new chain:
//! Add coin_type to csv-keys/src/bip44.rs:coin_type()
//! Add to derive_all_chain_keys() list in bip44.rs
//! Add address derivation to derive_address_from_key() in bip44.rs
//! Same mnemonic automatically derives keys for the new chain

use crate::config::{Chain, Config, Network};
use crate::output;
use crate::state::UnifiedStateManager;
use crate::wallet_identity::WalletIdentity;
use anyhow::Result;
use std::collections::HashMap;

use csv_keys::{Mnemonic, MnemonicType};
/// Initialize wallet with one-command setup.
pub fn cmd_init(
    network: Network,
    words: u8,
    account: u32,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("CSV Wallet Initialization");
    output::info("Setting up your cross-chain wallet...");

    // Step 1: Generate mnemonic
    let mnemonic = generate_mnemonic(words)?;
    output::success(&format!("Generated {}-word mnemonic", words));
    output::info("Write this mnemonic down securely. It is your wallet recovery phrase.");
    println!();
    output::kv("Mnemonic phrase", &mnemonic);
    println!();

    // Step 2: Generate wallets for all supported chains
    let mut addresses = HashMap::new();

    for chain in [
        Chain::new("bitcoin"),
        Chain::new("ethereum"),
        Chain::new("sui"),
        Chain::new("aptos"),
        Chain::new("solana"),
    ] {
        output::info(&format!("Generating {} wallet...", chain));
        let address = generate_wallet_for_chain(&chain, &network, &mnemonic, account, state)?;
        addresses.insert(chain.clone(), address.clone());
        output::success(&format!("{} wallet generated", chain));
    }

    // Step 3: Save configuration
    output::info("Saving wallet configuration...");
    state.storage.wallet.mnemonic = Some(mnemonic.clone());
    save_wallet_config(&mnemonic, &addresses, config)?;
    output::success("Configuration saved");

    // Step 4: Summary
    output::header("Wallet Setup Complete! Ready to build!");
    output::info("Your wallet addresses:");
    for (chain, address) in &addresses {
        output::info(&format!("  {}: {}", chain, address));
    }

    if account > 0 {
        output::info(&format!(
            "Bitcoin account index: {} (BIP-86 path: m/86'/0'/{}'/0/0)",
            account, account
        ));
    }

    output::warning("Store your mnemonic phrase securely. It can recover all your keys.");
    output::info("Check balances with: csv wallet balance --chain <chain>");
    output::info("Fund your wallets using chain faucets or exchanges");

    output::success("Start building: csv sanad create --chain bitcoin --value 100000");

    Ok(())
}

/// Generate a single wallet for a specific chain.
///
/// This requires an existing mnemonic from `wallet init` or `wallet import`.
/// It derives the account from the encrypted wallet mnemonic.
pub fn cmd_generate(
    chain: Chain,
    network: Network,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    match chain.as_str() {
        "bitcoin" => generate_bitcoin(network, state),
        "ethereum" => generate_from_mnemonic(&chain, network, state),
        "sui" => generate_from_mnemonic(&chain, network, state),
        "aptos" => generate_from_mnemonic(&chain, network, state),
        "solana" => generate_from_mnemonic(&chain, network, state),
        _ => Err(anyhow::anyhow!("Unknown chain: {}", chain)),
    }
}

/// Generate BIP-39 mnemonic phrase using keystore runtime.
fn generate_mnemonic(words: u8) -> Result<String> {
    // Phase 5: Use keystore's BIP-39 implementation
    let mnemonic_type = if words >= 24 {
        MnemonicType::Words24
    } else if words >= 12 {
        MnemonicType::Words12
    } else {
        MnemonicType::Words24
    };

    let mnemonic = Mnemonic::generate(mnemonic_type);
    Ok(mnemonic.as_str().to_string())
}

/// Generate wallet for a specific chain from the canonical mnemonic.
fn generate_wallet_for_chain(
    chain: &Chain,
    _network: &Network,
    mnemonic: &str,
    account: u32,
    state: &mut UnifiedStateManager,
) -> Result<String> {
    let identity = WalletIdentity::from_mnemonic(mnemonic)?;
    let address = identity.address(chain, account, 0)?;

    // Store in state with derivation path
    let (purpose, coin_type) = match chain.as_str() {
        "bitcoin" => ("86", "0"),
        "ethereum" => ("44", "60"),
        "sui" => ("44", "784"),
        "aptos" => ("44", "637"),
        "solana" => ("44", "501"),
        _ => ("44", "0"),
    };
    let derivation_path = format!("m/{}/{}'/{}'/0/0", purpose, coin_type, account);
    state.store_address_with_derivation(chain.clone(), address.clone(), Some(derivation_path));
    if let Some(account_record) = state.storage.wallet.get_account_mut(chain) {
        account_record.keystore_ref = None;
    }

    Ok(address)
}

// Individual chain generators (derive from existing mnemonic)

fn generate_bitcoin(network: Network, state: &mut UnifiedStateManager) -> Result<()> {
    // Check if mnemonic exists
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No mnemonic found. Run 'csv wallet init' first to generate a mnemonic.")
    })?;

    let identity = WalletIdentity::from_mnemonic(mnemonic_phrase)?;
    let seed_array = *identity.seed();

    // Derive BIP-86 xpub (safe to share, can derive addresses but not spend)
    use csv_keys::bip39::{BitcoinNetwork, derive_xpub};
    let bitcoin_network = match network {
        Network::Main => BitcoinNetwork::Mainnet,
        Network::Test => BitcoinNetwork::Signet,
        Network::Dev => BitcoinNetwork::Regtest,
    };
    let xpub = derive_xpub(&seed_array, bitcoin_network, 0)
        .map_err(|e| anyhow::anyhow!("Failed to derive xpub: {}", e))?;

    let address = identity.address(&Chain::new("bitcoin"), 0, 0)?;

    // Store address in state
    state.store_address(Chain::new("bitcoin"), address.clone());

    output::header("Bitcoin Wallet Generated");
    output::kv("Network", &network.to_string());
    output::kv("Address", &address);
    output::kv("Derivation Path", "m/86'/1'/0'/0/0 (BIP-86 Taproot)");
    output::kv("Xpub", &xpub);

    println!();
    output::info("Wallet derived from your existing mnemonic.");

    Ok(())
}

/// Generate a wallet for a specific chain from the existing mnemonic.
fn generate_from_mnemonic(
    chain: &Chain,
    _network: Network,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    // Check if mnemonic exists
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No mnemonic found. Run 'csv wallet init' first to generate a mnemonic.")
    })?;

    let identity = WalletIdentity::from_mnemonic(mnemonic_phrase)?;
    let address = identity.address(chain, 0, 0)?;

    // Store address in state with derivation path
    let (purpose, coin_type) = match chain.as_str() {
        "ethereum" => ("44", "60"),
        "sui" => ("44", "784"),
        "aptos" => ("44", "637"),
        "solana" => ("44", "501"),
        _ => ("44", "0"),
    };
    let derivation_path = format!("m/{}/{}'/0'/0/0", purpose, coin_type);
    state.store_address_with_derivation(
        chain.clone(),
        address.clone(),
        Some(derivation_path.clone()),
    );
    if let Some(account_record) = state.storage.wallet.get_account_mut(chain) {
        account_record.keystore_ref = None;
    }

    output::header(&format!("{} Wallet Generated", chain));
    output::kv("Address", &address);
    output::kv("Derivation Path", &derivation_path);

    println!();
    output::info("Wallet derived from your existing mnemonic.");
    output::info("The encrypted wallet mnemonic is the single signing authority.");

    Ok(())
}

fn save_wallet_config(
    mnemonic: &str,
    addresses: &HashMap<Chain, String>,
    _config: &Config,
) -> Result<()> {
    use csv_keys::bip39::Mnemonic as Bip39Mnemonic;
    use csv_keys::bip39::{BitcoinNetwork, derive_xpub};

    // Derive seed from mnemonic
    let mnemonic_obj = Bip39Mnemonic::from_phrase(mnemonic)
        .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;
    let seed = mnemonic_obj.to_seed(None);

    // Load existing config to preserve other settings
    let config_path = expand_path("~/.csv/config.toml");
    let mut config_data = if std::path::Path::new(&config_path).exists() {
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    // Derive and save Bitcoin xpub
    if addresses.contains_key(&Chain::new("bitcoin")) {
        let xpub = derive_xpub(seed.as_bytes(), BitcoinNetwork::Testnet, 0)
            .map_err(|e| anyhow::anyhow!("Failed to derive xpub: {}", e))?;

        // Add or update [wallets.bitcoin] section
        let wallet_section = format!("[wallets.bitcoin]\nxpub = \"{}\"\n", xpub);

        if config_data.contains("[wallets.bitcoin]") {
            // Replace existing section
            let Some(start) = config_data.find("[wallets.bitcoin]") else {
                return Err(anyhow::anyhow!(
                    "wallets.bitcoin section disappeared while updating config"
                ));
            };
            let end = config_data[start..]
                .find("\n[")
                .map(|i| i + start + 1)
                .unwrap_or(config_data.len());
            config_data.replace_range(start..end, &wallet_section);
        } else {
            // Append new section
            if !config_data.ends_with('\n') {
                config_data.push('\n');
            }
            config_data.push_str(&wallet_section);
        }
    }

    // Write updated config
    std::fs::create_dir_all(expand_path("~/.csv"))?;
    std::fs::write(&config_path, &config_data)?;

    output::info(&format!("Saved {} wallet addresses", addresses.len()));
    output::info(&format!("Configuration saved to {}", config_path));
    Ok(())
}

/// Expand ~ to home directory
fn expand_path(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(stripped).to_string_lossy().to_string();
    }
    path.to_string()
}
