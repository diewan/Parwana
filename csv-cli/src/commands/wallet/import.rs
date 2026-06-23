//! Wallet import from mnemonic phrase.
//!
//! Imports a mnemonic phrase (from csv-wallet or other source) and derives
//! all chain accounts using BIP-86 derivation for Bitcoin. The mnemonic is stored
//! in encrypted unified state and remains the single signing authority.

use crate::config::{Chain, Config, Network};
use crate::output;
use crate::state::UnifiedStateManager;
use crate::wallet_identity::WalletIdentity;
use anyhow::Result;
use csv_hash::chain_id::ChainId;
use csv_keys::bip39::Mnemonic;
use csv_store::state::WalletAccount;

/// Import wallet from mnemonic phrase.
pub fn cmd_import(
    phrase: &str,
    _network: Network,
    account: u32,
    _config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    output::header("Importing Wallet from Mnemonic");

    // Validate and parse mnemonic
    let _mnemonic = Mnemonic::from_phrase(phrase)
        .map_err(|e| anyhow::anyhow!("Invalid mnemonic phrase: {}", e))?;

    output::success("Mnemonic validated");

    let identity = WalletIdentity::from_mnemonic(phrase)?;

    output::info("Deriving addresses for all chains...");

    let mut imported = 0u32;
    for core_chain in ["bitcoin", "ethereum", "sui", "aptos", "solana"]
        .into_iter()
        .map(ChainId::new)
    {
        let identity_chain = Chain::new(core_chain.as_str());
        let address = identity.address(&identity_chain, account, 0)?;

        // Get coin type for derivation path
        let coin_type = match core_chain.to_string().as_str() {
            "bitcoin" => "0",
            "ethereum" => "60",
            "sui" => "784",
            "aptos" => "637",
            "solana" => "501",
            _ => "0",
        };
        let purpose = if core_chain.as_str() == "bitcoin" {
            86
        } else {
            44
        };
        let derivation_path = format!("m/{}'/{}'/{}'/0/0", purpose, coin_type, account);

        // Store account
        let store_chain = match core_chain.to_string().as_str() {
            "bitcoin" => ChainId::new("bitcoin"),
            "ethereum" => ChainId::new("ethereum"),
            "sui" => ChainId::new("sui"),
            "aptos" => ChainId::new("aptos"),
            "solana" => ChainId::new("solana"),
            _ => ChainId::new("bitcoin"),
        };

        state.set_account(WalletAccount {
            id: format!("imported-{}", store_chain),
            chain: store_chain.clone(),
            name: format!("{} Account (imported)", store_chain),
            address: address.clone(),
            keystore_ref: None,
            xpub: None,
            derivation_path: Some(derivation_path),
        });

        output::success(&format!("{}: {}", store_chain, address));
        imported += 1;
    }

    // Store mnemonic in encrypted unified storage.
    state.storage.wallet.mnemonic = Some(phrase.to_string());

    // Save state
    state.save()?;

    output::success(&format!("Imported {} chain accounts", imported));
    output::info("Wallet imported successfully. The mnemonic is encrypted in unified state.");

    Ok(())
}
