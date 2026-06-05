//! Cross-chain transfer command implementation (Phase 5 Compliant)
//!
//! Uses only csv-sdk runtime APIs - no direct chain adapter dependencies.
//! Lease management is delegated to csv-runtime.

use anyhow::Result;

use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_sdk::CsvClient;
use csv_sdk::prelude::NetworkType;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::{TransferRecord, TransferStatus, UnifiedStateManager};

use super::to_protocol_chain;

/// Execute cross-chain transfer using only runtime API
pub async fn cmd_transfer(
    from: Chain,
    to: Chain,
    sanad_id: String,
    dest_owner: Option<String>,
    finality_depth: Option<u64>,
    config: &Config,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let from_chain = to_protocol_chain(from.clone());
    let to_chain = to_protocol_chain(to.clone());

    output::header(&format!(
        "Cross-Chain Transfer: {:?} → {:?}",
        from_chain, to_chain
    ));

    // Parse sanad ID
    let bytes = hex::decode(sanad_id.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    if bytes.len() < 32 {
        return Err(anyhow::anyhow!(
            "Invalid Sanad ID: expected at least 32 bytes, got {} bytes",
            bytes.len()
        ));
    }
    let mut sanad_bytes = [0u8; 32];
    sanad_bytes.copy_from_slice(&bytes[..32]);
    let sanad_id_hash = Hash::new(sanad_bytes);

    // Check if we have the sanad
    if state.get_sanad(&sanad_id_hash.to_hex()).is_none() {
        return Err(anyhow::anyhow!(
            "Sanad {} not found in local state",
            sanad_id_hash
        ));
    }

    // Get destination owner address
    let dest_owner_str = dest_owner.or_else(|| state.get_address(&from).map(|s| s.to_string()));

    let Some(dest_addr) = dest_owner_str else {
        return Err(anyhow::anyhow!(
            "No destination address specified and no wallet address found for {:?}",
            to_chain
        ));
    };

    // Create client builder with source and destination chains
    // Build SDK config from CLI config
    let mut sdk_config = csv_sdk::config::Config::default();
    
    // Add source chain config
    if let Some(from_chain_config) = config.chain(&from).ok() {
        let chain_config = csv_sdk::config::ChainConfig {
            rpc: csv_sdk::config::RpcConfig {
                url: from_chain_config.rpc_url.clone(),
                api_key: None,
                timeout_ms: 30000,
                max_retries: 3,
            },
            finality_depth: finality_depth.unwrap_or(from_chain_config.finality_depth) as u32,
            enabled: true,
            xpub: None,
            contract_address: from_chain_config.contract_address.clone(),
            program_id: from_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: state.storage.wallet.sanad_seals.iter().map(|s| csv_sdk::config::SanadSealConfig {
                sanad_id: s.sanad_id.clone(),
                anchor_txid: s.anchor_txid.clone(),
                vout: s.vout,
            }).collect(),
        };
        sdk_config.chains.insert(from.to_string(), chain_config);
    }
    
    // Add destination chain config
    if let Some(to_chain_config) = config.chain(&to).ok() {
        let chain_config = csv_sdk::config::ChainConfig {
            rpc: csv_sdk::config::RpcConfig {
                url: to_chain_config.rpc_url.clone(),
                api_key: None,
                timeout_ms: 30000,
                max_retries: 3,
            },
            finality_depth: to_chain_config.finality_depth as u32,
            enabled: true,
            xpub: None,
            contract_address: to_chain_config.contract_address.clone(),
            program_id: to_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        };
        sdk_config.chains.insert(to.to_string(), chain_config);
    }
    
    let client = CsvClient::builder()
        .with_chain(from_chain.clone())
        .with_chain(to_chain.clone())
        .with_config(sdk_config)
        .with_runtime_coordinator()
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

    // Initialize chain adapters for the transfer
    // Get network type from config
    let network_type = match config.chain(&from)?.network {
        crate::config::Network::Test => NetworkType::Testnet,
        crate::config::Network::Main => NetworkType::Mainnet,
        crate::config::Network::Dev => NetworkType::Testnet, // Dev uses testnet
    };

    // Derive private keys from wallet mnemonic for chains that require signing
    let mnemonic_phrase = state.storage.wallet.mnemonic.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No wallet mnemonic found. Initialize or import a wallet first.")
    })?;

    let mnemonic = csv_keys::Mnemonic::from_phrase(mnemonic_phrase)
        .map_err(|e| anyhow::anyhow!("Invalid stored mnemonic: {}", e))?;
    let seed = mnemonic.to_seed(None);
    let seed_array = *seed.as_bytes();

    let mut private_keys = std::collections::HashMap::new();

    // Derive private key for source chain
    let from_key_hex = if from.as_str() == "bitcoin" {
        hex::encode(seed_array)
    } else {
        let (secret_key, _) = signing_key_for_chain(&from, 0, &seed_array, state)?;
        hex::encode(secret_key.as_bytes())
    };
    private_keys.insert(from.to_string(), Some(from_key_hex));

    // Derive private key for destination chain
    let to_key_hex = if to.as_str() == "bitcoin" {
        hex::encode(seed_array)
    } else {
        let (secret_key, _) = signing_key_for_chain(&to, 0, &seed_array, state)?;
        hex::encode(secret_key.as_bytes())
    };
    private_keys.insert(to.to_string(), Some(to_key_hex));

    // Note: SDK already initializes adapters via bitcoin_from_config with loaded UTXOs
    // Do NOT call init_adapters here as it would replace the adapters with fresh wallets

    // Execute the real cross-chain transfer via runtime
    output::info(&format!(
        "Locking Sanad {} on {:?}",
        sanad_id_hash, from_chain
    ));
    let sanad = SanadId(sanad_id_hash);
    let transfer_id = client
        .transfers()
        .cross_chain(sanad, to_chain.clone())
        .to_address(dest_addr.clone())
        .from_chain(from_chain.clone())
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("Transfer execution failed: {}", e))?;

    output::success(&format!(
        "Transfer {} initiated. Sanad locked on source chain.",
        transfer_id
    ));

    // Clone for use in record after get_address call
    let from_chain_clone = from.clone();
    let sender = state.get_address(&from).map(|s| s.to_string());

    // Record transfer in state
    let transfer_record = TransferRecord {
        id: transfer_id.clone(),
        source_chain: from_chain_clone,
        dest_chain: to,
        sanad_id: sanad_id_hash.to_string(),
        sender_address: sender,
        destination_address: Some(dest_addr),
        source_tx_hash: None,
        source_fee: None,
        dest_tx_hash: None,
        dest_fee: None,
        destination_contract: None,
        proof: None,
        status: TransferStatus::Initiated,
        created_at: chrono::Utc::now().timestamp() as u64,
        completed_at: None,
    };

    state.add_transfer(transfer_record);

    output::success(&format!(
        "Transfer {} recorded in local state.",
        transfer_id
    ));

    Ok(())
}

/// Generate deterministic transfer ID
fn generate_transfer_id(sanad_id: &Hash, from: &Chain, to: &Chain) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(sanad_id.as_bytes());
    hasher.update(from.to_string().as_bytes());
    hasher.update(to.to_string().as_bytes());
    hasher.update(chrono::Utc::now().timestamp().to_le_bytes());

    format!("0x{}", hex::encode(hasher.finalize()))
}

fn signing_key_for_chain(
    chain: &Chain,
    account: u32,
    seed_array: &[u8; 64],
    state: &UnifiedStateManager,
) -> Result<(csv_keys::memory::SecretKey, &'static str)> {
    // Try keystore first for all chains (not just Aptos)
    if let Some(secret_key) = load_keystore_key(chain, account, state)? {
        return Ok((secret_key, "keystore"));
    }

    let mut keys = csv_keys::bip44::derive_all_chain_keys(seed_array, account);
    let core_chain = csv_hash::ChainId::new(chain.as_str());
    let secret_key = keys
        .remove(&core_chain)
        .ok_or_else(|| anyhow::anyhow!("Failed to derive key for chain: {}", chain))?;

    Ok((secret_key, "mnemonic-derived"))
}

fn load_keystore_key(
    chain: &Chain,
    account: u32,
    state: &UnifiedStateManager,
) -> Result<Option<csv_keys::memory::SecretKey>> {
    let mut key_ids = Vec::new();
    if let Some(wallet_account) = state.get_account(chain) {
        if let Some(keystore_ref) = &wallet_account.keystore_ref {
            key_ids.push(keystore_ref.clone());
        }
    }
    key_ids.push(format!("{}-{}", chain.as_str(), account));

    let mut keystore = csv_keys::file_keystore::FileKeystore::new(None)?;
    let passphrase = csv_keys::memory::Passphrase::new(state.passphrase().to_string());

    for key_id in key_ids {
        match keystore.retrieve_key(&key_id, &passphrase) {
            Ok(secret_key) => return Ok(Some(secret_key)),
            Err(csv_keys::file_keystore::FileKeystoreError::KeyNotFound(_)) => {}
            Err(csv_keys::file_keystore::FileKeystoreError::InvalidPassphrase) => {
                // Key exists but wrong passphrase - fall back to mnemonic derivation
                log::warn!("Keystore key '{}' exists but decryption failed (wrong passphrase), falling back to mnemonic derivation", key_id);
            }
            Err(e) => return Err(anyhow::anyhow!("Failed to load key '{}': {}", key_id, e)),
        }
    }

    Ok(None)
}
