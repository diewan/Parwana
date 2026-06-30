//! Cross-chain transfer command implementation (Phase 5 Compliant)
//!
//! Uses only csv-sdk runtime APIs - no direct chain adapter dependencies.
//! Lease management is delegated to csv-runtime.

use anyhow::Result;

use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_sdk::CsvClient;

use crate::config::{Chain, Config};
use crate::output;
use crate::state::{TransferRecord, TransferStatus, UnifiedStateManager};

use super::to_protocol_chain;
use crate::wallet_identity::WalletIdentity;

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

    // Parse sanad ID using canonical parser
    let sanad_id_parsed = SanadId::parse_hex(&sanad_id)
        .map_err(|e| anyhow::anyhow!("Invalid Sanad ID: {}", e))?;
    let sanad_id_hash = Hash::new(*sanad_id_parsed.as_bytes());

    // Check if we have the sanad
    if state.get_sanad(&sanad_id_hash.to_hex()).is_none() {
        return Err(anyhow::anyhow!(
            "Sanad {} not found in local state",
            sanad_id_hash
        ));
    }

    // Get destination owner address using centralized identity resolver
    let dest_owner_str = if dest_owner.is_none() {
        if state.storage.wallet.mnemonic.is_some() {
            let identity = WalletIdentity::from_state(state)?;
            Some(identity.address(&to, 0, 0)?)
        } else {
            state.get_address(&to).map(|s| s.to_string())
        }
    } else {
        dest_owner
    };

    let Some(dest_addr) = dest_owner_str else {
        return Err(anyhow::anyhow!(
            "No destination address specified and no wallet address found for {:?}",
            to_chain
        ));
    };

    // Check chain capabilities before executing transfer
    // Create a minimal client for capability checks
    let mut sdk_config_check = csv_sdk::config::Config::default();
    
    // Add source chain config for capability check
    if let Some(from_chain_config) = config.chain(&from).ok() {
        let chain_config = csv_sdk::config::ChainConfig {
            rpc: csv_sdk::config::RpcConfig {
                url: from_chain_config.rpc_url.clone(),
                api_key: None,
                timeout_ms: 30000,
                max_retries: 3,
            },
            finality_depth: from_chain_config.finality_depth as u32,
            enabled: true,
            xpub: None,
            seed: None,
            contract_address: from_chain_config.contract_address.clone(),
            program_id: from_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        };
        sdk_config_check.chains.insert(from.to_string(), chain_config);
    }

    // Add destination chain config for capability check
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
            seed: None,
            contract_address: to_chain_config.contract_address.clone(),
            program_id: to_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        };
        sdk_config_check.chains.insert(to.to_string(), chain_config);
    }

    let check_client = CsvClient::builder()
        .with_chain(from_chain.clone())
        .with_chain(to_chain.clone())
        .with_config(sdk_config_check)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client for capability check: {}", e))?;

    let runtime = check_client.chain_runtime();

    // Check source chain can be cross-chain source
    let from_readiness = runtime
        .check_readiness(from_chain.clone(), 0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check source chain readiness: {}", e))?;

    if !from_readiness.cross_chain_source_supported {
        output::error(&format!(
            "Chain {:?} cannot be used as cross-chain transfer source",
            from_chain
        ));
        return Err(anyhow::anyhow!(
            "Cross-chain transfer not supported: source chain lacks capability"
        ));
    }

    // Check destination chain can be cross-chain destination
    let to_readiness = runtime
        .check_readiness(to_chain.clone(), 0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check destination chain readiness: {}", e))?;

    if !to_readiness.cross_chain_destination_supported {
        output::error(&format!(
            "Chain {:?} cannot be used as cross-chain transfer destination",
            to_chain
        ));
        return Err(anyhow::anyhow!(
            "Cross-chain transfer not supported: destination chain lacks capability"
        ));
    }

    output::success("Chain capability checks passed");

    // Create client builder with source and destination chains
    // Build SDK config from CLI config
    let mut sdk_config = csv_sdk::config::Config::default();

    // Add source chain config
    if let Some(from_chain_config) = config.chain(&from).ok() {
        // Include UTXOs from wallet state for Bitcoin
        let utxos = if from.as_str() == "bitcoin" {
            state
                .storage
                .wallet
                .utxos
                .iter()
                .map(|u| csv_sdk::config::UtxoConfig {
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value: u.value,
                    account: u.account,
                    index: u.index,
                    script_pubkey: u.script_pubkey.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };

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
            seed: (from.as_str() == "bitcoin")
                .then(|| {
                    WalletIdentity::from_state(state).map(|identity| identity.bitcoin_seed_hex())
                })
                .transpose()?,
            contract_address: from_chain_config.contract_address.clone(),
            program_id: from_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos,
            sanad_seals: state
                .storage
                .wallet
                .sanad_seals
                .iter()
                .map(|s| csv_sdk::config::SanadSealConfig {
                    sanad_id: s.sanad_id.clone(),
                    anchor_txid: s.anchor_txid.clone(),
                    vout: s.vout,
                })
                .collect(),
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
            seed: (to.as_str() == "bitcoin")
                .then(|| {
                    WalletIdentity::from_state(state).map(|identity| identity.bitcoin_seed_hex())
                })
                .transpose()?,
            contract_address: to_chain_config.contract_address.clone(),
            program_id: to_chain_config.program_id.clone(),
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        };
        sdk_config.chains.insert(to.to_string(), chain_config);
    }

    let identity = WalletIdentity::from_state(state)?;
    let private_keys = identity.signing_map(&[(&from, 0, 0), (&to, 0, 0)], state)?;

    let client = CsvClient::builder()
        .with_chain(from_chain.clone())
        .with_chain(to_chain.clone())
        .with_config(sdk_config)
        .with_private_keys(private_keys)
        .with_runtime_coordinator()
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create CSV client: {}", e))?;

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

    // Update local Sanad store: mark source Sanad as consumed
    if let Err(e) = state.consume_sanad(&sanad_id_hash.to_hex()) {
        log::warn!(
            "Failed to mark source Sanad as consumed in local store: {}",
            e
        );
    }

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
