//! Chain Registry — Config-Driven Chain Addition
//!
//! This module provides a unified registry for chain configurations.
//! Chains are loaded from TOML config files and can be extended without
//! modifying core protocol code.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Network type for a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    /// UTXO-based chains (Bitcoin)
    Utxo,
    /// Account-based chains (Ethereum, Solana, Sui, Aptos)
    Account,
    /// Data availability layers (Celestia)
    DataAvailability,
}

/// Chain features configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFeatures {
    /// State model: Utxo or Account
    pub state_model: String,
    /// Finality model
    pub finality_model: String,
    /// Finality depth in blocks/epochs
    pub finality_depth: u64,
    /// Whether finality is deterministic
    pub deterministic_finality: bool,
    /// Proof model used for inclusion proofs
    pub proof_model: String,
    /// Replay protection mechanism
    pub replay_protection: String,
    /// Whether the chain has native single-use seal semantics
    pub native_single_use_semantics: bool,
    /// Reorg risk level
    pub reorg_risk: String,
    /// Maximum safe reorg depth
    pub max_safe_reorg_depth: u64,
    /// Whether light client proofs are supported
    pub supports_light_client_proofs: bool,
    /// Whether state proofs are supported
    pub supports_state_proofs: bool,
    /// Whether transaction inclusion proofs are supported
    pub supports_transaction_inclusion_proofs: bool,
    /// Whether offline verification is supported
    pub supports_offline_verification: bool,
    /// Whether ZK proofs are supported
    pub supports_zk_proofs: bool,
    /// Chain role: Settlement, Execution, DataAvailability, etc.
    pub chain_role: String,
}

impl Default for ChainFeatures {
    fn default() -> Self {
        Self {
            state_model: "Account".to_string(),
            finality_model: "FinalizedCheckpoint".to_string(),
            finality_depth: 1,
            deterministic_finality: true,
            proof_model: "MerklePatricia".to_string(),
            replay_protection: "SmartContractNullifier".to_string(),
            native_single_use_semantics: false,
            reorg_risk: "Low".to_string(),
            max_safe_reorg_depth: 12,
            supports_light_client_proofs: true,
            supports_state_proofs: true,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: true,
            supports_zk_proofs: true,
            chain_role: "Settlement".to_string(),
        }
    }
}

/// Finality guarantee configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityGuarantee {
    /// Maximum reorg depth
    pub max_reorg_depth: u64,
    /// Whether finality is probabilistic
    pub is_probabilistic: bool,
    /// Validator honesty threshold
    pub validator_honesty_threshold: f64,
    /// Proof system type
    pub proof_system: String,
    /// Maximum proof age in blocks
    pub max_proof_age_blocks: u64,
    /// Minimum anchor sources required
    pub min_anchor_sources: u64,
}

impl Default for FinalityGuarantee {
    fn default() -> Self {
        Self {
            max_reorg_depth: 12,
            is_probabilistic: false,
            validator_honesty_threshold: 0.67,
            proof_system: "EthereumPos".to_string(),
            max_proof_age_blocks: 100,
            min_anchor_sources: 1,
        }
    }
}

/// Wallet configuration for a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Default derivation path
    pub derivation_path: String,
    /// Signature scheme: secp256k1, ed25519, etc.
    pub signature_scheme: String,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            signature_scheme: "secp256k1".to_string(),
        }
    }
}

/// Full chain configuration loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Unique chain identifier
    pub chain_id: String,
    /// Human-readable chain name
    pub chain_name: String,
    /// Default network (testnet, mainnet, devnet)
    pub default_network: String,
    /// RPC endpoint URLs
    pub rpc_endpoints: Vec<String>,
    /// Block explorer URLs
    pub block_explorer_urls: Vec<String>,
    /// Starting block height
    pub start_block: u64,
    /// Network type
    pub network_type: NetworkType,
    /// Chain capabilities and features
    pub features: ChainFeatures,
    /// Finality guarantee settings
    pub finality_guarantee: FinalityGuarantee,
    /// Wallet configuration
    pub wallet: WalletConfig,
    /// Custom chain-specific settings
    pub custom_settings: HashMap<String, serde_json::Value>,
}

impl ChainConfig {
    /// Load a chain config from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self, anyhow::Error> {
        let content = fs::read_to_string(path)?;
        let config: ChainConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Get the RPC endpoint URL for a given network.
    pub fn rpc_url(&self, network: &str) -> Option<String> {
        // In production, this would select based on network
        self.rpc_endpoints.first().cloned()
    }

    /// Check if the chain supports a given feature.
    pub fn supports(&self, feature: &str) -> bool {
        match feature {
            "light_client_proofs" => self.features.supports_light_client_proofs,
            "state_proofs" => self.features.supports_state_proofs,
            "transaction_inclusion_proofs" => self.features.supports_transaction_inclusion_proofs,
            "offline_verification" => self.features.supports_offline_verification,
            "zk_proofs" => self.features.supports_zk_proofs,
            _ => false,
        }
    }
}

/// Chain registry — loads and manages chain configurations.
#[derive(Debug, Clone, Default)]
pub struct ChainRegistry {
    /// Loaded chain configurations keyed by chain_id
    chains: HashMap<String, ChainConfig>,
    /// Path to the config directory
    config_dir: Option<PathBuf>,
}

impl ChainRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load all chain configs from a directory.
    ///
    /// Expects TOML files in the directory. Files are parsed and registered
    /// using the `chain_id` field from each config.
    pub fn load_from_dir(dir: &Path) -> Result<Self, anyhow::Error> {
        let mut registry = Self::new();
        registry.config_dir = Some(dir.to_path_buf());

        if !dir.exists() {
            return Ok(registry);
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "toml")
                && let Ok(config) = ChainConfig::from_toml(&path)
            {
                registry.register_chain(config);
            }
        }

        Ok(registry)
    }

    /// Register a chain configuration.
    pub fn register_chain(&mut self, config: ChainConfig) {
        self.chains.insert(config.chain_id.clone(), config);
    }

    /// Get a chain configuration by ID.
    pub fn get_chain(&self, chain_id: &str) -> Option<&ChainConfig> {
        self.chains.get(chain_id)
    }

    /// Get all registered chain IDs.
    pub fn chain_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.chains.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get all registered chain configs.
    pub fn all_chains(&self) -> Vec<&ChainConfig> {
        let mut chains: Vec<&ChainConfig> = self.chains.values().collect();
        chains.sort_by_key(|c| c.chain_id.clone());
        chains
    }

    /// Check if a chain is registered.
    pub fn has_chain(&self, chain_id: &str) -> bool {
        self.chains.contains_key(chain_id)
    }

    /// Get the number of registered chains.
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_empty() {
        let registry = ChainRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = ChainRegistry::new();
        let config = ChainConfig {
            chain_id: "test-chain".to_string(),
            chain_name: "Test Chain".to_string(),
            default_network: "testnet".to_string(),
            rpc_endpoints: vec!["http://localhost:8545".to_string()],
            block_explorer_urls: vec![],
            start_block: 0,
            network_type: NetworkType::Account,
            features: ChainFeatures::default(),
            finality_guarantee: FinalityGuarantee::default(),
            wallet: WalletConfig::default(),
            custom_settings: HashMap::new(),
        };

        registry.register_chain(config);
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.has_chain("test-chain"));
        assert!(registry.get_chain("test-chain").is_some());
        assert!(registry.get_chain("nonexistent").is_none());
    }

    #[test]
    fn test_chain_supports_features() {
        let config = ChainConfig {
            chain_id: "test".to_string(),
            chain_name: "Test".to_string(),
            default_network: "testnet".to_string(),
            rpc_endpoints: vec![],
            block_explorer_urls: vec![],
            start_block: 0,
            network_type: NetworkType::Account,
            features: ChainFeatures {
                supports_zk_proofs: true,
                supports_light_client_proofs: false,
                ..ChainFeatures::default()
            },
            finality_guarantee: FinalityGuarantee::default(),
            wallet: WalletConfig::default(),
            custom_settings: HashMap::new(),
        };

        assert!(config.supports("zk_proofs"));
        assert!(!config.supports("light_client_proofs"));
        assert!(!config.supports("nonexistent_feature"));
    }
}
