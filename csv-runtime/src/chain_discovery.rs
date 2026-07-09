//! Chain discovery for dynamic adapter loading
//!
//! This module provides chain discovery functionality that allows the runtime
//! to dynamically discover and load chain adapters based on configuration files
//! rather than compile-time feature flags.

use crate::adapter_registry::AdapterRegistryImpl;
use csv_hash::chain_id::ChainId;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// Error type for chain discovery operations
#[derive(Debug, thiserror::Error)]
pub enum ChainDiscoveryError {
    /// RwLock was poisoned due to a panic while holding the lock
    #[error("RwLock poisoned: {0}")]
    LockPoisoned(String),
    /// IO error during file operations
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// TOML parsing error
    #[error("TOML parsing error: {0}")]
    TomlParse(String),
}

/// Chain discovery service
///
/// Discovers available chains from configuration and provides
/// chain-specific adapter instances on demand.
pub struct ChainDiscovery {
    /// Registry of available adapters
    #[allow(dead_code)]
    adapter_registry: Arc<RwLock<AdapterRegistryImpl>>,
    /// Chain configurations
    chain_configs: Arc<RwLock<HashMap<ChainId, ChainConfig>>>,
}

/// Chain configuration from TOML file
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain identifier (e.g., "bitcoin-signet", "ethereum-sepolia")
    pub id: String,
    /// Chain name for display
    pub name: String,
    /// Default network
    pub network: String,
    /// RPC endpoint URLs
    pub rpc_urls: Vec<String>,
    /// Block explorer URLs
    pub block_explorer_urls: Vec<String>,
    /// Start block
    pub start_block: u64,
    /// Contract address (if applicable)
    pub contract_address: Option<String>,
    /// Whether this chain is enabled
    pub enabled: bool,
}

// serde default for the `enabled` field; called by the deserializer, not by us.
#[allow(dead_code)]
fn default_enabled() -> bool {
    true
}

// serde default; called by the deserializer, not by us.
#[allow(dead_code)]
fn default_network() -> String {
    "mainnet".to_string()
}

impl ChainDiscovery {
    /// Create a new chain discovery service
    ///
    /// # Arguments
    /// * `adapter_registry` - Registry of available adapters
    pub fn new(adapter_registry: Arc<RwLock<AdapterRegistryImpl>>) -> Self {
        Self {
            adapter_registry,
            chain_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a chain configuration
    ///
    /// # Arguments
    /// * `config` - The chain configuration
    pub fn register_chain(&self, config: ChainConfig) -> Result<(), ChainDiscoveryError> {
        let chain_id = ChainId::new(&config.id);
        let mut configs = self
            .chain_configs
            .write()
            .map_err(|e| ChainDiscoveryError::LockPoisoned(e.to_string()))?;
        configs.insert(chain_id, config);
        Ok(())
    }

    /// Get configuration for a chain
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// The chain configuration if found
    pub fn get_config(
        &self,
        chain_id: &ChainId,
    ) -> Result<Option<ChainConfig>, ChainDiscoveryError> {
        let configs = self
            .chain_configs
            .read()
            .map_err(|e| ChainDiscoveryError::LockPoisoned(e.to_string()))?;
        Ok(configs.get(chain_id).cloned())
    }

    /// Get the primary RPC URL for a chain
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// The first RPC URL if available
    pub fn get_rpc_url(&self, chain_id: &ChainId) -> Result<Option<String>, ChainDiscoveryError> {
        let configs = self
            .chain_configs
            .read()
            .map_err(|e| ChainDiscoveryError::LockPoisoned(e.to_string()))?;
        Ok(configs
            .get(chain_id)
            .and_then(|config| config.rpc_urls.first().cloned()))
    }

    /// Get all available chain configurations
    ///
    /// # Returns
    /// Iterator over all chain configurations
    pub fn all_configs(&self) -> Result<Vec<ChainConfig>, ChainDiscoveryError> {
        let configs = self
            .chain_configs
            .read()
            .map_err(|e| ChainDiscoveryError::LockPoisoned(e.to_string()))?;
        Ok(configs.values().cloned().collect())
    }

    /// Get all enabled chain IDs
    ///
    /// # Returns
    /// Iterator over enabled chain IDs
    pub fn enabled_chains(&self) -> Result<Vec<ChainId>, ChainDiscoveryError> {
        let configs = self
            .chain_configs
            .read()
            .map_err(|e| ChainDiscoveryError::LockPoisoned(e.to_string()))?;
        Ok(configs
            .iter()
            .filter(|(_, config)| config.enabled)
            .map(|(chain_id, _)| chain_id.clone())
            .collect())
    }

    /// Check if a chain is available and enabled
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// True if the chain is available and enabled
    pub fn is_chain_enabled(&self, chain_id: &ChainId) -> Result<bool, ChainDiscoveryError> {
        let configs = self
            .chain_configs
            .read()
            .map_err(|e| ChainDiscoveryError::LockPoisoned(e.to_string()))?;
        Ok(configs
            .get(chain_id)
            .map(|config| config.enabled)
            .unwrap_or(false))
    }

    /// Load chain configurations from a directory of TOML files
    ///
    /// # Arguments
    /// * `directory` - Path to directory containing chain TOML files
    ///
    /// # Returns
    /// Number of chains loaded
    pub fn load_from_directory(&self, directory: &Path) -> Result<usize, ChainDiscoveryError> {
        let chains_dir = directory;

        if !chains_dir.exists() {
            return Err(ChainDiscoveryError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Chains directory '{}' does not exist", chains_dir.display()),
            )));
        }

        let entries = std::fs::read_dir(chains_dir)?;
        let mut count = 0;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                // Parse TOML file and register chain
                match self.load_from_toml(&path) {
                    Ok(config) => {
                        self.register_chain(config)?;
                        count += 1;
                    }
                    Err(e) => {
                        eprintln!("Failed to load chain config from {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(count)
    }

    /// Load chain configuration from a TOML file
    ///
    /// # Arguments
    /// * `path` - Path to TOML file
    ///
    /// # Returns
    /// Parsed chain configuration
    pub fn load_from_toml(&self, path: &Path) -> Result<ChainConfig, ChainDiscoveryError> {
        let content = std::fs::read_to_string(path)?;
        let value: toml::Value =
            toml::from_str(&content).map_err(|e| ChainDiscoveryError::TomlParse(e.to_string()))?;

        // Extract fields manually to avoid complex nested structure deserialization
        let id = value
            .get("chain_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainDiscoveryError::TomlParse("Missing chain_id".to_string()))?
            .to_string();

        let name = value
            .get("chain_name")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        let network = value
            .get("default_network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet")
            .to_string();

        let rpc_urls = value
            .get("rpc_endpoints")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let block_explorer_urls = value
            .get("block_explorer_urls")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let start_block = value
            .get("start_block")
            .and_then(|v| v.as_integer())
            .unwrap_or(0) as u64;

        // Try to get contract_address from top level or custom_settings
        let contract_address = value
            .get("contract_address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                value
                    .get("custom_settings")
                    .and_then(|v| v.as_table())
                    .and_then(|table| table.get("contract_address"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });

        let enabled = value
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(ChainConfig {
            id,
            name,
            network,
            rpc_urls,
            block_explorer_urls,
            start_block,
            contract_address,
            enabled,
        })
    }
}

impl Default for ChainDiscovery {
    fn default() -> Self {
        Self {
            adapter_registry: Arc::new(RwLock::new(AdapterRegistryImpl::new())),
            chain_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
