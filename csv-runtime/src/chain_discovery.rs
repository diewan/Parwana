//! Chain discovery for dynamic adapter loading
//!
//! This module provides chain discovery functionality that allows the runtime
//! to dynamically discover and load chain adapters based on configuration files
//! rather than compile-time feature flags.

use crate::adapter_registry::AdapterRegistryImpl;
use csv_hash::chain_id::ChainId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Chain discovery service
///
/// Discovers available chains from configuration and provides
/// chain-specific adapter instances on demand.
pub struct ChainDiscovery {
    /// Registry of available adapters
    adapter_registry: Arc<RwLock<AdapterRegistryImpl>>,
    /// Chain configurations
    chain_configs: Arc<RwLock<HashMap<ChainId, ChainConfig>>>,
}

/// Chain configuration
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Chain identifier (e.g., "bitcoin", "ethereum")
    pub id: String,
    /// Chain name for display
    pub name: String,
    /// Network type (mainnet, testnet, devnet)
    pub network: String,
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Contract address (if applicable)
    pub contract_address: Option<String>,
    /// Whether this chain is enabled
    pub enabled: bool,
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
    pub fn register_chain(&self, config: ChainConfig) {
        let chain_id = ChainId::new(&config.id);
        self.chain_configs.write().unwrap().insert(chain_id, config);
    }

    /// Get configuration for a chain
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// The chain configuration if found
    pub fn get_config(&self, chain_id: &ChainId) -> Option<ChainConfig> {
        self.chain_configs.read().unwrap().get(chain_id).cloned()
    }

    /// Get all available chain configurations
    ///
    /// # Returns
    /// Iterator over all chain configurations
    pub fn all_configs(&self) -> Vec<ChainConfig> {
        self.chain_configs.read().unwrap().values().cloned().collect()
    }

    /// Get all enabled chain IDs
    ///
    /// # Returns
    /// Iterator over enabled chain IDs
    pub fn enabled_chains(&self) -> Vec<ChainId> {
        self.chain_configs
            .read()
            .unwrap()
            .iter()
            .filter(|(_, config)| config.enabled)
            .map(|(chain_id, _)| chain_id.clone())
            .collect()
    }

    /// Check if a chain is available and enabled
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// True if the chain is available and enabled
    pub fn is_chain_enabled(&self, chain_id: &ChainId) -> bool {
        self.chain_configs
            .read()
            .unwrap()
            .get(chain_id)
            .map(|config| config.enabled)
            .unwrap_or(false)
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
