//! Generic wallet operations trait for chain-agnostic wallet functionality
//!
//! This module defines the `WalletOperations` trait that all chain adapters
//! must implement to provide wallet functionality. This enables config-driven
//! chain addition without modifying core wallet code.

use crate::error::{Result, WalletError};
use async_trait::async_trait;
use csv_hash::chain_id::ChainId;
use std::collections::HashMap;
use std::sync::Arc;

/// Generic wallet operations trait
///
/// All chain adapters must implement this trait to provide wallet functionality.
/// This enables the wallet factory to dynamically discover and use chain-specific
/// wallet operations without hardcoding chain-specific logic.
#[async_trait]
pub trait WalletOperations: Send + Sync {
    /// Get the chain ID this wallet operations implementation supports
    fn chain_id(&self) -> ChainId;

    /// Derive an address from a seed
    ///
    /// # Arguments
    /// * `seed` - BIP-39 seed bytes
    /// * `account` - BIP-44 account index
    /// * `index` - Address index within the account
    ///
    /// # Returns
    /// The derived address as a string
    fn derive_address(
        &self,
        seed: &[u8],
        account: u32,
        index: u32,
    ) -> Result<String>;

    /// Get wallet balance
    ///
    /// # Arguments
    /// * `address` - The address to check balance for
    ///
    /// # Returns
    /// The balance as a string (chain-specific format)
    async fn get_balance(&self, address: &str) -> Result<String>;

    /// Sign a transaction
    ///
    /// # Arguments
    /// * `seed` - BIP-39 seed bytes
    /// * `tx_data` - Transaction data to sign (chain-specific format)
    ///
    /// # Returns
    /// The signed transaction as bytes
    async fn sign_transaction(&self, seed: &[u8], tx_data: &[u8]) -> Result<Vec<u8>>;

    /// Broadcast a transaction
    ///
    /// # Arguments
    /// * `signed_tx` - Signed transaction bytes
    ///
    /// # Returns
    /// The transaction hash as a string
    async fn broadcast_transaction(&self, signed_tx: &[u8]) -> Result<String>;

    /// Get transaction status
    ///
    /// # Arguments
    /// * `tx_hash` - Transaction hash
    ///
    /// # Returns
    /// Transaction status information as a key-value map
    async fn get_transaction_status(&self, tx_hash: &str) -> Result<HashMap<String, String>>;

    /// Scan for UTXOs (chain-specific, returns empty vector if not supported)
    ///
    /// # Arguments
    /// * `seed` - BIP-39 seed bytes
    /// * `account` - BIP-44 account index
    /// * `index` - Address index within the account
    /// * `rpc_url` - RPC endpoint URL for chain queries
    ///
    /// # Returns
    /// Vector of UTXOs as (txid, vout, value, scriptpubkey_hex) tuples
    async fn scan_utxos(
        &self,
        seed: &[u8],
        account: u32,
        index: u32,
        rpc_url: &str,
    ) -> Result<Vec<(String, u32, u64, Option<String>)>> {
        // Default implementation for chains that don't support UTXO scanning
        Ok(Vec::new())
    }
}

/// Wallet factory for dynamic chain discovery
///
/// The wallet factory maintains a registry of chain-specific wallet operations
/// implementations and provides methods to retrieve them by chain ID.
pub struct WalletFactory {
    /// Registry of wallet operations implementations by chain ID
    registry: HashMap<ChainId, Arc<dyn WalletOperations>>,
}

impl WalletFactory {
    /// Create a new wallet factory
    pub fn new() -> Self {
        Self {
            registry: HashMap::new(),
        }
    }

    /// Register a wallet operations implementation for a chain
    ///
    /// # Arguments
    /// * `ops` - The wallet operations implementation
    pub fn register(&mut self, ops: Box<dyn WalletOperations>) {
        let chain_id = ops.chain_id();
        self.registry.insert(chain_id, Arc::from(ops));
    }

    /// Get wallet operations for a chain
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// The wallet operations implementation if found
    pub fn get(&self, chain_id: &ChainId) -> Option<Arc<dyn WalletOperations>> {
        self.registry.get(chain_id).cloned()
    }

    /// Get all registered chain IDs
    ///
    /// # Returns
    /// Iterator over all registered chain IDs
    pub fn registered_chains(&self) -> impl Iterator<Item = &ChainId> {
        self.registry.keys()
    }

    /// Check if a chain is registered
    ///
    /// # Arguments
    /// * `chain_id` - The chain ID
    ///
    /// # Returns
    /// True if the chain is registered
    pub fn is_registered(&self, chain_id: &ChainId) -> bool {
        self.registry.contains_key(chain_id)
    }
}

impl Default for WalletFactory {
    fn default() -> Self {
        Self::new()
    }
}
