//! Adapter factory for dynamic chain adapter instantiation.
//!
//! This crate provides a trait-based factory pattern for creating chain adapters
//! without requiring direct imports of adapter-specific types in SDK and Runtime.
//!
//! This enforces the architectural requirement that SDK and Runtime depend only on
//! Protocol traits, not concrete adapter types.

use async_trait::async_trait;
use csv_protocol::backend::ChainBackend;
use csv_adapter_core::ChainAdapter;
use csv_hash::chain_id::ChainId;
use std::sync::Arc;

mod bitcoin;
#[cfg(feature = "ethereum")]
mod ethereum;
#[cfg(feature = "sui")]
mod sui;
#[cfg(feature = "aptos")]
mod aptos;
#[cfg(feature = "solana")]
mod solana;

pub use bitcoin::BitcoinFactory;
#[cfg(feature = "ethereum")]
pub use ethereum::EthereumFactory;
#[cfg(feature = "sui")]
pub use sui::SuiFactory;
#[cfg(feature = "aptos")]
pub use aptos::AptosFactory;
#[cfg(feature = "solana")]
pub use solana::SolanaFactory;

/// Configuration for creating a chain adapter.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Network type (testnet/mainnet)
    pub network: NetworkType,
    /// RPC endpoints with protocol and optional API key
    pub rpc_endpoints: Vec<RpcEndpoint>,
    /// Private key or seed (hex-encoded, optional)
    pub private_key: Option<String>,
    /// Account index for HD derivation
    pub account: u32,
    /// Index for HD derivation
    pub index: u32,
    /// Contract address (for EVM chains)
    pub contract_address: Option<String>,
    /// Program ID (for Solana)
    pub program_id: Option<String>,
    /// UTXOs (for Bitcoin)
    pub utxos: Vec<UtxoConfig>,
    /// Sanad seals (for Bitcoin)
    pub sanad_seals: Vec<SanadSealConfig>,
}

/// RPC endpoint configuration with protocol and optional API key.
#[derive(Debug, Clone)]
pub struct RpcEndpoint {
    /// RPC URL
    pub url: String,
    /// Protocol type
    pub protocol: RpcProtocol,
    /// API key (optional, URL-specific)
    pub api_key: Option<String>,
    /// Priority (lower = higher priority)
    pub priority: u32,
}

/// RPC protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcProtocol {
    /// REST API
    Rest,
    /// gRPC
    Grpc,
    /// WebSocket
    WebSocket,
    /// JSON-RPC
    JsonRpc,
}

/// UTXO configuration.
#[derive(Debug, Clone)]
pub struct UtxoConfig {
    /// Transaction ID (display format)
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: u64,
    /// Account index
    pub account: u32,
    /// Index for HD derivation
    pub index: u32,
    /// Script pubkey (hex)
    pub script_pubkey: Option<String>,
}

/// Sanad seal configuration.
#[derive(Debug, Clone)]
pub struct SanadSealConfig {
    /// Sanad ID (hex)
    pub sanad_id: String,
    /// Anchor transaction ID (display format)
    pub anchor_txid: String,
    /// Output index
    pub vout: u32,
}

/// Network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    Testnet,
    Mainnet,
}

/// Result of adapter creation.
pub struct AdapterResult {
    /// ChainBackend adapter for ChainRuntime
    pub chain_backend: Arc<dyn ChainBackend>,
    /// ChainAdapter for TransferCoordinator (optional)
    pub chain_adapter: Option<Box<dyn ChainAdapter>>,
}

/// Trait for creating chain adapters dynamically.
#[async_trait]
pub trait AdapterFactory: Send + Sync {
    /// Create adapters for the given chain.
    async fn create_adapter(&self, config: AdapterConfig) -> Result<AdapterResult, FactoryError>;

    /// Get the chain ID this factory supports.
    fn chain_id(&self) -> &str;
}

/// Factory error.
#[derive(Debug, thiserror::Error)]
pub enum FactoryError {
    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Adapter creation failed: {0}")]
    CreationFailed(String),
    
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
}

/// Registry of adapter factories.
pub struct FactoryRegistry {
    factories: std::collections::HashMap<String, Box<dyn AdapterFactory>>,
}

impl FactoryRegistry {
    /// Create a new factory registry.
    pub fn new() -> Self {
        Self {
            factories: std::collections::HashMap::new(),
        }
    }

    /// Register a factory for a chain.
    pub fn register(&mut self, factory: Box<dyn AdapterFactory>) {
        let chain_id = factory.chain_id().to_string();
        self.factories.insert(chain_id, factory);
    }

    /// Create adapters for a chain.
    pub async fn create(&self, chain_id: &str, config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        let factory = self.factories
            .get(chain_id)
            .ok_or_else(|| FactoryError::UnsupportedChain(chain_id.to_string()))?;
        factory.create_adapter(config).await
    }

    /// Check if a chain is supported.
    pub fn supports(&self, chain_id: &str) -> bool {
        self.factories.contains_key(chain_id)
    }
}

impl Default for FactoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}
