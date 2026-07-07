//! Adapter factory for dynamic chain adapter instantiation.
//!
//! This crate provides a trait-based factory pattern for creating chain adapters
//! without requiring direct imports of adapter-specific types in SDK and Runtime.
//!
//! This enforces the architectural requirement that SDK and Runtime depend only on
//! Protocol traits, not concrete adapter types.

use async_trait::async_trait;
use csv_adapter_core::ChainAdapter;
use csv_hash::chain_id::ChainId;
use csv_protocol::chain_adapter_traits::ChainBackend;
use csv_protocol::secret::SharedSecretHandle;
use std::sync::Arc;

#[cfg(feature = "aptos")]
mod aptos;
mod bitcoin;
#[cfg(feature = "ethereum")]
mod ethereum;
#[cfg(feature = "solana")]
mod solana;
#[cfg(feature = "sui")]
mod sui;

#[cfg(feature = "aptos")]
pub use aptos::AptosFactory;
pub use bitcoin::BitcoinFactory;
#[cfg(feature = "ethereum")]
pub use ethereum::EthereumFactory;
#[cfg(feature = "solana")]
pub use solana::SolanaFactory;
#[cfg(feature = "sui")]
pub use sui::SuiFactory;

/// Environment variable holding the RFC-0012 mint verifier's secp256k1 signing
/// key (32-byte secret, hex, with or without a `0x` prefix).
///
/// This is the private half of the verifier keypair whose public key is seeded
/// into each destination registry's verifier set (`add_verifier` /
/// `initialize_verifier_registry` / `init_mint_authority`). The runtime signs the
/// RFC-0012 §9.2 mint-attestation digest with it; the destination contract
/// verifies the recovered signer against its on-chain set. It is deliberately a
/// process secret (env), never a chain-config field, and never logged.
#[cfg(any(
    feature = "ethereum",
    feature = "sui",
    feature = "solana",
    feature = "aptos"
))]
pub const MINT_VERIFIER_KEY_ENV: &str = "CSV_MINT_VERIFIER_KEY";

/// Load the mint verifier signing key from [`MINT_VERIFIER_KEY_ENV`], if set.
///
/// Returns `None` when the variable is absent — in that case the destination
/// adapter is built without a verifier key and mint **fails closed** (the runtime
/// emits no verifier signature and the contract rejects it). A present-but-invalid
/// value (bad hex, wrong length, not a valid secp256k1 scalar) also yields `None`
/// with a warning, preserving fail-closed rather than panicking. The key material
/// is never included in the log line.
#[cfg(any(
    feature = "ethereum",
    feature = "sui",
    feature = "solana",
    feature = "aptos"
))]
pub(crate) fn load_mint_verifier_key() -> Option<secp256k1::SecretKey> {
    let raw = std::env::var(MINT_VERIFIER_KEY_ENV).ok()?;
    let trimmed = raw.trim().trim_start_matches("0x");
    let bytes = match hex::decode(trimmed) {
        Ok(b) => b,
        Err(_) => {
            log::warn!(
                "{MINT_VERIFIER_KEY_ENV} is set but is not valid hex; \
                 mint will fail closed (no verifier signature)"
            );
            return None;
        }
    };
    match secp256k1::SecretKey::from_slice(&bytes) {
        Ok(key) => {
            log::info!("Factory: loaded mint verifier signing key from {MINT_VERIFIER_KEY_ENV}");
            Some(key)
        }
        Err(_) => {
            log::warn!(
                "{MINT_VERIFIER_KEY_ENV} is set but is not a valid 32-byte secp256k1 \
                 secret; mint will fail closed (no verifier signature)"
            );
            None
        }
    }
}

/// Configuration for creating a chain adapter.
///
/// # Security
///
/// Private key material is passed via [`SharedSecretHandle`] which prevents:
/// - Raw hex strings flowing through config structs
/// - Accidental cloning of secret material (Arc-based sharing)
/// - Serialization of secret material to disk/network
/// - Printing of secret material in logs/errors
///
/// # Clone Behavior
///
/// `AdapterConfig` implements `Clone` by cloning the `Arc<SecretHandle>`
/// reference. This shares the same underlying secret across clones without
/// duplicating the key material in memory.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    /// Chain identifier
    pub chain_id: ChainId,
    /// Network type (testnet/mainnet)
    pub network: NetworkType,
    /// RPC endpoints with protocol and optional API key
    pub rpc_endpoints: Vec<RpcEndpoint>,
    /// Secret key handle for signing operations (shared via Arc)
    pub secret_key: SharedSecretHandle,
    /// BIP-39 seed for HD wallet derivation (64 bytes, 128 hex chars)
    /// Used for Bitcoin wallet creation when available.
    pub seed: Option<String>,
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
    /// REST API (esplora convention: /address/{addr}/utxo, /tx/{txid})
    Rest,
    /// gRPC
    Grpc,
    /// WebSocket
    WebSocket,
    /// JSON-RPC
    JsonRpc,
    /// Trezor Blockbook REST API (Alchemy Bitcoin UTXO API, self-hosted Blockbook)
    Blockbook,
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
    /// Tapret commitment (hex) embedded in the seal output's Taproot leaf.
    /// Needed to reconstruct the key-path tweak when the seal is spent (lock).
    pub commitment: Option<String>,
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
    pub async fn create(
        &self,
        chain_id: &str,
        config: AdapterConfig,
    ) -> Result<AdapterResult, FactoryError> {
        let factory = self
            .factories
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

#[cfg(all(test, any(feature = "sui", feature = "solana", feature = "aptos")))]
mod verifier_key_tests {
    use super::*;

    // All cases live in one test: they mutate a shared process env var, so they
    // must not run concurrently with each other.
    #[test]
    fn load_mint_verifier_key_cases() {
        let prev = std::env::var(MINT_VERIFIER_KEY_ENV).ok();
        // SAFETY: single-threaded within this test; restored before returning.
        unsafe {
            // Absent -> None (fail-closed).
            std::env::remove_var(MINT_VERIFIER_KEY_ENV);
            assert!(load_mint_verifier_key().is_none(), "absent must be None");

            // A valid 32-byte secp256k1 secret loads (bare hex).
            let valid = "0000000000000000000000000000000000000000000000000000000000000001";
            std::env::set_var(MINT_VERIFIER_KEY_ENV, valid);
            assert!(load_mint_verifier_key().is_some(), "valid hex must load");

            // 0x prefix is accepted.
            std::env::set_var(MINT_VERIFIER_KEY_ENV, format!("0x{valid}"));
            assert!(load_mint_verifier_key().is_some(), "0x-prefixed must load");

            // Bad hex -> None, not a panic.
            std::env::set_var(MINT_VERIFIER_KEY_ENV, "nothex");
            assert!(load_mint_verifier_key().is_none(), "bad hex must be None");

            // Wrong length -> None.
            std::env::set_var(MINT_VERIFIER_KEY_ENV, "00ff");
            assert!(load_mint_verifier_key().is_none(), "short key must be None");

            // Restore.
            match prev {
                Some(v) => std::env::set_var(MINT_VERIFIER_KEY_ENV, v),
                None => std::env::remove_var(MINT_VERIFIER_KEY_ENV),
            }
        }
    }
}
