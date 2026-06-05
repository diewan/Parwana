//! CSV Adapter Core
//!
//! This crate provides common traits and configuration types for all chain adapters,
//! reducing duplication and ensuring consistency across adapter implementations.

#![warn(missing_docs)]

use async_trait::async_trait;
use csv_hash::{Hash, commitment::Commitment};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_types::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use serde::{Deserialize, Serialize};

/// Common adapter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// Chain identifier
    pub chain_id: String,
    /// Network type (mainnet, testnet, devnet)
    pub network: String,
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Maximum number of concurrent RPC requests
    pub max_concurrent_requests: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            chain_id: "unknown".to_string(),
            network: "mainnet".to_string(),
            rpc_url: "http://localhost:8545".to_string(),
            max_concurrent_requests: 10,
            request_timeout_secs: 60,
        }
    }
}

/// Common adapter error type
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(String),
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    /// Generic error
    #[error("Generic error: {0}")]
    Generic(String),
}

/// Result type for adapter operations
pub type AdapterResult<T> = Result<T, AdapterError>;

/// Trait for proof verification operations
#[async_trait]
pub trait ProofAdapter: Send + Sync {
    /// Verify a proof bundle
    async fn verify_proof_bundle(&self, bundle: &ProofBundle) -> AdapterResult<bool>;

    /// Get chain-specific proof type
    fn proof_type(&self) -> String;
}

/// Trait for mint operations
#[async_trait]
pub trait MintAdapter: Send + Sync {
    /// Mint a Sanad commitment
    async fn mint_commitment(&self, commitment: &Commitment) -> AdapterResult<Hash>;

    /// Get mint status
    async fn get_mint_status(&self, tx_hash: &Hash) -> AdapterResult<MintStatus>;

    /// Get mint receipt
    async fn get_mint_receipt(&self, tx_hash: &Hash) -> AdapterResult<MintReceipt>;
}

/// Mint status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MintStatus {
    /// Pending
    Pending,
    /// Confirmed
    Confirmed,
    /// Failed
    Failed,
}

/// Mint receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintReceipt {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Block number
    pub block_number: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Gas used
    pub gas_used: u64,
}

/// Trait for chain operations
#[async_trait]
pub trait ChainOps: Send + Sync {
    /// Get chain height
    async fn get_chain_height(&self) -> AdapterResult<u64>;

    /// Get balance for an address
    async fn get_balance(&self, address: &str) -> AdapterResult<u64>;

    /// Get transaction status
    async fn get_transaction_status(&self, tx_hash: &Hash) -> AdapterResult<TransactionStatus>;

    /// Broadcast a transaction
    async fn broadcast_transaction(&self, tx_bytes: &[u8]) -> AdapterResult<Hash>;
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Pending
    Pending,
    /// Confirmed
    Confirmed,
    /// Failed
    Failed,
    /// Unknown
    Unknown,
}

/// Re-export common types for adapter use
pub use csv_protocol::seal_protocol::SealProtocol;

/// Cross-chain transfer data passed to adapters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossChainTransfer {
    /// Unique transfer ID
    pub id: String,
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Lock transaction hash on source chain
    pub lock_tx_hash: Vec<u8>,
    /// Lock output index on source chain
    pub lock_output_index: u32,
    /// Sanad ID being transferred
    pub sanad_id: Hash,
    /// Transition ID for the transfer
    pub transition_id: Vec<u8>,
}

/// Result of a lock operation.
#[derive(Debug, Clone)]
pub struct LockResult {
    /// Transaction hash of the lock
    pub tx_hash: String,
    /// Block height of the lock
    pub block_height: u64,
}

/// Result of a mint operation.
#[derive(Debug, Clone)]
pub struct MintResult {
    /// Transaction hash of the mint
    pub tx_hash: String,
    /// Block height of the mint
    pub block_height: u64,
}

/// Status of a seal in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealRegistryStatus {
    /// Seal is available for use
    Available,
    /// Seal has been consumed
    Consumed,
    /// Seal is locked
    Locked,
}

/// Capability lookup port.
pub trait ChainCapabilityPort: Send + Sync {
    /// Get the chain capabilities for the specified chain.
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities>;

    /// Get the signature scheme for the specified chain.
    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme>;
}

/// Source-chain locking port.
#[async_trait]
pub trait ChainLockPort: Send + Sync {
    /// Lock a Sanad on the source chain for cross-chain transfer.
    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError>;
}

/// Destination-chain minting port.
#[async_trait]
pub trait ChainMintPort: Send + Sync {
    /// Mint a Sanad on the destination chain using the provided proof bundle.
    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError>;
}

/// Seal/replay registry query port.
#[async_trait]
pub trait ChainSealRegistryPort: Send + Sync {
    /// Check the status of a seal in the registry.
    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError>;
}

/// Source-chain proof construction port.
#[async_trait]
pub trait ChainProofPort: Send + Sync {
    /// Build an inclusion proof for the locked transaction.
    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError>;

    /// Cryptographically validate source-chain proof material and bind it to
    /// the transfer whose mint is being authorized.
    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError>;
}

/// Non-mutating read port.
#[async_trait]
pub trait ChainReadPort: Send + Sync {
    /// Confirm a transaction on the chain.
    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError>;

    /// Get the balance for an address on the chain.
    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError>;
}

/// Compatibility facade for runtime paths that still need the full adapter surface.
#[async_trait]
pub trait AdapterRegistry: Send + Sync {
    /// Get the chain capabilities for the specified chain.
    fn capabilities(&self, chain_id: &str) -> Option<ChainCapabilities>;

    /// Get the signature scheme for the specified chain.
    fn signature_scheme(&self, chain_id: &str) -> Option<SignatureScheme>;

    /// Lock a Sanad on the source chain for cross-chain transfer.
    async fn lock_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError>;

    /// Mint a Sanad on the destination chain using the provided proof bundle.
    async fn mint_sanad(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError>;

    /// Check the status of a seal in the registry.
    async fn check_seal_registry(
        &self,
        chain_id: &str,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError>;

    /// Build an inclusion proof for the locked transaction.
    async fn build_inclusion_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError>;

    /// Cryptographically validate source-chain proof material and bind it to
    /// the transfer whose mint is being authorized.
    async fn validate_source_proof(
        &self,
        chain_id: &str,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError>;

    /// Confirm a transaction on the chain.
    async fn confirm_tx(&self, chain_id: &str, tx_hash: &str) -> Result<MintResult, AdapterError>;

    /// Get the balance for an address on the chain.
    async fn get_balance(&self, chain_id: &str, address: &str) -> Result<String, AdapterError>;
}

/// Legacy full chain adapter facade.
///
/// New code should request the narrow registry ports above. Adapters can migrate
/// to narrower internal modules while continuing to satisfy this compatibility
/// facade at the runtime boundary.
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Get the chain identifier for this adapter.
    fn chain_id(&self) -> &str;

    /// Get the chain capabilities for this adapter.
    fn capabilities(&self) -> ChainCapabilities;

    /// Get the signature scheme for this adapter.
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    /// Lock a Sanad on the source chain for cross-chain transfer.
    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError>;

    /// Mint a Sanad on the destination chain using the provided proof bundle.
    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError>;

    /// Build an inclusion proof for the locked transaction.
    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError>;

    /// Cryptographically validate source-chain proof material and bind it to
    /// the transfer whose mint is being authorized.
    async fn validate_source_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError>;

    /// Check the status of a seal in the registry.
    async fn check_seal_registry(&self, seal_id: &[u8])
    -> Result<SealRegistryStatus, AdapterError>;

    /// Confirm a transaction on the chain.
    async fn confirm_tx(&self, tx_hash: &str) -> Result<MintResult, AdapterError> {
        Err(AdapterError::Generic(format!(
            "confirm_tx is not implemented for transaction {}",
            tx_hash
        )))
    }

    /// Get the balance for an address on the chain.
    async fn get_balance(&self, address: &str) -> Result<String, AdapterError>;

    /// Downcast to concrete type for feature-specific operations
    fn as_any(&self) -> &dyn std::any::Any;
}
