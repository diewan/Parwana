//! CSV Adapter Core
//!
//! This crate provides common traits and configuration types for all chain adapters,
//! reducing duplication and ensuring consistency across adapter implementations.

#![warn(missing_docs)]

use async_trait::async_trait;
use csv_hash::{Hash, commitment::Commitment};
use csv_protocol::proof_types::{FinalityProof, ProofBundle};
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

    /// Verify finality proof
    async fn verify_finality(&self, proof: &FinalityProof) -> AdapterResult<bool>;

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
