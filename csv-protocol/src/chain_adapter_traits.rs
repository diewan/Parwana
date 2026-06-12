//! Core Chain Operation Traits
//!
//! This module defines the standardized traits that all chain adapters must implement
//! for production use. These traits provide a unified interface for:
//!
//! - **ChainQuery**: Querying balances, transactions, and chain state
//! - **ChainSigner**: Deriving addresses and signing transactions/messages
//! - **ChainBroadcaster**: Submitting and confirming transactions
//! - **ChainDeployer**: Deploying contracts and programs
//! - **ChainProofProvider**: Building and verifying cryptographic proofs
//! - **ChainSanadOps**: Managing sanads (create, consume, lock, mint, refund)
//!
//! All adapters must implement these traits to be registered in the production registry.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::proof_taxonomy::{FinalityProof, InclusionProof};
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::{CommitAnchor, SealPoint};

/// Result type for chain operations
pub type ChainOpResult<T> = Result<T, ChainOpError>;

/// Errors that can occur during chain operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainOpError {
    /// Chain is not supported or not configured
    UnsupportedChain(String),
    /// RPC connection failed or returned error
    RpcError(String),
    /// Transaction failed validation
    TransactionError(String),
    /// Signing operation failed
    SigningError(String),
    /// Proof verification failed
    ProofVerificationError(String),
    /// Contract deployment failed
    DeploymentError(String),
    /// Capability is not available (not yet implemented or not supported on this chain)
    CapabilityUnavailable(String),
    /// Feature is not enabled (requires configuration or feature flag)
    FeatureNotEnabled(String),
    /// Invalid input parameters
    InvalidInput(String),
    /// Timeout waiting for operation
    Timeout(String),
    /// Unknown error
    Unknown(String),
}

impl core::fmt::Display for ChainOpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainOpError::UnsupportedChain(msg) => write!(f, "Unsupported chain: {}", msg),
            ChainOpError::RpcError(msg) => write!(f, "RPC error: {}", msg),
            ChainOpError::TransactionError(msg) => write!(f, "Transaction error: {}", msg),
            ChainOpError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            ChainOpError::ProofVerificationError(msg) => {
                write!(f, "Proof verification error: {}", msg)
            }
            ChainOpError::DeploymentError(msg) => write!(f, "Deployment error: {}", msg),
            ChainOpError::CapabilityUnavailable(msg) => {
                write!(f, "Capability unavailable: {}", msg)
            }
            ChainOpError::FeatureNotEnabled(msg) => write!(f, "Feature not enabled: {}", msg),
            ChainOpError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ChainOpError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            ChainOpError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for ChainOpError {}

/// Status of a transaction on chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Transaction is pending/in mempool
    Pending,
    /// Transaction has been confirmed in a block
    Confirmed {
        /// Block height where transaction was confirmed
        block_height: u64,
        /// Number of confirmations since the block
        confirmations: u64,
    },
    /// Transaction failed
    Failed {
        /// Reason for the failure
        reason: String,
    },
    /// Transaction was dropped from mempool
    Dropped,
    /// Unknown status
    Unknown,
}

/// Status of contract deployment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeploymentStatus {
    /// Deployment is pending
    Pending,
    /// Deployment succeeded
    Success {
        /// Address of the deployed contract
        contract_address: String,
        /// Transaction hash of the deployment
        transaction_hash: String,
        /// Block height where deployment was confirmed
        block_height: u64,
    },
    /// Deployment failed
    Failed {
        /// Reason for the failure
        reason: String,
    },
}

/// Status of finality for a transaction or anchor
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalityStatus {
    /// Not yet finalized
    Pending,
    /// Finalized (safe from reorgs per chain's finality rules)
    Finalized {
        /// Block height of the transaction
        block_height: u64,
        /// Block height considered final
        finality_block: u64,
    },
    /// Orphaned due to reorg
    Orphaned,
}

/// Contract status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractStatus {
    /// Contract address/program ID
    pub address: String,
    /// Whether the contract is deployed and active
    pub is_deployed: bool,
    /// Current balance (if applicable)
    pub balance: Option<u64>,
    /// Owner of the contract
    pub owner: Option<String>,
    /// Chain-specific metadata (operational; not canonical).
    pub metadata: serde_json::Value,
}

/// Balance information for an address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceInfo {
    /// Address queried
    pub address: String,
    /// Total balance in smallest unit
    pub total: u64,
    /// Available/spendable balance
    pub available: u64,
    /// Locked/pending balance
    pub locked: u64,
    /// Token-specific balances (for chains with multiple tokens)
    pub tokens: Vec<TokenBalance>,
}

/// Token-specific balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token contract address or identifier
    pub token_id: String,
    /// Token symbol
    pub symbol: String,
    /// Token balance
    pub balance: u64,
    /// Number of decimals
    pub decimals: u8,
}

/// Transaction information returned from chain query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// Transaction hash/signature
    pub hash: String,
    /// Sender address
    pub sender: String,
    /// Recipient address (if applicable)
    pub recipient: Option<String>,
    /// Amount transferred (if applicable)
    pub amount: Option<u64>,
    /// Transaction status
    pub status: TransactionStatus,
    /// Block height (if confirmed)
    pub block_height: Option<u64>,
    /// Timestamp (if available)
    pub timestamp: Option<u64>,
    /// Gas/fee paid
    pub fee: Option<u64>,
    /// Raw transaction data (chain-specific)
    pub raw_data: Option<Vec<u8>>,
}

/// Sanad operation types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SanadOperation {
    /// Create a new sanad
    Create,
    /// Consume a sanad
    Consume,
    /// Lock a sanad for cross-chain transfer
    Lock,
    /// Mint a sanad on destination chain
    Mint,
    /// Refund a locked sanad
    Refund,
    /// Record sanad metadata
    RecordMetadata,
}

/// Result of a sanad operation
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Debug, Clone)]
pub struct SanadOperationResult {
    /// Sanad ID affected by the operation.
    pub sanad_id: SanadId,
    /// Operation that was applied to the sanad.
    pub operation: SanadOperation,
    /// Transaction hash
    pub transaction_hash: String,
    /// Block height
    pub block_height: u64,
    /// Chain ID
    pub chain_id: String,
    /// Additional chain-specific operational metadata (non-canonical; not hashed).
    pub metadata: Vec<u8>,
}

/// Trait for querying chain state
///
/// Implementors must provide real RPC-backed implementations.
/// No test or artificial data is allowed in production.
#[async_trait]
pub trait ChainQuery: Send + Sync {
    /// Get the balance for an address
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo>;

    /// Get transaction information by hash
    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo>;

    /// Get finality status for a transaction or anchor
    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus>;

    /// Get contract status at an address
    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus>;

    /// Get the latest block height
    async fn get_latest_block_height(&self) -> ChainOpResult<u64>;

    /// Get chain-specific information (version, protocol, etc.)
    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value>;

    /// Get the account nonce/sequence number for an address
    ///
    /// This is used for transaction construction to ensure proper
    /// ordering and prevent replay attacks.
    ///
    /// # Arguments
    /// * `address` - The account address to query
    ///
    /// # Returns
    /// * `Ok(u64)` - The current nonce/sequence number for the account
    /// * `Err` - If the query fails or the address is invalid
    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64>;

    /// Check if an address is valid for this chain
    fn validate_address(&self, address: &str) -> bool;
}

/// Trait for chain signing operations
///
/// All signing operations must use secure key storage.
/// Private keys must never be exposed in plaintext.
#[async_trait]
pub trait ChainSigner: Send + Sync {
    /// Derive an address from a public key or key identifier
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String>;

    /// Sign a transaction
    ///
    /// The transaction data must be canonical serialized before signing.
    async fn sign_transaction(&self, tx_data: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>>;

    /// Sign a message (for verification purposes)
    ///
    /// Messages should include domain separation.
    async fn sign_message(&self, message: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>>;

    /// Verify a signature
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool>;

    /// Get the signature scheme used by this chain
    fn signature_scheme(&self) -> crate::signature::SignatureScheme;
}

/// Trait for broadcasting transactions
///
/// Implementors must submit to real chain networks.
/// No artificial transaction acceptance is allowed.
#[async_trait]
pub trait ChainBroadcaster: Send + Sync {
    /// Submit a signed transaction to the chain
    ///
    /// Returns the transaction hash if successful.
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String>;

    /// Confirm a transaction by hash
    ///
    /// Waits for the transaction to reach the specified confirmation level.
    /// Returns the final status of the transaction.
    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus>;

    /// Get the current recommended fee/gas price
    async fn get_fee_estimate(&self) -> ChainOpResult<u64>;

    /// Validate a transaction before submission (dry-run where supported)
    ///
    /// This should perform a real dry-run on the chain when available,
    /// not a local test validation.
    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()>;
}

/// Trait for deploying contracts and programs
///
/// All deployments must happen on real chains.
/// No test deployments or temporary addresses allowed.
#[async_trait]
pub trait ChainDeployer: Send + Sync {
    /// Deploy a lock contract for cross-chain sanads
    ///
    /// This contract locks sanads on the source chain during transfers.
    async fn deploy_lock_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus>;

    /// Deploy a mint contract for cross-chain sanads
    ///
    /// This contract mints sanads on the destination chain after proof verification.
    async fn deploy_mint_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus>;

    /// Deploy or publish a seal program (chain-specific)
    ///
    /// For Solana: deploy Anchor program
    /// For Sui: publish Move package
    /// For Aptos: publish Move module
    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus>;

    /// Verify that a deployment succeeded and is active
    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool>;

    /// Get the estimated deployment cost
    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64>;
}

/// Trait for building and verifying cryptographic proofs
///
/// All proof operations must use real cryptographic verification.
/// No fake or deterministic proofs allowed in production.
#[async_trait]
pub trait ChainProofProvider: Send + Sync {
    /// Build an inclusion proof for a commitment
    ///
    /// Proves that a commitment was included in a specific block.
    /// The `anchor_id` provides additional transaction or anchor context
    /// necessary to construct a real inclusion proof (e.g., transaction signature).
    async fn build_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<InclusionProof>;

    /// Verify an inclusion proof
    ///
    /// Returns true if the proof is valid, false otherwise.
    fn verify_inclusion_proof(
        &self,
        proof: &InclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool>;

    /// Build a finality proof for a transaction or anchor
    ///
    /// Proves that a transaction has reached finality on this chain.
    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof>;

    /// Verify a finality proof
    ///
    /// Returns true if the proof is valid and the transaction is finalized.
    fn verify_finality_proof(&self, proof: &FinalityProof, tx_hash: &str) -> ChainOpResult<bool>;

    /// Get the domain separator for proof generation
    fn domain_separator(&self) -> [u8; 32];

    /// Verify a proof bundle (inclusion + finality)
    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &InclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool>;
}

/// Trait for sanad operations
///
/// All operations must be backed by real chain transactions.
/// No artificial sanad state changes allowed.
#[async_trait]
pub trait ChainSanadOps: Send + Sync {
    /// Create a new sanad on this chain
    ///
    /// Returns the operation result with transaction details.
    async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult>;

    /// Consume a sanad on this chain
    ///
    /// Marks the sanad as consumed and records the nullifier.
    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult>;

    /// Lock a sanad for cross-chain transfer
    ///
    /// Locks the sanad on this chain and prepares for cross-chain mint.
    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult>;

    /// Mint a sanad on this chain (destination chain of cross-chain transfer)
    ///
    /// Creates a corresponding sanad after verifying the lock proof.
    async fn mint_sanad(
        &self,
        source_chain: &str,
        source_sanad_id: &SanadId,
        lock_proof: &InclusionProof,
        new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult>;

    /// Refund a locked sanad
    ///
    /// Returns the sanad to the owner if the cross-chain transfer times out.
    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult>;

    /// Record sanad metadata on-chain
    ///
    /// Updates or adds metadata for a sanad.
    async fn record_sanad_metadata(
        &self,
        sanad_id: &SanadId,
        metadata: serde_json::Value,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult>;

    /// Verify that a sanad exists and is in the expected state
    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool>;
}

/// Canonical Sanad state for cross-chain consistency
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSanadState {
    /// The canonical state value (0-9)
    pub state: u8,
    /// Owner address
    pub owner: String,
    /// Commitment hash
    pub commitment: Hash,
    /// Nullifier (if registered)
    pub nullifier: Option<Hash>,
    /// Creation timestamp
    pub created_at: i64,
    /// Lock timestamp (if locked)
    pub locked_at: Option<i64>,
    /// Consumption timestamp (if consumed)
    pub consumed_at: Option<i64>,
    /// Mint timestamp (if minted)
    pub minted_at: Option<i64>,
    /// Refund timestamp (if refunded)
    pub refunded_at: Option<i64>,
}

/// Canonical lifecycle event for traceability
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLifecycleEvent {
    /// Event type
    pub event_type: String,
    /// Timestamp
    pub timestamp: i64,
    /// Transaction hash or identifier
    pub tx_hash: String,
    /// Additional data
    pub data: HashMap<String, String>,
}

/// Trait for reading sanad state from chain adapters
///
/// Provides unified state querying across all chains.
/// Replaces ad-hoc per-chain state checking in CLI.
#[async_trait]
pub trait SanadStateReader: Send + Sync {
    /// Get the canonical state of a Sanad
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState>;
    
    /// Get the canonical state of a Seal
    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState>;
    
    /// Trace the full lifecycle of a Sanad
    async fn trace_sanad(&self, sanad_id: &SanadId) -> ChainOpResult<Vec<CanonicalLifecycleEvent>>;
}

/// Canonical Seal state for cross-chain consistency
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalSealState {
    /// The canonical state value
    pub state: u8,
    /// Owner address
    pub owner: String,
    /// Commitment hash
    pub commitment: Hash,
    /// Creation timestamp
    pub created_at: i64,
    /// Consumption timestamp
    pub consumed_at: Option<i64>,
}

/// Combined trait for full chain backend capabilities
///
/// Implementors must provide real implementations for all operations.
/// Use `CapabilityUnavailable` error for operations not supported on a chain.
#[async_trait]
pub trait ChainBackend:
    ChainQuery + ChainSigner + ChainBroadcaster + ChainDeployer + ChainProofProvider + ChainSanadOps + SanadStateReader
{
    /// Get the chain identifier
    fn chain_id(&self) -> &'static str;

    /// Get the chain name
    fn chain_name(&self) -> &'static str;

    /// Check if a specific capability is available
    fn is_capability_available(&self, capability: ChainCapability) -> bool;

    /// Create a new seal on the chain.
    ///
    /// This method creates a real chain-native seal that can be used for
    /// anchoring commitments. The seal is created via the chain adapter's
    /// SealProtocol implementation.
    ///
    /// # Arguments
    /// * `value` - Optional value/funding for the seal (chain-specific units)
    ///
    /// # Returns
    /// * `Ok(SealPoint)` - The created seal reference
    /// * `Err` - If seal creation fails or is not supported
    async fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint>;

    /// Publish a commitment under a single-use seal.
    ///
    /// This method publishes a commitment hash to the chain using the provided seal.
    /// The seal is consumed atomically with the commitment publication.
    ///
    /// # Arguments
    /// * `seal` - The seal reference to use for publishing
    /// * `commitment` - Domain-separated commitment hash for the state transition
    ///
    /// # Returns
    /// * `Ok(CommitAnchor)` - The anchor reference containing tx hash and block height
    /// * `Err` - If publication fails or seal already consumed
    async fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor>;
}

/// Chain capabilities that may not be available on all chains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainCapability {
    /// Can query balances
    QueryBalance,
    /// Can sign transactions
    SignTransactions,
    /// Can broadcast transactions
    BroadcastTransactions,
    /// Can deploy contracts
    DeployContracts,
    /// Can build inclusion proofs
    BuildInclusionProofs,
    /// Can verify inclusion proofs
    VerifyInclusionProofs,
    /// Can build finality proofs
    BuildFinalityProofs,
    /// Can verify finality proofs
    VerifyFinalityProofs,
    /// Can create sanads
    CreateSanads,
    /// Can consume sanads
    ConsumeSanads,
    /// Can lock sanads for cross-chain
    LockSanads,
    /// Can mint sanads on destination
    MintSanads,
    /// Can refund locked sanads
    RefundSanads,
    /// Supports smart contracts
    SmartContracts,
    /// Supports NFTs
    Nfts,
    /// Supports cross-chain transfers
    CrossChain,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_op_error_display() {
        let err = ChainOpError::CapabilityUnavailable("test".into());
        assert_eq!(err.to_string(), "Capability unavailable: test");
    }

    #[test]
    fn test_chain_capability_equality() {
        assert_eq!(ChainCapability::QueryBalance, ChainCapability::QueryBalance);
        assert_ne!(
            ChainCapability::QueryBalance,
            ChainCapability::SignTransactions
        );
    }
}
