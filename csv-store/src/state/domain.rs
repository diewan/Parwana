//! Domain types: Sanads, transfers, contracts, seals, proofs, transactions.
//!
//! These types represent the core CSV (Client-Side Validation) domain model.

use super::core::ChainId;
use csv_core::SimplifiedTransferStatus;
use serde::{Deserialize, Serialize};

/// Status of a Sanad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SanadStatus {
    /// Sanad is active and can be used.
    Active,
    /// Sanad has been transferred to another owner.
    Transferred,
    /// Sanad has been consumed (seal used).
    Consumed,
}

impl std::fmt::Display for SanadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanadStatus::Active => write!(f, "active"),
            SanadStatus::Transferred => write!(f, "transferred"),
            SanadStatus::Consumed => write!(f, "consumed"),
        }
    }
}

/// A tracked Sanad (represents ownership of an asset/claim).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanadRecord {
    /// Sanad ID (hash).
    pub id: String,
    /// Chain where this Sanad is anchored.
    pub chain: ChainId,
    /// Seal reference (chain-specific bytes, base64 encoded for JSON).
    pub seal_ref: String,
    /// Current owner address.
    pub owner: String,
    /// Value/amount.
    pub value: u64,
    /// Commitment hash (base64).
    pub commitment: String,
    /// Nullifier (if consumed, base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    /// Current status.
    pub status: SanadStatus,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Chain-anchored transaction hash (the on-chain txid where this Sanad was published).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_tx_hash: Option<String>,
}

/// Status of a cross-chain transfer.
///
/// Re-exported from csv_core for compatibility.
/// Use [`csv_core::SimplifiedTransferStatus`] for the canonical definition.
pub type TransferStatus = SimplifiedTransferStatus;

/// A cross-chain transfer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    /// Transfer ID (hash of source seal + dest chain).
    pub id: String,
    /// Source chain.
    pub source_chain: ChainId,
    /// Destination chain.
    pub dest_chain: ChainId,
    /// Sanad ID being transferred.
    pub sanad_id: String,
    /// Sender address on source chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_address: Option<String>,
    /// Destination owner address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_address: Option<String>,
    /// Source transaction hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_tx_hash: Option<String>,
    /// Source transaction fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_fee: Option<u64>,
    /// Destination transaction hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_tx_hash: Option<String>,
    /// Destination transaction fee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest_fee: Option<u64>,
    /// Destination contract address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_contract: Option<String>,
    /// Inclusion proof (base64 encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Transfer status.
    pub status: TransferStatus,
    /// Created timestamp.
    pub created_at: u64,
    /// Completed timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<u64>,
}

/// Deployed contract info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRecord {
    /// Chain where contract is deployed.
    pub chain: ChainId,
    /// Contract address.
    pub address: String,
    /// Deployment transaction hash.
    pub tx_hash: String,
    /// Deployment timestamp.
    pub deployed_at: u64,
}

/// Status of a seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SealStatus {
    /// Seal is active and can be used.
    Active,
    /// Seal has been locked for a transfer.
    Locked,
    /// Seal has been consumed.
    Consumed,
    /// Seal has been transferred.
    Transferred,
}

impl std::fmt::Display for SealStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealStatus::Active => write!(f, "active"),
            SealStatus::Locked => write!(f, "locked"),
            SealStatus::Consumed => write!(f, "consumed"),
            SealStatus::Transferred => write!(f, "transferred"),
        }
    }
}

/// Seal record (single-use seal for CSV).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealRecord {
    /// Seal reference (base64 encoded).
    pub seal_ref: String,
    /// Chain where seal is anchored.
    pub chain: ChainId,
    /// Value associated with seal.
    pub value: u64,
    /// Whether seal has been consumed.
    pub consumed: bool,
    /// Seal status.
    pub status: SealStatus,
    /// Creation timestamp.
    pub created_at: u64,
    /// Sanad ID this seal is associated with (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanad_id: Option<String>,
    /// Sealed content hash (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Proof reference (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_ref: Option<String>,
}

impl SealRecord {
    /// Create a new active seal record.
    pub fn new(seal_ref: String, chain: ChainId, value: u64, created_at: u64) -> Self {
        Self {
            seal_ref,
            chain,
            value,
            consumed: false,
            status: SealStatus::Active,
            created_at,
            sanad_id: None,
            content: None,
            proof_ref: None,
        }
    }
}

/// Status of a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStatus {
    /// Proof generated but not yet submitted for verification.
    Generated,
    /// Proof is pending verification.
    Pending,
    /// Proof has been verified.
    Verified,
    /// Proof verification failed.
    Failed,
    /// Proof is invalid or could not be verified.
    Invalid,
}

impl std::fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofStatus::Generated => write!(f, "generated"),
            ProofStatus::Pending => write!(f, "pending"),
            ProofStatus::Verified => write!(f, "verified"),
            ProofStatus::Failed => write!(f, "failed"),
            ProofStatus::Invalid => write!(f, "invalid"),
        }
    }
}

/// Proof record (cryptographic proofs for CSV).
///
/// Stores both traditional inclusion proofs and ZK proofs (Phase 5).
/// For ZK proofs, the proof_data contains the serialized ZkSealProof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
    /// Chain where proof is valid.
    pub chain: ChainId,
    /// Sanad ID this proof is for.
    pub sanad_id: String,
    /// Proof type (e.g., "inclusion", "exclusion", "transition", "zk_seal").
    pub proof_type: String,
    /// Proof system used (e.g., "sp1", "groth16", "plonk" for ZK proofs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_system: Option<String>,
    /// Whether proof has been verified.
    pub verified: bool,
    /// Proof data (base64 encoded).
    /// For ZK proofs, this is the serialized ZkSealProof bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_data: Option<String>,
    /// Block height where the proof was generated/verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
    /// Timestamp when proof was created.
    pub created_at: u64,
    /// Timestamp when proof was verified (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<u64>,
    /// Proof status.
    pub status: ProofStatus,
    /// Seal reference this proof is for (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<String>,
    /// Target chain where proof will be verified (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_chain: Option<ChainId>,
    /// Verification transaction hash (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_tx_hash: Option<String>,
}

impl ProofRecord {
    /// Create a new ZK proof record.
    pub fn new_zk_proof(
        chain: ChainId,
        sanad_id: String,
        proof_system: &str,
        proof_data: Vec<u8>,
        block_height: u64,
    ) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        Self {
            chain,
            sanad_id,
            proof_type: "zk_seal".to_string(),
            proof_system: Some(proof_system.to_string()),
            verified: false,
            proof_data: Some(STANDARD.encode(proof_data)),
            block_height: Some(block_height),
            created_at: 0, // Should be set by caller
            verified_at: None,
            status: ProofStatus::Pending,
            seal_ref: None,
            target_chain: None,
            verification_tx_hash: None,
        }
    }

    /// Get the decoded proof data as bytes.
    pub fn decoded_proof_data(&self) -> Option<Vec<u8>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        self.proof_data
            .as_ref()
            .and_then(|data| STANDARD.decode(data).ok())
    }

    /// Mark the proof as verified.
    pub fn mark_verified(&mut self, timestamp: u64) {
        self.verified = true;
        self.verified_at = Some(timestamp);
    }

    /// Check if this is a ZK proof.
    pub fn is_zk_proof(&self) -> bool {
        self.proof_type == "zk_seal" || self.proof_system.is_some()
    }
}

/// Transaction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    /// Simple transfer.
    Transfer,
    /// Contract deployment.
    ContractDeployment,
    /// Contract function call.
    ContractCall,
    /// Sanad creation.
    SanadCreation,
    /// Sanad transfer.
    SanadTransfer,
    /// Seal creation.
    SealCreation,
    /// Seal consumption.
    SealConsumption,
    /// Cross-chain lock.
    CrossChainLock,
    /// Cross-chain mint.
    CrossChainMint,
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionType::Transfer => write!(f, "Transfer"),
            TransactionType::ContractDeployment => write!(f, "Contract Deployment"),
            TransactionType::ContractCall => write!(f, "Contract Call"),
            TransactionType::SanadCreation => write!(f, "Sanad Creation"),
            TransactionType::SanadTransfer => write!(f, "Sanad Transfer"),
            TransactionType::SealCreation => write!(f, "Seal Creation"),
            TransactionType::SealConsumption => write!(f, "Seal Consumption"),
            TransactionType::CrossChainLock => write!(f, "Cross-Chain Lock"),
            TransactionType::CrossChainMint => write!(f, "Cross-Chain Mint"),
        }
    }
}

/// Transaction status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionStatus {
    /// Transaction pending.
    Pending,
    /// Transaction confirmed.
    Confirmed,
    /// Transaction failed.
    Failed,
}

impl std::fmt::Display for TransactionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionStatus::Pending => write!(f, "pending"),
            TransactionStatus::Confirmed => write!(f, "confirmed"),
            TransactionStatus::Failed => write!(f, "failed"),
        }
    }
}

/// A transaction record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// Transaction ID.
    pub id: String,
    /// Chain where transaction occurred.
    pub chain: ChainId,
    /// Transaction hash.
    pub tx_hash: String,
    /// Transaction type.
    pub tx_type: TransactionType,
    /// Transaction status.
    pub status: TransactionStatus,
    /// Sender address.
    pub from_address: String,
    /// Recipient address (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
    /// Amount transferred (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Fee paid (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
    /// Block number (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Confirmations received (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Explorer URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
}

/// A test result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub id: String,
    pub from_chain: ChainId,
    pub to_chain: ChainId,
    pub status: TestStatus,
    pub message: String,
}

/// Test status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Pending,
    Running,
    Passed,
    Failed,
}

impl std::fmt::Display for TestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestStatus::Pending => write!(f, "pending"),
            TestStatus::Running => write!(f, "running"),
            TestStatus::Passed => write!(f, "passed"),
            TestStatus::Failed => write!(f, "failed"),
        }
    }
}
