//! Cross-chain stub module

use csv_hash::Hash;
use serde::{Deserialize, Serialize};

/// Lock event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockEvent {
    /// Source chain
    pub source_chain: String,
    /// Source transaction hash
    pub source_tx_hash: Hash,
    /// Source seal
    pub source_seal: SealInfo,
    /// Destination chain
    pub destination_chain: String,
    /// Sanad ID
    pub sanad_id: Hash,
}

/// Seal info
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealInfo {
    /// Seal ID
    pub id: Hash,
}

/// Cross-chain proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainProof {
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Proof data
    pub proof_data: Vec<u8>,
}

/// Cross-chain transfer proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainTransferProof {
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Transfer ID
    pub transfer_id: Vec<u8>,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Lock event
    pub lock_event: LockEvent,
}

impl CrossChainTransferProof {
    /// Create new cross-chain transfer proof
    pub fn new(
        source_chain: String,
        destination_chain: String,
        transfer_id: Vec<u8>,
        proof_data: Vec<u8>,
        lock_event: LockEvent,
    ) -> Self {
        Self {
            source_chain,
            destination_chain,
            transfer_id,
            proof_data,
            lock_event,
        }
    }
}
