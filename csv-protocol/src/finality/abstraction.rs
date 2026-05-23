//! Finality abstraction classes
//!
//! Defines the canonical finality types that all chains must implement.
//! Different chains have different finality models, but they all map to these canonical types.

use serde::{Deserialize, Serialize};

/// Canonical finality types
///
/// These represent the different ways chains achieve finality:
/// - Probabilistic: Bitcoin-style confirmations
/// - Economic: Ethereum-style economic finality
/// - Checkpoint: Sui-style checkpoint finality
/// - Quorum: Aptos-style validator quorum
/// - Instant: Instant finality chains
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityType {
    /// Probabilistic finality (e.g., Bitcoin confirmations)
    Probabilistic {
        /// Number of confirmations required
        confirmations: u64,
        /// Current confirmation depth
        depth: u64,
    },

    /// Economic finality (e.g., Ethereum Casper FFG)
    Economic {
        /// Validator signatures attesting to finality
        validator_signatures: Vec<Vec<u8>>,
        /// Epoch number
        epoch: u64,
    },

    /// Checkpoint finality (e.g., Sui checkpoints)
    Checkpoint {
        /// Checkpoint sequence number
        sequence: u64,
        /// Checkpoint digest
        digest: [u8; 32],
    },

    /// Validator quorum finality (e.g., Aptos certified state)
    Quorum {
        /// Quorum certificate
        quorum_cert: Vec<u8>,
        /// Validator set version
        validator_set_version: u64,
    },

    /// Instant finality (e.g., some L2s)
    Instant {
        /// Block height
        height: u64,
        /// Block hash
        hash: [u8; 32],
    },
}

impl FinalityType {
    /// Check if finality is sufficient for the given requirements
    pub fn is_final(&self, required: &FinalityRequirement) -> bool {
        match (self, required) {
            (FinalityType::Probabilistic { depth, .. }, FinalityRequirement::Confirmations(n)) => {
                depth >= n
            }
            (FinalityType::Economic { .. }, FinalityRequirement::Economic) => true,
            (FinalityType::Checkpoint { .. }, FinalityRequirement::Checkpoint) => true,
            (FinalityType::Quorum { .. }, FinalityRequirement::Quorum) => true,
            (FinalityType::Instant { .. }, FinalityRequirement::Instant) => true,
            _ => false,
        }
    }
}

/// Finality requirements
///
/// Defines what level of finality is required for a given operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityRequirement {
    /// Require N confirmations
    Confirmations(u64),
    /// Require economic finality
    Economic,
    /// Require checkpoint finality
    Checkpoint,
    /// Require quorum finality
    Quorum,
    /// Require instant finality
    Instant,
}

/// Finality proof
///
/// Evidence that a block has reached finality according to chain rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Block height
    pub block_height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Finality type
    pub finality_type: FinalityType,
    /// Timestamp when finality was achieved (Unix epoch seconds)
    pub achieved_at: u64,
}

impl FinalityProof {
    /// Create a new finality proof
    pub fn new(
        block_height: u64,
        block_hash: [u8; 32],
        finality_type: FinalityType,
        achieved_at: u64,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            finality_type,
            achieved_at,
        }
    }

    /// Check if this proof meets the given requirement
    pub fn meets_requirement(&self, requirement: &FinalityRequirement) -> bool {
        self.finality_type.is_final(requirement)
    }
}
