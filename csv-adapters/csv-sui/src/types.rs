//! Sui-specific type definitions

use serde::{Deserialize, Serialize};

/// Sui seal reference (owned object with one_time attribute)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SuiSealPoint {
    /// Object ID (32 bytes)
    pub object_id: [u8; 32],
    /// Object version
    pub version: u64,
    /// Nonce for replay resistance
    pub nonce: u64,
}

impl SuiSealPoint {
    /// Create a new Sui seal reference
    pub fn new(object_id: [u8; 32], version: u64, nonce: u64) -> Self {
        Self {
            object_id,
            version,
            nonce,
        }
    }

    /// Serialize to bytes
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 8);
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }
}

/// Sui anchor reference (dynamic object field containing commitment)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SuiCommitAnchor {
    /// Object ID containing the commitment
    pub object_id: [u8; 32],
    /// Transaction digest that created the anchor
    pub tx_digest: [u8; 32],
    /// Checkpoint sequence number
    pub checkpoint: u64,
}

impl SuiCommitAnchor {
    /// Create a new Sui anchor reference
    pub fn new(object_id: [u8; 32], tx_digest: [u8; 32], checkpoint: u64) -> Self {
        Self {
            object_id,
            tx_digest,
            checkpoint,
        }
    }
}

/// Sui inclusion proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiInclusionProof {
    /// Object proof bytes
    pub object_proof: Vec<u8>,
    /// Checkpoint hash
    pub checkpoint_hash: [u8; 32],
    /// Checkpoint sequence number
    pub checkpoint_number: u64,
}

impl SuiInclusionProof {
    /// Create a new Sui inclusion proof
    pub fn new(object_proof: Vec<u8>, checkpoint_hash: [u8; 32], checkpoint_number: u64) -> Self {
        Self {
            object_proof,
            checkpoint_hash,
            checkpoint_number,
        }
    }
}

/// Sui finality proof (2f+1 Byzantine agreement checkpoint)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiFinalityProof {
    /// Checkpoint sequence number
    pub checkpoint: u64,
    /// Whether checkpoint is certified
    pub is_certified: bool,
}

impl SuiFinalityProof {
    /// Create a new Sui finality proof
    pub fn new(checkpoint: u64, is_certified: bool) -> Self {
        Self {
            checkpoint,
            is_certified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_ref_creation() {
        let seal = SuiSealPoint::new([1u8; 32], 1, 42);
        assert_eq!(seal.version, 1);
    }

    #[test]
    fn test_anchor_ref_creation() {
        let anchor = SuiCommitAnchor::new([2u8; 32], [3u8; 32], 100);
        assert_eq!(anchor.checkpoint, 100);
    }
}
