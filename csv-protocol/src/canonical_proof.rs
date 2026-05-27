//! Canonical proof anti-corruption layer.
//!
//! This module defines the CanonicalProof type which serves as the anti-corruption
//! layer between chain-specific proof formats and the protocol's verification logic.
//! Chain-specific fields remain in adapters and never leak into protocol/verifier.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical proof — protocol-agnostic proof representation.
///
/// This is the anti-corruption layer that normalizes chain-specific proof formats
/// into a canonical representation used by the verifier. Chain-specific fields
/// remain in adapters and never leak into protocol/verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalProof {
    /// Block height of the proof.
    pub block_height: u64,
    /// Block hash.
    pub block_hash: [u8; 32],
    /// State root.
    pub state_root: [u8; 32],
    /// Proof nodes (Merkle proof or accumulator path).
    pub proof_nodes: Vec<Vec<u8>>,
    /// Chain-specific metadata (key-value pairs for extensibility).
    pub metadata: HashMap<String, Vec<u8>>,
}

impl CanonicalProof {
    /// Create a new canonical proof.
    pub fn new(
        block_height: u64,
        block_hash: [u8; 32],
        state_root: [u8; 32],
        proof_nodes: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            block_height,
            block_hash,
            state_root,
            proof_nodes,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the proof.
    pub fn with_metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get metadata value by key.
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }

    /// Validate the proof has required fields.
    pub fn validate(&self) -> Result<(), ProofValidationError> {
        if self.block_hash == [0u8; 32] {
            return Err(ProofValidationError::ZeroBlockHash);
        }
        if self.state_root == [0u8; 32] {
            return Err(ProofValidationError::ZeroStateRoot);
        }
        if self.proof_nodes.is_empty() {
            return Err(ProofValidationError::EmptyProofNodes);
        }
        Ok(())
    }
}

/// Proof validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofValidationError {
    #[error("Block hash is all zeros")]
    ZeroBlockHash,
    #[error("State root is all zeros")]
    ZeroStateRoot,
    #[error("Proof nodes are empty")]
    EmptyProofNodes,
    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_canonical_proof() {
        let proof = CanonicalProof::new(
            100,
            [1u8; 32],
            [2u8; 32],
            vec![vec![3u8; 32], vec![4u8; 32]],
        );
        assert_eq!(proof.block_height, 100);
        assert_eq!(proof.block_hash, [1u8; 32]);
        assert_eq!(proof.state_root, [2u8; 32]);
        assert_eq!(proof.proof_nodes.len(), 2);
    }

    #[test]
    fn test_with_metadata() {
        let proof = CanonicalProof::new(100, [1u8; 32], [2u8; 32], vec![vec![3u8; 32]])
            .with_metadata("key1".to_string(), vec![5u8; 32])
            .with_metadata("key2".to_string(), vec![6u8; 32]);

        assert_eq!(proof.get_metadata("key1"), Some(&vec![5u8; 32]));
        assert_eq!(proof.get_metadata("key2"), Some(&vec![6u8; 32]));
        assert_eq!(proof.get_metadata("key3"), None);
    }

    #[test]
    fn test_validate_success() {
        let proof = CanonicalProof::new(100, [1u8; 32], [2u8; 32], vec![vec![3u8; 32]]);
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_block_hash() {
        let proof = CanonicalProof::new(100, [0u8; 32], [2u8; 32], vec![vec![3u8; 32]]);
        assert_eq!(proof.validate(), Err(ProofValidationError::ZeroBlockHash));
    }

    #[test]
    fn test_validate_zero_state_root() {
        let proof = CanonicalProof::new(100, [1u8; 32], [0u8; 32], vec![vec![3u8; 32]]);
        assert_eq!(proof.validate(), Err(ProofValidationError::ZeroStateRoot));
    }

    #[test]
    fn test_validate_empty_proof_nodes() {
        let proof = CanonicalProof::new(100, [1u8; 32], [2u8; 32], vec![]);
        assert_eq!(proof.validate(), Err(ProofValidationError::EmptyProofNodes));
    }
}
