//! Canonical proof anti-corruption layer.
//!
//! This module defines the CanonicalProof type which serves as the anti-corruption
//! layer between chain-specific proof formats and the protocol's verification logic.
//! Chain-specific fields remain in adapters and never leak into protocol/verifier.

use csv_codec::manual_encoder::{CanonicalEncoding, EncodingFormat, ManualEncoder};
use csv_codec::CodecError;
use std::collections::HashMap;

/// Canonical proof — protocol-agnostic proof representation.
///
/// This is the anti-corruption layer that normalizes chain-specific proof formats
/// into a canonical representation used by the verifier. Chain-specific fields
/// remain in adapters and never leak into protocol/verifier.
///
/// **Layer:** L1
/// **Serde:** FORBIDDEN - uses manual CanonicalEncoding via csv-codec
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl CanonicalEncoding for CanonicalProof {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => self.encode_manual(),
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self> where Self: Sized {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::decode_manual(bytes),
        }
    }

    fn encode_mce(&self) -> csv_codec::CodecResult<Vec<u8>> {
        // MCE format: fixed-width encoding
        // block_height(8) + block_hash(32) + state_root(32) + proof_nodes_count(4) + proof_nodes...
        let mut result = Vec::new();
        result.extend_from_slice(&ManualEncoder::encode_u64_le(self.block_height));
        result.extend_from_slice(&ManualEncoder::encode_hash(&self.block_hash));
        result.extend_from_slice(&ManualEncoder::encode_hash(&self.state_root));
        result.extend_from_slice(&ManualEncoder::encode_u32_le(self.proof_nodes.len() as u32));
        for node in &self.proof_nodes {
            result.extend_from_slice(&ManualEncoder::encode_u32_le(node.len() as u32));
            result.extend_from_slice(node);
        }
        // Encode metadata as key-value pairs
        result.extend_from_slice(&ManualEncoder::encode_u32_le(self.metadata.len() as u32));
        for (key, value) in &self.metadata {
            result.extend_from_slice(&ManualEncoder::encode_bytes(key.as_bytes()));
            result.extend_from_slice(&ManualEncoder::encode_bytes(value));
        }
        Ok(result)
    }

    fn decode_mce(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        let mut pos = 0;
        let block_height = ManualEncoder::decode_u64_le(bytes, &mut pos)?;
        let block_hash = ManualEncoder::decode_hash(bytes, &mut pos)?;
        let state_root = ManualEncoder::decode_hash(bytes, &mut pos)?;
        let proof_nodes_count = ManualEncoder::decode_u32_le(bytes, &mut pos)? as usize;
        let mut proof_nodes = Vec::with_capacity(proof_nodes_count);
        for _ in 0..proof_nodes_count {
            let node_len = ManualEncoder::decode_u32_le(bytes, &mut pos)? as usize;
            if bytes.len() < pos + node_len {
                return Err(CodecError::DeserializationError("Insufficient bytes for proof node".to_string()));
            }
            proof_nodes.push(bytes[pos..pos + node_len].to_vec());
            pos += node_len;
        }
        let metadata_count = ManualEncoder::decode_u32_le(bytes, &mut pos)? as usize;
        let mut metadata = HashMap::new();
        for _ in 0..metadata_count {
            let key = ManualEncoder::decode_bytes(bytes, &mut pos)?;
            let value = ManualEncoder::decode_bytes(bytes, &mut pos)?;
            metadata.insert(String::from_utf8(key).map_err(|e| CodecError::DeserializationError(format!("Invalid metadata key: {}", e)))?, value);
        }
        Ok(Self {
            block_height,
            block_hash,
            state_root,
            proof_nodes,
            metadata,
        })
    }

    fn encode_manual(&self) -> csv_codec::CodecResult<Vec<u8>> {
        // Manual binary format: length-prefixed encoding
        let mut result = Vec::new();
        result.extend_from_slice(&ManualEncoder::encode_u64_le(self.block_height));
        result.extend_from_slice(&ManualEncoder::encode_bytes(&self.block_hash));
        result.extend_from_slice(&ManualEncoder::encode_bytes(&self.state_root));
        result.extend_from_slice(&ManualEncoder::encode_u32_le(self.proof_nodes.len() as u32));
        for node in &self.proof_nodes {
            result.extend_from_slice(&ManualEncoder::encode_bytes(node));
        }
        result.extend_from_slice(&ManualEncoder::encode_u32_le(self.metadata.len() as u32));
        for (key, value) in &self.metadata {
            result.extend_from_slice(&ManualEncoder::encode_bytes(key.as_bytes()));
            result.extend_from_slice(&ManualEncoder::encode_bytes(value));
        }
        Ok(result)
    }

    fn decode_manual(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        let mut pos = 0;
        let block_height = ManualEncoder::decode_u64_le(bytes, &mut pos)?;
        let block_hash = ManualEncoder::decode_hash(bytes, &mut pos)?;
        let state_root = ManualEncoder::decode_hash(bytes, &mut pos)?;
        let proof_nodes_count = ManualEncoder::decode_u32_le(bytes, &mut pos)? as usize;
        let mut proof_nodes = Vec::with_capacity(proof_nodes_count);
        for _ in 0..proof_nodes_count {
            proof_nodes.push(ManualEncoder::decode_bytes(bytes, &mut pos)?);
        }
        let metadata_count = ManualEncoder::decode_u32_le(bytes, &mut pos)? as usize;
        let mut metadata = HashMap::new();
        for _ in 0..metadata_count {
            let key = ManualEncoder::decode_bytes(bytes, &mut pos)?;
            let value = ManualEncoder::decode_bytes(bytes, &mut pos)?;
            metadata.insert(String::from_utf8(key).map_err(|e| CodecError::DeserializationError(format!("Invalid metadata key: {}", e)))?, value);
        }
        Ok(Self {
            block_height,
            block_hash,
            state_root,
            proof_nodes,
            metadata,
        })
    }
}

impl CanonicalProof {
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
