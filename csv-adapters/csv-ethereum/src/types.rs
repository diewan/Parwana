//! Ethereum-specific type definitions

use serde::{Deserialize, Serialize};

/// Ethereum seal reference (storage slot with one-time write)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthereumSealPoint {
    /// Contract address
    pub contract_address: [u8; 20],
    /// Storage slot index
    pub slot_index: u64,
    /// Nonce for replay resistance
    pub nonce: u64,
    /// 32-byte seal identifier used for the SealUsed event
    pub seal_id: [u8; 32],
}

impl EthereumSealPoint {
    /// Create a new Ethereum seal reference
    pub fn new(contract_address: [u8; 20], slot_index: u64, nonce: u64) -> Self {
        let mut seal_id = [0u8; 32];
        seal_id[..20].copy_from_slice(&contract_address);
        seal_id[20..28].copy_from_slice(&slot_index.to_le_bytes());
        seal_id[28..].copy_from_slice(&nonce.to_le_bytes()[..4]); // Only use first 4 bytes for nonce to fit 32
        Self {
            contract_address,
            slot_index,
            nonce,
            seal_id,
        }
    }

    /// Serialize to bytes
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + 8 + 8);
        out.extend_from_slice(&self.contract_address);
        out.extend_from_slice(&self.slot_index.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }
}

/// Ethereum anchor reference (Transaction + log index)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EthereumCommitAnchor {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Log index within the transaction
    pub log_index: u64,
    /// Block number
    pub block_number: u64,
}

impl EthereumCommitAnchor {
    /// Create a new Ethereum anchor reference
    pub fn new(tx_hash: [u8; 32], log_index: u64, block_number: u64) -> Self {
        Self {
            tx_hash,
            log_index,
            block_number,
        }
    }
}

/// Ethereum inclusion proof (receipt proof + Merkle-Patricia proof)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumInclusionProof {
    /// Receipt RLP bytes
    pub receipt_rlp: Vec<u8>,
    /// Merkle-Patricia proof bytes
    pub merkle_proof: Vec<u8>,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Block number
    pub block_number: u64,
    /// Log index
    pub log_index: u64,
}

impl EthereumInclusionProof {
    /// Create a new Ethereum inclusion proof
    pub fn new(
        receipt_rlp: Vec<u8>,
        merkle_proof: Vec<u8>,
        block_hash: [u8; 32],
        block_number: u64,
        log_index: u64,
    ) -> Self {
        Self {
            receipt_rlp,
            merkle_proof,
            block_hash,
            block_number,
            log_index,
        }
    }

    /// Check if confirmed with required depth
    pub fn is_confirmed(&self, current_block: u64, required_depth: u64) -> bool {
        self.block_number + required_depth <= current_block
    }
}

/// Ethereum finality proof (confirmations or finalized checkpoint)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumFinalityProof {
    /// Number of confirmations
    pub confirmations: u64,
    /// Whether the block is finalized (post-merge)
    pub is_finalized: bool,
    /// Required confirmation depth
    pub required_depth: u64,
}

impl EthereumFinalityProof {
    /// Create a new Ethereum finality proof
    pub fn new(confirmations: u64, required_depth: u64, is_finalized: bool) -> Self {
        Self {
            confirmations,
            is_finalized,
            required_depth,
        }
    }

    /// Check if finality is achieved
    pub fn is_final(&self) -> bool {
        self.is_finalized || self.confirmations >= self.required_depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_ref_creation() {
        let seal = EthereumSealPoint::new([1u8; 20], 42, 1);
        assert_eq!(seal.slot_index, 42);
        assert_eq!(seal.nonce, 1);
    }

    #[test]
    fn test_anchor_ref_creation() {
        let anchor = EthereumCommitAnchor::new([2u8; 32], 5, 1000);
        assert_eq!(anchor.log_index, 5);
        assert_eq!(anchor.block_number, 1000);
    }

    #[test]
    fn test_inclusion_proof_confirmed() {
        let proof = EthereumInclusionProof::new(vec![], vec![], [3u8; 32], 1000, 5);
        assert!(proof.is_confirmed(1015, 15));
        assert!(!proof.is_confirmed(1010, 15));
    }

    #[test]
    fn test_finality_proof() {
        let proof = EthereumFinalityProof::new(15, 15, false);
        assert!(proof.is_final());

        let proof = EthereumFinalityProof::new(10, 15, false);
        assert!(!proof.is_final());

        let proof = EthereumFinalityProof::new(5, 15, true);
        assert!(proof.is_final()); // Finalized via checkpoint
    }
}
