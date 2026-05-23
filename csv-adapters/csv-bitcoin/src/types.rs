//! Bitcoin-specific type definitions

use serde::{Deserialize, Serialize};

/// Bitcoin seal reference (UTXO OutPoint)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BitcoinSealPoint {
    /// Transaction ID (32 bytes)
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Optional nonce for replay resistance
    pub nonce: Option<u64>,
}

impl BitcoinSealPoint {
    /// Create a new Bitcoin seal reference
    pub fn new(txid: [u8; 32], vout: u32, nonce: Option<u64>) -> Self {
        Self { txid, vout, nonce }
    }

    /// Serialize to bytes
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 8);
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.vout.to_le_bytes());
        if let Some(nonce) = self.nonce {
            out.extend_from_slice(&nonce.to_le_bytes());
        } else {
            out.extend_from_slice(&[0u8; 8]);
        }
        out
    }

    /// Get txid as hex string
    pub fn txid_hex(&self) -> String {
        hex::encode(self.txid)
    }
}

/// Bitcoin anchor reference (Transaction containing commitment)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BitcoinCommitAnchor {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Output index (for OP_RETURN or Taproot leaf)
    pub output_index: u32,
    /// Block height where transaction was included
    pub block_height: u64,
}

impl BitcoinCommitAnchor {
    /// Create a new Bitcoin anchor reference
    pub fn new(txid: [u8; 32], output_index: u32, block_height: u64) -> Self {
        Self {
            txid,
            output_index,
            block_height,
        }
    }
}

/// Bitcoin inclusion proof (Merkle proof + block header)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinInclusionProof {
    /// Merkle branch hashes
    pub merkle_branch: Vec<[u8; 32]>,
    /// Block header hash
    pub block_hash: [u8; 32],
    /// Transaction index in block
    pub tx_index: u32,
    /// Block height
    pub block_height: u64,
}

impl BitcoinInclusionProof {
    /// Create a new Bitcoin inclusion proof
    pub fn new(
        merkle_branch: Vec<[u8; 32]>,
        block_hash: [u8; 32],
        tx_index: u32,
        block_height: u64,
    ) -> Self {
        Self {
            merkle_branch,
            block_hash,
            tx_index,
            block_height,
        }
    }

    /// Check if confirmed with required depth
    pub fn is_confirmed(&self, current_height: u64, required_depth: u32) -> bool {
        self.block_height + required_depth as u64 <= current_height
    }
}

/// Bitcoin finality proof (confirmation depth)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinFinalityProof {
    /// Number of confirmations
    pub confirmations: u64,
    /// Whether the required depth is met
    pub meets_required_depth: bool,
    /// Required confirmation depth
    pub required_depth: u32,
}

impl BitcoinFinalityProof {
    /// Create a new Bitcoin finality proof
    pub fn new(confirmations: u64, required_depth: u32) -> Self {
        Self {
            confirmations,
            meets_required_depth: confirmations >= required_depth as u64,
            required_depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_ref_creation() {
        let seal = BitcoinSealPoint::new([1u8; 32], 0, Some(42));
        assert_eq!(seal.vout, 0);
        assert_eq!(seal.nonce, Some(42));
    }

    #[test]
    fn test_anchor_ref_creation() {
        let anchor = BitcoinCommitAnchor::new([2u8; 32], 1, 100);
        assert_eq!(anchor.output_index, 1);
        assert_eq!(anchor.block_height, 100);
    }

    #[test]
    fn test_inclusion_proof_confirmed() {
        let proof = BitcoinInclusionProof::new(vec![], [3u8; 32], 0, 100);
        assert!(proof.is_confirmed(106, 6));
        assert!(!proof.is_confirmed(105, 6));
    }

    #[test]
    fn test_finality_proof() {
        let proof = BitcoinFinalityProof::new(6, 6);
        assert!(proof.meets_required_depth);

        let proof = BitcoinFinalityProof::new(5, 6);
        assert!(!proof.meets_required_depth);
    }
}
