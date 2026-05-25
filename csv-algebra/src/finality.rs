/// Pure finality types.
///
/// Cryptographic commitment types for finality evidence.
/// No serde, no IO, no infrastructure dependencies.

use alloc::vec::Vec;

/// Evidence of finality for a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityEvidence {
    /// Block hash that is finalized
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Quorum certificate or equivalent proof
    pub proof_data: Vec<u8>,
    /// Timestamp when finality was achieved
    pub timestamp: u64,
}

impl FinalityEvidence {
    pub fn new(block_hash: [u8; 32], block_height: u64, proof_data: Vec<u8>, timestamp: u64) -> Self {
        Self {
            block_hash,
            block_height,
            proof_data,
            timestamp,
        }
    }

    pub fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    pub fn proof_data(&self) -> &[u8] {
        &self.proof_data
    }
}
