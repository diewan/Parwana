//! Provenance metadata for chain-sourced proof material.

/// Proof provenance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofProvenance {
    /// Chain ID
    pub chain_id: String,
    /// Block height
    pub block_height: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl ProofProvenance {
    /// Create new proof provenance
    pub fn new(chain_id: String, block_height: u64, timestamp: u64) -> Self {
        Self {
            chain_id,
            block_height,
            timestamp,
        }
    }
}
