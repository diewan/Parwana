//! Provenance metadata for chain-sourced proof material.

use serde::{Deserialize, Serialize};

/// Proof provenance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofProvenance {
    /// Chain ID
    #[serde(default)]
    pub chain_id: String,
    /// Block height
    #[serde(default)]
    pub block_height: u64,
    /// Timestamp
    #[serde(default)]
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
