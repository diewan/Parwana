//! Chain configuration types for CSV protocol

use serde::{Deserialize, Serialize};

/// Chain configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID
    pub chain_id: String,
    /// Chain name
    pub chain_name: String,
    /// Block time in seconds
    pub block_time: u64,
    /// Finality threshold
    pub finality_threshold: u32,
}

impl ChainConfig {
    /// Create a new chain configuration
    pub fn new(
        chain_id: String,
        chain_name: String,
        block_time: u64,
        finality_threshold: u32,
    ) -> Self {
        Self {
            chain_id,
            chain_name,
            block_time,
            finality_threshold,
        }
    }
}
