//! Chain configuration stub module

use serde::{Deserialize, Serialize};

/// Ethereum finality stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthereumFinalityStage {
    /// Latest block
    Latest,
    /// Safe block
    Safe,
    /// Finalized block
    Finalized,
}

/// Solana commitment grade
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolanaCommitmentGrade {
    /// Processed
    Processed,
    /// Confirmed
    Confirmed,
    /// Finalized
    Finalized,
}

/// Chain capabilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCapabilities {
    /// Supports finality proofs
    pub supports_finality: bool,
    /// Supports inclusion proofs
    pub supports_inclusion: bool,
}

impl ChainCapabilities {
    /// Create new chain capabilities
    pub fn new(supports_finality: bool, supports_inclusion: bool) -> Self {
        Self {
            supports_finality,
            supports_inclusion,
        }
    }
}
