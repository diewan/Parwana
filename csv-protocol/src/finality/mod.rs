//! Finality State Model
//!
//! This module provides a structured approach to defining and monitoring
//! different levels of transaction finality across chains.

#![allow(missing_docs)]

pub mod monitor;
pub mod policy;
pub mod state;
pub mod abstraction;
pub mod capabilities;

// Re-exports
pub use monitor::FinalityMonitor;
pub use policy::{ChainFinalityPolicy, FinalityThreshold};
pub use state::{FinalityState, FinalityStatus};
pub use abstraction::{FinalityType, FinalityRequirement};
pub use capabilities::{ChainCapabilities, Capability};

/// Proof that a specific chain state has been finalized and cannot be reversed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FinalityProof {
    pub chain_id: String,
    pub block_height: u64,
    pub finality_evidence: FinalityEvidence,
    pub confirmations: u64,
}

/// Evidence types for different chain finality mechanisms.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum FinalityEvidence {
    /// Bitcoin: block header with accumulated work
    CumulativeWork {
        header_hash: [u8; 32],
        cumulative_work: u128,
    },
    /// Ethereum: finalized checkpoint epoch number and root
    FinalizedCheckpoint {
        epoch: u64,
        checkpoint_root: [u8; 32],
    },
    /// Solana: finalized slot with bank hash
    FinalizedSlot { slot: u64, bank_hash: [u8; 32] },
    /// Aptos/Sui: validator-quorum certificate
    ValidatorCertificate {
        round: u64,
        certificate_hash: [u8; 32],
    },
    /// Celestia: DA header inclusion
    DaHeaderInclusion {
        height: u64,
        data_hash: [u8; 32],
    },
}

/// Separate from ChainVerifier. Adapters implement this independently.
/// This trait MUST be implemented before an adapter may be used in production.
pub trait FinalityVerifier: Send + Sync {
    /// Verify that the given block/slot/checkpoint is finalized.
    /// Returns FinalityProof on success; VerificationFailure on any failure.
    /// MUST NOT return Ok if finality is uncertain.
    fn verify_finality(
        &self,
        block_height: u64,
        chain_id: &str,
    ) -> Result<FinalityProof, crate::verified::VerificationFailure>;

    /// The chain capability this verifier satisfies.
    fn capabilities(&self) -> &ChainCapabilities;
}
