//! Multi-dimensional verification result types.
//!
//! Inclusion strength and finality strength are orthogonal — do not collapse
//! them into a single scalar. The production gate (`meets_chain_thresholds`)
//! checks each component against the per-chain minimum declared in
//! `ChainCapabilities`, not against a total ordering.

#![allow(missing_docs)]
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Coarse assurance level. Useful for UI display and logging.
/// NOT a total ordering suitable for mint authorization — use
/// `VerificationResult::meets_chain_thresholds` for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationAssurance {
    /// Proof structure was parsed but no cryptographic check performed.
    Structural,
    /// At least one cryptographic check passed (e.g. Merkle path or signature)
    /// but not all components are verified.
    PartialCryptographic,
    /// All cryptographic checks passed. Finality may still be pending.
    Cryptographic,
    /// All cryptographic checks passed AND finality confirmed per chain policy.
    ConsensusBound,
}

/// Typed strength for inclusion proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InclusionStrength {
    /// Not checked.
    None,
    /// Internal checksum only — not cryptographically binding.
    Checksum,
    /// Full Merkle branch or MPT path verified against a block/state root.
    MerklePath,
    /// Merkle path verified AND root anchored to a trusted state (light client).
    AnchoredMerklePath,
}

/// Typed strength for finality verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityStrength {
    /// Not checked.
    None,
    /// Probabilistic finality: N confirmations on a PoW chain.
    Probabilistic { confirmations: u64 },
    /// Deterministic finality: BFT certificate or finalized checkpoint.
    Deterministic,
}

/// Per-component verification record. Each field is independently checked.
/// The production gate reads this struct directly — it does not reduce
/// components to a scalar before comparing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedComponents {
    pub inclusion: InclusionStrength,
    pub finality: FinalityStrength,
    pub replay_checked: bool,
    pub ownership_signature: bool,
}

/// Explicit failure reason. Replaces `Ok(false)`, `Ok(vec![])`, `Err(String)`.
#[derive(Debug, Clone, Serialize, Deserialize, Error)]
pub enum VerificationFailure {
    #[error("Inclusion proof Merkle path is invalid")]
    InvalidMerklePath,
    #[error("Proof of work does not meet target")]
    InvalidProofOfWork,
    #[error("Pairing equation check failed (Groth16)")]
    PairingCheckFailed,
    #[error("Seal has already been consumed (replay detected)")]
    ReplayDetected,
    #[error("Required finality depth not reached: need {required}, have {actual}")]
    FinalityNotReached { required: u64, actual: u64 },
    #[error("Chain reorg detected at height {0}")]
    ReorgDetected(u64),
    #[error("RPC nodes disagree on chain state")]
    RpcDisagreement,
    #[error("Required data is missing from proof bundle: {0}")]
    MissingData(String),
    #[error("Chain capability not supported: {0}")]
    UnsupportedCapability(String),
    #[error("Ownership signature verification failed")]
    InvalidOwnershipSignature,
    #[error("Chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: String, actual: String },
    #[error("Seal ID mismatch in proof bundle")]
    SealIdMismatch,
    #[error("Verification failed: {0}")]
    Failed(String),
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
}

/// A strongly-typed verification result.
/// `valid: false` means the proof was checked and failed — not that it was skipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub assurance: VerificationAssurance,
    pub verified_components: VerifiedComponents,
    pub error: Option<VerificationFailure>,
}

impl VerificationResult {
    /// Create a valid structural result (no cryptographic checks).
    pub fn valid_structural() -> Self {
        Self {
            valid: true,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::Checksum,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        }
    }

    /// Create an invalid result with an error.
    pub fn invalid(error: VerificationFailure) -> Self {
        Self {
            valid: false,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: Some(error),
        }
    }

    /// Check each component against the per-chain minimums declared in
    /// ChainCapabilities. This is the production mint authorization gate.
    /// Do NOT replace this with a scalar enum comparison.
    pub fn meets_chain_thresholds(
        &self,
        caps: &crate::finality::capabilities::ChainCapabilities,
    ) -> Result<(), VerificationFailure> {
        if !self.valid {
            return Err(self.error.clone().unwrap_or(
                VerificationFailure::InvalidMerklePath
            ));
        }
        // Check inclusion independently of finality
        if !caps.inclusion_threshold_met(&self.verified_components.inclusion) {
            return Err(VerificationFailure::InvalidMerklePath);
        }
        // Check finality independently of inclusion
        if !caps.finality_threshold_met(&self.verified_components.finality) {
            return Err(VerificationFailure::FinalityNotReached {
                required: caps.finality_depth,
                actual: match self.verified_components.finality {
                    FinalityStrength::Probabilistic { confirmations } => confirmations,
                    FinalityStrength::Deterministic => caps.finality_depth,
                    FinalityStrength::None => 0,
                },
            });
        }
        Ok(())
    }
}
