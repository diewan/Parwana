//! Verification types for CSV protocol

use thiserror::Error;

/// Verification failure
#[derive(Debug, Error)]
pub enum VerificationFailure {
    /// Verification failed
    #[error("Verification failed: {0}")]
    Failed(String),

    /// Invalid proof
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Finality not reached
    #[error("Finality not reached: {0}")]
    FinalityNotReached(String),
}
