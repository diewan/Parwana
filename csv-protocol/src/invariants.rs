//! Protocol invariants
//!
//! This module defines the core invariants that the CSV protocol must maintain.
//! These invariants are enforced through the type system and verification logic.

use std::fmt;

/// Protocol invariant violations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// Proof size exceeds maximum
    ProofSizeExceeded,
    /// Finality data size exceeds maximum
    FinalityDataSizeExceeded,
    /// Signatures size exceeds maximum
    SignaturesSizeExceeded,
    /// Proof bundle size exceeds maximum
    ProofBundleSizeExceeded,
    /// Confirmations below minimum
    InsufficientConfirmations,
    /// Proof age exceeds maximum
    ProofExpired,
    /// Invalid state transition
    InvalidStateTransition,
    /// Replay detected
    ReplayDetected,
}

impl fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantViolation::ProofSizeExceeded => write!(f, "Proof size exceeds maximum"),
            InvariantViolation::FinalityDataSizeExceeded => write!(f, "Finality data size exceeds maximum"),
            InvariantViolation::SignaturesSizeExceeded => write!(f, "Signatures size exceeds maximum"),
            InvariantViolation::ProofBundleSizeExceeded => write!(f, "Proof bundle size exceeds maximum"),
            InvariantViolation::InsufficientConfirmations => write!(f, "Confirmations below minimum"),
            InvariantViolation::ProofExpired => write!(f, "Proof age exceeds maximum"),
            InvariantViolation::InvalidStateTransition => write!(f, "Invalid state transition"),
            InvariantViolation::ReplayDetected => write!(f, "Replay detected"),
        }
    }
}

impl std::error::Error for InvariantViolation {}

/// Result type for invariant checks
pub type InvariantResult<T> = Result<T, InvariantViolation>;
