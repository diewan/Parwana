//! Verification levels for proof verification results

use serde::Serialize;

/// Explicit verification tier returned by all proof verification paths.
///
/// Callers MUST check this. `is_valid: true` with `StructuralOnly`
/// does not constitute cryptographic proof of state transition validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLevel {
    /// Script/structure checked. No cryptographic proof verified.
    StructuralOnly,
    /// Merkle inclusion verified. Finality not yet confirmed.
    MerkleVerified,
    /// Full cryptographic verification complete.
    FullyVerified,
    /// Consensus-confirmed on source chain; finality threshold met.
    ConsensusVerified,
}
