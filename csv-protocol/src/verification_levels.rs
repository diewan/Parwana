//! Verification levels for proof verification results

/// Explicit verification tier returned by all proof verification paths.
///
/// Callers MUST check this. `is_valid: true` with `StructuralOnly`
/// does not constitute cryptographic proof of state transition validity.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
