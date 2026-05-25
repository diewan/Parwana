//! Chain-native inclusion + finality bundle verification (RULE 1 / RULE 3).
//!
//! Adapters implement [`ChainNativeProofVerifier`] for RPC/MPT checks only.
//! Composing inclusion + finality into a bundle MUST use [`verify_chain_proof_bundle`]
//! so protocol semantics stay in csv-verifier, not adapter `ops.rs`.

use csv_hash::Hash;
use csv_protocol::proof::{FinalityProof, InclusionProof};
use csv_protocol::backend::{ChainOpError, ChainProofProvider};
use thiserror::Error;

/// Policy applied after native chain checks (confirmations window, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainBundlePolicy {
    /// Minimum confirmations required on the finality proof (chain-specific).
    pub min_confirmations: Option<u64>,
    /// Maximum confirmations before the proof is treated as stale.
    pub max_confirmations: Option<u64>,
}

impl ChainBundlePolicy {
    /// Bitcoin mainnet-style defaults (6 conf minimum, ~1 week max).
    pub fn bitcoin() -> Self {
        Self {
            min_confirmations: Some(6),
            max_confirmations: Some(1008),
        }
    }

    /// No extra confirmation policy (adapter/RPC already enforced finality).
    pub fn permissive() -> Self {
        Self::default()
    }
}

/// Errors from chain-native bundle verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainBundleError {
    /// Native inclusion check failed or returned an error.
    #[error("inclusion verification failed: {0}")]
    Inclusion(String),
    /// Native finality check failed or returned an error.
    #[error("finality verification failed: {0}")]
    Finality(String),
    /// Policy rejected the finality proof (confirmations window).
    #[error("finality policy rejected: {0}")]
    Policy(String),
}

/// Chain adapter surface for native proof checks only (no protocol bundle logic).
pub trait ChainNativeProofVerifier {
    /// Verify chain-native inclusion (MPT, object proof, etc.).
    fn verify_inclusion_proof(
        &self,
        proof: &InclusionProof,
        commitment: &Hash,
    ) -> Result<bool, ChainBundleError>;

    /// Verify chain-native finality for the anchor referenced by `anchor_ref`.
    fn verify_finality_proof(
        &self,
        proof: &FinalityProof,
        anchor_ref: &str,
    ) -> Result<bool, ChainBundleError>;
}

/// Derive the anchor reference string from an inclusion proof (block hash hex).
pub fn inclusion_anchor_ref(inclusion: &InclusionProof) -> String {
    hex::encode(inclusion.block_hash.as_bytes())
}

/// Canonical chain bundle verification — single composition path for adapters (RULE 1).
pub fn verify_chain_proof_bundle<V: ChainNativeProofVerifier + ?Sized>(
    verifier: &V,
    inclusion_proof: &InclusionProof,
    finality_proof: &FinalityProof,
    commitment: &Hash,
    policy: &ChainBundlePolicy,
) -> Result<bool, ChainBundleError> {
    if !verifier.verify_inclusion_proof(inclusion_proof, commitment)? {
        return Ok(false);
    }

    let anchor_ref = inclusion_anchor_ref(inclusion_proof);
    if !verifier.verify_finality_proof(finality_proof, &anchor_ref)? {
        return Ok(false);
    }

    if let Some(min) = policy.min_confirmations {
        if finality_proof.confirmations < min {
            return Ok(false);
        }
    }
    if let Some(max) = policy.max_confirmations {
        if finality_proof.confirmations > max {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Adapter object-safe wrapper for [`ChainProofProvider`] (SDK / runtime wiring).
pub struct DynChainProofVerifier<'a>(pub &'a dyn ChainProofProvider);

impl ChainNativeProofVerifier for DynChainProofVerifier<'_> {
    fn verify_inclusion_proof(
        &self,
        proof: &InclusionProof,
        commitment: &Hash,
    ) -> Result<bool, ChainBundleError> {
        self.0
            .verify_inclusion_proof(proof, commitment)
            .map_err(|e| ChainBundleError::Inclusion(e.to_string()))
    }

    fn verify_finality_proof(
        &self,
        proof: &FinalityProof,
        anchor_ref: &str,
    ) -> Result<bool, ChainBundleError> {
        self.0
            .verify_finality_proof(proof, anchor_ref)
            .map_err(|e| ChainBundleError::Finality(e.to_string()))
    }
}

/// Map [`ChainOpError`] from adapter calls.
impl From<ChainOpError> for ChainBundleError {
    fn from(e: ChainOpError) -> Self {
        ChainBundleError::Inclusion(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_protocol::proof::{FinalityProof, InclusionProof};

    struct AlwaysValid;

    impl ChainNativeProofVerifier for AlwaysValid {
        fn verify_inclusion_proof(
            &self,
            _proof: &InclusionProof,
            _commitment: &Hash,
        ) -> Result<bool, ChainBundleError> {
            Ok(true)
        }

        fn verify_finality_proof(
            &self,
            _proof: &FinalityProof,
            _anchor_ref: &str,
        ) -> Result<bool, ChainBundleError> {
            Ok(true)
        }
    }

    #[test]
    fn rejects_insufficient_confirmations() {
        let inclusion = InclusionProof::default();
        let mut finality = FinalityProof::default();
        finality.confirmations = 1;
        let commitment = Hash::zero();
        let ok = verify_chain_proof_bundle(
            &AlwaysValid,
            &inclusion,
            &finality,
            &commitment,
            &ChainBundlePolicy {
                min_confirmations: Some(6),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!ok);
    }
}
