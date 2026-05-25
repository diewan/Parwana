//! Proof pipeline traits — chain-specific verification hooks.
//!
//! Canonical bundle verification lives in `csv-verifier`; this module exposes
//! async chain hooks used by adapters and the wallet.

use async_trait::async_trait;

use crate::error::Result;
use csv_hash::Hash;
use csv_protocol::proof_types::{FinalityProof, InclusionProof, ProofBundle};
use csv_protocol::verified::VerificationResult;

/// Chain-specific verifier used during proof and seal checks.
#[async_trait]
pub trait ChainVerifier: Send + Sync {
    /// Verify an inclusion proof against an expected state root.
    async fn verify_inclusion(
        &self,
        proof: &InclusionProof,
        expected_root: Hash,
    ) -> Result<VerificationResult>;

    /// Verify finality proof data.
    async fn verify_finality(&self, proof: &FinalityProof) -> Result<VerificationResult>;

    /// Verify a zero-knowledge proof payload.
    async fn verify_zk(&self, proof: &[u8]) -> Result<VerificationResult>;

    /// Check seal registry (returns valid=true if seal is available).
    async fn verify_seal_registry(&self, seal_id: Hash) -> Result<VerificationResult>;

    /// Verify bundle signatures.
    async fn verify_signature(&self, bundle: &ProofBundle) -> Result<VerificationResult>;
}

/// Validate proof bundle structure (structural checks; full crypto via `csv-verifier`).
pub async fn validate_proof_bundle(
    bundle: &ProofBundle,
    _verifier: &dyn ChainVerifier,
) -> Result<VerificationResult> {
    if bundle.seal_ref.id.is_empty() {
        return Ok(VerificationResult::invalid(
            csv_protocol::verified::VerificationFailure::MissingData("empty seal id".into()),
        ));
    }
    if bundle.inclusion_proof.proof_bytes.is_empty() {
        return Ok(VerificationResult::invalid(
            csv_protocol::verified::VerificationFailure::MissingData(
                "empty inclusion proof".into(),
            ),
        ));
    }
    Ok(VerificationResult::valid_structural())
}
