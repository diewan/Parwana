//! Proof bundle types for off-chain verification
//!
//! Proof bundles are exchanged between peers for verification.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use std::vec::Vec;

use crate::provenance::ProofProvenance;
use csv_hash::Hash;
use csv_hash::HashDomain;
use csv_hash::canonical::to_canonical_cbor;
use csv_hash::dag::DAGSegment;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_hash::tagged_hash::tagged_hash;

// Re-export canonical proof types from proof_types
pub use crate::proof_types::{FinalityProof, InclusionProof};

/// Maximum proof bundle size in bytes
pub const MAX_PROOF_BYTES: usize = 1_000_000;
/// Maximum finality data size in bytes
pub const MAX_FINALITY_DATA: usize = 100_000;
/// Maximum total signatures size
pub const MAX_SIGNATURES_TOTAL_SIZE: usize = 10_000;

/// Globally unique transfer identity. Prevents replay across process restarts
/// and across chain reorganizations.
///
/// Every transfer MUST derive a ReplayId before any state transition.
/// The replay database is append-only; a ReplayId already present means
/// the transfer has been seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayId {
    /// Protocol version this replay ID was generated for
    pub version: u32,
    /// 32-byte replay ID payload
    pub id: [u8; 32],
}

impl ReplayId {
    /// Current protocol version for replay IDs.
    pub const CURRENT_VERSION: u32 = 1;

    /// Derive a ReplayId from all inputs that uniquely identify a transfer.
    /// The hash binds together source chain, transaction, seal, transition,
    /// and destination chain so that no two legitimate transfers share an ID.
    /// Uses canonical CBOR serialization + tagged hashing.
    ///
    /// Returns error if CBOR serialization fails, ensuring replay ID correctness.
    pub fn derive(
        source_chain: &str,
        source_txid: &[u8],
        source_output_index: u32,
        seal_id: &[u8],
        transition_id: &[u8],
        destination_chain: &str,
    ) -> crate::error::Result<Self> {
        #[derive(Serialize)]
        struct ReplayIdInputs<'a> {
            source_chain: &'a str,
            source_txid: &'a [u8],
            source_output_index: u32,
            seal_id: &'a [u8],
            transition_id: &'a [u8],
            destination_chain: &'a str,
        }
        let inputs = ReplayIdInputs {
            source_chain,
            source_txid,
            source_output_index,
            seal_id,
            transition_id,
            destination_chain,
        };
        let cbor = to_canonical_cbor(&inputs).map_err(|e| {
            crate::error::ProofError::SerializationError(format!(
                "Failed to serialize replay ID inputs: {}",
                e
            ))
        })?;
        let id = tagged_hash(HashDomain::ReplayIdV1, &cbor).hash.0;
        Ok(ReplayId {
            version: Self::CURRENT_VERSION,
            id,
        })
    }

    /// Return the raw 32-byte replay ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.id
    }

    /// Derive a ReplayId from a cross-chain transfer proof.
    ///
    /// Binds together source chain, lock tx hash, source seal,
    /// destination chain, and sanad ID for deterministic replay prevention.
    ///
    /// Returns error if CBOR serialization fails, ensuring replay ID correctness.
    pub fn from_cross_chain_proof(
        proof: &crate::cross_chain::CrossChainTransferProof,
    ) -> crate::error::Result<Self> {
        use csv_hash::canonical::to_canonical_cbor;

        #[derive(Serialize)]
        struct CrossChainReplayInputs<'a> {
            source_chain: &'a str,
            lock_tx_hash: &'a [u8; 32],
            source_seal: &'a [u8],
            destination_chain: &'a str,
            sanad_id: &'a [u8; 32],
        }

        let inputs = CrossChainReplayInputs {
            source_chain: proof.lock_event.source_chain.as_str(),
            lock_tx_hash: proof.lock_event.source_tx_hash.as_bytes(),
            source_seal: proof.lock_event.source_seal.id.as_bytes(),
            destination_chain: proof.lock_event.destination_chain.as_str(),
            sanad_id: proof.lock_event.sanad_id.as_bytes(),
        };

        let cbor = to_canonical_cbor(&inputs).map_err(|e| {
            crate::error::ProofError::SerializationError(format!(
                "Failed to serialize cross-chain replay inputs: {}",
                e
            ))
        })?;
        let id = tagged_hash(HashDomain::ReplayIdV1, &cbor).hash.0;
        Ok(ReplayId {
            version: Self::CURRENT_VERSION,
            id,
        })
    }
}

#[cfg(test)]
mod replay_id_tests {
    use super::*;

    #[test]
    fn test_replay_id_determinism() {
        let id1 = ReplayId::derive("bitcoin", &[1u8; 32], 0, &[2u8; 32], &[3u8; 32], "ethereum")
            .expect("replay ID derivation should succeed");
        let id2 = ReplayId::derive("bitcoin", &[1u8; 32], 0, &[2u8; 32], &[3u8; 32], "ethereum")
            .expect("replay ID derivation should succeed");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_replay_id_uniqueness() {
        let id1 = ReplayId::derive("bitcoin", &[1u8; 32], 0, &[2u8; 32], &[3u8; 32], "ethereum")
            .expect("replay ID derivation should succeed");
        let id2 = ReplayId::derive(
            "bitcoin", &[1u8; 32], 0, &[2u8; 32], &[3u8; 32],
            "solana", // different destination
        )
        .expect("replay ID derivation should succeed");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_replay_id_different_txid() {
        let id1 = ReplayId::derive("bitcoin", &[1u8; 32], 0, &[2u8; 32], &[3u8; 32], "ethereum")
            .expect("replay ID derivation should succeed");
        let id2 = ReplayId::derive("bitcoin", &[9u8; 32], 0, &[2u8; 32], &[3u8; 32], "ethereum")
            .expect("replay ID derivation should succeed");
        assert_ne!(id1, id2);
    }
}

/// Complete proof bundle for peer-to-peer verification
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Protocol version this bundle conforms to
    pub version: u32,
    /// State transition DAG segment
    pub transition_dag: DAGSegment,
    /// Authorizing signatures
    pub signatures: Vec<Vec<u8>>,
    /// Seal reference
    pub seal_ref: SealPoint,
    /// Anchor reference
    pub anchor_ref: CommitAnchor,
    /// Inclusion proof
    pub inclusion_proof: InclusionProof,
    /// Finality proof
    pub finality_proof: FinalityProof,
    /// Provenance metadata for tracking proof origin and verification chain
    pub provenance: Option<crate::provenance::ProofProvenance>,
    /// Deterministic certification for reproducible verification
    pub certification: Option<crate::certification::ProofCertification>,
}

impl ProofBundle {
    /// Current protocol version for proof bundles.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new proof bundle
    ///
    /// # Arguments
    /// * `transition_dag` - State transition DAG segment
    /// * `signatures` - Authorizing signatures (total max 1MB)
    /// * `seal_ref` - Seal reference
    /// * `anchor_ref` - Anchor reference
    /// * `inclusion_proof` - Inclusion proof
    /// * `finality_proof` - Finality proof
    ///
    /// # Errors
    /// Returns an error if signatures exceed the maximum total size
    pub fn new(
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
    ) -> Result<Self, &'static str> {
        Self::with_certification(
            Self::CURRENT_VERSION,
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
            None,
            None,
        )
    }

    /// Create a new proof bundle with provenance metadata
    ///
    /// # Arguments
    /// * `transition_dag` - State transition DAG segment
    /// * `signatures` - Authorizing signatures (total max 1MB)
    /// * `seal_ref` - Seal reference
    /// * `anchor_ref` - Anchor reference
    /// * `inclusion_proof` - Inclusion proof
    /// * `finality_proof` - Finality proof
    /// * `provenance` - Optional provenance metadata
    ///
    /// # Errors
    /// Returns an error if signatures exceed the maximum total size
    pub fn with_provenance(
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
        provenance: Option<crate::provenance::ProofProvenance>,
    ) -> Result<Self, &'static str> {
        Self::with_certification(
            Self::CURRENT_VERSION,
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
            provenance,
            None,
        )
    }

    /// Create a new proof bundle with certification
    ///
    /// # Arguments
    /// * `version` - Protocol version this bundle conforms to
    /// * `transition_dag` - State transition DAG segment
    /// * `signatures` - Authorizing signatures (total max 1MB)
    /// * `seal_ref` - Seal reference
    /// * `anchor_ref` - Anchor reference
    /// * `inclusion_proof` - Inclusion proof
    /// * `finality_proof` - Finality proof
    /// * `provenance` - Optional provenance metadata
    /// * `certification` - Optional deterministic certification
    ///
    /// # Errors
    /// Returns an error if signatures exceed the maximum total size
    pub fn with_certification(
        version: u32,
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
        provenance: Option<crate::provenance::ProofProvenance>,
        certification: Option<crate::certification::ProofCertification>,
    ) -> Result<Self, &'static str> {
        // Validate total signature size
        let total_sig_size: usize = signatures.iter().map(|s: &Vec<u8>| s.len()).sum();
        if total_sig_size > MAX_SIGNATURES_TOTAL_SIZE {
            return Err("total signatures size exceeds maximum allowed (1MB)");
        }
        Ok(Self {
            version,
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
            provenance,
            certification,
        })
    }

    /// Set the provenance metadata
    pub fn set_provenance(&mut self, provenance: crate::provenance::ProofProvenance) {
        self.provenance = Some(provenance);
    }

    /// Get the provenance metadata
    pub fn provenance(&self) -> Option<&crate::provenance::ProofProvenance> {
        self.provenance.as_ref()
    }

    /// Check if the proof bundle has complete provenance
    pub fn has_complete_provenance(&self) -> bool {
        self.provenance
            .as_ref()
            .map(|p: &crate::provenance::ProofProvenance| p.is_verification_complete())
            .unwrap_or(false)
    }

    /// Set the certification metadata
    pub fn set_certification(&mut self, certification: crate::certification::ProofCertification) {
        self.certification = Some(certification);
    }

    /// Get the certification metadata
    pub fn certification(&self) -> Option<&crate::certification::ProofCertification> {
        self.certification.as_ref()
    }

    /// Check if the proof bundle has deterministic certification
    pub fn has_certification(&self) -> bool {
        self.certification.is_some()
    }

    /// Create a new $1 without validation.
    ///
    /// # Safety
    /// The caller MUST ensure all fields are valid and consistent.
    pub unsafe fn new_unchecked(
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
            provenance: None,
            certification: None,
        }
    }

    /// Serialize the proof bundle using canonical CBOR
    pub fn to_bytes(&self) -> Result<Vec<u8>, csv_codec::CodecError> {
        csv_codec::to_canonical_cbor(self)
    }

    /// Deserialize the proof bundle with size limit (10MB max)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, csv_codec::CodecError> {
        const MAX_SIZE: usize = 10 * 1024 * 1024; // 10MB
        if bytes.len() > MAX_SIZE {
            return Err(csv_codec::CodecError::SerializationError(format!(
                "ProofBundle too large: {} bytes (max {})",
                bytes.len(),
                MAX_SIZE
            )));
        }
        csv_codec::from_canonical_cbor(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inclusion_proof_creation() {
        let proof = InclusionProof::new(vec![1, 2, 3], Hash::zero(), 0, 0).unwrap();
        assert_eq!(proof.proof_bytes, vec![1, 2, 3]);
    }

    #[test]
    fn test_proof_bundle_without_provenance() {
        let proof = FinalityProof::new(vec![0xCD; 32], 6, false).unwrap();
        assert_eq!(proof.confirmations, 6);
        assert!(!proof.is_deterministic);
    }

    #[test]
    fn test_proof_bundle_serialization() {
        let bundle = ProofBundle::new(
            DAGSegment::new(vec![], Hash::zero()),
            vec![vec![0xAB; 64]],
            SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
            CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
            InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
            FinalityProof::new(vec![], 6, false).unwrap(),
        )
        .unwrap();

        let bytes = bundle.to_bytes().unwrap();
        let restored = ProofBundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle, restored);
    }

    #[test]
    fn test_inclusion_proof_too_large() {
        let large_proof = vec![0u8; MAX_PROOF_BYTES + 1];
        let result = InclusionProof::new(large_proof, Hash::zero(), 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_finality_proof_too_large() {
        let large_data = vec![0u8; MAX_FINALITY_DATA + 1];
        let result = FinalityProof::new(large_data, 6, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_bundle_signatures_too_large() {
        let large_sigs = vec![vec![0u8; MAX_SIGNATURES_TOTAL_SIZE / 2 + 1]; 2];
        let result = ProofBundle::new(
            DAGSegment::new(vec![], Hash::zero()),
            large_sigs,
            SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
            CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
            InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
            FinalityProof::new(vec![], 6, false).unwrap(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_bundle_provenance() {
        let mut bundle = ProofBundle::new(
            DAGSegment::new(vec![], Hash::zero()),
            vec![],
            SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
            CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
            InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
            FinalityProof::new(vec![], 6, false).unwrap(),
        )
        .unwrap();

        assert!(bundle.provenance().is_none());
        assert!(!bundle.has_complete_provenance());

        let provenance =
            crate::provenance::ProofProvenance::new("bitcoin".to_string(), 1000, 1_700_000_000);

        bundle.set_provenance(provenance);
        assert!(bundle.provenance().is_some());
        assert!(bundle.has_complete_provenance());
    }

    #[test]
    fn test_proof_bundle_certification() {
        let mut bundle = ProofBundle::new(
            DAGSegment::new(vec![], Hash::zero()),
            vec![],
            SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
            CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
            InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
            FinalityProof::new(vec![], 6, false).unwrap(),
        )
        .unwrap();

        assert!(bundle.certification().is_none());
        assert!(!bundle.has_certification());

        let certification = crate::certification::ProofCertification {
            status: crate::certification::CertificationStatus::Certified,
            certifier_id: "runtime-1".to_string(),
            timestamp: 1_700_000_000,
        };

        bundle.set_certification(certification);
        assert!(bundle.certification().is_some());
        assert!(bundle.has_certification());
    }
}
