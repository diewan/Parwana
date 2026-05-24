#![cfg(any())]
//! Proof Encoding Rules — Protocol Constitution Section 4
//!
//! Tests for proof bundle structure and lifecycle requirements.

#[cfg(test)]
mod tests {
    use csv_core::Hash;
    use csv_core::proof::{FinalityProof, InclusionProof, ProofPhase};
    use csv_core::seal::{CommitAnchor, SealPoint};

    /// Property: ProofPhase has correct number of stages
    #[test]
    fn test_proof_phase_count() {
        // Constructed(0) -> StructuralValidated(1) -> CryptographicallyValidated(2)
        // -> FinalityValidated(3) -> ReplayChecked(4) -> ConsensusBound(5)
        assert_eq!(ProofPhase::Constructed as u8, 0);
        assert_eq!(ProofPhase::StructuralValidated as u8, 1);
        assert_eq!(ProofPhase::CryptographicallyValidated as u8, 2);
        assert_eq!(ProofPhase::FinalityValidated as u8, 3);
        assert_eq!(ProofPhase::ReplayChecked as u8, 4);
        assert_eq!(ProofPhase::ConsensusBound as u8, 5);
    }

    /// Property: ProofPhase is ordered
    #[test]
    fn test_proof_phase_ordering() {
        assert!(ProofPhase::StructuralValidated > ProofPhase::Constructed);
        assert!(ProofPhase::CryptographicallyValidated > ProofPhase::StructuralValidated);
        assert!(ProofPhase::FinalityValidated > ProofPhase::CryptographicallyValidated);
        assert!(ProofPhase::ReplayChecked > ProofPhase::FinalityValidated);
        assert!(ProofPhase::ConsensusBound > ProofPhase::ReplayChecked);
    }

    /// Property: InclusionProof validates size
    #[test]
    fn test_inclusion_proof_size_validation() {
        // MAX_PROOF_BYTES = 64KB
        let large_proof = vec![0u8; 65536 + 1];
        let result = InclusionProof::new(large_proof, Hash::zero(), 1000, 0);
        assert!(
            result.is_err(),
            "Proof exceeding MAX_PROOF_BYTES must be rejected"
        );
    }

    /// Property: InclusionProof accepts valid size
    #[test]
    fn test_inclusion_proof_valid_size() {
        let proof = vec![0xABu8; 1024];
        let result = InclusionProof::new(proof, Hash::zero(), 1000, 0);
        assert!(result.is_ok(), "Valid-size proof must be accepted");
    }

    /// Property: FinalityProof validates confirmations
    #[test]
    fn test_finality_proof_zero_confirmations_rejected() {
        let result = FinalityProof::new(vec![], 0, false);
        assert!(
            result.is_err(),
            "Zero confirmations for probabilistic finality must be rejected"
        );
    }

    /// Property: FinalityProof accepts valid confirmations
    #[test]
    fn test_finality_proof_valid_confirmations() {
        let result = FinalityProof::new(vec![0xABu8; 64], 6, true);
        assert!(result.is_ok(), "Valid confirmations must be accepted");
    }

    /// Property: SealPoint in ProofBundle is validated
    #[test]
    fn test_seal_point_validation() {
        let seal = SealPoint::new(vec![0xABu8; 32], Some(1)).unwrap();
        assert!(!seal.id.is_empty());
    }

    /// Property: CommitAnchor in ProofBundle is validated
    #[test]
    fn test_commit_anchor_validation() {
        let anchor = CommitAnchor::new(vec![0xABu8; 32], 1000, vec![0xCDu8; 64]).unwrap();
        assert!(!anchor.anchor_id.is_empty());
        assert!(anchor.block_height > 0);
    }

    /// Property: ProofBundle fields are non-empty for valid bundle
    #[test]
    fn test_proof_bundle_required_fields() {
        let seal = SealPoint::new(vec![0xABu8; 32], Some(1)).unwrap();
        let anchor = CommitAnchor::new(vec![0xCDu8; 32], 1000, vec![]).unwrap();
        let inclusion = InclusionProof::new(vec![0xEFu8; 64], Hash::zero(), 1000, 0).unwrap();
        let finality = FinalityProof::new(vec![0x12u8; 32], 6, true).unwrap();

        // Verify all components are valid
        assert!(!seal.id.is_empty());
        assert!(!anchor.anchor_id.is_empty());
        assert!(!inclusion.proof_bytes.is_empty());
    }
}
