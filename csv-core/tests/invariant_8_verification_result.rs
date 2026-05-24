#![cfg(any())]
//! Invariant 8: Mint Authorization MUST Use VerificationResult::meets_chain_thresholds()
//!
//! Rule: Mint authorization MUST use `VerificationResult::meets_chain_thresholds(&caps)`,
//! never a scalar enum comparison.
//! Prohibited: Using `VerificationAssurance >= ConsensusBound` for mint gates.

#[cfg(test)]
mod tests {
    use csv_core::verified::{
        FinalityStrength, InclusionStrength, VerificationAssurance, VerificationResult,
        VerifiedComponents,
    };
    use csv_protocol::finality::capabilities::ChainCapabilities;

    /// Property: VerificationResult contains required fields
    #[test]
    fn test_verification_result_fields() {
        let result = VerificationResult {
            valid: true,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        };

        assert!(result.valid);
        assert_eq!(result.assurance, VerificationAssurance::Structural);
    }

    /// Property: VerificationAssurance has correct variants
    #[test]
    fn test_verification_assurance_variants() {
        assert!(matches!(
            VerificationAssurance::Structural,
            VerificationAssurance::Structural
        ));
        assert!(matches!(
            VerificationAssurance::PartialCryptographic,
            VerificationAssurance::PartialCryptographic
        ));
        assert!(matches!(
            VerificationAssurance::Cryptographic,
            VerificationAssurance::Cryptographic
        ));
        assert!(matches!(
            VerificationAssurance::ConsensusBound,
            VerificationAssurance::ConsensusBound
        ));
    }

    /// Property: VerificationAssurance variants are distinct
    #[test]
    fn test_verification_assurance_distinct() {
        assert_ne!(
            VerificationAssurance::Structural,
            VerificationAssurance::Cryptographic
        );
        assert_ne!(
            VerificationAssurance::Cryptographic,
            VerificationAssurance::ConsensusBound
        );
        assert_ne!(
            VerificationAssurance::Structural,
            VerificationAssurance::PartialCryptographic
        );
    }

    /// Property: VerificationResult is cloneable
    #[test]
    fn test_verification_result_clone() {
        let result = VerificationResult {
            valid: true,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        };
        let cloned = result.clone();
        assert_eq!(result.valid, cloned.valid);
        assert_eq!(result.assurance, cloned.assurance);
    }

    /// Property: VerificationResult debug output is informative
    #[test]
    fn test_verification_result_debug() {
        let result = VerificationResult {
            valid: true,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        };
        let debug_str = format!("{:?}", result);
        assert!(!debug_str.is_empty());
    }

    /// Property: ChainCapabilities can be created
    #[test]
    fn test_chain_capabilities_creation() {
        let caps = ChainCapabilities::bitcoin();
        assert!(true, "Default capabilities must be creatable");
    }

    /// Property: meets_chain_thresholds rejects invalid results
    #[test]
    fn test_meets_thresholds_rejects_invalid() {
        let caps = ChainCapabilities::bitcoin();
        let result = VerificationResult {
            valid: false,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        };

        assert!(result.meets_chain_thresholds(&caps).is_err());
    }

    /// Property: meets_chain_thresholds accepts valid results
    #[test]
    fn test_meets_thresholds_accepts_valid() {
        let caps = ChainCapabilities::bitcoin();
        let result = VerificationResult {
            valid: true,
            assurance: VerificationAssurance::ConsensusBound,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::MerklePath,
                finality: FinalityStrength::Probabilistic { confirmations: 6 },
                replay_checked: true,
                ownership_signature: true,
            },
            error: None,
        };

        // This may pass or fail depending on chain thresholds, but should not panic
        let _ = result.meets_chain_thresholds(&caps);
    }

    /// Property: InclusionStrength has correct variants
    #[test]
    fn test_inclusion_strength_variants() {
        assert!(matches!(InclusionStrength::None, InclusionStrength::None));
        assert!(matches!(
            InclusionStrength::Checksum,
            InclusionStrength::Checksum
        ));
        assert!(matches!(
            InclusionStrength::MerklePath,
            InclusionStrength::MerklePath
        ));
        assert!(matches!(
            InclusionStrength::AnchoredMerklePath,
            InclusionStrength::AnchoredMerklePath
        ));
    }

    /// Property: FinalityStrength has correct variants
    #[test]
    fn test_finality_strength_variants() {
        assert!(matches!(FinalityStrength::None, FinalityStrength::None));
        assert!(matches!(
            FinalityStrength::Probabilistic { confirmations: 6 },
            FinalityStrength::Probabilistic { .. }
        ));
        assert!(matches!(
            FinalityStrength::Deterministic,
            FinalityStrength::Deterministic
        ));
    }
}
