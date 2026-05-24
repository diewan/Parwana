//! Multi-dimensional verification result types.
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::verified` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all verification types from csv-protocol
pub use csv_protocol::verified::{
    VerificationAssurance, VerificationFailure, VerificationResult, VerifiedComponents,
    InclusionStrength, FinalityStrength,
};

// Re-export meets_chain_thresholds method for backward compatibility
// This method depends on csv-core's ChainCapabilities which is not yet migrated
use crate::chain_config::ChainCapabilities;

/// Extension trait for VerificationResult to add csv-core-specific methods.
/// This is needed because VerificationResult is defined in csv-protocol,
/// but meets_chain_thresholds depends on csv-core's ChainCapabilities.
pub trait VerificationResultExt {
    /// Check each component against the per-chain minimums declared in
    /// ChainCapabilities. This is the production mint authorization gate.
    /// Do NOT replace this with a scalar enum comparison.
    fn meets_chain_thresholds(
        &self,
        caps: &ChainCapabilities,
    ) -> Result<(), VerificationFailure>;
}

impl VerificationResultExt for VerificationResult {
    fn meets_chain_thresholds(
        &self,
        caps: &ChainCapabilities,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_config::ChainCapabilities;

    #[test]
    fn test_verification_result_passes_thresholds() {
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
        assert!(result.meets_chain_thresholds(&caps).is_ok());
    }

    #[test]
    fn test_verification_result_fails_invalid_inclusion() {
        let caps = ChainCapabilities::bitcoin();
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
        assert!(result.meets_chain_thresholds(&caps).is_err());
    }

    #[test]
    fn test_verification_result_fails_insufficient_finality() {
        let caps = ChainCapabilities::bitcoin();
        let result = VerificationResult {
            valid: true,
            assurance: VerificationAssurance::Cryptographic,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::MerklePath,
                finality: FinalityStrength::Probabilistic { confirmations: 3 },
                replay_checked: true,
                ownership_signature: true,
            },
            error: None,
        };
        let err = result.meets_chain_thresholds(&caps).unwrap_err();
        match err {
            VerificationFailure::FinalityNotReached { required, actual } => {
                assert_eq!(required, 6);
                assert_eq!(actual, 3);
            }
            other => panic!("Expected FinalityNotReached, got {:?}", other),
        }
    }

    #[test]
    fn test_verification_result_fails_when_not_valid() {
        let caps = ChainCapabilities::ethereum();
        let result = VerificationResult {
            valid: false,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: Some(VerificationFailure::InvalidMerklePath),
        };
        assert!(result.meets_chain_thresholds(&caps).is_err());
    }

    #[test]
    fn test_deterministic_finality_passes_bitcoin() {
        let caps = ChainCapabilities::bitcoin();
        let result = VerificationResult {
            valid: true,
            assurance: VerificationAssurance::Cryptographic,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::MerklePath,
                finality: FinalityStrength::Deterministic,
                replay_checked: true,
                ownership_signature: true,
            },
            error: None,
        };
        // Bitcoin's finality_threshold_met returns true for Deterministic
        assert!(result.meets_chain_thresholds(&caps).is_ok());
    }

    #[test]
    fn test_celestia_da_chain_cannot_mint() {
        let caps = ChainCapabilities::celestia();
        assert!(!caps.can_authorize_mint());
    }

    #[test]
    fn test_solana_slot_confirmation_inclusion() {
        let caps = ChainCapabilities::solana();
        // Solana accepts Checksum and MerklePath for inclusion
        assert!(caps.inclusion_threshold_met(&InclusionStrength::Checksum));
        assert!(caps.inclusion_threshold_met(&InclusionStrength::MerklePath));
        assert!(!caps.inclusion_threshold_met(&InclusionStrength::None));
    }

    #[test]
    fn test_aptos_deterministic_finality() {
        let caps = ChainCapabilities::aptos();
        assert!(caps.finality_threshold_met(&FinalityStrength::Deterministic));
        assert!(!caps.finality_threshold_met(&FinalityStrength::None));
    }
}
