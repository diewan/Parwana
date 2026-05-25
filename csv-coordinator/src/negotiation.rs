//! Capability negotiation using FinalityGuarantee.
//!
//! This module provides the CapabilityNegotiator which uses FinalityGuaranteeSpec
//! to make security decisions at runtime, replacing boolean capability flags.

use csv_protocol::finality::{FinalityGuaranteeSpec, ProofSystem};
use std::collections::HashMap;
use thiserror::Error;

/// Chain identifier for capability negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainId(pub [u8; 32]);

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Security requirements for a transfer.
#[derive(Debug, Clone)]
pub struct SecurityRequirements {
    /// Whether the transfer requires deterministic finality.
    pub requires_deterministic_finality: bool,
    /// Minimum reorg depth required.
    pub min_reorg_depth: u64,
    /// Minimum validator honesty threshold required.
    pub min_honesty_threshold: f32,
}

impl Default for SecurityRequirements {
    fn default() -> Self {
        Self {
            requires_deterministic_finality: true,
            min_reorg_depth: 0,
            min_honesty_threshold: 0.67,
        }
    }
}

/// Negotiated execution plan.
#[derive(Debug, Clone)]
pub struct NegotiatedPlan {
    /// Proof system to use.
    pub proof_system: ProofSystem,
    /// Confirmation depth required.
    pub confirmation_depth: u64,
    /// Maximum proof age in blocks.
    pub max_proof_age_blocks: u64,
}

/// Negotiation errors.
#[derive(Debug, Clone, Error)]
pub enum NegotiationError {
    #[error("Unknown chain: {0}")]
    UnknownChain(String),

    #[error("Finality mismatch: required {required}, available {available} on chain {chain}")]
    FinalityMismatch {
        required: &'static str,
        available: &'static str,
        chain: ChainId,
    },

    #[error("Insufficient reorg protection: required {required}, available {available}")]
    InsufficientReorgProtection { required: u64, available: u64 },

    #[error("Insufficient validator trust: required {required}, available {available}")]
    InsufficientValidatorTrust {
        required: f32,
        available: f32,
    },

    #[error("No suitable proof system available")]
    NoProofSystem,
}

/// Capability negotiator using FinalityGuarantee.
///
/// This negotiator uses FinalityGuaranteeSpec — not booleans — to make
/// security decisions at runtime.
pub struct CapabilityNegotiator {
    chain_guarantees: HashMap<ChainId, FinalityGuaranteeSpec>,
}

impl CapabilityNegotiator {
    /// Create a new capability negotiator.
    pub fn new() -> Self {
        Self {
            chain_guarantees: HashMap::new(),
        }
    }

    /// Register a finality guarantee for a chain.
    pub fn register_chain(&mut self, chain_id: ChainId, guarantee: FinalityGuaranteeSpec) {
        self.chain_guarantees.insert(chain_id, guarantee);
    }

    /// Validate that a proposed transfer can meet the required security level.
    ///
    /// Returns the negotiated execution plan or an explicit refusal with reason.
    pub fn negotiate(
        &self,
        source_chain: &ChainId,
        required: &SecurityRequirements,
    ) -> Result<NegotiatedPlan, NegotiationError> {
        let source_guarantee = self
            .chain_guarantees
            .get(source_chain)
            .ok_or_else(|| NegotiationError::UnknownChain(format!("{:?}", source_chain)))?;

        // Determinism requirement: reject probabilistic finality if caller requires deterministic
        if required.requires_deterministic_finality && source_guarantee.is_probabilistic {
            return Err(NegotiationError::FinalityMismatch {
                required: "deterministic",
                available: "probabilistic",
                chain: *source_chain,
            });
        }

        // Reorg depth requirement
        if source_guarantee.max_reorg_depth < required.min_reorg_depth {
            return Err(NegotiationError::InsufficientReorgProtection {
                required: required.min_reorg_depth,
                available: source_guarantee.max_reorg_depth,
            });
        }

        // Validator honesty threshold
        if source_guarantee.validator_honesty_threshold < required.min_honesty_threshold {
            return Err(NegotiationError::InsufficientValidatorTrust {
                required: required.min_honesty_threshold,
                available: source_guarantee.validator_honesty_threshold,
            });
        }

        // Compute fallback plan if primary proof system is unavailable
        let proof_system = self.select_proof_system(source_guarantee)?;

        Ok(NegotiatedPlan {
            proof_system,
            confirmation_depth: source_guarantee.max_reorg_depth + 1,
            max_proof_age_blocks: source_guarantee.max_proof_age_blocks,
        })
    }

    /// Select the appropriate proof system for a chain.
    fn select_proof_system(
        &self,
        guarantee: &FinalityGuaranteeSpec,
    ) -> Result<ProofSystem, NegotiationError> {
        // Use the chain's configured proof system
        Ok(guarantee.proof_system.clone())
    }
}

impl Default for CapabilityNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_deterministic_success() {
        let mut negotiator = CapabilityNegotiator::new();
        let chain_id = ChainId([1u8; 32]);

        negotiator.register_chain(
            chain_id,
            FinalityGuaranteeSpec {
                max_reorg_depth: 0,
                is_probabilistic: false,
                validator_honesty_threshold: 0.67,
                proof_system: ProofSystem::BftQc {
                    quorum_fraction: 0.67,
                },
                max_proof_age_blocks: 100,
                min_anchor_sources: 1,
            },
        );

        let required = SecurityRequirements {
            requires_deterministic_finality: true,
            min_reorg_depth: 0,
            min_honesty_threshold: 0.67,
        };

        let plan = negotiator.negotiate(&chain_id, &required).unwrap();
        assert_eq!(plan.confirmation_depth, 1);
    }

    #[test]
    fn test_negotiate_probabilistic_rejected() {
        let mut negotiator = CapabilityNegotiator::new();
        let chain_id = ChainId([1u8; 32]);

        negotiator.register_chain(
            chain_id,
            FinalityGuaranteeSpec {
                max_reorg_depth: 6,
                is_probabilistic: true,
                validator_honesty_threshold: 0.5,
                proof_system: ProofSystem::BitcoinSpv { confirmations: 6 },
                max_proof_age_blocks: 100,
                min_anchor_sources: 1,
            },
        );

        let required = SecurityRequirements {
            requires_deterministic_finality: true,
            min_reorg_depth: 0,
            min_honesty_threshold: 0.67,
        };

        let result = negotiator.negotiate(&chain_id, &required);
        assert!(matches!(
            result,
            Err(NegotiationError::FinalityMismatch { .. })
        ));
    }

    #[test]
    fn test_negotiate_insufficient_reorg_depth() {
        let mut negotiator = CapabilityNegotiator::new();
        let chain_id = ChainId([1u8; 32]);

        negotiator.register_chain(
            chain_id,
            FinalityGuaranteeSpec {
                max_reorg_depth: 0,
                is_probabilistic: false,
                validator_honesty_threshold: 0.67,
                proof_system: ProofSystem::BftQc {
                    quorum_fraction: 0.67,
                },
                max_proof_age_blocks: 100,
                min_anchor_sources: 1,
            },
        );

        let required = SecurityRequirements {
            requires_deterministic_finality: true,
            min_reorg_depth: 10,
            min_honesty_threshold: 0.67,
        };

        let result = negotiator.negotiate(&chain_id, &required);
        assert!(matches!(
            result,
            Err(NegotiationError::InsufficientReorgProtection { .. })
        ));
    }
}
