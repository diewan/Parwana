//! Typed finality guarantee — chain-agnostic, runtime-enforceable.
//!
//! Adapters produce `FinalityGuarantee` values. The runtime evaluates them
//! against `FinalityPolicy`. Adapters never embed policy decisions.

use serde::{Deserialize, Serialize};

/// Canonical finality guarantee — typed, chain-agnostic.
///
/// Adapters produce this. The runtime reasons about it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FinalityGuarantee {
    /// Probabilistic finality: Bitcoin, pre-checkpoint Ethereum
    Probabilistic {
        /// Number of confirmations achieved
        confirmations: u64,
        /// Minimum required by protocol policy
        required: u64,
        /// Estimated reorg probability at this depth (0.0–1.0)
        reorg_probability: f64,
    },

    /// Deterministic finality: Solana root, Aptos quorum cert, Sui checkpoint
    Deterministic {
        /// Checkpoint/ledger hash that covers the anchor
        checkpoint_hash: [u8; 32],
        /// Checkpoint sequence number / ledger version
        sequence: u64,
        /// Quorum size that certified this checkpoint (2f+1 style)
        quorum_weight: Option<u64>,
    },

    /// Economic finality: slashing-backed (future EVM rollups)
    Economic {
        /// USD value of slashable stake backing this finality (in cents)
        slash_cost_usd_cents: u128,
        /// Challenge period remaining in seconds (0 = challengeable now)
        challenge_window_secs: u64,
    },
}

impl FinalityGuarantee {
    /// Returns true if this guarantee meets the required policy.
    /// The policy is provided by the runtime — not the adapter.
    pub fn meets_policy(&self, policy: &FinalityPolicy) -> bool {
        match (self, policy) {
            (
                FinalityGuarantee::Probabilistic { confirmations, .. },
                FinalityPolicy::MinConfirmations(required),
            ) => *confirmations >= *required,

            (
                FinalityGuarantee::Deterministic { sequence, .. },
                FinalityPolicy::DeterministicCheckpoint { min_sequence },
            ) => *sequence >= *min_sequence,

            (
                FinalityGuarantee::Economic { challenge_window_secs, .. },
                FinalityPolicy::EconomicSettlement,
            ) => *challenge_window_secs == 0,

            _ => false, // type mismatch = reject
        }
    }

    /// Returns the minimum confirmation count for probabilistic finality, if applicable.
    pub fn confirmations(&self) -> Option<u64> {
        match self {
            FinalityGuarantee::Probabilistic { confirmations, .. } => Some(*confirmations),
            FinalityGuarantee::Deterministic { sequence, .. } => Some(*sequence),
            FinalityGuarantee::Economic { .. } => None,
        }
    }
}

/// Runtime-owned finality policy. Adapters NEVER set this.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FinalityPolicy {
    /// Require at least N confirmations (Bitcoin, Ethereum pre-Dencun)
    MinConfirmations(u64),
    /// Require deterministic checkpoint at or above a given sequence
    DeterministicCheckpoint { min_sequence: u64 },
    /// Require economic settlement (challenge window expired)
    EconomicSettlement,
}

/// Finality policy registry — maps chain IDs to their required policies.
#[derive(Clone, Debug, Default)]
pub struct FinalityPolicyRegistry {
    policies: alloc::collections::BTreeMap<String, FinalityPolicy>,
}

impl FinalityPolicyRegistry {
    /// Create a new empty policy registry.
    pub fn new() -> Self {
        Self {
            policies: alloc::collections::BTreeMap::new(),
        }
    }

    /// Register a finality policy for a chain.
    pub fn register(&mut self, chain: String, policy: FinalityPolicy) {
        self.policies.insert(chain, policy);
    }

    /// Get the finality policy for a chain.
    pub fn get(&self, chain: &str) -> Option<&FinalityPolicy> {
        self.policies.get(chain)
    }

    /// Check if a finality guarantee meets the policy for a given chain.
    pub fn check(&self, chain: &str, guarantee: &FinalityGuarantee) -> bool {
        match self.policies.get(chain) {
            Some(policy) => guarantee.meets_policy(policy),
            None => false, // No policy = reject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probabilistic_meets_policy() {
        let guarantee = FinalityGuarantee::Probabilistic {
            confirmations: 10,
            required: 6,
            reorg_probability: 0.001,
        };
        let policy = FinalityPolicy::MinConfirmations(6);
        assert!(guarantee.meets_policy(&policy));

        let policy_strict = FinalityPolicy::MinConfirmations(12);
        assert!(!guarantee.meets_policy(&policy_strict));
    }

    #[test]
    fn test_deterministic_meets_policy() {
        let guarantee = FinalityGuarantee::Deterministic {
            checkpoint_hash: [0x42; 32],
            sequence: 1000,
            quorum_weight: Some(3),
        };
        let policy = FinalityPolicy::DeterministicCheckpoint { min_sequence: 500 };
        assert!(guarantee.meets_policy(&policy));

        let policy_strict = FinalityPolicy::DeterministicCheckpoint { min_sequence: 2000 };
        assert!(!guarantee.meets_policy(&policy_strict));
    }

    #[test]
    fn test_economic_meets_policy() {
        let guarantee = FinalityGuarantee::Economic {
            slash_cost_usd_cents: 1_000_000,
            challenge_window_secs: 0,
        };
        let policy = FinalityPolicy::EconomicSettlement;
        assert!(guarantee.meets_policy(&policy));

        let active = FinalityGuarantee::Economic {
            slash_cost_usd_cents: 1_000_000,
            challenge_window_secs: 3600,
        };
        assert!(!active.meets_policy(&policy));
    }

    #[test]
    fn test_type_mismatch_rejects() {
        let prob = FinalityGuarantee::Probabilistic {
            confirmations: 100,
            required: 6,
            reorg_probability: 0.0,
        };
        let econ_policy = FinalityPolicy::EconomicSettlement;
        assert!(!prob.meets_policy(&econ_policy));
    }

    #[test]
    fn test_policy_registry() {
        let mut registry = FinalityPolicyRegistry::new();
        registry.register("bitcoin".to_string(), FinalityPolicy::MinConfirmations(6));
        registry.register("solana".to_string(), FinalityPolicy::DeterministicCheckpoint { min_sequence: 0 });

        let prob = FinalityGuarantee::Probabilistic {
            confirmations: 10,
            required: 6,
            reorg_probability: 0.0,
        };
        assert!(registry.check("bitcoin", &prob));
        assert!(!registry.check("ethereum", &prob)); // No policy registered

        let det = FinalityGuarantee::Deterministic {
            checkpoint_hash: [0x01; 32],
            sequence: 500,
            quorum_weight: None,
        };
        assert!(registry.check("solana", &det));
    }
}
