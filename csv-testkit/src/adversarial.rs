//! Adversarial and Byzantine simulation framework (audit item 11).

use csv_verifier::{CanonicalVerifier, CanonicalVerifierImpl, VerificationContext};
use csv_proof::proof::ProofBundle;
use csv_core::signature::SignatureScheme;

/// Simulated Byzantine RPC behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByzantineBehavior {
    /// Return stale block data.
    StaleBlocks,
    /// Omit transactions from responses.
    CensoredTx,
    /// Return conflicting hashes across calls.
    ConflictingRoots,
    /// Accept invalid proof bundles.
    AcceptInvalidProofs,
}

/// Configuration for adversarial test runs.
#[derive(Debug, Clone)]
pub struct AdversarialConfig {
    /// Behaviors to simulate.
    pub behaviors: Vec<ByzantineBehavior>,
    /// Number of simulated RPC nodes.
    pub node_count: usize,
    /// Quorum threshold (honest majority).
    pub quorum: usize,
}

impl Default for AdversarialConfig {
    fn default() -> Self {
        Self {
            behaviors: vec![ByzantineBehavior::ConflictingRoots],
            node_count: 4,
            quorum: 3,
        }
    }
}

/// Adversarial test runner — exercises verifier under hostile inputs.
pub struct AdversarialRunner {
    verifier: CanonicalVerifierImpl,
    config: AdversarialConfig,
}

impl AdversarialRunner {
    /// Create a runner with default canonical verifier.
    pub fn new(config: AdversarialConfig) -> Self {
        Self {
            verifier: CanonicalVerifierImpl::default(),
            config,
        }
    }

    /// Verify that a tampered bundle is rejected by the canonical verifier.
    pub fn assert_tampered_bundle_rejected(&self, bundle: &ProofBundle, chain_id: &str) -> bool {
        let ctx = VerificationContext {
            chain_id: chain_id.to_string(),
            signature_scheme: SignatureScheme::Secp256k1,
            required_confirmations: 6,
            current_block_height: Some(1000),
            seal_registry: None,
            chain_data: None,
        };
        self.verifier
            .verify_proof_bundle(bundle, &ctx)
            .map(|r| !r.is_valid)
            .unwrap_or(true)
    }

    /// Simulate quorum: returns true when at least `quorum` nodes agree on a hash.
    pub fn quorum_agrees(&self, responses: &[Option<[u8; 32]>]) -> bool {
        use std::collections::HashMap;
        let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
        for hash in responses.iter().flatten() {
            *counts.entry(*hash).or_insert(0) += 1;
        }
        counts.values().any(|&c| c >= self.config.quorum)
    }

    /// Returns true if configured behaviors include proof acceptance attacks.
    pub fn simulates_invalid_proof_acceptance(&self) -> bool {
        self.config
            .behaviors
            .contains(&ByzantineBehavior::AcceptInvalidProofs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_requires_majority() {
        let runner = AdversarialRunner::new(AdversarialConfig::default());
        let h = [1u8; 32];
        let responses = vec![
            Some(h),
            Some(h),
            Some(h),
            Some([2u8; 32]),
        ];
        assert!(runner.quorum_agrees(&responses));
    }
}
