//! Adversarial and Byzantine simulation framework (audit item 11).

use csv_protocol::proof_types::ProofBundle;
use csv_protocol::signature::SignatureScheme;
use csv_verifier::{CanonicalVerifier, CanonicalVerifierImpl, VerificationContext};

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
            native_proof_validated: false,
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

/// Byzantine RPC — returns plausible but cryptographically invalid responses.
///
/// Used to verify that the verifier correctly rejects them.
pub struct ByzantineRpcReader {
    fault_mode: ByzantineFaultMode,
}

/// Byzantine fault modes for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByzantineFaultMode {
    /// Returns valid-looking zero hashes for all block hashes.
    ZeroHashInjection,
    /// Returns success status for all transactions regardless of actual status.
    AlwaysSuccessStatus,
    /// Truncates hex strings to test parse_hex_bytes32 hardening.
    TruncatedHex {
        /// Maximum length to truncate hex strings to
        truncate_to: usize,
    },
    /// Returns responses from a different block height (stale data).
    StaleHeightInjection {
        /// Number of blocks to lag behind current height
        lag_blocks: u64,
    },
    /// Silently drops every Nth response (simulates censorship).
    SelectiveCensorship {
        /// Censor every Nth response
        every_n: usize,
    },
}

impl ByzantineRpcReader {
    /// Create a new Byzantine RPC reader with the specified fault mode.
    pub fn new(fault_mode: ByzantineFaultMode) -> Self {
        Self { fault_mode }
    }

    /// Get the current fault mode.
    pub fn fault_mode(&self) -> ByzantineFaultMode {
        self.fault_mode
    }

    /// Simulate a block hash response with the fault applied.
    pub fn simulate_block_hash(&self, original: [u8; 32]) -> [u8; 32] {
        match self.fault_mode {
            ByzantineFaultMode::ZeroHashInjection => [0u8; 32],
            _ => original,
        }
    }

    /// Simulate a transaction status response with the fault applied.
    pub fn simulate_transaction_status(&self, original: bool) -> bool {
        match self.fault_mode {
            ByzantineFaultMode::AlwaysSuccessStatus => true,
            _ => original,
        }
    }

    /// Simulate a hex string response with the fault applied.
    pub fn simulate_hex_string(&self, original: &str) -> String {
        match self.fault_mode {
            ByzantineFaultMode::TruncatedHex { truncate_to } => {
                original.chars().take(truncate_to).collect()
            }
            _ => original.to_string(),
        }
    }

    /// Simulate a block height response with the fault applied.
    pub fn simulate_block_height(&self, original: u64) -> u64 {
        match self.fault_mode {
            ByzantineFaultMode::StaleHeightInjection { lag_blocks } => {
                original.saturating_sub(lag_blocks)
            }
            _ => original,
        }
    }

    /// Check if a response should be dropped based on selective censorship.
    pub fn should_drop_response(&self, response_index: usize) -> bool {
        match self.fault_mode {
            ByzantineFaultMode::SelectiveCensorship { every_n } => {
                response_index > 0 && response_index % every_n == 0
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_requires_majority() {
        let runner = AdversarialRunner::new(AdversarialConfig::default());
        let h = [1u8; 32];
        let responses = vec![Some(h), Some(h), Some(h), Some([2u8; 32])];
        assert!(runner.quorum_agrees(&responses));
    }

    #[test]
    fn test_byzantine_zero_hash_injection() {
        let reader = ByzantineRpcReader::new(ByzantineFaultMode::ZeroHashInjection);
        let original = [1u8; 32];
        let result = reader.simulate_block_hash(original);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_byzantine_always_success_status() {
        let reader = ByzantineRpcReader::new(ByzantineFaultMode::AlwaysSuccessStatus);
        assert!(reader.simulate_transaction_status(false));
        assert!(reader.simulate_transaction_status(true));
    }

    #[test]
    fn test_byzantine_truncated_hex() {
        let reader = ByzantineRpcReader::new(ByzantineFaultMode::TruncatedHex { truncate_to: 4 });
        let result = reader.simulate_hex_string("0x12345678");
        assert_eq!(result, "0x12");
    }

    #[test]
    fn test_byzantine_stale_height() {
        let reader = ByzantineRpcReader::new(ByzantineFaultMode::StaleHeightInjection { lag_blocks: 10 });
        let result = reader.simulate_block_height(100);
        assert_eq!(result, 90);
    }

    #[test]
    fn test_byzantine_selective_censorship() {
        let reader = ByzantineRpcReader::new(ByzantineFaultMode::SelectiveCensorship { every_n: 3 });
        assert!(!reader.should_drop_response(0));
        assert!(!reader.should_drop_response(1));
        assert!(reader.should_drop_response(3));
        assert!(reader.should_drop_response(6));
    }
}
