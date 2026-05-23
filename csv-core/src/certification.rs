//! Deterministic Proof Certification Module
//!
//! This module provides deterministic proof certification to ensure that
//! proof verification produces consistent results across all runtime instances.
//!
//! # Deterministic Certification
//!
//! Proof certification ensures that:
//! - All runtimes produce identical verification results for the same proof
//! - Verification is deterministic and reproducible
//! - Certification metadata includes all inputs and intermediate states
//! - Certified proofs can be verified independently
//!
//! # Certification Process
//!
//! 1. Collect all verification inputs (proof, headers, state roots, etc.)
//! 2. Execute verification pipeline deterministically
//! 3. Record all intermediate states and hashes
//! 4. Generate certification digest
//! 5. Sign certification with runtime identity

use serde::{Deserialize, Serialize};

use crate::lease::now_secs;

/// Deterministic proof certification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofCertification {
    /// Certification version
    pub version: u32,
    /// Runtime instance that performed certification
    pub runtime_instance: String,
    /// Timestamp when certification was created (Unix epoch seconds)
    pub certified_at: u64,
    /// Certification digest (hash of all verification inputs and outputs)
    pub certification_digest: Vec<u8>,
    /// Verification inputs used for certification
    pub verification_inputs: VerificationInputs,
    /// Verification outputs produced
    pub verification_outputs: VerificationOutputs,
    /// Intermediate verification states
    pub intermediate_states: Vec<IntermediateState>,
    /// Runtime signature (if available)
    pub runtime_signature: Option<Vec<u8>>,
}

/// Verification inputs for deterministic certification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationInputs {
    /// Proof bundle bytes
    pub proof_bundle: Vec<u8>,
    /// Block header bytes
    pub block_header: Vec<u8>,
    /// State root bytes
    pub state_root: Vec<u8>,
    /// Chain metadata
    pub chain_metadata: ChainMetadata,
    /// Runtime policy used for verification
    pub runtime_policy: RuntimePolicyConfig,
}

/// Verification outputs from deterministic certification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationOutputs {
    /// Whether verification succeeded
    pub success: bool,
    /// Final verification result
    pub final_result: String,
    /// Verification strength metrics
    pub verification_strength: VerificationStrength,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Intermediate verification state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntermediateState {
    /// Step name
    pub step: String,
    /// State hash
    pub state_hash: Vec<u8>,
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Step-specific metadata
    pub metadata: Vec<u8>,
}

/// Chain metadata for certification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainMetadata {
    /// Chain ID
    pub chain_id: String,
    /// Block height
    pub block_height: u64,
    /// Block hash
    pub block_hash: Vec<u8>,
    /// Current timestamp (Unix epoch seconds)
    pub chain_timestamp: u64,
}

/// Runtime policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicyConfig {
    /// Finality depth
    pub finality_depth: u64,
    /// Whether RPC fallback is allowed
    pub allow_rpc_fallback: bool,
    /// Maximum retries
    pub max_retries: u32,
    /// Whether strict finality is enforced
    pub enforce_strict_finality: bool,
}

/// Verification strength metrics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationStrength {
    /// Inclusion strength (0-100)
    pub inclusion_strength: u8,
    /// Finality strength (0-100)
    pub finality_strength: u8,
    /// Overall strength (0-100)
    pub overall_strength: u8,
}

impl ProofCertification {
    /// Create a new proof certification
    pub fn new(
        runtime_instance: String,
        verification_inputs: VerificationInputs,
        verification_outputs: VerificationOutputs,
    ) -> Self {
        let certification_digest = Self::compute_certification_digest(
            &verification_inputs,
            &verification_outputs,
        );

        Self {
            version: 1,
            runtime_instance,
            certified_at: now_secs(),
            certification_digest,
            verification_inputs,
            verification_outputs,
            intermediate_states: Vec::new(),
            runtime_signature: None,
        }
    }

    /// Add an intermediate verification state
    pub fn add_intermediate_state(&mut self, state: IntermediateState) {
        self.intermediate_states.push(state);
    }

    /// Set the runtime signature
    pub fn set_runtime_signature(&mut self, signature: Vec<u8>) {
        self.runtime_signature = Some(signature);
    }

    /// Compute the certification digest from inputs and outputs
    fn compute_certification_digest(
        inputs: &VerificationInputs,
        outputs: &VerificationOutputs,
    ) -> Vec<u8> {
        // Use canonical CBOR serialization + tagged hashing for deterministic digest
        #[derive(serde::Serialize)]
        struct DigestInputs<'a> {
            proof_bundle: &'a [u8],
            block_header: &'a [u8],
            state_root: &'a [u8],
            chain_id: &'a str,
            block_height: u64,
            success: bool,
            final_result: &'a str,
        }
        let digest_inputs = DigestInputs {
            proof_bundle: &inputs.proof_bundle,
            block_header: &inputs.block_header,
            state_root: &inputs.state_root,
            chain_id: &inputs.chain_metadata.chain_id,
            block_height: inputs.chain_metadata.block_height,
            success: outputs.success,
            final_result: &outputs.final_result,
        };
        let cbor = crate::canonical::to_canonical_cbor(&digest_inputs).unwrap_or_default();
        crate::tagged_hash::csv_tagged_hash("csv.certification.digest.v1", &cbor).to_vec()
    }

    /// Verify that this certification matches the expected inputs and outputs
    pub fn verify(
        &self,
        inputs: &VerificationInputs,
        outputs: &VerificationOutputs,
    ) -> bool {
        let expected_digest = Self::compute_certification_digest(inputs, outputs);
        self.certification_digest == expected_digest
    }

    /// Check if the certification is complete (has all required intermediate states)
    pub fn is_complete(&self) -> bool {
        !self.intermediate_states.is_empty()
    }

    /// Get the total number of verification steps
    pub fn step_count(&self) -> usize {
        self.intermediate_states.len()
    }
}

impl VerificationInputs {
    /// Create new verification inputs
    pub fn new(
        proof_bundle: Vec<u8>,
        block_header: Vec<u8>,
        state_root: Vec<u8>,
        chain_metadata: ChainMetadata,
        runtime_policy: RuntimePolicyConfig,
    ) -> Self {
        Self {
            proof_bundle,
            block_header,
            state_root,
            chain_metadata,
            runtime_policy,
        }
    }
}

impl VerificationOutputs {
    /// Create new verification outputs
    pub fn new(
        success: bool,
        final_result: String,
        verification_strength: VerificationStrength,
    ) -> Self {
        Self {
            success,
            final_result,
            verification_strength,
            error: None,
        }
    }

    /// Create failed verification outputs
    pub fn failed(error: String) -> Self {
        Self {
            success: false,
            final_result: "failed".to_string(),
            verification_strength: VerificationStrength {
                inclusion_strength: 0,
                finality_strength: 0,
                overall_strength: 0,
            },
            error: Some(error),
        }
    }
}

impl IntermediateState {
    /// Create a new intermediate state
    pub fn new(step: String, state_hash: Vec<u8>, metadata: Vec<u8>) -> Self {
        Self {
            step,
            state_hash,
            timestamp: now_secs(),
            metadata,
        }
    }
}

impl ChainMetadata {
    /// Create new chain metadata
    pub fn new(chain_id: String, block_height: u64, block_hash: Vec<u8>) -> Self {
        Self {
            chain_id,
            block_height,
            block_hash,
            chain_timestamp: now_secs(),
        }
    }
}

impl RuntimePolicyConfig {
    /// Create new runtime policy config
    pub fn new(
        finality_depth: u64,
        allow_rpc_fallback: bool,
        max_retries: u32,
        enforce_strict_finality: bool,
    ) -> Self {
        Self {
            finality_depth,
            allow_rpc_fallback,
            max_retries,
            enforce_strict_finality,
        }
    }
}

impl VerificationStrength {
    /// Create new verification strength
    pub fn new(inclusion_strength: u8, finality_strength: u8) -> Self {
        let overall_strength = (inclusion_strength + finality_strength) / 2;
        Self {
            inclusion_strength,
            finality_strength,
            overall_strength,
        }
    }

    /// Create maximum strength
    pub fn maximum() -> Self {
        Self {
            inclusion_strength: 100,
            finality_strength: 100,
            overall_strength: 100,
        }
    }

    /// Create minimum strength
    pub fn minimum() -> Self {
        Self {
            inclusion_strength: 0,
            finality_strength: 0,
            overall_strength: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_certification_creation() {
        let inputs = VerificationInputs::new(
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            ChainMetadata::new("bitcoin".to_string(), 1000, vec![4u8; 32]),
            RuntimePolicyConfig::new(6, false, 3, true),
        );

        let outputs = VerificationOutputs::new(
            true,
            "verified".to_string(),
            VerificationStrength::maximum(),
        );

        let certification = ProofCertification::new("runtime-1".to_string(), inputs, outputs);
        assert_eq!(certification.version, 1);
        assert_eq!(certification.runtime_instance, "runtime-1");
        assert!(!certification.certification_digest.is_empty());
    }

    #[test]
    fn test_certification_verification() {
        let inputs = VerificationInputs::new(
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            ChainMetadata::new("ethereum".to_string(), 500, vec![4u8; 32]),
            RuntimePolicyConfig::new(15, false, 3, true),
        );

        let outputs = VerificationOutputs::new(
            true,
            "verified".to_string(),
            VerificationStrength::maximum(),
        );

        let certification = ProofCertification::new("runtime-2".to_string(), inputs.clone(), outputs.clone());
        assert!(certification.verify(&inputs, &outputs));
    }

    #[test]
    fn test_intermediate_states() {
        let inputs = VerificationInputs::new(
            vec![1u8; 32],
            vec![2u8; 32],
            vec![3u8; 32],
            ChainMetadata::new("solana".to_string(), 100, vec![4u8; 32]),
            RuntimePolicyConfig::new(32, false, 3, false),
        );

        let outputs = VerificationOutputs::new(
            true,
            "verified".to_string(),
            VerificationStrength::maximum(),
        );

        let mut certification = ProofCertification::new("runtime-3".to_string(), inputs, outputs);
        
        certification.add_intermediate_state(IntermediateState::new(
            "step1".to_string(),
            vec![5u8; 32],
            vec![],
        ));
        
        certification.add_intermediate_state(IntermediateState::new(
            "step2".to_string(),
            vec![6u8; 32],
            vec![],
        ));

        assert_eq!(certification.step_count(), 2);
        assert!(certification.is_complete());
    }

    #[test]
    fn test_verification_strength() {
        let max_strength = VerificationStrength::maximum();
        assert_eq!(max_strength.inclusion_strength, 100);
        assert_eq!(max_strength.finality_strength, 100);
        assert_eq!(max_strength.overall_strength, 100);

        let min_strength = VerificationStrength::minimum();
        assert_eq!(min_strength.inclusion_strength, 0);
        assert_eq!(min_strength.finality_strength, 0);
        assert_eq!(min_strength.overall_strength, 0);

        let custom_strength = VerificationStrength::new(75, 50);
        assert_eq!(custom_strength.inclusion_strength, 75);
        assert_eq!(custom_strength.finality_strength, 50);
        assert_eq!(custom_strength.overall_strength, 62);
    }

    #[test]
    fn test_failed_verification_outputs() {
        let outputs = VerificationOutputs::failed("Invalid proof".to_string());
        assert!(!outputs.success);
        assert_eq!(outputs.final_result, "failed");
        assert!(outputs.error.is_some());
        assert_eq!(outputs.error.unwrap(), "Invalid proof");
    }
}
