//! Provenance Tracking Module
//!
//! This module provides provenance tracking for proof bundles, ensuring
//! complete traceability of proof origin, verification chain, and
//! cryptographic guarantees.
//!
//! # Provenance Information
//!
//! Each proof bundle includes:
//! - Origin chain and block height
//! - Runtime instance that created the proof
//! - Verification timestamps
//! - Cryptographic hashes of intermediate states
//! - Adapter signatures
//!
//! # Verification Chain
//!
//! The verification chain tracks each step of proof validation:
//! 1. Initial proof creation
//! 2. Inclusion proof verification
//! 3. Finality verification
//! 4. Seal registry verification
//! 5. Replay protection check

use serde::{Deserialize, Serialize};

use crate::lease::now_secs;

/// Provenance metadata for a proof bundle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofProvenance {
    /// Chain where the proof originated
    pub origin_chain: String,
    /// Block height where the proof was created
    pub origin_block_height: u64,
    /// Runtime instance that created the proof
    pub runtime_instance: String,
    /// Timestamp when the proof was created (Unix epoch seconds)
    pub created_at: u64,
    /// Verification chain tracking each validation step
    pub verification_chain: Vec<VerificationStep>,
    /// Cryptographic hash of the proof bundle
    pub proof_hash: Vec<u8>,
    /// Adapter signature (if available)
    pub adapter_signature: Option<AdapterSignature>,
}

/// A single step in the verification chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationStep {
    /// Type of verification performed
    pub step_type: VerificationStepType,
    /// Component that performed the verification
    pub component: String,
    /// Timestamp when verification occurred (Unix epoch seconds)
    pub timestamp: u64,
    /// Whether verification succeeded
    pub success: bool,
    /// Optional error message if verification failed
    pub error: Option<String>,
    /// Cryptographic hash of the state after verification
    pub state_hash: Option<Vec<u8>>,
}

/// Types of verification steps
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VerificationStepType {
    /// Initial proof creation
    ProofCreation,
    /// Inclusion proof verification
    InclusionProofVerification,
    /// Finality verification
    FinalityVerification,
    /// Seal registry verification
    SealRegistryVerification,
    /// Replay protection check
    ReplayProtectionCheck,
    /// Adapter signature verification
    AdapterSignatureVerification,
}

/// Adapter signature for proof verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterSignature {
    /// Adapter that signed the proof
    pub adapter_id: String,
    /// Signature data
    pub signature: Vec<u8>,
    /// Timestamp when signature was created (Unix epoch seconds)
    pub signed_at: u64,
}

impl ProofProvenance {
    /// Create new provenance metadata
    pub fn new(
        origin_chain: String,
        origin_block_height: u64,
        runtime_instance: String,
        proof_hash: Vec<u8>,
    ) -> Self {
        Self {
            origin_chain,
            origin_block_height,
            runtime_instance,
            created_at: now_secs(),
            verification_chain: Vec::new(),
            proof_hash,
            adapter_signature: None,
        }
    }

    /// Add a verification step to the chain
    pub fn add_verification_step(&mut self, step: VerificationStep) {
        self.verification_chain.push(step);
    }

    /// Set the adapter signature
    pub fn set_adapter_signature(&mut self, signature: AdapterSignature) {
        self.adapter_signature = Some(signature);
    }

    /// Check if the verification chain is complete
    pub fn is_verification_complete(&self) -> bool {
        let required_steps = [
            VerificationStepType::ProofCreation,
            VerificationStepType::InclusionProofVerification,
            VerificationStepType::FinalityVerification,
            VerificationStepType::SealRegistryVerification,
            VerificationStepType::ReplayProtectionCheck,
        ];

        let step_types: crate::collections::HashSet<_> = self
            .verification_chain
            .iter()
            .map(|s| &s.step_type)
            .collect();

        required_steps.iter().all(|step| step_types.contains(step))
            && self.verification_chain.iter().all(|s| s.success)
    }

    /// Get the most recent verification step
    pub fn latest_step(&self) -> Option<&VerificationStep> {
        self.verification_chain.last()
    }

    /// Check if any verification step failed
    pub fn has_failed_verification(&self) -> bool {
        self.verification_chain.iter().any(|s| !s.success)
    }
}

impl VerificationStep {
    /// Create a new verification step
    pub fn new(
        step_type: VerificationStepType,
        component: String,
        success: bool,
    ) -> Self {
        Self {
            step_type,
            component,
            timestamp: now_secs(),
            success,
            error: None,
            state_hash: None,
        }
    }

    /// Set the error message
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    /// Set the state hash
    pub fn with_state_hash(mut self, hash: Vec<u8>) -> Self {
        self.state_hash = Some(hash);
        self
    }
}

impl AdapterSignature {
    /// Create a new adapter signature
    pub fn new(adapter_id: String, signature: Vec<u8>) -> Self {
        Self {
            adapter_id,
            signature,
            signed_at: now_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_provenance_creation() {
        let provenance = ProofProvenance::new(
            "bitcoin".to_string(),
            1000,
            "runtime-1".to_string(),
            vec![1u8; 32],
        );

        assert_eq!(provenance.origin_chain, "bitcoin");
        assert_eq!(provenance.origin_block_height, 1000);
        assert_eq!(provenance.runtime_instance, "runtime-1");
        assert!(!provenance.is_verification_complete());
    }

    #[test]
    fn test_verification_chain_completeness() {
        let mut provenance = ProofProvenance::new(
            "ethereum".to_string(),
            500,
            "runtime-2".to_string(),
            vec![2u8; 32],
        );

        // Add all required verification steps
        provenance.add_verification_step(VerificationStep::new(
            VerificationStepType::ProofCreation,
            "adapter".to_string(),
            true,
        ));
        provenance.add_verification_step(VerificationStep::new(
            VerificationStepType::InclusionProofVerification,
            "runtime".to_string(),
            true,
        ));
        provenance.add_verification_step(VerificationStep::new(
            VerificationStepType::FinalityVerification,
            "runtime".to_string(),
            true,
        ));
        provenance.add_verification_step(VerificationStep::new(
            VerificationStepType::SealRegistryVerification,
            "adapter".to_string(),
            true,
        ));
        provenance.add_verification_step(VerificationStep::new(
            VerificationStepType::ReplayProtectionCheck,
            "runtime".to_string(),
            true,
        ));

        assert!(provenance.is_verification_complete());
    }

    #[test]
    fn test_verification_chain_with_failure() {
        let mut provenance = ProofProvenance::new(
            "solana".to_string(),
            100,
            "runtime-3".to_string(),
            vec![3u8; 32],
        );

        provenance.add_verification_step(VerificationStep::new(
            VerificationStepType::ProofCreation,
            "adapter".to_string(),
            true,
        ));
        provenance.add_verification_step(
            VerificationStep::new(
                VerificationStepType::InclusionProofVerification,
                "runtime".to_string(),
                false,
            )
            .with_error("Invalid proof".to_string()),
        );

        assert!(provenance.has_failed_verification());
        assert!(!provenance.is_verification_complete());
    }

    #[test]
    fn test_adapter_signature() {
        let signature = AdapterSignature::new("bitcoin-adapter".to_string(), vec![4u8; 64]);
        assert_eq!(signature.adapter_id, "bitcoin-adapter");
        assert_eq!(signature.signature.len(), 64);
    }
}
