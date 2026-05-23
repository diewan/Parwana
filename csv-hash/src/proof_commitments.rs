//! Proof commitments
//!
//! This module provides commitment schemes for proofs.

use super::Hash;
use crate::domain_hash::DomainSeparatedHash;
use crate::domains::ProofBundleDomain;

/// Proof commitment
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProofCommitment {
    /// Commitment hash
    pub hash: Hash,
    /// Salt used for commitment
    pub salt: [u8; 32],
}

impl ProofCommitment {
    /// Create a new proof commitment
    pub fn new(data: &[u8]) -> Self {
        let salt = [0u8; 32]; // Placeholder: use random salt
        let combined = Self::combine_data_and_salt(data, &salt);
        let hash = DomainSeparatedHash::<ProofBundleDomain>::hash(&combined);
        Self { hash, salt }
    }

    /// Verify a proof commitment
    pub fn verify(&self, data: &[u8]) -> bool {
        let combined = Self::combine_data_and_salt(data, &self.salt);
        let computed = DomainSeparatedHash::<ProofBundleDomain>::hash(&combined);
        computed == self.hash
    }

    /// Combine data and salt using domain separation
    fn combine_data_and_salt(data: &[u8], salt: &[u8; 32]) -> Vec<u8> {
        let mut combined = Vec::with_capacity(data.len() + 32);
        combined.extend_from_slice(data);
        combined.extend_from_slice(salt);
        combined
    }

    /// Get the commitment hash
    pub fn hash(&self) -> Hash {
        self.hash
    }
}
