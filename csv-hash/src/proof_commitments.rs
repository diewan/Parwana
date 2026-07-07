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
    /// Create a new proof commitment binding `data` under the caller-supplied
    /// `salt`.
    ///
    /// The salt is what gives the commitment its hiding property: without a
    /// high-entropy, unpredictable salt this reduces to a plain hash of `data`,
    /// so commitments to low-entropy inputs become brute-forceable and equal
    /// inputs produce equal commitments. Callers MUST pass a cryptographically
    /// random 32-byte salt (e.g. `rand::random()`), never a constant. The salt
    /// is required rather than defaulted precisely so it cannot silently be
    /// left as zero.
    pub fn new(data: &[u8], salt: [u8; 32]) -> Self {
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
