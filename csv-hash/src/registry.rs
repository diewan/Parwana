//! Hash Registry - Domain-separated hash types
//!
//! This module provides a registry of hash domains for the CSV protocol.
//! Each domain has a unique tag to prevent cross-domain hash collisions.
//!
//! # Hash Domains
//!
//! The CSV protocol uses domain-separated hashing to prevent cross-protocol
//! binding attacks. Each hash domain has a unique tag that is prepended to
//! the data before hashing.
//!
//! # Typed Hash Wrappers
//!
//! This module provides typed hash wrappers that forbid the use of raw Vec<u8>
//! or String for protocol hashes. This prevents hash confusion attacks where
//! a hash from one domain is mistakenly used in another domain.

use crate::Hash;

/// Typed hash domain tags for CSV protocol (distinct from hash_registry::HashDomain)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TypedHashDomain {
    /// Sanad header hash
    SanadHeader,
    /// Sanad content hash
    SanadContent,
    /// Proof bundle hash
    ProofBundle,
    /// Replay nullifier hash
    ReplayNullifier,
    /// Seal commitment hash
    SealCommitment,
    /// Transition commitment hash
    TransitionCommitment,
    /// Merkle leaf hash
    MerkleLeaf,
    /// Merkle internal node hash
    MerkleInternal,
    /// MPC tree leaf hash
    MpcLeaf,
    /// MPC tree internal node hash
    MpcInternal,
    /// Verification proof hash
    VerificationProof,
    /// Finality proof hash
    FinalityProof,
    /// Inclusion proof hash
    InclusionProof,
}

impl TypedHashDomain {
    /// Get the domain tag as bytes
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            TypedHashDomain::SanadHeader => b"csv.sanad.header.v1",
            TypedHashDomain::SanadContent => b"csv.sanad.content.v1",
            TypedHashDomain::ProofBundle => b"csv.proof.bundle.v1",
            TypedHashDomain::ReplayNullifier => b"csv.replay.nullifier.v1",
            TypedHashDomain::SealCommitment => b"csv.seal.commitment.v1",
            TypedHashDomain::TransitionCommitment => b"csv.transition.commitment.v1",
            TypedHashDomain::MerkleLeaf => b"csv.merkle.leaf.v1",
            TypedHashDomain::MerkleInternal => b"csv.merkle.internal.v1",
            TypedHashDomain::MpcLeaf => b"csv.mpc.leaf.v1",
            TypedHashDomain::MpcInternal => b"csv.mpc.internal.v1",
            TypedHashDomain::VerificationProof => b"csv.verification.proof.v1",
            TypedHashDomain::FinalityProof => b"csv.finality.proof.v1",
            TypedHashDomain::InclusionProof => b"csv.inclusion.proof.v1",
        }
    }
}

/// Typed hash wrapper for content hashes
///
/// This type prevents hash confusion by ensuring content hashes are only
/// used in their intended domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ContentHash(Hash);

impl ContentHash {
    /// Create a new content hash from raw bytes
    ///
    /// # Safety
    /// The caller MUST ensure the hash was computed with the correct domain tag.
    pub unsafe fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self(Hash::new(bytes))
    }

    /// Get the underlying hash
    pub fn as_hash(&self) -> Hash {
        self.0
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Typed hash wrapper for proof hashes
///
/// This type prevents hash confusion by ensuring proof hashes are only
/// used in their intended domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ProofHash(Hash);

impl ProofHash {
    /// Create a new proof hash from raw bytes
    ///
    /// # Safety
    /// The caller MUST ensure the hash was computed with the correct domain tag.
    pub unsafe fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self(Hash::new(bytes))
    }

    /// Get the underlying hash
    pub fn as_hash(&self) -> Hash {
        self.0
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

/// Typed hash wrapper for seal hashes
///
/// This type prevents hash confusion by ensuring seal hashes are only
/// used in their intended domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SealHash(Hash);

impl SealHash {
    /// Create a new seal hash from raw bytes
    ///
    /// # Safety
    /// The caller MUST ensure the hash was computed with the correct domain tag.
    pub unsafe fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self(Hash::new(bytes))
    }

    /// Get the underlying hash
    pub fn as_hash(&self) -> Hash {
        self.0
    }

    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_domain_tags_are_unique() {
        let domains = [
            TypedHashDomain::SanadHeader,
            TypedHashDomain::SanadContent,
            TypedHashDomain::ProofBundle,
            TypedHashDomain::ReplayNullifier,
            TypedHashDomain::SealCommitment,
            TypedHashDomain::TransitionCommitment,
            TypedHashDomain::MerkleLeaf,
            TypedHashDomain::MerkleInternal,
            TypedHashDomain::MpcLeaf,
            TypedHashDomain::MpcInternal,
            TypedHashDomain::VerificationProof,
            TypedHashDomain::FinalityProof,
            TypedHashDomain::InclusionProof,
        ];

        let tags: Vec<_> = domains.iter().map(|d| d.as_bytes()).collect();
        let unique_tags: Vec<_> = tags
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .cloned()
            .collect();

        assert_eq!(
            tags.len(),
            unique_tags.len(),
            "All hash domain tags must be unique"
        );
    }

    #[test]
    fn test_typed_hash_wrappers() {
        let hash_bytes = [1u8; 32];
        let content_hash = unsafe { ContentHash::from_bytes_unchecked(hash_bytes) };
        let proof_hash = unsafe { ProofHash::from_bytes_unchecked(hash_bytes) };
        let seal_hash = unsafe { SealHash::from_bytes_unchecked(hash_bytes) };

        // All should have the same underlying bytes
        assert_eq!(content_hash.as_bytes(), &hash_bytes);
        assert_eq!(proof_hash.as_bytes(), &hash_bytes);
        assert_eq!(seal_hash.as_bytes(), &hash_bytes);

        // But they are different Rust types, so call sites cannot mix them accidentally.
        assert_ne!(
            std::any::TypeId::of::<ContentHash>(),
            std::any::TypeId::of::<ProofHash>()
        );
    }
}
