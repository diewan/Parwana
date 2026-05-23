//! Selective disclosure proofs for Merkleized content
//!
//! Allows proving subtree validity without exposing entire content.

use serde::{Deserialize, Serialize};

/// Selective disclosure proof
///
/// Proves that a specific subtree is valid without revealing the entire content tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureProof {
    /// Path to the disclosed subtree
    pub path: Vec<u8>,
    /// Merkle proof for the path
    pub merkle_proof: Vec<[u8; 32]>,
    /// Hash of the disclosed subtree
    pub subtree_hash: [u8; 32],
    /// Whether the subtree is redacted
    pub is_redacted: bool,
}

/// Redacted Merkle proof
///
/// Proves that a subtree exists but its content is hidden.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedMerkleProof {
    /// Path to the redacted node
    pub path: Vec<u8>,
    /// Merkle proof up to the redacted node
    pub merkle_proof: Vec<[u8; 32]>,
    /// Commitment to the redacted content (hash only)
    pub commitment: [u8; 32],
    /// Size of redacted content (bytes)
    pub size: u64,
}

/// Encrypted subtree proof
///
/// Proves that a subtree is encrypted and provides decryption key access control.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSubtreeProof {
    /// Path to the encrypted node
    pub path: Vec<u8>,
    /// Merkle proof for the path
    pub merkle_proof: Vec<[u8; 32]>,
    /// Encryption key identifier
    pub key_id: String,
    /// Encryption algorithm
    pub algorithm: String,
    /// Commitment to encrypted content
    pub commitment: [u8; 32],
}

impl DisclosureProof {
    /// Create a new disclosure proof
    pub fn new(
        path: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
        subtree_hash: [u8; 32],
        is_redacted: bool,
    ) -> Self {
        Self {
            path,
            merkle_proof,
            subtree_hash,
            is_redacted,
        }
    }

    /// Verify the disclosure proof
    pub fn verify(&self, root_hash: [u8; 32]) -> bool {
        // TODO: Implement Merkle proof verification
        // This would verify that the path leads to the subtree_hash
        // given the root_hash
        true
    }
}

impl RedactedMerkleProof {
    /// Create a new redacted Merkle proof
    pub fn new(
        path: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
        commitment: [u8; 32],
        size: u64,
    ) -> Self {
        Self {
            path,
            merkle_proof,
            commitment,
            size,
        }
    }

    /// Verify the redacted proof
    pub fn verify(&self, root_hash: [u8; 32]) -> bool {
        // TODO: Implement Merkle proof verification
        // This would verify that the commitment exists at the path
        // given the root_hash
        true
    }
}

impl EncryptedSubtreeProof {
    /// Create a new encrypted subtree proof
    pub fn new(
        path: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
        key_id: String,
        algorithm: String,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            path,
            merkle_proof,
            key_id,
            algorithm,
            commitment,
        }
    }

    /// Verify the encrypted subtree proof
    pub fn verify(&self, root_hash: [u8; 32]) -> bool {
        // TODO: Implement Merkle proof verification
        // This would verify that the encrypted commitment exists at the path
        // given the root_hash
        true
    }
}
