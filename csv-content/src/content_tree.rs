//! Merkleized content tree system
//!
//! Provides a canonical Merkle tree structure for organizing Sanad content.
//! Supports selective disclosure, encrypted subtrees, and resource accounting.
//!
//! # Design
//!
//! The content tree is a binary Merkle tree where:
//! - Leaf nodes contain content chunks or metadata
//! - Internal nodes contain hashes of their children
//! - The root hash commits to all content
//! - Proofs can verify individual leaves without revealing the full tree

use std::vec::Vec;

use csv_hash::{Hash, merkle::tree::MerkleTree as CanonicalMerkleTree};
use serde::{Deserialize, Serialize};
// L2 types containing L0 Hash fields cannot use serde
// Use manual serialization instead

/// The type of a content node.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// A leaf node containing content data.
    Leaf,
    /// An internal node containing hashes of children.
    Internal,
    /// An encrypted subtree node.
    Encrypted,
    /// A metadata node (schema, encoding, etc.).
    Metadata,
}

/// A node in the content tree.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentNode {
    /// The type of this node.
    pub node_type: NodeType,
    /// The hash of this node (computed from children or data).
    pub hash: Hash,
    /// For leaf nodes: the content data.
    pub data: Option<Vec<u8>>,
    /// For internal nodes: the hashes of child nodes.
    pub children: Vec<Hash>,
    /// Optional encryption key ID for encrypted nodes.
    pub encryption_key_id: Option<String>,
    /// Node metadata (schema version, encoding, etc.).
    pub metadata: NodeMetadata,
}

/// Metadata for a content node.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeMetadata {
    /// Schema ID for this node.
    pub schema_id: Option<String>,
    /// Encoding type (e.g., "json", "protobuf", "cbor").
    pub encoding: Option<String>,
    /// Content type (e.g., "text/plain", "application/pdf").
    pub content_type: Option<String>,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Access control list for this node.
    pub access_control: Option<AccessControl>,
}

/// Access control for a content node.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessControl {
    /// Who can read this node.
    pub readers: Vec<String>,
    /// Who can write this node.
    pub writers: Vec<String>,
    /// Minimum disclosure level required.
    pub min_disclosure_level: u8,
}

/// A content tree with Merkle-based integrity.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTree {
    /// The root hash of the tree.
    pub root_hash: Hash,
    /// All leaf hashes in order.
    pub leaf_hashes: Vec<Hash>,
    /// Tree depth.
    pub depth: usize,
    /// Number of leaves.
    pub leaf_count: usize,
    /// Node metadata indexed by hash.
    pub node_metadata: std::collections::HashMap<Hash, NodeMetadata>,
}

impl ContentTree {
    /// Create a new content tree from leaf data.
    ///
    /// # Arguments
    /// * `leaves` - Slice of leaf data to include in the tree
    ///
    /// # Returns
    /// The constructed ContentTree
    pub fn from_leaves(leaves: Vec<Vec<u8>>) -> Self {
        if leaves.is_empty() {
            return Self::empty();
        }

        // Hash each leaf with domain separation
        let leaf_hashes: Vec<Hash> = leaves.iter().map(|data| Self::hash_leaf(data)).collect();

        // Build canonical Merkle tree
        let canonical = match CanonicalMerkleTree::from_leaves(leaf_hashes.clone()) {
            Some(canonical) => canonical,
            None => return Self::empty(),
        };

        Self {
            root_hash: canonical.root,
            leaf_hashes,
            depth: canonical.depth,
            leaf_count: canonical.leaf_count(),
            node_metadata: std::collections::HashMap::new(),
        }
    }

    /// Create an empty content tree.
    pub fn empty() -> Self {
        Self {
            root_hash: Hash::default(),
            leaf_hashes: Vec::new(),
            depth: 0,
            leaf_count: 0,
            node_metadata: std::collections::HashMap::new(),
        }
    }

    /// Hash a leaf value with domain separation.
    pub fn hash_leaf(data: &[u8]) -> Hash {
        CanonicalMerkleTree::hash_leaf(data)
    }

    /// Generate a Merkle proof for a leaf at the given index.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf (0-based)
    ///
    /// # Returns
    /// A ContentProof if the index is valid
    pub fn proof(&self, leaf_index: usize) -> Option<ContentProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        // Build a temporary canonical tree to generate the proof
        let canonical = CanonicalMerkleTree::from_leaves(self.leaf_hashes.clone())?;
        let merkle_proof = canonical.proof(leaf_index)?;

        Some(ContentProof {
            leaf_index,
            leaf_hash: self.leaf_hashes[leaf_index],
            siblings: merkle_proof.siblings,
            root_hash: self.root_hash,
        })
    }

    /// Verify a leaf is included in this tree.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf
    /// * `leaf_data` - Raw leaf data
    ///
    /// # Returns
    /// True if the leaf is included
    pub fn verify_inclusion(&self, leaf_index: usize, leaf_data: &[u8]) -> bool {
        let leaf_hash = Self::hash_leaf(leaf_data);
        if let Some(proof) = self.proof(leaf_index) {
            proof.verify(leaf_hash)
        } else {
            false
        }
    }

    /// Add metadata for a node.
    pub fn set_node_metadata(&mut self, hash: Hash, metadata: NodeMetadata) {
        self.node_metadata.insert(hash, metadata);
    }

    /// Get metadata for a node.
    pub fn get_node_metadata(&self, hash: &Hash) -> Option<&NodeMetadata> {
        self.node_metadata.get(hash)
    }

    /// Compute the verification cost for this tree.
    pub fn verification_cost(&self) -> VerificationCost {
        VerificationCost {
            cpu: self.leaf_count as u64 * 10,
            memory: (self.leaf_count as u64) * 32 * (self.depth as u64 + 1),
            io: self.leaf_count as u64,
            recursion_depth: self.depth as u32,
        }
    }
}

impl Default for ContentTree {
    fn default() -> Self {
        Self::empty()
    }
}

/// A proof that a leaf is included in a content tree.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentProof {
    /// Index of the leaf in the tree.
    pub leaf_index: usize,
    /// Hash of the leaf.
    pub leaf_hash: Hash,
    /// Sibling hashes along the proof path.
    pub siblings: Vec<Hash>,
    /// Expected root hash.
    pub root_hash: Hash,
}

impl ContentProof {
    /// Verify this proof against a leaf hash.
    ///
    /// # Arguments
    /// * `leaf_hash` - The hash of the leaf to verify
    ///
    /// # Returns
    /// True if the proof is valid
    pub fn verify(&self, leaf_hash: Hash) -> bool {
        if leaf_hash != self.leaf_hash {
            return false;
        }

        // Use the canonical Merkle proof verification
        csv_hash::merkle::verifier::verify_merkle_proof(
            leaf_hash,
            &self.siblings,
            self.leaf_index,
            self.root_hash,
        )
    }

    /// Compute the root from this proof.
    ///
    /// # Arguments
    /// * `leaf_hash` - The hash of the leaf
    ///
    /// # Returns
    /// The computed root hash
    pub fn compute_root(&self, leaf_hash: Hash) -> Hash {
        csv_hash::merkle::verifier::compute_root_from_proof(
            leaf_hash,
            &self.siblings,
            self.leaf_index,
        )
    }
}

/// Resource accounting for verification paths.
///
/// Every verification path must calculate these costs
/// to reject pathological content.
/// L2 type without Hash fields - can use serde
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationCost {
    /// Estimated CPU cycles.
    pub cpu: u64,
    /// Estimated memory bytes.
    pub memory: u64,
    /// Estimated I/O operations.
    pub io: u64,
    /// Maximum recursion depth.
    pub recursion_depth: u32,
}

impl VerificationCost {
    /// Check if this cost is within acceptable limits.
    ///
    /// # Arguments
    /// * `max_cpu` - Maximum allowed CPU cycles
    /// * `max_memory` - Maximum allowed memory bytes
    /// * `max_io` - Maximum allowed I/O operations
    /// * `max_recursion` - Maximum allowed recursion depth
    ///
    /// # Returns
    /// True if all limits are respected
    pub fn is_acceptable(
        &self,
        max_cpu: u64,
        max_memory: u64,
        max_io: u64,
        max_recursion: u32,
    ) -> bool {
        self.cpu <= max_cpu
            && self.memory <= max_memory
            && self.io <= max_io
            && self.recursion_depth <= max_recursion
    }

    /// Check if this cost exceeds any limit.
    ///
    /// # Returns
    /// An error message if any limit is exceeded, None otherwise
    pub fn validate(
        &self,
        max_cpu: u64,
        max_memory: u64,
        max_io: u64,
        max_recursion: u32,
    ) -> Result<(), VerificationCostError> {
        if self.cpu > max_cpu {
            return Err(VerificationCostError::CpuExceeded {
                requested: self.cpu,
                limit: max_cpu,
            });
        }
        if self.memory > max_memory {
            return Err(VerificationCostError::MemoryExceeded {
                requested: self.memory,
                limit: max_memory,
            });
        }
        if self.io > max_io {
            return Err(VerificationCostError::IoExceeded {
                requested: self.io,
                limit: max_io,
            });
        }
        if self.recursion_depth > max_recursion {
            return Err(VerificationCostError::RecursionDepthExceeded {
                requested: self.recursion_depth,
                limit: max_recursion,
            });
        }
        Ok(())
    }
}

/// Error when verification cost exceeds limits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerificationCostError {
    #[error("CPU cost exceeded: requested {requested}, limit {limit}")]
    CpuExceeded { requested: u64, limit: u64 },
    #[error("Memory cost exceeded: requested {requested}, limit {limit}")]
    MemoryExceeded { requested: u64, limit: u64 },
    #[error("I/O cost exceeded: requested {requested}, limit {limit}")]
    IoExceeded { requested: u64, limit: u64 },
    #[error("Recursion depth exceeded: requested {requested}, limit {limit}")]
    RecursionDepthExceeded { requested: u32, limit: u32 },
}

/// A selective disclosure proof.
///
/// Allows proving subtree validity without exposing the full content.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureProof {
    /// The root of the disclosed subtree.
    pub subtree_root: Hash,
    /// Proof that the subtree root is included in the content tree root.
    pub inclusion_proof: ContentProof,
}

impl DisclosureProof {
    /// Verify this disclosure proof.
    ///
    /// # Arguments
    /// * `content_root` - The root hash of the full content tree
    ///
    /// # Returns
    /// True if the proof is valid
    pub fn verify(&self, content_root: Hash) -> bool {
        if self.inclusion_proof.root_hash != content_root {
            return false;
        }
        // Verify the subtree root is included in the content tree
        if !self.inclusion_proof.verify(self.subtree_root) {
            return false;
        }

        true
    }
}

/// A redacted Merkle proof.
///
/// Proves a leaf exists without revealing its content.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedMerkleProof {
    /// The hash of the redacted leaf.
    pub leaf_hash: Hash,
    /// The Merkle proof.
    pub proof: ContentProof,
    /// The redaction method used (e.g., "sha256", "blake3").
    pub redaction_method: String,
}

impl RedactedMerkleProof {
    /// Verify this redacted proof.
    pub fn verify(&self) -> bool {
        self.proof.verify(self.leaf_hash)
    }
}

/// An encrypted subtree proof.
///
/// Proves knowledge of an encrypted subtree without revealing its contents.
/// L2 type: uses serde for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSubtreeProof {
    /// The hash of the encrypted subtree root.
    pub encrypted_root: Hash,
    /// Proof that the encrypted root is in the content tree.
    pub inclusion_proof: ContentProof,
    /// Encryption algorithm used.
    pub encryption_algorithm: String,
    /// Key ID used for encryption.
    pub key_id: String,
}

impl EncryptedSubtreeProof {
    /// Verify this encrypted subtree proof.
    pub fn verify(&self, content_root: Hash) -> bool {
        self.inclusion_proof.root_hash == content_root
            && self.inclusion_proof.verify(self.encrypted_root)
    }
}
