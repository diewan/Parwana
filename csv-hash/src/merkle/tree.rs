//! Canonical Merkle tree implementation
//!
//! This module provides a canonical Merkle tree with:
//! - Ordered hashing (left < right deterministically)
//! - Leaf tagging (leaves are domain-separated from internal nodes)
//! - Internal node tagging (internal nodes use a different domain)
//! - Deterministic balancing (odd leaves are duplicated to maintain balance)
//! - Proof compression (sibling hashes only, no position metadata needed)

use std::vec::Vec;

use crate::Hash;
use crate::HashDomain;

/// A canonical Merkle tree with deterministic properties.
///
/// Properties:
/// 1. **Ordered hashing**: Children are always hashed as min(left, right) || max(left, right)
/// 2. **Leaf tagging**: Leaf nodes use the MerkleLeaf domain
/// 3. **Internal node tagging**: Internal nodes use the MerkleCombine domain
/// 4. **Deterministic balancing**: Odd leaves are duplicated to maintain a complete binary tree
/// 5. **Proof compression**: Proofs contain only sibling hashes, position is implicit
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// The root hash of the tree.
    pub root: Hash,
    /// All leaf hashes (before balancing).
    pub leaves: Vec<Hash>,
    /// The number of levels in the tree.
    pub depth: usize,
    /// The number of leaves after balancing (power of 2).
    pub balanced_count: usize,
}

impl MerkleTree {
    /// Build a canonical Merkle tree from leaf data.
    ///
    /// The tree is constructed with the following properties:
    /// - Leaves are hashed with domain separation (MerkleLeaf domain)
    /// - Internal nodes are hashed with domain separation (MerkleCombine domain)
    /// - Children are ordered deterministically (min || max)
    /// - Odd leaves are duplicated to maintain a complete binary tree
    ///
    /// # Arguments
    /// * `leaves` - Raw leaf data to hash and include in the tree
    ///
    /// # Returns
    /// The constructed MerkleTree, or None if no leaves are provided
    pub fn new(leaves: Vec<Vec<u8>>) -> Option<Self> {
        if leaves.is_empty() {
            return None;
        }

        // Hash leaves with domain separation
        let hashed_leaves: Vec<Hash> = leaves
            .iter()
            .map(|data| Self::hash_leaf(data))
            .collect();

        // Balance the tree (duplicate odd leaves)
        let balanced = Self::balance_leaves(hashed_leaves.clone());
        let balanced_count = balanced.len();

        // Build the tree
        let (root, depth) = Self::build_tree(balanced);

        Some(Self {
            root,
            leaves: hashed_leaves,
            depth,
            balanced_count,
        })
    }

    /// Build a Merkle tree from pre-hashed leaf values.
    ///
    /// Use this when leaves have already been hashed with domain separation.
    ///
    /// # Arguments
    /// * `leaf_hashes` - Pre-hashed leaf values
    ///
    /// # Returns
    /// The constructed MerkleTree, or None if no leaves are provided
    pub fn from_leaves(leaf_hashes: Vec<Hash>) -> Option<Self> {
        if leaf_hashes.is_empty() {
            return None;
        }

        let balanced = Self::balance_leaves(leaf_hashes.clone());
        let balanced_count = balanced.len();
        let (root, depth) = Self::build_tree(balanced);

        Some(Self {
            root,
            leaves: leaf_hashes,
            depth,
            balanced_count,
        })
    }

    /// Hash a leaf value with domain separation.
    ///
    /// Uses the MerkleLeaf domain to prevent cross-domain collisions.
    pub fn hash_leaf(data: &[u8]) -> Hash {
        use crate::tagged_hash::tagged_hash;
        tagged_hash(HashDomain::MerkleLeaf, data).hash
    }

    /// Combine two child hashes into a parent hash with domain separation.
    ///
    /// Uses ordered hashing: the smaller hash is always on the left.
    /// Uses the MerkleCombine domain to prevent cross-domain collisions.
    fn combine_children(left: &Hash, right: &Hash) -> Hash {
        use crate::tagged_hash::tagged_hash;

        // Ordered hashing: min || max
        let (lo, hi) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };

        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&lo.0);
        combined.extend_from_slice(&hi.0);

        tagged_hash(HashDomain::MerkleCombine, &combined).hash
    }

    /// Balance leaves to form a complete binary tree.
    ///
    /// If the number of leaves is odd and greater than 1, the last leaf is duplicated.
    /// A single leaf is left as-is (no duplication needed).
    /// The result is always a power of 2 (or 1).
    pub(crate) fn balance_leaves(leaves: Vec<Hash>) -> Vec<Hash> {
        if leaves.len() <= 1 {
            return leaves;
        }
        let mut balanced = leaves;
        while balanced.len() % 2 != 0 {
            let last = *balanced.last().unwrap();
            balanced.push(last);
        }
        balanced
    }

    /// Build the Merkle tree from balanced leaves.
    ///
    /// Returns the root hash and tree depth.
    pub(crate) fn build_tree(leaves: Vec<Hash>) -> (Hash, usize) {
        if leaves.len() == 1 {
            return (leaves[0], 0);
        }

        let mut current_level = leaves;
        let mut depth = 0;

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);

            for chunk in current_level.chunks(2) {
                match chunk {
                    [left, right] => {
                        next_level.push(Self::combine_children(left, right));
                    }
                    [single] => {
                        // Should not happen after balancing, but handle gracefully
                        next_level.push(*single);
                    }
                    _ => unreachable!(),
                }
            }

            current_level = next_level;
            depth += 1;
        }

        (current_level[0], depth)
    }

    /// Generate a Merkle proof for the leaf at the given index.
    ///
    /// The proof contains only sibling hashes. The leaf position is implicit
    /// in the proof verification process.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf to prove (0-based)
    ///
    /// # Returns
    /// A MerkleProof if the index is valid, None otherwise
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        // Build proof by traversing the tree level by level
        let mut siblings = Vec::new();
        let mut current_leaves = MerkleTree::balance_leaves(self.leaves.clone());
        let mut index = leaf_index;

        while current_leaves.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_leaves.chunks(2) {
                match chunk {
                    [left, right] => {
                        next_level.push(Self::combine_children(left, right));
                    }
                    [single] => {
                        next_level.push(*single);
                    }
                    _ => unreachable!(),
                }
            }

            // Determine sibling at this level based on current index
            if index % 2 == 0 {
                // Current is left child, sibling is the next element
                if index + 1 < current_leaves.len() {
                    siblings.push(current_leaves[index + 1]);
                }
            } else {
                // Current is right child, sibling is the previous element
                siblings.push(current_leaves[index - 1]);
            }

            current_leaves = next_level;
            index /= 2;
        }

        Some(MerkleProof {
            siblings,
            leaf_index,
            leaf_count: self.leaves.len(),
            balanced_count: self.balanced_count,
        })
    }

    /// Verify a leaf is included in this tree.
    ///
    /// This is a convenience method that generates a proof and verifies it.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf to verify
    /// * `leaf_data` - Raw leaf data
    ///
    /// # Returns
    /// True if the leaf is included in the tree
    pub fn verify_inclusion(&self, leaf_index: usize, leaf_data: &[u8]) -> bool {
        let leaf_hash = Self::hash_leaf(leaf_data);
        if let Some(proof) = self.proof(leaf_index) {
            proof.verify(leaf_hash, self.root)
        } else {
            false
        }
    }

    /// Get the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get the balanced leaf count (power of 2).
    pub fn balanced_leaf_count(&self) -> usize {
        self.balanced_count
    }
}

/// A Merkle proof consisting of sibling hashes.
///
/// The proof is compressed: it contains only sibling hashes, and the leaf
/// position is implicit in the verification process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// The sibling hashes along the path from leaf to root.
    pub siblings: Vec<Hash>,
    /// The leaf index in the original (unbalanced) tree.
    pub leaf_index: usize,
    /// The number of leaves in the original tree.
    pub leaf_count: usize,
    /// The number of leaves after balancing (power of 2).
    pub balanced_count: usize,
}

impl MerkleProof {
    /// Combine two node hashes with ordered hashing and domain separation.
    fn combine_nodes(left: &Hash, right: &Hash) -> Hash {
        use crate::tagged_hash::tagged_hash;

        let (lo, hi) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };

        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&lo.0);
        combined.extend_from_slice(&hi.0);

        tagged_hash(HashDomain::MerkleCombine, &combined).hash
    }

    /// Verify this proof against a known root.
    ///
    /// The verification process:
    /// 1. Start with the leaf hash
    /// 2. For each sibling, combine with current hash using ordered hashing
    /// 3. The final hash must equal the root
    ///
    /// # Arguments
    /// * `leaf` - The hashed leaf value
    /// * `root` - The expected root hash
    ///
    /// # Returns
    /// True if the proof is valid
    pub fn verify(&self, leaf: Hash, root: Hash) -> bool {
        if self.leaf_count == 0 {
            return false;
        }

        let mut current = leaf;
        let mut index = self.leaf_index;

        for sibling in &self.siblings {
            current = Self::combine_nodes(&current, sibling);
            index /= 2;
        }

        current == root
    }
}
