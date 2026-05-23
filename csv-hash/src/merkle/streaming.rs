//! Streaming Merkle tree computation
//!
//! Provides incremental Merkle tree construction for large datasets
/// that cannot fit in memory all at once.

use std::vec::Vec;

use crate::Hash;
use super::tree::{MerkleTree, MerkleProof};

/// A streaming Merkle tree builder.
///
/// Allows incremental construction of a Merkle tree by adding leaves
/// one at a time. The tree is built in memory but can handle large
/// datasets by processing leaves in batches.
#[derive(Debug, Clone)]
pub struct StreamingMerkleBuilder {
    leaves: Vec<Hash>,
    balanced_count: usize,
}

impl StreamingMerkleBuilder {
    /// Create a new streaming Merkle builder.
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            balanced_count: 0,
        }
    }

    /// Add a leaf to the tree.
    ///
    /// # Arguments
    /// * `data` - The leaf data to add
    pub fn add_leaf(&mut self, data: &[u8]) {
        let leaf_hash = MerkleTree::hash_leaf(data);
        self.leaves.push(leaf_hash);
    }

    /// Add multiple leaves to the tree.
    ///
    /// # Arguments
    /// * `data` - Slice of leaf data to add
    pub fn add_leaves(&mut self, data: &[&[u8]]) {
        for &item in data {
            self.add_leaf(item);
        }
    }

    /// Build the final Merkle tree.
    ///
    /// # Returns
    /// The constructed MerkleTree, or None if no leaves were added
    pub fn build(&self) -> Option<MerkleTree> {
        MerkleTree::from_leaves(self.leaves.clone())
    }

    /// Get the number of leaves added so far.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get the current root hash (if tree is balanced).
    ///
    /// Note: This returns the root of the current (possibly unbalanced) tree.
    /// For the final root, use `build()`.
    pub fn current_root(&self) -> Option<Hash> {
        if self.leaves.is_empty() {
            return None;
        }

        let balanced = MerkleTree::balance_leaves(self.leaves.clone());
        let (root, _) = MerkleTree::build_tree(balanced);
        Some(root)
    }
}

impl Default for StreamingMerkleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A streaming Merkle proof generator.
///
/// Generates proofs for leaves as they are added to the tree.
/// Useful for applications that need to generate proofs incrementally.
///
/// Note: Proofs generated during incremental addition may become invalid
/// when more leaves are added. Use `build_proofs()` after all leaves
/// are added to get valid proofs for the final tree.
#[derive(Debug)]
pub struct StreamingMerkleProofGenerator {
    builder: StreamingMerkleBuilder,
    proofs: Vec<Option<MerkleProof>>,
}

impl StreamingMerkleProofGenerator {
    /// Create a new streaming proof generator.
    pub fn new() -> Self {
        Self {
            builder: StreamingMerkleBuilder::new(),
            proofs: Vec::new(),
        }
    }

    /// Add a leaf to the generator.
    ///
    /// # Arguments
    /// * `data` - The leaf data to add
    pub fn add_leaf(&mut self, data: &[u8]) {
        self.builder.add_leaf(data);
    }

    /// Add a leaf and generate a proof for it.
    ///
    /// # Arguments
    /// * `data` - The leaf data to add
    ///
    /// # Returns
    /// The proof for the added leaf, or None if the tree is empty
    ///
    /// Note: This proof is based on the current tree state and may become
    /// invalid when more leaves are added. Use `build_proofs()` for
    /// valid proofs of the final tree.
    pub fn add_and_prove(&mut self, data: &[u8]) -> Option<MerkleProof> {
        let index = self.builder.leaf_count();
        self.builder.add_leaf(data);

        // Build tree to generate proof
        let tree = self.builder.build()?;
        let proof = tree.proof(index);

        // Update proofs vector
        while self.proofs.len() <= index {
            self.proofs.push(None);
        }
        self.proofs[index] = proof.clone();

        proof
    }

    /// Get the proof for a previously added leaf.
    ///
    /// # Arguments
    /// * `index` - The index of the leaf
    ///
    /// # Returns
    /// The proof for the leaf, or None if not yet generated
    pub fn get_proof(&self, index: usize) -> Option<&MerkleProof> {
        self.proofs.get(index).and_then(|p| p.as_ref())
    }

    /// Build the final tree without generating proofs.
    ///
    /// Use this when you only need the final tree root.
    pub fn build(&self) -> Option<MerkleTree> {
        self.builder.build()
    }

    /// Build the final tree and regenerate all proofs.
    ///
    /// This should be called after all leaves are added to get valid
    /// proofs for the final tree structure.
    ///
    /// # Returns
    /// The constructed MerkleTree, or None if no leaves were added
    pub fn build_proofs(&mut self) -> Option<MerkleTree> {
        let tree = self.builder.build()?;

        // Regenerate all proofs
        self.proofs.clear();
        for i in 0..tree.leaf_count() {
            self.proofs.push(tree.proof(i));
        }

        Some(tree)
    }
}

impl Default for StreamingMerkleProofGenerator {
    fn default() -> Self {
        Self::new()
    }
}
