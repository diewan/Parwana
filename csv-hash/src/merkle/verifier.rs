//! Merkle proof verifier
//!
//! Provides standalone verification of Merkle proofs without requiring
//! the full tree structure. Useful for SPV clients and light nodes.

use crate::tagged_hash::tagged_hash;
use crate::{Hash, HashDomain};

/// Combine two node hashes with ordered hashing and domain separation.
fn combine_nodes(left: &Hash, right: &Hash) -> Hash {
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

/// Verifies a Merkle proof against a known root and leaf.
///
/// This is a stateless verification function that can be used by
/// light clients and SPV nodes to verify inclusion proofs.
///
/// # Arguments
/// * `leaf` - The hashed leaf value
/// * `siblings` - The sibling hashes along the proof path
/// * `leaf_index` - The index of the leaf in the tree
/// * `root` - The expected root hash
///
/// # Returns
/// True if the proof is valid
pub fn verify_merkle_proof(leaf: Hash, siblings: &[Hash], leaf_index: usize, root: Hash) -> bool {
    if siblings.is_empty() {
        return leaf == root;
    }

    let mut current = leaf;
    let mut index = leaf_index;

    for sibling in siblings {
        current = combine_nodes(&current, sibling);
        index /= 2;
    }

    current == root
}

/// Verifies multiple Merkle proofs in batch.
///
/// Useful for verifying multiple leaves against the same root.
///
/// # Arguments
/// * `proofs` - Slice of (leaf, siblings, leaf_index) tuples
/// * `root` - The expected root hash
///
/// # Returns
/// A vector of booleans indicating whether each proof is valid
pub fn verify_merkle_proofs_batch(proofs: &[(Hash, Vec<Hash>, usize)], root: Hash) -> Vec<bool> {
    proofs
        .iter()
        .map(|(leaf, siblings, index)| verify_merkle_proof(*leaf, siblings, *index, root))
        .collect()
}

/// Computes the root hash from a leaf and its proof path.
///
/// Useful for reconstructing the root from a proof for comparison.
///
/// # Arguments
/// * `leaf` - The hashed leaf value
/// * `siblings` - The sibling hashes along the proof path
/// * `leaf_index` - The index of the leaf in the tree
///
/// # Returns
/// The computed root hash
pub fn compute_root_from_proof(leaf: Hash, siblings: &[Hash], leaf_index: usize) -> Hash {
    let mut current = leaf;
    let mut index = leaf_index;

    for sibling in siblings {
        current = combine_nodes(&current, sibling);
        index /= 2;
    }

    current
}
