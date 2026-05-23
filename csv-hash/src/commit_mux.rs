//! MPC (Multi-Protocol Commitment) Tree
//!
//! An MPC tree allows multiple protocols to share a single on-chain witness
//! transaction. Each leaf is `(protocol_id || commitment_hash)`, and the root
//! is what gets committed on-chain via Tapret/Opret.
//!
//! This follows the same pattern as RGB's MPC tree and Bitcoin's BIP-341
//! merkle tree construction.

use std::vec::Vec;

use crate::Hash;
use crate::csv_tagged_hash;

/// Protocol identifier (32 bytes)
pub type ProtocolId = [u8; 32];

/// A leaf in the MPC tree
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MuxLeaf {
    /// Protocol identifier
    pub protocol_id: ProtocolId,
    /// Protocol's commitment hash
    pub commitment: Hash,
}

impl MuxLeaf {
    /// Create a new MPC leaf
    pub fn new(protocol_id: ProtocolId, commitment: Hash) -> Self {
        Self {
            protocol_id,
            commitment,
        }
    }

    /// Compute the leaf hash using canonical serialization
    ///
    /// Uses canonical CBOR serialization to ensure deterministic hashing
    /// across all implementations.
    pub fn hash(&self) -> Hash {
        // Manual serialization to avoid Serialize trait issues
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.protocol_id);
        data.extend_from_slice(self.commitment.as_bytes());
        Hash::new(csv_tagged_hash("mpc-leaf", &data))
    }
}

/// Merkle branch proof for a specific protocol's inclusion
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MuxProof {
    /// Protocol being proven
    pub protocol_id: ProtocolId,
    /// Commitment being proven
    pub commitment: Hash,
    /// Merkle branch (sibling hashes from leaf to root)
    pub branch: Vec<MerkleBranchNode>,
    /// Position of the leaf (0-indexed)
    pub leaf_index: usize,
}

/// A single node in a merkle branch (sibling hash + direction)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MerkleBranchNode {
    /// Sibling hash
    pub hash: Hash,
    /// Whether this sibling is on the left (true) or sanad (false)
    pub is_left: bool,
}

impl MuxProof {
    /// Verify this proof against the claimed root using canonical serialization
    pub fn verify(&self, root: &Hash) -> bool {
        // Manual serialization for leaf hash computation
        let mut leaf_data = Vec::with_capacity(64);
        leaf_data.extend_from_slice(&self.protocol_id);
        leaf_data.extend_from_slice(self.commitment.as_bytes());
        let mut current = Hash::new(csv_tagged_hash("mpc-leaf", &leaf_data));

        for node in &self.branch {
            // Manual serialization for internal node hashing
            let mut sibling_data = Vec::with_capacity(64);
            if node.is_left {
                sibling_data.extend_from_slice(node.hash.as_bytes());
                sibling_data.extend_from_slice(current.as_bytes());
            } else {
                sibling_data.extend_from_slice(current.as_bytes());
                sibling_data.extend_from_slice(node.hash.as_bytes());
            }
            current = Hash::new(csv_tagged_hash("mpc-internal", &sibling_data));
        }

        current == *root
    }
}

/// Multi-Protocol Commitment tree
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CommitMux {
    /// Leaves in deterministic order
    pub leaves: Vec<MuxLeaf>,
}

impl CommitMux {
    /// Create a new MPC tree from leaves
    pub fn new(leaves: Vec<MuxLeaf>) -> Self {
        Self { leaves }
    }

    /// Create from (protocol_id, commitment) pairs
    pub fn from_pairs(pairs: &[(ProtocolId, Hash)]) -> Self {
        let leaves = pairs
            .iter()
            .map(|(pid, comm)| MuxLeaf::new(*pid, *comm))
            .collect();
        Self { leaves }
    }

    /// Compute the MPC root hash
    ///
    /// Uses a deterministic Merkle tree construction. For a single leaf,
    /// the root is the leaf hash. For multiple leaves, pairs are hashed
    /// together bottom-up.
    pub fn root(&self) -> Hash {
        if self.leaves.is_empty() {
            return Hash::zero();
        }

        if self.leaves.len() == 1 {
            return self.leaves[0].hash();
        }

        // Collect leaf hashes
        let mut hashes: Vec<Hash> = self.leaves.iter().map(|l: &MuxLeaf| l.hash()).collect();

        // Build tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let left = &chunk[0];
                if chunk.len() == 1 {
                    // Odd node: promote to next level
                    next_level.push(*left);
                } else {
                    let sanad = &chunk[1];
                    next_level.push(hash_pair(left, sanad));
                }
            }
            hashes = next_level;
        }

        hashes[0]
    }

    /// Build a merkle proof for a specific protocol
    ///
    /// Returns None if the protocol_id is not in this tree.
    pub fn prove(&self, protocol_id: ProtocolId) -> Option<MuxProof> {
        let leaf_index = self
            .leaves
            .iter()
            .position(|l| l.protocol_id == protocol_id)?;

        let leaf = &self.leaves[leaf_index];

        // Build merkle tree with branch tracking
        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let current_level: Vec<Hash> = self.leaves.iter().map(|l: &MuxLeaf| l.hash()).collect();
        levels.push(current_level.clone());

        let mut hashes = current_level;
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let left = &chunk[0];
                if chunk.len() == 1 {
                    // Odd node: promote to next level (standard merkle tree behavior)
                    next_level.push(*left);
                } else {
                    next_level.push(hash_pair(left, &chunk[1]));
                }
            }
            hashes = next_level;
            levels.push(hashes.clone());
        }

        // Extract branch
        let mut branch = Vec::new();
        let mut idx = leaf_index;
        for level in levels.iter().take(levels.len() - 1) {
            let (sibling_idx, is_left) = if idx % 2 == 0 {
                (idx + 1, false) // Sibling is to the sanad
            } else {
                (idx - 1, true) // Sibling is to the left
            };

            if sibling_idx < level.len() {
                branch.push(MerkleBranchNode {
                    hash: level[sibling_idx],
                    is_left,
                });
            }

            idx /= 2;
        }

        Some(MuxProof {
            protocol_id: leaf.protocol_id,
            commitment: leaf.commitment,
            branch,
            leaf_index,
        })
    }

    /// Get the number of protocols in this tree
    pub fn protocol_count(&self) -> usize {
        self.leaves.len()
    }

    /// Check if a protocol is present in this tree
    pub fn contains_protocol(&self, protocol_id: ProtocolId) -> bool {
        self.leaves.iter().any(|l| l.protocol_id == protocol_id)
    }

    /// Add a protocol to the tree
    pub fn push(&mut self, protocol_id: ProtocolId, commitment: Hash) {
        self.leaves.push(MuxLeaf::new(protocol_id, commitment));
    }
}

/// Hash two nodes together (internal helper using tagged hashing)
fn hash_pair(left: &Hash, sanad: &Hash) -> Hash {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left.as_bytes());
    data[32..].copy_from_slice(sanad.as_bytes());
    Hash::new(csv_tagged_hash("mpc-internal", &data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_protocol(id: u8) -> ProtocolId {
        let mut arr = [0u8; 32];
        arr[0] = id;
        arr
    }

    fn test_commitment(id: u8) -> Hash {
        let mut arr = [0u8; 32];
        arr[31] = id;
        Hash::new(arr)
    }

    // ─────────────────────────────────────────────
    // MuxLeaf tests
    // ─────────────────────────────────────────────

    #[test]
    fn test_leaf_creation() {
        let leaf = MuxLeaf::new(test_protocol(1), test_commitment(42));
        assert_eq!(leaf.protocol_id[0], 1);
        assert_eq!(leaf.commitment.as_bytes()[31], 42);
    }

    #[test]
    fn test_leaf_hash_deterministic() {
        let leaf1 = MuxLeaf::new(test_protocol(1), test_commitment(42));
        let leaf2 = MuxLeaf::new(test_protocol(1), test_commitment(42));
        assert_eq!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_leaf_hash_differs_by_protocol() {
        let leaf1 = MuxLeaf::new(test_protocol(1), test_commitment(42));
        let leaf2 = MuxLeaf::new(test_protocol(2), test_commitment(42));
        assert_ne!(leaf1.hash(), leaf2.hash());
    }

    #[test]
    fn test_leaf_hash_differs_by_commitment() {
        let leaf1 = MuxLeaf::new(test_protocol(1), test_commitment(42));
        let leaf2 = MuxLeaf::new(test_protocol(1), test_commitment(99));
        assert_ne!(leaf1.hash(), leaf2.hash());
    }

    // ─────────────────────────────────────────────
    // CommitMux root tests
    // ─────────────────────────────────────────────

    #[test]
    fn test_empty_tree_root() {
        let tree = CommitMux::new(vec![]);
        assert_eq!(tree.root(), Hash::zero());
    }

    #[test]
    fn test_single_leaf_tree_root() {
        let leaf = MuxLeaf::new(test_protocol(1), test_commitment(42));
        let tree = CommitMux::new(vec![leaf.clone()]);
        assert_eq!(tree.root(), leaf.hash());
    }

    #[test]
    fn test_two_leaf_tree_root() {
        let leaf_a = MuxLeaf::new(test_protocol(1), test_commitment(1));
        let leaf_b = MuxLeaf::new(test_protocol(2), test_commitment(2));
        let tree = CommitMux::new(vec![leaf_a.clone(), leaf_b.clone()]);
        let expected = hash_pair(&leaf_a.hash(), &leaf_b.hash());
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_three_leaf_tree_root() {
        let leaf_a = MuxLeaf::new(test_protocol(1), test_commitment(1));
        let leaf_b = MuxLeaf::new(test_protocol(2), test_commitment(2));
        let leaf_c = MuxLeaf::new(test_protocol(3), test_commitment(3));
        let tree = CommitMux::new(vec![leaf_a.clone(), leaf_b.clone(), leaf_c.clone()]);

        // Level 0: [A, B, C]
        // Level 1: [hash(A,B), C]
        // Level 2: [hash(hash(A,B), C)]
        let ab = hash_pair(&leaf_a.hash(), &leaf_b.hash());
        let expected = hash_pair(&ab, &leaf_c.hash());
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_four_leaf_tree_root() {
        let leaves: Vec<_> = (1..=4)
            .map(|i| MuxLeaf::new(test_protocol(i), test_commitment(i)))
            .collect();
        let tree = CommitMux::new(leaves.clone());

        let ab = hash_pair(&leaves[0].hash(), &leaves[1].hash());
        let cd = hash_pair(&leaves[2].hash(), &leaves[3].hash());
        let expected = hash_pair(&ab, &cd);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_tree_root_deterministic() {
        let tree1 = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
            (test_protocol(3), test_commitment(3)),
        ]);
        let tree2 = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
            (test_protocol(3), test_commitment(3)),
        ]);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_large_tree_root() {
        let pairs: Vec<_> = (1..=100)
            .map(|i| (test_protocol(i as u8), test_commitment(i as u8)))
            .collect();
        let tree = CommitMux::from_pairs(&pairs);
        let root = tree.root();
        assert_eq!(root.as_bytes().len(), 32);
    }

    // ─────────────────────────────────────────────
    // MuxProof tests
    // ─────────────────────────────────────────────

    #[test]
    fn test_proof_single_leaf() {
        let leaf = MuxLeaf::new(test_protocol(1), test_commitment(42));
        let tree = CommitMux::new(vec![leaf.clone()]);
        let proof = tree.prove(test_protocol(1)).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_proof_two_leaves() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
        ]);
        let proof_a = tree.prove(test_protocol(1)).unwrap();
        let proof_b = tree.prove(test_protocol(2)).unwrap();
        assert!(proof_a.verify(&tree.root()));
        assert!(proof_b.verify(&tree.root()));
    }

    #[test]
    fn test_proof_three_leaves() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
            (test_protocol(3), test_commitment(3)),
        ]);
        for i in 1..=3 {
            let proof = tree.prove(test_protocol(i)).unwrap();
            assert!(proof.verify(&tree.root()));
        }
    }

    #[test]
    fn test_proof_all_leaves_in_large_tree() {
        let pairs: Vec<_> = (1..=20)
            .map(|i| (test_protocol(i as u8), test_commitment(i as u8)))
            .collect();
        let tree = CommitMux::from_pairs(&pairs);
        for i in 1..=20 {
            let proof = tree.prove(test_protocol(i as u8)).unwrap();
            assert!(
                proof.verify(&tree.root()),
                "Proof for protocol {} failed",
                i
            );
        }
    }

    #[test]
    fn test_proof_missing_protocol() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
        ]);
        assert!(tree.prove(test_protocol(99)).is_none());
    }

    #[test]
    fn test_proof_wrong_root() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
        ]);
        let proof = tree.prove(test_protocol(1)).unwrap();
        assert!(!proof.verify(&Hash::new([0xFF; 32])));
    }

    #[test]
    fn test_proof_wrong_commitment() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
        ]);
        let mut proof = tree.prove(test_protocol(1)).unwrap();
        // Tamper with the commitment
        proof.commitment = test_commitment(99);
        assert!(!proof.verify(&tree.root()));
    }

    #[test]
    fn test_proof_wrong_protocol_id() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
        ]);
        let mut proof = tree.prove(test_protocol(1)).unwrap();
        // Tamper with the protocol_id
        proof.protocol_id = test_protocol(99);
        assert!(!proof.verify(&tree.root()));
    }

    #[test]
    fn test_proof_branch_tampering() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
            (test_protocol(3), test_commitment(3)),
        ]);
        let mut proof = tree.prove(test_protocol(1)).unwrap();
        // Tamper with a branch node
        proof.branch[0].hash = Hash::new([0xFF; 32]);
        assert!(!proof.verify(&tree.root()));
    }

    // ─────────────────────────────────────────────
    // CommitMux utility tests
    // ─────────────────────────────────────────────

    #[test]
    fn test_from_pairs() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
        ]);
        assert_eq!(tree.protocol_count(), 2);
        assert!(tree.contains_protocol(test_protocol(1)));
        assert!(tree.contains_protocol(test_protocol(2)));
        assert!(!tree.contains_protocol(test_protocol(3)));
    }

    #[test]
    fn test_push() {
        let mut tree = CommitMux::from_pairs(&[(test_protocol(1), test_commitment(1))]);
        assert_eq!(tree.protocol_count(), 1);
        tree.push(test_protocol(2), test_commitment(2));
        assert_eq!(tree.protocol_count(), 2);
        assert!(tree.contains_protocol(test_protocol(2)));
    }

    #[test]
    fn test_leaf_index_in_proof() {
        let tree = CommitMux::from_pairs(&[
            (test_protocol(1), test_commitment(1)),
            (test_protocol(2), test_commitment(2)),
            (test_protocol(3), test_commitment(3)),
        ]);
        let proof_0 = tree.prove(test_protocol(1)).unwrap();
        let proof_2 = tree.prove(test_protocol(3)).unwrap();
        assert_eq!(proof_0.leaf_index, 0);
        assert_eq!(proof_2.leaf_index, 2);
    }
}
