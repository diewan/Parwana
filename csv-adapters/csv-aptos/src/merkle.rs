//! Aptos Merkle Accumulator implementation
//!
//! This module provides production-grade Merkle accumulator support for Aptos,
//! implementing the native state verification using the Merkle Accumulator structure.

use csv_hash::{AptosAnchorDomain, DomainSeparatedHash};

/// Merkle accumulator errors
#[derive(Debug, thiserror::Error)]
pub enum MerkleAccumulatorError {
    #[error("Invalid accumulator proof")]
    InvalidProof,
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Empty accumulator")]
    EmptyAccumulator,
}

/// Result type for Merkle accumulator operations
pub type MerkleAccumulatorResult<T> = Result<T, MerkleAccumulatorError>;

/// A leaf in the Merkle accumulator
#[derive(Clone, Debug)]
pub struct Leaf {
    /// The hash of the data
    pub hash: [u8; 32],
    /// The index of this leaf
    pub index: u64,
    /// The data itself
    pub data: Vec<u8>,
}

/// A node in the Merkle accumulator
#[derive(Clone, Debug)]
pub enum MerkleNode {
    /// Leaf node
    Leaf(Leaf),
    /// Internal node with left and sanad children
    Internal {
        hash: [u8; 32],
        left: Box<MerkleNode>,
        sanad: Box<MerkleNode>,
    },
    /// Empty node
    Empty,
}

impl MerkleNode {
    /// Compute the hash of this node
    pub fn hash(&self) -> [u8; 32] {
        match self {
            MerkleNode::Leaf(leaf) => leaf.hash,
            MerkleNode::Internal { hash, .. } => *hash,
            MerkleNode::Empty => Self::empty_hash(),
        }
    }

    /// Compute the hash of an empty subtree at a given depth
    pub fn empty_hash() -> [u8; 32] {
        // Empty hash uses domain-separated hashing
        let hash = DomainSeparatedHash::<AptosAnchorDomain>::hash(b"");
        hash.as_bytes().to_vec().try_into().unwrap_or([0u8; 32])
    }

    /// Compute the hash of an internal node from its children
    /// Uses domain separation to prevent second-preimage attacks
    pub fn compute_internal_hash(left_hash: [u8; 32], sanad_hash: [u8; 32]) -> [u8; 32] {
        // Build payload with domain separator 0x01 per RFC 6962
        let mut payload = Vec::with_capacity(65);
        payload.push(0x01u8);
        payload.extend_from_slice(&left_hash);
        payload.extend_from_slice(&sanad_hash);

        let hash = DomainSeparatedHash::<AptosAnchorDomain>::hash(&payload);
        hash.as_bytes().to_vec().try_into().unwrap_or([0u8; 32])
    }
}

/// Merkle accumulator for Aptos state verification
#[derive(Clone, Debug)]
pub struct MerkleAccumulator {
    /// Root node of the accumulator
    root: MerkleNode,
    /// Number of leaves
    num_leaves: u64,
}

impl Default for MerkleAccumulator {
    fn default() -> Self {
        Self {
            root: MerkleNode::Empty,
            num_leaves: 0,
        }
    }
}

impl MerkleAccumulator {
    /// Create a new empty Merkle accumulator
    pub fn new() -> Self {
        Self {
            root: MerkleNode::Empty,
            num_leaves: 0,
        }
    }

    /// Create a Merkle accumulator from a set of leaf hashes.
    ///
    /// Uses iterative index-based computation on a flat `Vec<[u8;32]>` to avoid
    /// cloning entire node trees per level. Memory-efficient O(n) allocation.
    pub fn from_leaves(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return Self::new();
        }

        let num_leaves = leaves.len() as u64;

        // Build tree iteratively using index-based computation on a flat hash vec.
        // This avoids cloning MerkleNode trees at each level (PF-04 optimization).
        let mut hashes: Vec<[u8; 32]> = leaves.to_vec();

        while hashes.len() > 1 {
            let mut next_level = Vec::with_capacity(hashes.len().div_ceil(2));
            let mut i = 0;
            while i < hashes.len() {
                if i + 1 < hashes.len() {
                    // Pair: hash(0x01 || left || right)
                    let h = MerkleNode::compute_internal_hash(hashes[i], hashes[i + 1]);
                    next_level.push(h);
                    i += 2;
                } else {
                    // Odd node: duplicate last (Aptos accumulator convention)
                    let h = MerkleNode::compute_internal_hash(hashes[i], hashes[i]);
                    next_level.push(h);
                    i += 1;
                }
            }
            hashes = next_level;
        }

        // Build the actual MerkleNode tree from the root hash using the leaf hashes.
        // For verification purposes, we only need the root hash and leaf count.
        let root = if hashes.len() == 1 {
            // Create a minimal node structure with the computed root hash
            // The actual tree structure is implicit in the leaf ordering
            MerkleNode::Internal {
                hash: hashes[0],
                left: Box::new(MerkleNode::Empty),
                sanad: Box::new(MerkleNode::Empty),
            }
        } else {
            MerkleNode::Empty
        };

        Self { root, num_leaves }
    }

    /// Build a Merkle tree from a slice of nodes — optimized to avoid deep clones.
    ///
    /// Retained as the reference tree builder; the adapter verifies supplied proofs
    /// rather than constructing trees.
    #[allow(dead_code)]
    fn build_tree(nodes: &[MerkleNode]) -> MerkleNode {
        if nodes.is_empty() {
            return MerkleNode::Empty;
        }

        if nodes.len() == 1 {
            return nodes[0].clone();
        }

        // Extract hashes first, build iteratively, then reconstruct tree.
        // This avoids cloning the entire node tree at each level (PF-04).
        let mut hashes: Vec<[u8; 32]> = nodes.iter().map(|n| n.hash()).collect();

        while hashes.len() > 1 {
            let mut next_level = Vec::with_capacity(hashes.len().div_ceil(2));
            let mut i = 0;
            while i < hashes.len() {
                if i + 1 < hashes.len() {
                    let h = MerkleNode::compute_internal_hash(hashes[i], hashes[i + 1]);
                    next_level.push(h);
                    i += 2;
                } else {
                    let h = MerkleNode::compute_internal_hash(hashes[i], hashes[i]);
                    next_level.push(h);
                    i += 1;
                }
            }
            hashes = next_level;
        }

        // Reconstruct a minimal node with the computed root hash
        if hashes.len() == 1 {
            MerkleNode::Internal {
                hash: hashes[0],
                left: Box::new(MerkleNode::Empty),
                sanad: Box::new(MerkleNode::Empty),
            }
        } else {
            MerkleNode::Empty
        }
    }

    /// Get the root hash
    pub fn root_hash(&self) -> [u8; 32] {
        self.root.hash()
    }

    /// Get the number of leaves
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    /// Verify a Merkle proof for a leaf at a given index
    pub fn verify_proof(&self, leaf_hash: [u8; 32], index: u64, proof: &[MerkleProofItem]) -> bool {
        if proof.is_empty() {
            // If no proof, we're at the root
            return self.root_hash() == leaf_hash && self.num_leaves == 1;
        }

        // Compute the root from the leaf and proof
        let computed_root = Self::compute_root_from_leaf(leaf_hash, index, proof);
        computed_root == self.root_hash()
    }

    /// Compute the root hash from a leaf hash and its proof
    fn compute_root_from_leaf(
        leaf_hash: [u8; 32],
        index: u64,
        proof: &[MerkleProofItem],
    ) -> [u8; 32] {
        let mut current_hash = leaf_hash;
        let mut _current_index = index;

        for item in proof {
            match item {
                MerkleProofItem::Left { hash } => {
                    // The sibling is on the left
                    current_hash = MerkleNode::compute_internal_hash(*hash, current_hash);
                }
                MerkleProofItem::Sanad { hash } => {
                    // The sibling is on the sanad
                    current_hash = MerkleNode::compute_internal_hash(current_hash, *hash);
                }
            }
            _current_index /= 2;
        }

        current_hash
    }
}

/// A proof item in the Merkle accumulator
#[derive(Clone, Debug)]
pub enum MerkleProofItem {
    /// Sibling hash on the left
    Left { hash: [u8; 32] },
    /// Sibling hash on the sanad
    Sanad { hash: [u8; 32] },
}

/// State proof for Aptos resource verification
#[derive(Clone, Debug)]
pub struct StateProof {
    /// The account address
    pub address: [u8; 32],
    /// The resource type tag
    pub resource_type: String,
    /// Whether the resource exists
    pub exists: bool,
    /// Resource data if it exists
    pub data: Option<Vec<u8>>,
    /// Merkle proof against accumulator root
    pub accumulator_proof: Vec<MerkleProofItem>,
    /// State version this proof is for
    pub version: u64,
    /// The leaf hash
    pub leaf_hash: [u8; 32],
}

impl StateProof {
    /// Create a new state proof
    pub fn new(
        address: [u8; 32],
        resource_type: String,
        exists: bool,
        data: Option<Vec<u8>>,
        accumulator_proof: Vec<MerkleProofItem>,
        version: u64,
        leaf_hash: [u8; 32],
    ) -> Self {
        Self {
            address,
            resource_type,
            exists,
            data,
            accumulator_proof,
            version,
            leaf_hash,
        }
    }

    /// Compute the leaf hash for this state proof
    pub fn compute_leaf_hash(&self) -> [u8; 32] {
        // Build payload with domain separation
        let mut payload = Vec::new();
        payload.extend_from_slice(b"APTOS::STATE::LEAF");
        payload.extend_from_slice(&self.address);
        payload.extend_from_slice(self.resource_type.as_bytes());
        if self.exists {
            payload.extend_from_slice(b"EXISTS");
            if let Some(data) = &self.data {
                payload.extend_from_slice(data);
            }
        } else {
            payload.extend_from_slice(b"NOT_EXISTS");
        }

        let hash = DomainSeparatedHash::<AptosAnchorDomain>::hash(&payload);
        hash.as_bytes().to_vec().try_into().unwrap_or([0u8; 32])
    }

    /// Verify this state proof against an expected root
    pub fn verify(&self, expected_root: [u8; 32]) -> bool {
        let leaf_hash = self.compute_leaf_hash();

        // Verify the leaf hash matches what we computed
        if leaf_hash != self.leaf_hash {
            return false;
        }

        // Verify the proof produces the expected root
        let computed_root = MerkleAccumulator::compute_root_from_leaf(
            leaf_hash,
            0, // In production, use the actual leaf index
            &self.accumulator_proof,
        );

        computed_root == expected_root
    }
}

/// Transaction proof for Aptos transaction verification
#[derive(Clone, Debug)]
pub struct TransactionProof {
    /// Transaction version
    pub version: u64,
    /// Transaction hash
    pub hash: [u8; 32],
    /// State change hash
    pub state_change_hash: [u8; 32],
    /// Event root hash
    pub event_root_hash: [u8; 32],
    /// State checkpoint hash
    pub state_checkpoint_hash: Option<[u8; 32]>,
    /// Epoch
    pub epoch: u64,
    /// Round
    pub round: u64,
    /// Merkle proof against ledger root
    pub ledger_proof: Vec<MerkleProofItem>,
}

impl TransactionProof {
    /// Create a new transaction proof
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u64,
        hash: [u8; 32],
        state_change_hash: [u8; 32],
        event_root_hash: [u8; 32],
        state_checkpoint_hash: Option<[u8; 32]>,
        epoch: u64,
        round: u64,
        ledger_proof: Vec<MerkleProofItem>,
    ) -> Self {
        Self {
            version,
            hash,
            state_change_hash,
            event_root_hash,
            state_checkpoint_hash,
            epoch,
            round,
            ledger_proof,
        }
    }
}

/// Event proof for Aptos event verification
#[derive(Clone, Debug)]
pub struct EventProof {
    /// Event hash
    pub hash: [u8; 32],
    /// Event index
    pub index: u64,
    /// Merkle proof against event root
    pub event_proof: Vec<MerkleProofItem>,
}

impl EventProof {
    /// Create a new event proof
    pub fn new(hash: [u8; 32], index: u64, event_proof: Vec<MerkleProofItem>) -> Self {
        Self {
            hash,
            index,
            event_proof,
        }
    }

    /// Verify this event proof against an event root
    pub fn verify(&self, event_root: [u8; 32]) -> bool {
        let computed_root =
            MerkleAccumulator::compute_root_from_leaf(self.hash, self.index, &self.event_proof);

        computed_root == event_root
    }
}

/// Ledger proof for verifying ledger version
#[derive(Clone, Debug)]
pub struct LedgerProof {
    /// Ledger version
    pub version: u64,
    /// Ledger root hash
    pub root_hash: [u8; 32],
    /// Chain ID
    pub chain_id: u64,
    /// Epoch
    pub epoch: u64,
    /// Merkle proof
    pub proof: Vec<MerkleProofItem>,
}

impl LedgerProof {
    /// Create a new ledger proof
    pub fn new(
        version: u64,
        root_hash: [u8; 32],
        chain_id: u64,
        epoch: u64,
        proof: Vec<MerkleProofItem>,
    ) -> Self {
        Self {
            version,
            root_hash,
            chain_id,
            epoch,
            proof,
        }
    }

    /// Structural pre-check only. Does NOT verify the Merkle accumulator path.
    /// Use `verify_against_accumulator()` in production code.
    #[cfg(any(test, feature = "dev-mocks"))]
    pub fn verify_structure_only(&self) -> bool {
        self.root_hash != [0u8; 32]
    }

    /// Full Merkle accumulator proof verification.
    ///
    /// Verifies that `self.root_hash` is a valid leaf at position `self.version`
    /// in the Aptos JMT accumulator rooted at `expected_accumulator_root`.
    ///
    /// The Aptos accumulator uses a bottom-up hash rule:
    ///   parent = sha3_256(0x01 || left || right)
    /// where left/right ordering depends on position parity.
    pub fn verify_against_accumulator(
        &self,
        expected_accumulator_root: [u8; 32],
    ) -> Result<bool, MerkleAccumulatorError> {
        if self.proof.is_empty() && self.root_hash != expected_accumulator_root {
            return Err(MerkleAccumulatorError::InvalidProof);
        }
        if self.proof.is_empty() {
            return Ok(true);
        }

        // Walk the sibling hashes bottom-up using the Aptos accumulator hash rule:
        //   parent = sha3_256(0x01 || left || right)
        let mut current = self.root_hash;
        let mut pos = self.version;
        for sibling in &self.proof {
            let (left, right) = if pos.is_multiple_of(2) {
                (
                    current,
                    match sibling {
                        MerkleProofItem::Left { hash } => *hash,
                        MerkleProofItem::Sanad { hash } => *hash,
                    },
                )
            } else {
                (
                    match sibling {
                        MerkleProofItem::Left { hash } => *hash,
                        MerkleProofItem::Sanad { hash } => *hash,
                    },
                    current,
                )
            };
            current = MerkleNode::compute_internal_hash(left, right);
            pos /= 2;
        }

        if current == expected_accumulator_root {
            Ok(true)
        } else {
            Err(MerkleAccumulatorError::HashMismatch)
        }
    }

    /// Legacy verification — kept for backward compatibility.
    /// In production code, use `verify_against_accumulator()` instead.
    #[deprecated(
        since = "0.5.0",
        note = "Use verify_against_accumulator() for real verification"
    )]
    pub fn verify(&self) -> bool {
        self.root_hash != [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_accumulator_empty() {
        let acc = MerkleAccumulator::new();
        assert_eq!(acc.num_leaves(), 0);
        assert_ne!(acc.root_hash(), [0u8; 32]); // Empty hash is not zero
    }

    #[test]
    fn test_merkle_accumulator_single_leaf() {
        let leaves = [[1u8; 32]];
        let acc = MerkleAccumulator::from_leaves(&leaves);
        assert_eq!(acc.num_leaves(), 1);
        assert_eq!(acc.root_hash(), leaves[0]);
    }

    #[test]
    fn test_merkle_accumulator_two_leaves() {
        let leaves = [[1u8; 32], [2u8; 32]];
        let acc = MerkleAccumulator::from_leaves(&leaves);
        assert_eq!(acc.num_leaves(), 2);
        assert_ne!(acc.root_hash(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_node_compute_internal_hash() {
        let left = [1u8; 32];
        let sanad = [2u8; 32];
        let hash = MerkleNode::compute_internal_hash(left, sanad);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_state_proof_leaf_hash() {
        let proof = StateProof::new(
            [1u8; 32],
            "CSV::Seal".to_string(),
            true,
            Some(vec![1, 2, 3]),
            vec![],
            100,
            [0u8; 32],
        );
        let hash = proof.compute_leaf_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_ledger_proof_verification() {
        let proof = LedgerProof::new(100, [1u8; 32], 1, 1, vec![]);
        // Empty proof with matching root returns Ok(true)
        assert!(proof.verify_against_accumulator([1u8; 32]).unwrap());
    }
}
