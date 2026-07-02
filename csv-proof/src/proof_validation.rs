//! Proof validation
//!
//! This module provides real cryptographic proof validation for inclusion proofs
//! (Merkle tree verification) and finality proofs (structural validation).
//!
//! ## Inclusion Proof Validation
//!
//! Recomputes the Merkle root from the leaf and sibling path, then compares
//! against the expected root. This is the core cryptographic verification.
//!
//! ## Finality Proof Validation
//!
//! Validates structural properties: non-zero block hash, reasonable confirmation
//! count, non-empty finality data, and source consistency.
//!
//! ## Design Notes
//!
//! - This module performs **structural** and **cryptographic** validation only.
//! - Chain-specific verification (e.g., Bitcoin SPV, Ethereum MPT, Solana proof)
//!   is handled by chain adapters implementing the `SanadStateReader` trait.
//! - The canonical verifier (`csv-verifier`) orchestrates all validation steps
//!   including signature verification, nullifier checks, and policy enforcement.

use csv_hash::{Hash, verify_merkle_proof};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof, ProofBundle};

/// Maximum allowed proof bytes size (1 MB)
const MAX_PROOF_BYTES: usize = 1_048_576;

/// Maximum allowed sibling path length (256 levels = 2^256 tree)
const MAX_SIBLINGS: usize = 256;

/// Minimum required confirmations for finality
const MIN_CONFIRMATIONS: u64 = 1;

/// Maximum allowed confirmations (safety bound against overflow)
const MAX_CONFIRMATIONS: u64 = u64::MAX / 2;

/// Proof validator with real cryptographic verification.
pub struct ProofValidator;

impl ProofValidator {
    /// Validate a proof bundle.
    ///
    /// Performs:
    /// 1. Size bounds checking on all proof components
    /// 2. Inclusion proof Merkle root verification
    /// 3. Finality proof structural validation
    ///
    /// ## Returns
    ///
    /// - `ValidationResult::Valid` if all checks pass
    /// - `ValidationResult::InvalidInclusionProof` if Merkle verification fails
    /// - `ValidationResult::InvalidFinalityProof` if finality validation fails
    /// - `ValidationResult::InvalidMaterial` if size bounds are exceeded
    pub fn validate_bundle(bundle: &ProofBundle) -> ValidationResult {
        // Check overall size bounds
        if bundle.inclusion_proof.proof_bytes.len() > MAX_PROOF_BYTES {
            return ValidationResult::InvalidMaterial;
        }
        if bundle.finality_proof.finality_data.len() > MAX_PROOF_BYTES {
            return ValidationResult::InvalidMaterial;
        }

        // Validate inclusion proof (Merkle verification)
        match Self::validate_inclusion(&bundle.inclusion_proof) {
            true => {}
            false => return ValidationResult::InvalidInclusionProof,
        }

        // Validate finality proof (structural validation)
        match Self::validate_finality(&bundle.finality_proof) {
            true => {}
            false => return ValidationResult::InvalidFinalityProof,
        }

        ValidationResult::Valid
    }

    /// Validate an inclusion proof by verifying the Merkle path.
    ///
    /// Recomputes the Merkle root from the leaf and sibling path, then
    /// compares against the expected root.
    ///
    /// ## Validation Steps
    ///
    /// 1. Check sibling path length is reasonable (0-256)
    /// 2. Check leaf and root are non-zero
    /// 3. Verify the Merkle path: recompute root from leaf + siblings
    /// 4. Compare computed root with expected root
    ///
    /// ## Returns
    ///
    /// `true` if the Merkle proof is valid, `false` otherwise.
    pub fn validate_inclusion(proof: &InclusionProof) -> bool {
        // Check sibling path length is reasonable
        if proof.siblings.len() > MAX_SIBLINGS {
            return false;
        }

        // Check leaf and root are non-zero (structural validity)
        if Self::is_zero_hash(&proof.leaf) || Self::is_zero_hash(&proof.root) {
            return false;
        }

        // If there are no siblings, the leaf must equal the root
        if proof.siblings.is_empty() {
            return proof.leaf == proof.root;
        }

        // Verify the Merkle path using the canonical Merkle verification
        // The proof structure has: leaf, siblings (ordered by level), leaf_index
        // We need to verify that hashing leaf with siblings at the correct positions
        // produces the expected root.
        Self::verify_merkle_path(&proof.leaf, &proof.siblings, proof.leaf_index, &proof.root)
    }

    /// Validate a finality proof by checking structural properties.
    ///
    /// ## Validation Steps
    ///
    /// 1. Block hash must be non-zero
    /// 2. Confirmations must be within reasonable bounds (1 to MAX_CONFIRMATIONS)
    /// 3. Finality data must be non-empty
    /// 4. Source must be non-empty
    ///
    /// ## Returns
    ///
    /// `true` if the finality proof has valid structure, `false` otherwise.
    ///
    /// ## Note
    ///
    /// This performs structural validation only. Chain-specific finality
    /// verification (e.g., checking Bitcoin confirmations, Ethereum finality
    /// stage, Solana commitment grade) is handled by chain adapters.
    pub fn validate_finality(proof: &FinalityProof) -> bool {
        // Block hash must be non-zero
        if Self::is_zero_hash(&proof.block_hash) {
            return false;
        }

        // Confirmations must be within reasonable bounds
        if proof.confirmations < MIN_CONFIRMATIONS {
            return false;
        }
        if proof.confirmations > MAX_CONFIRMATIONS {
            return false;
        }

        // Finality data must be non-empty
        if proof.data.is_empty() {
            return false;
        }

        // Source must be non-empty
        if proof.source.is_empty() {
            return false;
        }

        true
    }

    /// Verify proof material is within size bounds.
    ///
    /// ## Returns
    ///
    /// `true` if the material is within acceptable size limits, `false` otherwise.
    pub fn verify_material(material: &[u8]) -> bool {
        !material.is_empty() && material.len() <= MAX_PROOF_BYTES
    }

    /// Verify a Merkle path by recomputing the root.
    ///
    /// ## Algorithm
    ///
    /// Starting from the leaf, iteratively hash with sibling hashes at each level.
    /// The sibling position (left or right) is determined by the bit at each level
    /// of the leaf_index.
    ///
    /// ```text
    /// current = leaf
    /// for each level i:
    ///     if bit i of leaf_index is 0:
    ///         current = hash(sibling[i] || current)
    ///     else:
    ///         current = hash(current || sibling[i])
    /// return current == root
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `leaf` — The leaf hash being proven
    /// * `siblings` — The sibling path (ordered by level, lowest first)
    /// * `leaf_index` — The index of the leaf in the Merkle tree
    /// * `expected_root` — The expected Merkle root
    ///
    /// ## Returns
    ///
    /// `true` if the computed root matches the expected root.
    fn verify_merkle_path(
        leaf: &Hash,
        siblings: &[Hash],
        leaf_index: usize,
        expected_root: &Hash,
    ) -> bool {
        if siblings.is_empty() {
            return leaf == expected_root;
        }

        let mut current = *leaf;

        for (i, sibling) in siblings.iter().enumerate() {
            // Check that we don't exceed the sibling path length
            if i >= siblings.len() {
                return false;
            }

            // Determine sibling position based on leaf_index bit at this level
            let bit = (leaf_index >> i) & 1;

            if bit == 0 {
                // Current is on the left, sibling is on the right
                current = Self::hash_pair(current.as_bytes(), sibling.as_bytes());
            } else {
                // Current is on the right, sibling is on the left
                current = Self::hash_pair(sibling.as_bytes(), current.as_bytes());
            }
        }

        current == *expected_root
    }

    /// Check if a Hash is all zeros.
    fn is_zero_hash(hash: &Hash) -> bool {
        hash.as_bytes().iter().all(|&b| b == 0)
    }

    /// Compute SHA256 hash of two 32-byte hashes concatenated with ordered hashing.
    ///
    /// Uses ordered hashing: the smaller hash is always on the left.
    /// Uses the MerkleCombine domain to match MerkleTree::combine_children.
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> Hash {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;
        // Ordered hashing: min || max
        let (lo, hi) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(lo);
        combined.extend_from_slice(hi);
        tagged_hash(HashDomain::MerkleCombine, &combined).hash
    }
}

/// Validation result with specific failure reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Proof is valid
    Valid,
    /// Inclusion proof is invalid (Merkle verification failed)
    InvalidInclusionProof,
    /// Finality proof is invalid (structural validation failed)
    InvalidFinalityProof,
    /// Proof material is invalid (size bounds exceeded or empty)
    InvalidMaterial,
}

impl ValidationResult {
    /// Returns true if the proof passed validation.
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    /// Returns a human-readable reason for failure, or None if valid.
    pub fn failure_reason(&self) -> Option<&'static str> {
        match self {
            ValidationResult::Valid => None,
            ValidationResult::InvalidInclusionProof => Some(
                "Inclusion proof Merkle verification failed: computed root does not match expected root",
            ),
            ValidationResult::InvalidFinalityProof => {
                Some("Finality proof structural validation failed: missing required fields")
            }
            ValidationResult::InvalidMaterial => {
                Some("Proof material invalid: empty or exceeds size bounds")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_hash::dag::DAGSegment;
    use csv_hash::merkle::MerkleTree;
    use csv_protocol::{CommitAnchor, SealPoint, signature::SignatureScheme};

    #[test]
    fn test_validate_inclusion_empty_siblings_leaf_equals_root() {
        let leaf = Hash::new([1u8; 32]);
        let root = Hash::new([1u8; 32]);
        let proof = InclusionProof {
            proof_bytes: Vec::new(),
            block_hash: Hash::new([2u8; 32]),
            position: 0,
            block_number: 1,
            leaf,
            root,
            siblings: Vec::new(),
            leaf_index: 0,
            source: "test".to_string(),
        };
        assert!(ProofValidator::validate_inclusion(&proof));
    }

    #[test]
    fn test_validate_inclusion_empty_siblings_leaf_not_equals_root() {
        let leaf = Hash::new([1u8; 32]);
        let root = Hash::new([2u8; 32]);
        let proof = InclusionProof {
            proof_bytes: Vec::new(),
            block_hash: Hash::new([3u8; 32]),
            position: 0,
            block_number: 1,
            leaf,
            root,
            siblings: Vec::new(),
            leaf_index: 0,
            source: "test".to_string(),
        };
        assert!(!ProofValidator::validate_inclusion(&proof));
    }

    #[test]
    fn test_validate_inclusion_zero_leaf_fails() {
        let proof = InclusionProof {
            proof_bytes: Vec::new(),
            block_hash: Hash::new([1u8; 32]),
            position: 0,
            block_number: 1,
            leaf: Hash::zero(),
            root: Hash::new([1u8; 32]),
            siblings: Vec::new(),
            leaf_index: 0,
            source: "test".to_string(),
        };
        assert!(!ProofValidator::validate_inclusion(&proof));
    }

    #[test]
    fn test_validate_inclusion_zero_root_fails() {
        let proof = InclusionProof {
            proof_bytes: Vec::new(),
            block_hash: Hash::new([1u8; 32]),
            position: 0,
            block_number: 1,
            leaf: Hash::new([1u8; 32]),
            root: Hash::zero(),
            siblings: Vec::new(),
            leaf_index: 0,
            source: "test".to_string(),
        };
        assert!(!ProofValidator::validate_inclusion(&proof));
    }

    #[test]
    fn test_validate_finality_zero_block_hash_fails() {
        let proof = FinalityProof {
            finality_data: vec![1u8; 32],
            block_hash: Hash::zero(),
            threshold: 2,
            confirmations: 6,
            data: vec![2u8; 32],
            source: "ethereum".to_string(),
            is_deterministic: false,
        };
        assert!(!ProofValidator::validate_finality(&proof));
    }

    #[test]
    fn test_validate_finality_zero_confirmations_fails() {
        let proof = FinalityProof {
            finality_data: vec![1u8; 32],
            block_hash: Hash::new([1u8; 32]),
            threshold: 2,
            confirmations: 0,
            data: vec![2u8; 32],
            source: "ethereum".to_string(),
            is_deterministic: false,
        };
        assert!(!ProofValidator::validate_finality(&proof));
    }

    #[test]
    fn test_validate_finality_empty_data_fails() {
        let proof = FinalityProof {
            finality_data: vec![1u8; 32],
            block_hash: Hash::new([1u8; 32]),
            threshold: 2,
            confirmations: 6,
            data: Vec::new(),
            source: "ethereum".to_string(),
            is_deterministic: false,
        };
        assert!(!ProofValidator::validate_finality(&proof));
    }

    #[test]
    fn test_validate_finality_empty_source_fails() {
        let proof = FinalityProof {
            finality_data: vec![1u8; 32],
            block_hash: Hash::new([1u8; 32]),
            threshold: 2,
            confirmations: 6,
            data: vec![2u8; 32],
            source: String::new(),
            is_deterministic: false,
        };
        assert!(!ProofValidator::validate_finality(&proof));
    }

    #[test]
    fn test_validate_finality_valid() {
        let proof = FinalityProof {
            finality_data: vec![1u8; 32],
            block_hash: Hash::new([1u8; 32]),
            threshold: 2,
            confirmations: 6,
            data: vec![2u8; 32],
            source: "ethereum".to_string(),
            is_deterministic: false,
        };
        assert!(ProofValidator::validate_finality(&proof));
    }

    #[test]
    fn test_verify_material_empty_fails() {
        assert!(!ProofValidator::verify_material(&[]));
    }

    #[test]
    fn test_verify_material_valid() {
        assert!(ProofValidator::verify_material(&[1u8; 32]));
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let h1 = ProofValidator::hash_pair(&left, &right);
        let h2 = ProofValidator::hash_pair(&left, &right);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_pair_order_independent() {
        // With ordered hashing (min || max), the order of inputs should not matter
        let left = [1u8; 32];
        let right = [2u8; 32];
        let h1 = ProofValidator::hash_pair(&left, &right);
        let h2 = ProofValidator::hash_pair(&right, &left);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_validate_inclusion_with_real_merkle_tree() {
        // Create a Merkle tree with 4 leaves
        let leaves: Vec<Hash> = (0..4).map(|i| Hash::new([i as u8; 32])).collect();
        let tree = MerkleTree::from_leaves(leaves.clone()).expect("Failed to create MerkleTree");
        let root = tree.root;

        // Get Merkle proof for leaf at index 1
        let proof = tree.proof(1).unwrap();

        // Verify the proof
        assert!(ProofValidator::verify_merkle_path(
            &leaves[1],
            &proof.siblings,
            1,
            &root
        ));
    }

    #[test]
    fn test_validate_bundle_valid() {
        // Create a valid inclusion proof
        let leaves: Vec<Hash> = (0..4).map(|i| Hash::new([i as u8; 32])).collect();
        let tree = MerkleTree::from_leaves(leaves.clone()).expect("Failed to create MerkleTree");
        let root = tree.root;

        let inclusion = InclusionProof {
            proof_bytes: vec![1u8; 32],
            block_hash: Hash::new([1u8; 32]),
            position: 0,
            block_number: 1,
            leaf: leaves[1],
            root,
            siblings: vec![Hash::new([10u8; 32]), Hash::new([11u8; 32])],
            leaf_index: 1,
            source: "test".to_string(),
        };

        // Fix: use the actual Merkle proof siblings
        let merkle_proof = tree.proof(1).unwrap();
        let inclusion = InclusionProof {
            proof_bytes: vec![1u8; 32],
            block_hash: Hash::new([1u8; 32]),
            position: 0,
            block_number: 1,
            leaf: leaves[1],
            root,
            siblings: merkle_proof.siblings,
            leaf_index: 1,
            source: "test".to_string(),
        };

        let finality = FinalityProof {
            finality_data: vec![1u8; 32],
            block_hash: Hash::new([2u8; 32]),
            threshold: 2,
            confirmations: 6,
            data: vec![2u8; 32],
            source: "ethereum".to_string(),
            is_deterministic: false,
        };

        let bundle = ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], Hash::new([0u8; 32])),
            signatures: vec![],
            signature_scheme: SignatureScheme::Ed25519,
            seal_ref: SealPoint {
                id: vec![0u8; 32],
                nonce: None,
                version: None,
            },
            anchor_ref: CommitAnchor {
                anchor_id: vec![0u8; 32],
                block_height: 0,
                metadata: vec![],
            },
            inclusion_proof: inclusion,
            finality_proof: finality,
        };

        assert!(ProofValidator::validate_bundle(&bundle).is_valid());
    }

    #[test]
    fn test_validation_result_failure_reasons() {
        assert!(ValidationResult::Valid.failure_reason().is_none());
        assert!(
            ValidationResult::InvalidInclusionProof
                .failure_reason()
                .is_some()
        );
        assert!(
            ValidationResult::InvalidFinalityProof
                .failure_reason()
                .is_some()
        );
        assert!(ValidationResult::InvalidMaterial.failure_reason().is_some());
    }
}
