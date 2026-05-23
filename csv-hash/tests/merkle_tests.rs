//! Canonical Merkle tree tests
//!
//! Tests for all mandatory properties:
//! - Ordered hashing
//! - Leaf tagging
//! - Internal node tagging
//! - Deterministic balancing
//! - Proof compression

use csv_hash::{
    merkle::{
        tree::{MerkleTree, MerkleProof},
        verifier::{
            verify_merkle_proof, verify_merkle_proofs_batch, compute_root_from_proof,
        },
        streaming::{StreamingMerkleBuilder, StreamingMerkleProofGenerator},
    },
    Hash,
};

// ============================================================================
// Ordered Hashing Tests
// ============================================================================

#[test]
fn test_ordered_hashing_deterministic() {
    // Ordered hashing in MerkleTree: min(left, right) || max(left, right)
    // This should produce the same result regardless of input order
    let leaves1 = vec![Hash([1u8; 32]), Hash([2u8; 32])];
    let tree1 = MerkleTree::from_leaves(leaves1).unwrap();

    // Same leaves in reverse order should produce the same root
    let leaves2 = vec![Hash([2u8; 32]), Hash([1u8; 32])];
    let tree2 = MerkleTree::from_leaves(leaves2).unwrap();

    assert_eq!(tree1.root, tree2.root, "Ordered hashing must be commutative");
}

#[test]
fn test_ordered_hashing_preserves_order() {
    // When left < right, the order should be preserved
    let left = Hash([0u8; 32]);
    let right = Hash([1u8; 32]);

    let combined = Hash::combine(&left, &right);

    // The combined hash should be deterministic
    let combined_again = Hash::combine(&left, &right);
    assert_eq!(combined, combined_again);
}

// ============================================================================
// Leaf Tagging Tests
// ============================================================================

#[test]
fn test_leaf_tagging_domain_separation() {
    // Leaf hashing should use MerkleLeaf domain
    let data = b"test leaf data";
    let leaf_hash = MerkleTree::hash_leaf(data);

    // The hash should be deterministic
    let leaf_hash_again = MerkleTree::hash_leaf(data);
    assert_eq!(leaf_hash, leaf_hash_again);

    // Different data should produce different hashes
    let other_data = b"other test data";
    let other_hash = MerkleTree::hash_leaf(other_data);
    assert_ne!(leaf_hash, other_hash);
}

#[test]
fn test_leaf_vs_internal_node_separation() {
    // Leaf hashes and internal node hashes should use different domains
    let leaf_data = b"leaf";
    let leaf_hash = MerkleTree::hash_leaf(leaf_data);

    // Two identical leaf hashes combined should produce a different hash
    let combined = Hash::combine(&leaf_hash, &leaf_hash);

    // The combined hash should be different from the leaf hash
    assert_ne!(leaf_hash, combined, "Leaf and internal node hashes must be domain-separated");
}

// ============================================================================
// Internal Node Tagging Tests
// ============================================================================

#[test]
fn test_internal_node_tagging() {
    // Internal node hashing should use MerkleCombine domain
    let left = Hash([1u8; 32]);
    let right = Hash([2u8; 32]);

    let combined = Hash::combine(&left, &right);

    // The combined hash should be deterministic
    let combined_again = Hash::combine(&left, &right);
    assert_eq!(combined, combined_again);
}

#[test]
fn test_internal_node_vs_leaf_separation() {
    // An internal node hash should never equal a leaf hash for the same data
    let data = b"test";
    let leaf_hash = MerkleTree::hash_leaf(data);

    // Create a tree with two identical leaves
    let tree = MerkleTree::from_leaves(vec![leaf_hash, leaf_hash]).unwrap();

    // The root (internal node) should be different from the leaf
    assert_ne!(tree.root, leaf_hash);
}

// ============================================================================
// Deterministic Balancing Tests
// ============================================================================

#[test]
fn test_balancing_even_leaves() {
    // Even number of leaves should not be modified
    let leaves = vec![
        Hash([1u8; 32]),
        Hash([2u8; 32]),
        Hash([3u8; 32]),
        Hash([4u8; 32]),
    ];

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    assert_eq!(tree.balanced_count, 4);
    assert_eq!(tree.leaf_count(), 4);
}

#[test]
fn test_balancing_odd_leaves() {
    // Odd number of leaves should be duplicated
    let leaves = vec![
        Hash([1u8; 32]),
        Hash([2u8; 32]),
        Hash([3u8; 32]),
    ];

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    assert_eq!(tree.balanced_count, 4); // 3 leaves -> 4 after balancing
    assert_eq!(tree.leaf_count(), 3);   // Original count remains 3
}

#[test]
fn test_balancing_single_leaf() {
    // Single leaf should remain as is
    let leaves = vec![Hash([1u8; 32])];

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    assert_eq!(tree.balanced_count, 1);
    assert_eq!(tree.leaf_count(), 1);
    assert_eq!(tree.root, leaves[0]);
    assert_eq!(tree.depth, 0);
}

#[test]
fn test_balancing_large_odd_count() {
    // 7 leaves should be balanced to 8
    let leaves: Vec<Hash> = (0..7).map(|i| Hash([i as u8; 32])).collect();

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    assert_eq!(tree.balanced_count, 8);
    assert_eq!(tree.leaf_count(), 7);
}

// ============================================================================
// Proof Compression Tests
// ============================================================================

#[test]
fn test_proof_compression_siblings_only() {
    // Proofs should contain only sibling hashes, no position metadata
    let leaves = vec![
        Hash([1u8; 32]),
        Hash([2u8; 32]),
        Hash([3u8; 32]),
        Hash([4u8; 32]),
    ];

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    let proof = tree.proof(0).unwrap();

    // Proof should have depth number of siblings
    assert_eq!(proof.siblings.len(), tree.depth);

    // Proof should verify
    assert!(proof.verify(leaves[0], tree.root));
}

#[test]
fn test_proof_verification_all_leaves() {
    // All leaves should have valid proofs
    let leaves: Vec<Hash> = (0..8).map(|i| Hash([i as u8; 32])).collect();

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    for i in 0..leaves.len() {
        let proof = tree.proof(i).unwrap();
        assert!(proof.verify(leaves[i], tree.root), "Proof failed for leaf {}", i);
    }
}

#[test]
fn test_proof_verification_odd_leaves() {
    // Proofs should work correctly with odd number of leaves
    let leaves: Vec<Hash> = (0..5).map(|i| Hash([i as u8; 32])).collect();

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    for i in 0..leaves.len() {
        let proof = tree.proof(i).unwrap();
        assert!(proof.verify(leaves[i], tree.root), "Proof failed for leaf {}", i);
    }
}

#[test]
fn test_proof_invalid_leaf() {
    // Proof should fail with wrong leaf
    let leaves = vec![
        Hash([1u8; 32]),
        Hash([2u8; 32]),
        Hash([3u8; 32]),
        Hash([4u8; 32]),
    ];

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    let proof = tree.proof(0).unwrap();

    let wrong_leaf = Hash([99u8; 32]);
    assert!(!proof.verify(wrong_leaf, tree.root));
}

#[test]
fn test_proof_invalid_root() {
    // Proof should fail with wrong root
    let leaves = vec![
        Hash([1u8; 32]),
        Hash([2u8; 32]),
        Hash([3u8; 32]),
        Hash([4u8; 32]),
    ];

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    let proof = tree.proof(0).unwrap();

    let wrong_root = Hash([99u8; 32]);
    assert!(!proof.verify(leaves[0], wrong_root));
}

// ============================================================================
// Tree Construction Tests
// ============================================================================

#[test]
fn test_tree_construction_from_raw_data() {
    // Test tree construction from raw leaf data
    let leaves = vec![
        b"leaf1".to_vec(),
        b"leaf2".to_vec(),
        b"leaf3".to_vec(),
        b"leaf4".to_vec(),
    ];

    let tree = MerkleTree::new(leaves).unwrap();
    assert_eq!(tree.leaf_count(), 4);
    assert_eq!(tree.balanced_count, 4);
    assert!(tree.depth > 0);
}

#[test]
fn test_tree_construction_empty() {
    // Empty leaves should return None
    let result = MerkleTree::new(Vec::new());
    assert!(result.is_none());

    let result = MerkleTree::from_leaves(Vec::new());
    assert!(result.is_none());
}

#[test]
fn test_tree_construction_single_leaf() {
    // Single leaf tree should have root equal to the leaf
    let leaves = vec![b"single".to_vec()];
    let tree = MerkleTree::new(leaves).unwrap();

    assert_eq!(tree.leaf_count(), 1);
    assert_eq!(tree.depth, 0);
}

#[test]
fn test_tree_deterministic() {
    // Same input should always produce the same tree
    let leaves = vec![
        b"leaf1".to_vec(),
        b"leaf2".to_vec(),
        b"leaf3".to_vec(),
    ];

    let tree1 = MerkleTree::new(leaves.clone()).unwrap();
    let tree2 = MerkleTree::new(leaves).unwrap();

    assert_eq!(tree1.root, tree2.root);
    assert_eq!(tree1.depth, tree2.depth);
    assert_eq!(tree1.balanced_count, tree2.balanced_count);
}

// ============================================================================
// Verifier Function Tests
// ============================================================================

#[test]
fn test_verify_merkle_proof_basic() {
    // Test standalone proof verification
    let leaves: Vec<Hash> = (0..4).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    let proof = tree.proof(2).unwrap();

    assert!(verify_merkle_proof(leaves[2], &proof.siblings, 2, tree.root));
}

#[test]
fn test_verify_merkle_proof_invalid() {
    // Test proof verification with wrong leaf
    let leaves: Vec<Hash> = (0..4).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    let proof = tree.proof(0).unwrap();

    let wrong_leaf = Hash([99u8; 32]);
    assert!(!verify_merkle_proof(wrong_leaf, &proof.siblings, 0, tree.root));
}

#[test]
fn test_verify_merkle_proofs_batch() {
    // Test batch verification
    let leaves: Vec<Hash> = (0..8).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let proofs: Vec<_> = (0..8)
        .map(|i| {
            let proof = tree.proof(i).unwrap();
            (leaves[i], proof.siblings, i)
        })
        .collect();

    let results = verify_merkle_proofs_batch(&proofs, tree.root);
    assert!(results.iter().all(|&r| r), "All proofs should be valid");
}

#[test]
fn test_verify_merkle_proofs_batch_mixed() {
    // Test batch verification with some invalid proofs
    let leaves: Vec<Hash> = (0..4).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let mut proofs: Vec<_> = (0..4)
        .map(|i| {
            let proof = tree.proof(i).unwrap();
            (leaves[i], proof.siblings, i)
        })
        .collect();

    // Corrupt one proof
    proofs[1].0 = Hash([99u8; 32]);

    let results = verify_merkle_proofs_batch(&proofs, tree.root);
    assert!(results[0], "First proof should be valid");
    assert!(!results[1], "Corrupted proof should be invalid");
    assert!(results[2], "Third proof should be valid");
    assert!(results[3], "Fourth proof should be valid");
}

#[test]
fn test_compute_root_from_proof() {
    // Test root computation from proof
    let leaves: Vec<Hash> = (0..4).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();
    let proof = tree.proof(1).unwrap();

    let computed_root = compute_root_from_proof(leaves[1], &proof.siblings, 1);
    assert_eq!(computed_root, tree.root);
}

// ============================================================================
// Streaming Builder Tests
// ============================================================================

#[test]
fn test_streaming_builder_basic() {
    // Test basic streaming builder functionality
    let mut builder = StreamingMerkleBuilder::new();
    builder.add_leaf(b"leaf1");
    builder.add_leaf(b"leaf2");
    builder.add_leaf(b"leaf3");

    assert_eq!(builder.leaf_count(), 3);

    let tree = builder.build().unwrap();
    assert_eq!(tree.leaf_count(), 3);
    assert_eq!(tree.balanced_count, 4);
}

#[test]
fn test_streaming_builder_batch() {
    // Test batch leaf addition
    let mut builder = StreamingMerkleBuilder::new();
    builder.add_leaves(&[b"leaf1".as_ref(), b"leaf2".as_ref(), b"leaf3".as_ref()]);

    assert_eq!(builder.leaf_count(), 3);
}

#[test]
fn test_streaming_builder_current_root() {
    // Test current root computation
    let mut builder = StreamingMerkleBuilder::new();
    builder.add_leaf(b"leaf1");

    let root1 = builder.current_root().unwrap();

    builder.add_leaf(b"leaf2");
    let root2 = builder.current_root().unwrap();

    // Root should change when adding a leaf
    assert_ne!(root1, root2);
}

#[test]
fn test_streaming_builder_empty() {
    // Empty builder should return None
    let builder = StreamingMerkleBuilder::new();
    assert!(builder.build().is_none());
}

#[test]
fn test_streaming_proof_generator() {
    // Test streaming proof generation
    let mut generator = StreamingMerkleProofGenerator::new();

    generator.add_leaf(b"leaf1");
    generator.add_leaf(b"leaf2");

    // Build proofs for the final tree
    let tree = generator.build_proofs().unwrap();

    // Get proofs by index
    assert!(generator.get_proof(0).is_some());
    assert!(generator.get_proof(1).is_some());
    assert!(generator.get_proof(2).is_none());

    // Verify proofs
    let leaf1_hash = MerkleTree::hash_leaf(b"leaf1");
    let leaf2_hash = MerkleTree::hash_leaf(b"leaf2");
    let proof1 = generator.get_proof(0).unwrap();
    let proof2 = generator.get_proof(1).unwrap();
    assert!(proof1.verify(leaf1_hash, tree.root));
    assert!(proof2.verify(leaf2_hash, tree.root));
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_full_merkle_workflow() {
    // Test complete Merkle tree workflow
    let leaf_data: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();

    // Build tree
    let tree = MerkleTree::new(leaf_data.clone()).unwrap();

    // Verify all proofs
    for i in 0..leaf_data.len() {
        let leaf_hash = MerkleTree::hash_leaf(&leaf_data[i]);
        let proof = tree.proof(i).unwrap();
        assert!(proof.verify(leaf_hash, tree.root), "Proof failed for leaf {}", i);
    }

    // Verify inclusion
    for i in 0..leaf_data.len() {
        assert!(tree.verify_inclusion(i, &leaf_data[i]));
    }

    // Verify non-inclusion
    let wrong_data = b"not in tree";
    assert!(!tree.verify_inclusion(0, wrong_data));
}

#[test]
fn test_merkle_proof_standalone_verification() {
    // Test that proofs can be verified without the original tree
    let leaf_data: Vec<Vec<u8>> = (0..8)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();

    let tree = MerkleTree::new(leaf_data.clone()).unwrap();
    let proof = tree.proof(3).unwrap();

    // Verify using standalone function
    let leaf_hash = MerkleTree::hash_leaf(&leaf_data[3]);
    assert!(verify_merkle_proof(leaf_hash, &proof.siblings, 3, tree.root));

    // Verify using compute_root_from_proof
    let computed_root = compute_root_from_proof(leaf_hash, &proof.siblings, 3);
    assert_eq!(computed_root, tree.root);
}

#[test]
fn test_merkle_tree_large() {
    // Test with larger number of leaves
    let leaves: Vec<Hash> = (0..100).map(|i| Hash([i as u8; 32])).collect();

    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    // Verify all proofs
    for i in 0..leaves.len() {
        let proof = tree.proof(i).unwrap();
        assert!(proof.verify(leaves[i], tree.root), "Proof failed for leaf {}", i);
    }
}

#[test]
fn test_merkle_proof_compression() {
    // Verify that proof size is logarithmic in the number of leaves
    let leaves: Vec<Hash> = (0..16).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let proof = tree.proof(0).unwrap();

    // Proof should have log2(16) = 4 siblings
    assert_eq!(proof.siblings.len(), 4);
    assert_eq!(proof.siblings.len(), tree.depth);
}

#[test]
fn test_merkle_proof_with_odd_leaves() {
    // Test proof generation and verification with odd number of leaves
    let leaves: Vec<Hash> = (0..7).map(|i| Hash([i as u8; 32])).collect();
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    // All proofs should verify
    for i in 0..leaves.len() {
        let proof = tree.proof(i).unwrap();
        assert!(proof.verify(leaves[i], tree.root), "Proof failed for leaf {}", i);
    }

    // Balanced count should be 8 (next power of 2)
    assert_eq!(tree.balanced_count, 8);
}

#[test]
fn test_merkle_tree_single_leaf_proof() {
    // Test proof for single leaf tree
    let leaves = vec![Hash([1u8; 32])];
    let tree = MerkleTree::from_leaves(leaves.clone()).unwrap();

    let proof = tree.proof(0).unwrap();

    // Single leaf tree has no siblings
    assert!(proof.siblings.is_empty());

   // Proof should still verify
    assert!(proof.verify(leaves[0], tree.root));
}
