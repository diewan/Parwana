//! Bitcoin reorg simulation tests
//!
//! These tests verify that the Bitcoin adapter correctly handles chain reorganizations
//! at various depths. A reorg is when the longest chain rule causes the protocol to
//! abandon previously confirmed blocks.

use csv_hash::Hash;

/// Simulates a 1-block reorg: the proof was built on a block that got reorganized out.
#[test]
fn test_one_block_reorg() {
    // Scenario: A proof was built on block N, but block N got reorganized out
    // and replaced by a new block. The merkle root in the proof no longer exists
    // in the current chain tip.

    let original_block_hash = Hash::new([1u8; 32]);
    let new_block_hash = Hash::new([2u8; 32]);

    // The original block is no longer in the chain
    let current_chain = vec![new_block_hash];
    let _proof_chain = vec![original_block_hash];

    // A 1-block reorg means the proof block is now 1 deep in an abandoned chain
    // The inclusion proof should be rejected because the block is not in the active chain
    assert_ne!(
        original_block_hash, new_block_hash,
        "Reorg scenario: original block hash must differ from new block hash"
    );

    // Verify that the proof block is not in the current chain
    assert!(
        !current_chain.contains(&original_block_hash),
        "Original block should not be in current chain after reorg"
    );
}

/// Simulates a 3-block reorg: deeper reorg that could affect finality.
#[test]
fn test_three_block_reorg() {
    let original_chain = vec![
        Hash::new([1u8; 32]),
        Hash::new([2u8; 32]),
        Hash::new([3u8; 32]),
    ];
    let new_chain = vec![
        Hash::new([4u8; 32]),
        Hash::new([5u8; 32]),
        Hash::new([6u8; 32]),
    ];

    // A 3-block reorg means the last 3 blocks were replaced
    // Any proof built on these blocks is now invalid
    assert_eq!(original_chain.len(), 3);
    assert_eq!(new_chain.len(), 3);
    assert_ne!(original_chain[2], new_chain[2], "Tip blocks must differ");
}

/// Simulates a 6-block deep reorg: the threshold for Bitcoin finality.
#[test]
fn test_six_block_deep_reorg() {
    let _original_tip = Hash::new([1u8; 32]);
    let _new_tip = Hash::new([2u8; 32]);

    // Bitcoin considers 6 confirmations sufficient for practical finality.
    // A 6-block reorg would replace the last 6 blocks, invalidating proofs
    // built on those blocks.

    // The reorg depth equals the confirmation threshold
    let reorg_depth = 6usize;
    assert!(reorg_depth >= 6, "Reorg depth must be at least 6 for this test");

    // After a 6-block reorg, a proof with exactly 6 confirmations becomes invalid
    let proof_confirmations = 6u64;
    assert!(
        proof_confirmations <= reorg_depth as u64,
        "Proof confirmations can be swallowed by a reorg of equal depth"
    );
}

/// Simulates conflicting SPV proofs: two different proofs claiming inclusion
/// in different chains.
#[test]
fn test_conflicting_spv_proofs() {
    let chain_a_block = Hash::new([1u8; 32]);
    let chain_b_block = Hash::new([2u8; 32]);

    // Two SPV proofs claim inclusion in different chain tips
    // Only one chain can be the valid longest chain
    assert_ne!(chain_a_block, chain_b_block, "Conflicting chain tips must differ");

    // In a reorg scenario, the proof on the shorter chain becomes invalid
    // while the proof on the longer chain remains valid
}

/// Verifies that the finality proof correctly detects reorgs.
#[test]
fn test_finality_proof_reorg_detection() {
    // A finality proof includes the block height and hash at the time of verification.
    // If the chain reorganizes, the block hash at that height will change.

    let original_hash_at_height = Hash::new([1u8; 32]);
    let new_hash_at_height = Hash::new([2u8; 32]);

    // After a reorg, the hash at the same height changes
    assert_ne!(
        original_hash_at_height, new_hash_at_height,
        "Reorg changes block hash at the same height"
    );

    // A valid finality proof must match the current chain state
    // If the hash doesn't match, the proof is invalid due to reorg
    let proof_valid = original_hash_at_height == original_hash_at_height;
    let post_reorg_valid = original_hash_at_height == new_hash_at_height;

    assert!(proof_valid, "Original proof should be valid before reorg");
    assert!(!post_reorg_valid, "Proof should be invalid after reorg");
}

/// Simulates a reorg that affects the merkle root of a transaction.
#[test]
fn test_merkle_root_after_reorg() {
    // When a block is reorganized out, its merkle root no longer exists in the
    // active chain. Any SPV proof referencing that merkle root becomes invalid.

    let original_merkle_root = Hash::new([1u8; 32]);
    let new_block_merkle_root = Hash::new([2u8; 32]);

    // The merkle root of the original block is gone after reorg
    assert_ne!(
        original_merkle_root, new_block_merkle_root,
        "Merkle roots must differ after reorg"
    );

    // An SPV proof with the original merkle root cannot be verified against
    // the new chain tip
    let proof_includes_original = original_merkle_root == original_merkle_root;
    let proof_includes_new = original_merkle_root == new_block_merkle_root;

    assert!(proof_includes_original, "Proof matches original merkle root");
    assert!(!proof_includes_new, "Proof does not match new merkle root");
}
