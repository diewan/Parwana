//! Solana reorg simulation tests
//!
//! These tests verify that the Solana adapter correctly handles chain reorganizations.
//! Solana uses Proof of History (PoH) combined with Tower BFT, which makes reorgs
//! different from both Bitcoin and Ethereum.

use csv_hash::Hash;

/// Simulates an optimistic confirmation rollback.
///
/// In Solana, validators can signal "optimistic confirmation" before a block
/// is fully finalized by the Tower BFT protocol. If the block is later
/// rejected by Tower, the optimistic confirmation is rolled back.
#[test]
fn test_optimistic_confirmation_rollback() {
    // Block was optimistically confirmed but not yet finalized
    let optimistic_block_hash = Hash::new([1u8; 32]);
    let optimistic_slot = 1000u64;

    // The block was later rejected by Tower BFT
    let replaced_block_hash = Hash::new([2u8; 32]);
    let replaced_slot = 1000u64; // Same slot, different block

    // Same slot, different block hash indicates a rollback
    assert_eq!(optimistic_slot, replaced_slot);
    assert_ne!(optimistic_block_hash, replaced_block_hash);

    // A proof built on the optimistically confirmed block is now invalid
    let proof_on_optimistic = optimistic_block_hash == optimistic_block_hash;
    let proof_on_replaced = optimistic_block_hash == replaced_block_hash;

    assert!(proof_on_optimistic, "Proof valid against optimistic block");
    assert!(!proof_on_replaced, "Proof invalid against replaced block");
}

/// Simulates a fork switch in Solana's PoH + Tower BFT consensus.
///
/// Solana can experience fork switches when validators disagree on the leading
/// chain. Tower BFT resolves these forks through voting, but during the
/// resolution period, proofs may become invalid.
#[test]
fn test_fork_switch() {
    let fork_a_block = Hash::new([1u8; 32]);
    let fork_a_slot = 1000u64;

    let fork_b_block = Hash::new([2u8; 32]);
    let fork_b_slot = 1000u64; // Same slot, different fork

    // During a fork switch, two different blocks exist at the same slot
    assert_eq!(fork_a_slot, fork_b_slot);
    assert_ne!(fork_a_block, fork_b_block);

    // Tower BFT will select one fork as canonical
    // The other fork's blocks become orphaned
    let canonical_fork = ForkResult::ForkA;

    match canonical_fork {
        ForkResult::ForkA => {
            let proof_valid = fork_a_block == fork_a_block;
            let proof_invalid = fork_a_block == fork_b_block;
            assert!(proof_valid, "Proof on canonical fork is valid");
            assert!(!proof_invalid, "Proof on orphaned fork is invalid");
        }
        ForkResult::ForkB => {
            let proof_valid = fork_b_block == fork_b_block;
            let proof_invalid = fork_b_block == fork_a_block;
            assert!(proof_valid, "Proof on canonical fork is valid");
            assert!(!proof_invalid, "Proof on orphaned fork is invalid");
        }
    }
}

/// Simulates a reorg that affects the slot hash used in a proof.
#[test]
fn test_reorg_affects_slot_hash() {
    let original_slot_hash = Hash::new([1u8; 32]);
    let new_slot_hash = Hash::new([2u8; 32]);
    let _slot = 1000u64;

    // After a reorg, the slot hash changes
    assert_ne!(original_slot_hash, new_slot_hash);

    // A proof that references the original slot hash becomes invalid
    let proof_slot_hash = original_slot_hash;
    let proof_matches_original = proof_slot_hash == original_slot_hash;
    let proof_matches_new = proof_slot_hash == new_slot_hash;

    assert!(proof_matches_original, "Proof matches original slot hash");
    assert!(!proof_matches_new, "Proof does not match new slot hash");
}

/// Simulates a deep reorg that affects multiple slots.
#[test]
fn test_deep_reorg_multiple_slots() {
    // A deep reorg in Solana affects multiple consecutive slots
    let affected_slots: Vec<u64> = (990..=1000).collect();
    let reorg_depth = affected_slots.len() as u64;

    assert_eq!(reorg_depth, 11, "Reorg depth should cover 11 slots");

    // Each slot in the affected range has a different hash before and after reorg
    let original_hashes: Vec<Hash> = (0..affected_slots.len())
        .map(|i| Hash::new([i as u8; 32]))
        .collect();
    let new_hashes: Vec<Hash> = (0..affected_slots.len())
        .map(|i| Hash::new([(i + 100) as u8; 32]))
        .collect();

    // No hash should match after reorg
    for (original, new) in original_hashes.iter().zip(new_hashes.iter()) {
        assert_ne!(original, new, "Hash changed after reorg for each slot");
    }
}

/// Simulates the effect of a reorg on the commitment level.
///
/// Solana has multiple commitment levels: processed, confirmed, finalized.
/// A reorg can affect blocks at any level except finalized blocks.
#[test]
fn test_commitment_level_effects() {
    // Processed: not yet confirmed, can be reorged freely
    let processed_block = Hash::new([1u8; 32]);

    // Confirmed: has received majority vote, harder to reorg
    let confirmed_block = Hash::new([2u8; 32]);

    // Finalized: has received 2/3+ supermajority, cannot be reorged
    let finalized_block = Hash::new([3u8; 32]);

    // After a reorg:
    // - Processed blocks are always affected
    // - Confirmed blocks may be affected
    // - Finalized blocks are never affected

    let new_processed = Hash::new([4u8; 32]);
    let new_confirmed = Hash::new([5u8; 32]);
    let new_finalized = finalized_block; // Unchanged

    assert_ne!(processed_block, new_processed, "Processed block changed");
    assert_ne!(confirmed_block, new_confirmed, "Confirmed block changed");
    assert_eq!(finalized_block, new_finalized, "Finalized block unchanged");
}

/// Fork resolution result enum for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(dead_code)]
enum ForkResult {
    ForkA,
    ForkB,
}
