// Protocol Replay Protection Tests
//
// Invariant: Replay protection must be impossible to bypass
// and must work across all chains.

use csv_hash::{
    Hash,
    nullifier::{SealNullifier, SealConsumption, SealStatus, DoubleSpendError, ChainId},
    sanad::SanadId,
    seal::SealPoint,
};
use csv_proof::proof::ReplayId;
use std::collections::BTreeMap;

/// Test that duplicate proofs are rejected by the seal nullifier registry.
#[test]
fn replay_is_impossible() {
    let mut registry = SealNullifier::new();

    // Create a seal
    let seal = SealPoint::new(vec![0x01; 16], None).unwrap();
    let sanad_id = SanadId::new([0xCD; 32]);
    let chain = ChainId::new("bitcoin");

    // First consumption should succeed
    let consumption1 = SealConsumption {
        chain: chain.clone(),
        seal_ref: seal.clone(),
        sanad_id: sanad_id.clone(),
        block_height: 100,
        tx_hash: Hash::new([0xAB; 32]),
        recorded_at: 1_000_000,
    };
    assert!(
        registry.record_consumption(consumption1).is_ok(),
        "First consumption must succeed"
    );

    // Second consumption of the same seal must be rejected (replay detected)
    let consumption2 = SealConsumption {
        chain: chain.clone(),
        seal_ref: seal.clone(),
        sanad_id: SanadId::new([0xEF; 32]),
        block_height: 200,
        tx_hash: Hash::new([0xBC; 32]),
        recorded_at: 2_000_000,
    };
    let result = registry.record_consumption(consumption2);
    assert!(
        result.is_err(),
        "Duplicate seal consumption must be rejected"
    );

    // Verify the error is a double-spend error
    let err = result.unwrap_err();
    assert_eq!(
        err.seal_ref.id, seal.id,
        "DoubleSpendError must reference the replayed seal"
    );

    // Verify seal status shows double-spend
    match registry.check_seal_status(&seal) {
        SealStatus::DoubleSpent { consumptions } => {
            assert_eq!(
                consumptions.len(),
                2,
                "Double-spend must record both consumption attempts"
            );
        }
        _ => panic!("Expected DoubleSpent status"),
    }

    // Verify the registry tracks the double-spend count
    assert_eq!(
        registry.double_spend_count(),
        1,
        "Registry must track one double-spend incident"
    );
}

/// Test that replay nullifiers are deterministic and domain-separated.
#[test]
fn replay_nullifiers_are_deterministic() {
    // 1. Same inputs must produce the same ReplayId
    let id1 = ReplayId::derive(
        "bitcoin",
        &[1u8; 32],
        0,
        &[2u8; 32],
        &[3u8; 32],
        "ethereum",
    ).expect("replay ID derivation");

    let id2 = ReplayId::derive(
        "bitcoin",
        &[1u8; 32],
        0,
        &[2u8; 32],
        &[3u8; 32],
        "ethereum",
    ).expect("replay ID derivation");

    assert_eq!(id1, id2, "Same inputs must produce identical ReplayId");

    // 2. Different source chain must produce different ReplayId
    let id3 = ReplayId::derive(
        "ethereum", // different source
        &[1u8; 32],
        0,
        &[2u8; 32],
        &[3u8; 32],
        "ethereum",
    ).expect("replay ID derivation");
    assert_ne!(id1, id3, "Different source chain must produce different ReplayId");

    // 3. Different destination chain must produce different ReplayId
    let id4 = ReplayId::derive(
        "bitcoin",
        &[1u8; 32],
        0,
        &[2u8; 32],
        &[3u8; 32],
        "solana", // different destination
    ).expect("replay ID derivation");
    assert_ne!(id1, id4, "Different destination chain must produce different ReplayId");

    // 4. Different seal ID must produce different ReplayId
    let id5 = ReplayId::derive(
        "bitcoin",
        &[1u8; 32],
        0,
        &[9u8; 32], // different seal
        &[3u8; 32],
        "ethereum",
    ).expect("replay ID derivation");
    assert_ne!(id1, id5, "Different seal ID must produce different ReplayId");

    // 5. Different transition ID must produce different ReplayId
    let id6 = ReplayId::derive(
        "bitcoin",
        &[1u8; 32],
        0,
        &[2u8; 32],
        &[9u8; 32], // different transition
        "ethereum",
    ).expect("replay ID derivation");
    assert_ne!(id1, id6, "Different transition ID must produce different ReplayId");

    // 6. ReplayId version must be CURRENT_VERSION
    assert_eq!(
        id1.version,
        ReplayId::CURRENT_VERSION,
        "ReplayId version must match CURRENT_VERSION"
    );
}

/// Test that cross-chain replay is prevented by the seal nullifier.
#[test]
fn cross_chain_replay_is_prevented() {
    let mut registry = SealNullifier::new();

    // Same seal consumed on Bitcoin
    let seal = SealPoint::new(vec![0x01; 16], None).unwrap();
    let sanad_id = SanadId::new([0xCD; 32]);
    let btc_chain = ChainId::new("bitcoin");

    let consumption_btc = SealConsumption {
        chain: btc_chain.clone(),
        seal_ref: seal.clone(),
        sanad_id: sanad_id.clone(),
        block_height: 100,
        tx_hash: Hash::new([0xAB; 32]),
        recorded_at: 1_000_000,
    };
    registry.record_consumption(consumption_btc).unwrap();

    // Try to consume the same seal on Ethereum (cross-chain replay)
    let eth_chain = ChainId::new("ethereum");
    let consumption_eth = SealConsumption {
        chain: eth_chain.clone(),
        seal_ref: seal.clone(),
        sanad_id: sanad_id.clone(),
        block_height: 50,
        tx_hash: Hash::new([0xBC; 32]),
        recorded_at: 1_500_000,
    };

    let result = registry.record_consumption(consumption_eth);
    assert!(
        result.is_err(),
        "Cross-chain replay of the same seal must be rejected"
    );

    // Verify the error indicates cross-chain double-spend
    let err = result.unwrap_err();
    let double_spend = err.as_ref();
    // The DoubleSpendError should indicate this is cross-chain
    let display = format!("{}", double_spend);
    assert!(
        display.contains("Cross-chain") || display.contains("cross-chain"),
        "Error must indicate cross-chain double-spend: {}",
        display
    );
}

/// Test that rollback replay is detected (same seal consumed after rollback).
#[test]
fn rollback_replay_is_detected() {
    let mut registry = SealNullifier::new();

    let seal = SealPoint::new(vec![0x02; 16], None).unwrap();
    let sanad_id = SanadId::new([0x11; 32]);
    let chain = ChainId::new("bitcoin");

    // First consumption
    let c1 = SealConsumption {
        chain: chain.clone(),
        seal_ref: seal.clone(),
        sanad_id: sanad_id.clone(),
        block_height: 100,
        tx_hash: Hash::new([0x01; 32]),
        recorded_at: 1_000_000,
    };
    registry.record_consumption(c1).unwrap();

    // Simulate rollback: try to consume the same seal again
    let c2 = SealConsumption {
        chain: chain.clone(),
        seal_ref: seal.clone(),
        sanad_id: SanadId::new([0x22; 32]),
        block_height: 90, // lower block height (rollback)
        tx_hash: Hash::new([0x02; 32]),
        recorded_at: 900_000,
    };

    let result = registry.record_consumption(c2);
    assert!(
        result.is_err(),
        "Rollback replay (same seal consumed again) must be detected"
    );

    // Verify both consumptions are recorded for forensic analysis
    match registry.check_seal_status(&seal) {
        SealStatus::DoubleSpent { consumptions } => {
            assert_eq!(consumptions.len(), 2, "Both consumptions must be recorded");
            // The original consumption should have lower block height
            assert_eq!(consumptions[0].block_height, 100);
            assert_eq!(consumptions[1].block_height, 90);
        }
        _ => panic!("Expected DoubleSpent status for rollback replay"),
    }
}
