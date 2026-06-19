//! Roundtrip tests for proof deserialization
//!
//! Tests that serialize → deserialize produces identical data for:
//! - InclusionProof
//! - FinalityProof
//! - TransferState

use csv_protocol::proof_taxonomy::{InclusionProof, FinalityProof};
use csv_protocol::cross_chain::TransferState;
use csv_hash::Hash;
use csv_hash::seal::SealPoint;

#[test]
fn test_inclusion_proof_roundtrip() {
    let original = InclusionProof {
        proof_bytes: vec![1u8, 2u8, 3u8, 4u8],
        block_hash: Hash::new([1u8; 32]),
        position: 42,
        block_number: 100,
        leaf: Hash::new([2u8; 32]),
        root: Hash::new([3u8; 32]),
        siblings: vec![Hash::new([4u8; 32]), Hash::new([5u8; 32])],
        leaf_index: 7,
        source: "test_source".to_string(),
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = InclusionProof::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_inclusion_proof_empty_siblings() {
    let original = InclusionProof {
        proof_bytes: vec![],
        block_hash: Hash::zero(),
        position: 0,
        block_number: 0,
        leaf: Hash::zero(),
        root: Hash::zero(),
        siblings: vec![],
        leaf_index: 0,
        source: "".to_string(),
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = InclusionProof::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_finality_proof_roundtrip() {
    let original = FinalityProof {
        finality_data: vec![10u8, 20u8, 30u8],
        block_hash: Hash::new([6u8; 32]),
        threshold: 100,
        confirmations: 50,
        data: vec![40u8, 50u8],
        source: "ethereum".to_string(),
        is_deterministic: true,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = FinalityProof::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_finality_proof_non_deterministic() {
    let original = FinalityProof {
        finality_data: vec![],
        block_hash: Hash::zero(),
        threshold: 0,
        confirmations: 0,
        data: vec![],
        source: "".to_string(),
        is_deterministic: false,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = FinalityProof::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_locked_roundtrip() {
    let original = TransferState::Locked {
        source_tx: "0x1234567890abcdef".to_string(),
        lock_height: 12345,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_awaiting_finality_roundtrip() {
    let original = TransferState::AwaitingFinality {
        confirmations_needed: 100,
        confirmations_have: 50,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_building_proof_roundtrip() {
    let original = TransferState::BuildingProof;

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_proof_ready_with_bundle_roundtrip() {
    let original = TransferState::ProofReady {
        bundle_bytes: Some(vec![1u8, 2u8, 3u8, 4u8]),
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_proof_ready_without_bundle_roundtrip() {
    let original = TransferState::ProofReady {
        bundle_bytes: None,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_minting_with_tx_roundtrip() {
    let original = TransferState::Minting {
        dest_tx: Some("0xabcdef1234567890".to_string()),
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_minting_without_tx_roundtrip() {
    let original = TransferState::Minting {
        dest_tx: None,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_complete_roundtrip() {
    let dest_seal = SealPoint::new(vec![1u8, 2u8, 3u8], Some(42), Some(1)).unwrap();
    let original = TransferState::Complete {
        dest_tx: "0xcomplete123456".to_string(),
        dest_seal,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_complete_minimal_roundtrip() {
    let dest_seal = SealPoint::new(vec![1u8], None, None).unwrap();
    let original = TransferState::Complete {
        dest_tx: "".to_string(),
        dest_seal,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_failed_roundtrip() {
    let original = TransferState::Failed {
        reason: "Insufficient confirmations".to_string(),
        recoverable: true,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_transfer_state_failed_non_recoverable_roundtrip() {
    let original = TransferState::Failed {
        reason: "Invalid proof".to_string(),
        recoverable: false,
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let restored = TransferState::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_inclusion_proof_deserialization_error_empty_bytes() {
    let result = InclusionProof::from_canonical_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_finality_proof_deserialization_error_empty_bytes() {
    let result = FinalityProof::from_canonical_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_transfer_state_deserialization_error_empty_bytes() {
    let result = TransferState::from_canonical_bytes(&[]);
    assert!(result.is_err());
}

#[test]
fn test_transfer_state_deserialization_error_invalid_variant() {
    let bytes = vec![99u8]; // Invalid variant
    let result = TransferState::from_canonical_bytes(&bytes);
    assert!(result.is_err());
}
