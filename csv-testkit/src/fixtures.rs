//! Test fixtures
//!
//! This module provides shared test fixtures for CSV protocol testing.
//! All fixtures use safe constructors with valid test data.

use csv_hash::Hash;
use csv_hash::dag::DAGSegment;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_proof::proof::{FinalityProof, InclusionProof, ProofBundle};

/// Test proof bundle fixture
pub struct TestProofBundle;

impl TestProofBundle {
    /// Create a minimal valid proof bundle for testing
    /// Uses safe constructors with cryptographically valid test data
    pub fn minimal() -> ProofBundle {
        // Use valid test data that passes validation
        let inclusion_proof = InclusionProof::new(
            vec![1u8; 32],        // Valid block hash (non-zero)
            Hash::new([2u8; 32]), // Valid commitment hash
            100,                  // Valid block height
            0,                    // Valid transaction index
        )
        .expect("Valid inclusion proof data");

        let finality_proof = FinalityProof::new(
            vec![3u8; 64], // Valid proof data
            6,             // Valid confirmations (>= minimum)
            true,          // Valid finality flag
        )
        .expect("Valid finality proof data");

        let transition_dag = DAGSegment::new(vec![], Hash::new([4u8; 32]));
        let seal_ref = SealPoint::new(vec![5u8; 32], Some(42)).unwrap();
        let anchor_ref = CommitAnchor::new(vec![6u8; 32], 100, vec![]).unwrap();

        ProofBundle::new(
            transition_dag,
            vec![vec![7u8; 64]], // Valid signatures
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .expect("Valid proof bundle data")
    }
}

/// Test transfer fixture
pub struct TestTransfer;

impl TestTransfer {
    /// Create a minimal valid transfer for testing
    pub fn minimal() -> Vec<u8> {
        vec![0u8; 64]
    }
}
