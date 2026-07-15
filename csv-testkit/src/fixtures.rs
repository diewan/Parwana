//! Test fixtures
//!
//! This module provides shared test fixtures for CSV protocol testing.
//! All fixtures use safe constructors with valid test data.

use csv_hash::Hash;
use csv_hash::dag::{DAGNode, DAGSegment};
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof, ProofBundle};
use csv_protocol::signature::SignatureScheme;
use hex;

/// Test proof bundle fixture
pub struct TestProofBundle;

impl TestProofBundle {
    /// Create a minimal valid proof bundle for testing
    /// Uses safe constructors with cryptographically valid test data
    pub fn minimal() -> ProofBundle {
        // Use valid test data that passes validation
        let proof_bytes = vec![1u8; 32]; // Proof bytes that will be used in both anchor and inclusion
        let inclusion_proof = InclusionProof::new(
            proof_bytes.clone(),  // Proof bytes
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

        // Create a valid DAG with at least one node
        let dag_node = DAGNode::new(Hash::new([8u8; 32]), vec![], vec![], vec![vec![]], vec![]);
        let root_commitment = Hash::new([4u8; 32]);
        let transition_dag = DAGSegment::new(vec![dag_node], root_commitment);
        let seal_ref = SealPoint::new(vec![5u8; 32], Some(42), None).unwrap();
        // anchor_ref.metadata must match inclusion_proof.proof_bytes
        let anchor_ref = CommitAnchor::new(vec![1u8; 32], 100, proof_bytes.clone()).unwrap();

        // Create signature that signs the actual root commitment
        let signature = create_valid_signature(&root_commitment);

        ProofBundle::with_signature_scheme(
            SignatureScheme::Ed25519,
            transition_dag,
            vec![signature], // Valid signature with proper format
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .expect("Valid proof bundle data")
    }
}

/// Create a valid signature in the expected format
/// Format: [pk_len (4 bytes LE)] [public_key (pk_len bytes)] [signature (remaining bytes)]
fn create_valid_signature(commitment: &Hash) -> Vec<u8> {
    use ed25519_dalek::{Signer, SigningKey};

    // Use a deterministic keypair for reproducible test signatures
    let signing_key_bytes = [1u8; 32]; // Fixed seed for deterministic key
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(commitment.as_bytes());

    // Format: [pk_len (4 bytes LE)] [public_key (32 bytes)] [signature (64 bytes)]
    let mut sig_bytes = Vec::with_capacity(4 + 32 + 64);
    sig_bytes.extend_from_slice(&32u32.to_le_bytes());
    sig_bytes.extend_from_slice(verifying_key.as_bytes());
    sig_bytes.extend_from_slice(signature.to_bytes().as_slice());
    sig_bytes
}

/// Test transfer fixture
pub struct TestTransfer;

impl TestTransfer {
    /// Create a minimal valid transfer for testing
    pub fn minimal() -> Vec<u8> {
        vec![0u8; 64]
    }
}

/// Test adapter for testing chain adapter operations
///
/// This is a mock adapter that implements the ChainAdapter trait
/// with fake proof builders for testing purposes only.
pub struct TestAdapter {
    /// Chain capabilities for this test adapter
    pub caps: ChainCapabilities,
}

impl TestAdapter {
    /// Create a new test adapter with Bitcoin capabilities
    pub fn new_bitcoin() -> Self {
        Self {
            caps: ChainCapabilities::bitcoin(),
        }
    }

    /// Create a new test adapter with Ethereum capabilities
    pub fn new_ethereum() -> Self {
        Self {
            caps: ChainCapabilities::ethereum(),
        }
    }

    /// Create a new test adapter with custom capabilities
    pub fn new(caps: ChainCapabilities) -> Self {
        Self { caps }
    }

    /// Build a fake inclusion proof for testing
    ///
    /// # Warning
    /// This uses fake proof bytes (0xA5 repeated) and should only be used in tests.
    pub fn build_fake_inclusion_proof(sanad_id: &csv_hash::Hash) -> Result<ProofBundle, String> {
        let root_commitment = csv_hash::Hash::new([9u8; 32]);

        // Use deterministic ed25519 signature for consistency
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key_bytes = [2u8; 32]; // Different fixed seed
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(root_commitment.as_bytes());

        let mut encoded_signature = Vec::with_capacity(4 + 32 + 64);
        encoded_signature.extend_from_slice(&32u32.to_le_bytes());
        encoded_signature.extend_from_slice(verifying_key.as_bytes());
        encoded_signature.extend_from_slice(signature.to_bytes().as_slice());

        let proof_bytes = vec![0xA5u8; 32]; // Fake proof bytes for testing only
        let node = DAGNode::new(
            csv_hash::Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![],
        );
        ProofBundle::with_signature_scheme(
            SignatureScheme::Ed25519,
            DAGSegment::new(vec![node], root_commitment),
            vec![encoded_signature],
            SealPoint::new(sanad_id.as_bytes().to_vec(), Some(0), None).unwrap(),
            // anchor_ref.metadata must match inclusion_proof.proof_bytes
            CommitAnchor::new(vec![1u8; 32], 100, proof_bytes.clone()).unwrap(),
            InclusionProof::new(proof_bytes, csv_hash::Hash::new([0xBBu8; 32]), 100, 0).unwrap(),
            FinalityProof::new(vec![0u8; 32], 6, true).unwrap(),
        )
        .map_err(|e| e.to_string())
    }

    /// Build a fake lock result for testing
    pub fn build_fake_lock_result() -> csv_chain_ports::LockResult {
        csv_chain_ports::LockResult {
            tx_hash: hex::encode([0x11u8; 32]),
            block_height: 100,
        }
    }

    /// Build a fake mint result for testing
    pub fn build_fake_mint_result() -> csv_chain_ports::MintResult {
        csv_chain_ports::MintResult {
            tx_hash: hex::encode([0x22u8; 32]),
            block_height: 200,
            materialization: csv_chain_ports::DestinationMaterialization::unavailable("test-chain"),
        }
    }
}
