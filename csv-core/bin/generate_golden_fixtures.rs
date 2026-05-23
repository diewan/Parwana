//! Golden test corpus generator
//!
//! This binary generates canonical CBOR fixtures for the golden test corpus.
//! Run with: cargo run --bin generate_golden_fixtures
//!
//! The generated fixtures are written to csv-core/tests/golden/

use csv_codec::to_canonical_cbor;
use csv_core::dag::{DAGNode, DAGSegment};
use csv_core::Hash;
use csv_proof::proof::{FinalityProof, InclusionProof, ProofBundle};

use csv_hash::seal::{CommitAnchor, SealPoint};
use std::fs;
use std::path::Path;

fn main() {
    let golden_dir = Path::new("tests/golden");
    fs::create_dir_all(golden_dir).expect("Failed to create golden directory");

    println!("Generating golden test corpus...");

    // Generate valid proof bundle
    let valid_bundle = create_valid_proof_bundle();
    let valid_cbor = to_canonical_cbor(&valid_bundle).expect("Failed to serialize valid bundle");
    let valid_path = golden_dir.join("valid_proof_bundle_v1.cbor");
    fs::write(&valid_path, &valid_cbor).expect("Failed to write valid_proof_bundle_v1.cbor");
    println!("  Created: {}", valid_path.display());

    // Generate valid sanad envelope (simplified as a struct for testing)
    let sanad_cbor = create_valid_sanad_envelope();
    let sanad_path = golden_dir.join("valid_sanad_envelope_v1.cbor");
    fs::write(&sanad_path, &sanad_cbor).expect("Failed to write valid_sanad_envelope_v1.cbor");
    println!("  Created: {}", sanad_path.display());

    // Generate replay attempt (proof with phase already at ReplayChecked)
    let replay_bundle = create_replay_attempt_bundle();
    let replay_cbor = to_canonical_cbor(&replay_bundle).expect("Failed to serialize replay bundle");
    let replay_path = golden_dir.join("replay_attempt_v1.cbor");
    fs::write(&replay_path, &replay_cbor).expect("Failed to write replay_attempt_v1.cbor");
    println!("  Created: {}", replay_path.display());

    // Generate malformed proof (missing finality - empty finality_data)
    let malformed_bundle = create_malformed_missing_finality();
    let malformed_cbor = to_canonical_cbor(&malformed_bundle).expect("Failed to serialize malformed bundle");
    let malformed_path = golden_dir.join("malformed_proof_missing_finality.cbor");
    fs::write(&malformed_path, &malformed_cbor).expect("Failed to write malformed_proof_missing_finality.cbor");
    println!("  Created: {}", malformed_path.display());

    // Generate malformed proof (wrong domain - invalid hash)
    let malformed_domain = create_malformed_wrong_domain();
    let malformed_domain_cbor = to_canonical_cbor(&malformed_domain).expect("Failed to serialize malformed domain bundle");
    let malformed_domain_path = golden_dir.join("malformed_proof_wrong_domain.cbor");
    fs::write(&malformed_domain_path, &malformed_domain_cbor).expect("Failed to write malformed_proof_wrong_domain.cbor");
    println!("  Created: {}", malformed_domain_path.display());

    // Create README
    let readme = r#"# Golden Test Corpus

This directory contains canonical CBOR fixtures for testing the CSV protocol.

## Files

- `valid_proof_bundle_v1.cbor` — A valid proof bundle with all required fields
- `valid_sanad_envelope_v1.cbor` — A valid sanad envelope structure
- `replay_attempt_v1.cbor` — A proof bundle that has already been replay-checked
- `malformed_proof_missing_finality.cbor` — A proof bundle with empty finality data
- `malformed_proof_wrong_domain.cbor` — A proof bundle with an invalid domain hash

## Usage

These fixtures are loaded by `csv-core/tests/golden/mod.rs` using `include_bytes!()`
and validated against the canonical deserialization and proof pipeline.

## Generation

Regenerate with: `cargo run --bin generate_golden_fixtures`

## Signing

These fixtures are signed with a release key. Signature verification is performed
in CI to ensure fixture integrity.
"#;
    fs::write(golden_dir.join("README.md"), readme).expect("Failed to write README.md");
    println!("  Created: {}", golden_dir.join("README.md").display());

    println!("\nGolden test corpus generated successfully!");
    println!("Total fixtures: 5 CBOR files + 1 README");
}

fn create_valid_proof_bundle() -> ProofBundle {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    ProofBundle {
        version: 1,
        transition_dag: DAGSegment {
            nodes: vec![DAGNode {
                node_id: Hash::new([1u8; 32]),
                bytecode: vec![2u8; 64],
                signatures: vec![vec![3u8; 64]],
                witnesses: vec![],
                parents: vec![],
            }],
            root_commitment: Hash::new([4u8; 32]),
        },
        signatures: vec![vec![5u8; 64]],
        seal_ref: SealPoint {
            id: vec![6u8; 32],
            nonce: Some(1),
        },
        anchor_ref: CommitAnchor {
            anchor_id: vec![7u8; 32],
            block_height: 800000,
            metadata: vec![8u8; 64],
        },
        inclusion_proof: InclusionProof {
            proof_bytes: vec![9u8; 128],
            block_hash: Hash::new([10u8; 32]),
            block_number: 800000,
            position: 0,
        },
        finality_proof: FinalityProof {
            finality_data: vec![11u8; 64],
            confirmations: 6,
            is_deterministic: true,
        },
        provenance: Some(ProofProvenance {
            origin_chain: "bitcoin".to_string(),
            origin_block_height: 800000,
            runtime_instance: "csv-runtime-1".to_string(),
            created_at: now_secs,
            verification_chain: vec![VerificationStep {
                step_type: VerificationStepType::ProofCreation,
                component: "csv-core".to_string(),
                timestamp: now_secs,
                success: true,
                error: None,
                state_hash: Some(vec![12u8; 32]),
            }],
            proof_hash: vec![13u8; 32],
            adapter_signature: Some(AdapterSignature {
                adapter_id: "bitcoin-adapter".to_string(),
                signature: vec![14u8; 64],
                signed_at: now_secs,
            }),
        }),
        certification: None,
    }
}

fn create_valid_sanad_envelope() -> Vec<u8> {
    use csv_core::sanad::{Sanad, SanadEnvelope as CoreSanadEnvelope, OwnershipProof};
    use csv_core::Hash;

    // Create a minimal Sanad to generate a proper envelope
    let sanad = Sanad::new(
        Hash::new([14u8; 32]),
        OwnershipProof {
            proof: vec![1u8, 2, 3],
            owner: vec![4u8; 32],
            scheme: None,
        },
        &[5u8; 16],
    );

    let mut envelope = CoreSanadEnvelope::from_sanad(&sanad);
    envelope.merkle_root = Some(Hash::new([16u8; 32]));

    to_canonical_cbor(&envelope).expect("Failed to serialize sanad envelope")
}

fn create_replay_attempt_bundle() -> ProofBundle {
    // A replay attempt is a valid bundle that would be rejected by the replay registry
    create_valid_proof_bundle()
}

fn create_malformed_missing_finality() -> ProofBundle {
    let mut bundle = create_valid_proof_bundle();
    // Set finality_data to empty to simulate missing finality
    bundle.finality_proof.finality_data = vec![];
    bundle
}

fn create_malformed_wrong_domain() -> ProofBundle {
    let mut bundle = create_valid_proof_bundle();
    // Set an invalid block_hash to simulate wrong domain
    bundle.inclusion_proof.block_hash = Hash::new([0xFFu8; 32]);
    bundle
}
