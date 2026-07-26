//! Versioned Solana closure vectors (PAR-SOL-001).
//!
//! Each vector builds a real digest chain — record → slot entries → bank hash —
//! and lets the verifier reconstruct it from bytes. The finality vectors pin
//! Solana's tighter rule: only a full node can establish finality, so every
//! other trust mode reports closure as unproven.

use csv_chain_ports::encode_entries;
use csv_hash::Hash;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode, ConsumedStateRef,
    FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};
use csv_solana::closure::{
    SOLANA_CLOSURE_PROOF_KIND, SolanaBankHash, SolanaClosureDeployment, SolanaClosureMaterial,
    SolanaClosureRecord, solana_digest,
};
use csv_solana::closure_verifier::{
    SolanaClosureVerificationError, SolanaClosureVerificationInput, verify_solana_closure,
};

const TOKEN: u16 = 7;
const SLOT: u64 = 777;

fn deployment() -> SolanaClosureDeployment {
    SolanaClosureDeployment {
        network_id: "devnet".into(),
        program_id: [0xAB; 32],
        deployment_id: "closure-program-1".into(),
    }
}

fn source() -> ConsumedStateRef {
    ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
}

fn successor() -> Hash {
    Hash::new([5; 32])
}

struct Fixture {
    material: SolanaClosureMaterial,
    checkpoint: FinalizedCheckpoint,
}

fn build_closure(
    deployment: &SolanaClosureDeployment,
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
) -> Fixture {
    let record = SolanaClosureRecord {
        nullifier: *SourceNullifier::derive(consumed).as_bytes(),
        binding: *deployment
            .expected_binding(consumed, successor_commitment)
            .as_bytes(),
        program_id: deployment.program_id,
        slot: SLOT,
    };
    let entries = vec![[0x22; 32], record.digest(), [0x33; 32]];
    let bank_hash = SolanaBankHash {
        slot: SLOT,
        entries_digest: solana_digest(&encode_entries(&entries)),
        parent_hash: [0x44; 32],
    };
    let checkpoint = FinalizedCheckpoint {
        chain_id: "solana".into(),
        network_id: deployment.network_id.clone(),
        block_height: SLOT,
        block_id: bank_hash.digest().to_vec(),
        finality_policy: FinalityPolicy::Deterministic("rooted-slot".into()),
    };
    Fixture {
        material: SolanaClosureMaterial {
            record,
            slot_entries: entries,
            bank_hash,
        },
        checkpoint,
    }
}

fn proof_for(
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
    material: &SolanaClosureMaterial,
) -> ClosureProof {
    ClosureProof {
        consumed_state: *consumed,
        successor_commitment: *successor_commitment,
        proof_kind: ClosureProofKind::ChainSpecific(SOLANA_CLOSURE_PROOF_KIND.into()),
        proof_material: material.encode(),
    }
}

fn verify_with(
    deployment: &SolanaClosureDeployment,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    rooted_slot: u64,
    trust_mode: ClosureTrustMode,
) -> Result<csv_protocol::ClosureVerificationResult, SolanaClosureVerificationError> {
    verify_solana_closure(SolanaClosureVerificationInput {
        proof,
        deployment,
        checkpoint,
        observed_rooted_slot: rooted_slot,
        max_checkpoint_age: Some(10_000),
        proof_provider_id: "vectors",
        trust_mode,
    })
}

fn verify(
    deployment: &SolanaClosureDeployment,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    rooted_slot: u64,
) -> Result<csv_protocol::ClosureVerificationResult, SolanaClosureVerificationError> {
    verify_with(
        deployment,
        proof,
        checkpoint,
        rooted_slot,
        ClosureTrustMode::FullNode,
    )
}

#[test]
fn vector_positive_closure_verifies() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SLOT).unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Satisfied
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
    assert_eq!(result.reason_codes, vec!["SOLANA.CLOSURE.VERIFIED"]);
    result.validate().expect("result must be self-consistent");
}

#[test]
fn vector_positive_is_deterministic() {
    let deployment = deployment();
    let first = build_closure(&deployment, &source(), &successor());
    let second = build_closure(&deployment, &source(), &successor());
    assert_eq!(first.material.encode(), second.material.encode());
}

#[test]
fn vector_only_a_full_node_can_establish_solana_finality() {
    // Solana publishes no artifact a light client could verify, so unlike Sui
    // and Aptos even LightClient must report Indeterminate here.
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    for trust_mode in [
        ClosureTrustMode::LightClient,
        ClosureTrustMode::RpcQuorum,
        ClosureTrustMode::AttestedRegistry,
    ] {
        let result =
            verify_with(&deployment, &proof, &fixture.checkpoint, SLOT, trust_mode).unwrap();
        assert_eq!(
            result.proof_validity,
            ClosureDimensionStatus::Satisfied,
            "inclusion is still verifiable under {trust_mode:?}"
        );
        assert_eq!(
            result.checkpoint_finality,
            ClosureDimensionStatus::Indeterminate,
            "{trust_mode:?} must not establish Solana finality"
        );
        assert_eq!(
            result.source_closure,
            ClosureDimensionStatus::Indeterminate,
            "{trust_mode:?} must not report closure"
        );
    }
}

#[test]
fn vector_replay_across_deployments_fails() {
    let first = deployment();
    let mut second = deployment();
    second.program_id = [0xCD; 32];
    second.deployment_id = "closure-program-2".into();

    let fixture = build_closure(&first, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    assert_eq!(
        verify(&second, &proof, &fixture.checkpoint, SLOT).unwrap_err(),
        SolanaClosureVerificationError::WrongDeployment
    );
}

#[test]
fn vector_replay_across_networks_fails() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let mut mainnet = deployment.clone();
    mainnet.network_id = "mainnet-beta".into();
    assert_eq!(
        verify(&mainnet, &proof, &fixture.checkpoint, SLOT).unwrap_err(),
        SolanaClosureVerificationError::WrongNetwork
    );
}

#[test]
fn vector_replay_across_proof_kinds_fails() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_kind = ClosureProofKind::BitcoinTransactionInclusion;

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, SLOT).unwrap_err(),
        SolanaClosureVerificationError::WrongProofKind
    );
}

#[test]
fn vector_wrong_domain_second_successor_is_not_proven() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &Hash::new([6; 32]), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SLOT).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
}

#[test]
fn vector_wrong_domain_other_source_is_not_proven() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut other = source();
    other.output_index += 1;
    let proof = proof_for(&other, &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SLOT).unwrap();
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
}

#[test]
fn vector_insufficient_finality_is_not_closure() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SLOT - 1).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(result.checkpoint_finality, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);
}

#[test]
fn vector_reorganization_orphans_the_checkpoint() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let mut orphaned = fixture.checkpoint.clone();
    orphaned.block_id = vec![0xEE; 32];
    assert_eq!(
        verify(&deployment, &proof, &orphaned, SLOT).unwrap_err(),
        SolanaClosureVerificationError::WrongCheckpointDigest
    );
}

#[test]
fn a_record_from_another_slot_is_rejected() {
    let deployment = deployment();
    let mut fixture = build_closure(&deployment, &source(), &successor());
    fixture.material.record.slot = SLOT + 1;
    let proof = proof_for(&source(), &successor(), &fixture.material);

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, SLOT).unwrap_err(),
        SolanaClosureVerificationError::WrongSlot
    );
}

#[test]
fn a_tampered_entries_digest_is_rejected() {
    let deployment = deployment();
    let mut fixture = build_closure(&deployment, &source(), &successor());
    fixture.material.bank_hash.entries_digest[0] ^= 0xFF;
    let checkpoint = FinalizedCheckpoint {
        block_id: fixture.material.bank_hash.digest().to_vec(),
        ..fixture.checkpoint.clone()
    };
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &checkpoint, SLOT).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
}

#[test]
fn random_bytes_are_not_a_proof() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_material = vec![0xAB; 256];

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, SLOT).unwrap_err(),
        SolanaClosureVerificationError::MalformedProofMaterial
    );
}
