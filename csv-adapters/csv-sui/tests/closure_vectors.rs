//! Versioned Sui closure vectors (PAR-SUI-001).
//!
//! Each vector builds a real digest chain — record → checkpoint contents →
//! summary — and lets the verifier reconstruct it from bytes. The finality
//! vectors additionally pin the trust-mode rule: an RPC quorum can establish
//! inclusion but never certification, and must therefore never report closure
//! as satisfied.

use csv_chain_ports::encode_entries;
use csv_hash::Hash;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode, ConsumedStateRef,
    FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};
use csv_sui::closure::{
    SUI_CLOSURE_PROOF_KIND, SuiCheckpointSummary, SuiClosureDeployment, SuiClosureMaterial,
    SuiClosureRecord, sui_digest,
};
use csv_sui::closure_verifier::{
    SuiClosureVerificationError, SuiClosureVerificationInput, verify_sui_closure,
};

const TOKEN: u16 = 7;
const SEQUENCE: u64 = 900;

fn deployment() -> SuiClosureDeployment {
    SuiClosureDeployment {
        network_id: "testnet".into(),
        package_id: [0xAB; 32],
        deployment_id: "closure-package-1".into(),
    }
}

fn source() -> ConsumedStateRef {
    ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
}

fn successor() -> Hash {
    Hash::new([5; 32])
}

struct Fixture {
    material: SuiClosureMaterial,
    checkpoint: FinalizedCheckpoint,
}

fn build_closure(
    deployment: &SuiClosureDeployment,
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
) -> Fixture {
    let record = SuiClosureRecord {
        nullifier: *SourceNullifier::derive(consumed).as_bytes(),
        binding: *deployment
            .expected_binding(consumed, successor_commitment)
            .as_bytes(),
        object_id: [0x11; 32],
        object_version: 4,
        package_id: deployment.package_id,
    };
    // Unrelated entries either side, so inclusion is a genuine search.
    let contents = vec![[0x22; 32], record.digest(), [0x33; 32]];
    let summary = SuiCheckpointSummary {
        sequence_number: SEQUENCE,
        epoch: 12,
        content_digest: sui_digest(&encode_entries(&contents)),
    };
    let checkpoint = FinalizedCheckpoint {
        chain_id: "sui".into(),
        network_id: deployment.network_id.clone(),
        block_height: SEQUENCE,
        block_id: summary.digest().to_vec(),
        finality_policy: FinalityPolicy::Deterministic("validator-certified".into()),
    };
    Fixture {
        material: SuiClosureMaterial {
            record,
            checkpoint_contents: contents,
            summary,
        },
        checkpoint,
    }
}

fn proof_for(
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
    material: &SuiClosureMaterial,
) -> ClosureProof {
    ClosureProof {
        consumed_state: *consumed,
        successor_commitment: *successor_commitment,
        proof_kind: ClosureProofKind::ChainSpecific(SUI_CLOSURE_PROOF_KIND.into()),
        proof_material: material.encode(),
    }
}

fn verify_with(
    deployment: &SuiClosureDeployment,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    certified_sequence: u64,
    trust_mode: ClosureTrustMode,
) -> Result<csv_protocol::ClosureVerificationResult, SuiClosureVerificationError> {
    verify_sui_closure(SuiClosureVerificationInput {
        proof,
        deployment,
        checkpoint,
        observed_certified_sequence: certified_sequence,
        max_checkpoint_age: Some(10_000),
        proof_provider_id: "vectors",
        trust_mode,
    })
}

fn verify(
    deployment: &SuiClosureDeployment,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    certified_sequence: u64,
) -> Result<csv_protocol::ClosureVerificationResult, SuiClosureVerificationError> {
    verify_with(
        deployment,
        proof,
        checkpoint,
        certified_sequence,
        ClosureTrustMode::FullNode,
    )
}

#[test]
fn vector_positive_closure_verifies() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE).unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Satisfied
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
    assert_eq!(result.reason_codes, vec!["SUI.CLOSURE.VERIFIED"]);
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
fn vector_rpc_quorum_cannot_establish_closure() {
    // The whole point of the trust-mode split: identical bytes, identical
    // inclusion, but an RPC quorum cannot certify a checkpoint, so closure is
    // reported unproven rather than fabricated.
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify_with(
        &deployment,
        &proof,
        &fixture.checkpoint,
        SEQUENCE,
        ClosureTrustMode::RpcQuorum,
    )
    .unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Indeterminate
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);
    assert_eq!(
        result.reason_codes,
        vec!["SUI.FINALITY.TRUST_MODE_CANNOT_ESTABLISH"]
    );
}

#[test]
fn vector_attested_registry_cannot_establish_closure() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify_with(
        &deployment,
        &proof,
        &fixture.checkpoint,
        SEQUENCE,
        ClosureTrustMode::AttestedRegistry,
    )
    .unwrap();
    assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);
}

#[test]
fn vector_replay_across_deployments_fails() {
    let first = deployment();
    let mut second = deployment();
    second.package_id = [0xCD; 32];
    second.deployment_id = "closure-package-2".into();

    let fixture = build_closure(&first, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    assert_eq!(
        verify(&second, &proof, &fixture.checkpoint, SEQUENCE).unwrap_err(),
        SuiClosureVerificationError::WrongDeployment
    );
}

#[test]
fn vector_replay_across_networks_fails() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let mut mainnet = deployment.clone();
    mainnet.network_id = "mainnet".into();
    assert_eq!(
        verify(&mainnet, &proof, &fixture.checkpoint, SEQUENCE).unwrap_err(),
        SuiClosureVerificationError::WrongNetwork
    );
}

#[test]
fn vector_replay_across_proof_kinds_fails() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_kind = ClosureProofKind::BitcoinTransactionInclusion;

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE).unwrap_err(),
        SuiClosureVerificationError::WrongProofKind
    );
}

#[test]
fn vector_wrong_domain_second_successor_is_not_proven() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &Hash::new([6; 32]), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
    assert_eq!(
        result.reason_codes,
        vec!["SUI.CLOSURE.RECORD_NOT_COMMITTED"]
    );
}

#[test]
fn vector_wrong_domain_other_source_is_not_proven() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut other = source();
    other.output_index += 1;
    let proof = proof_for(&other, &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE).unwrap();
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
}

#[test]
fn vector_insufficient_finality_is_not_closure() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE - 1).unwrap();
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
        verify(&deployment, &proof, &orphaned, SEQUENCE).unwrap_err(),
        SuiClosureVerificationError::WrongCheckpointDigest
    );
}

#[test]
fn a_record_smuggled_into_the_entry_list_is_rejected() {
    // Real contents bytes, but a claimed entry list that also contains the
    // attacker's record. The chain walk requires the two to agree.
    let deployment = deployment();
    let mut fixture = build_closure(&deployment, &source(), &successor());
    fixture.material.checkpoint_contents.push([0x44; 32]);
    let proof = proof_for(&source(), &successor(), &fixture.material);

    // The summary digest no longer matches, or inclusion fails; either way it
    // must not verify.
    if let Ok(result) = verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE) {
        assert_ne!(result.source_closure, ClosureDimensionStatus::Satisfied);
    }
}

#[test]
fn a_tampered_content_digest_is_rejected() {
    let deployment = deployment();
    let mut fixture = build_closure(&deployment, &source(), &successor());
    fixture.material.summary.content_digest[0] ^= 0xFF;
    // Recompute the checkpoint identity so the summary is self-consistent; the
    // contents no longer hash to the committed digest.
    let checkpoint = FinalizedCheckpoint {
        block_id: fixture.material.summary.digest().to_vec(),
        ..fixture.checkpoint.clone()
    };
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &checkpoint, SEQUENCE).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
}

#[test]
fn random_bytes_are_not_a_proof() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_material = vec![0xAB; 256];

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE).unwrap_err(),
        SuiClosureVerificationError::MalformedProofMaterial
    );
}

#[test]
fn consuming_a_later_object_version_is_a_different_closure() {
    let deployment = deployment();
    let mut fixture = build_closure(&deployment, &source(), &successor());
    fixture.material.record.object_version += 1;
    let proof = proof_for(&source(), &successor(), &fixture.material);

    // The record digest changed, so it is no longer the one the checkpoint
    // committed.
    let result = verify(&deployment, &proof, &fixture.checkpoint, SEQUENCE).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
}
