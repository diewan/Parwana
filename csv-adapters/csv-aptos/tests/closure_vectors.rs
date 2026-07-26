//! Versioned Aptos closure vectors (PAR-APT-001).
//!
//! Each vector builds a real digest chain — record → transaction accumulator →
//! ledger info — and lets the verifier reconstruct it from bytes.

use csv_aptos::closure::{
    APTOS_CLOSURE_PROOF_KIND, AptosClosureDeployment, AptosClosureMaterial, AptosClosureRecord,
    AptosLedgerInfo, aptos_digest,
};
use csv_aptos::closure_verifier::{
    AptosClosureVerificationError, AptosClosureVerificationInput, verify_aptos_closure,
};
use csv_chain_ports::encode_entries;
use csv_hash::Hash;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode, ConsumedStateRef,
    FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};

const TOKEN: u16 = 7;
const VERSION: u64 = 4_200;

fn deployment() -> AptosClosureDeployment {
    AptosClosureDeployment {
        network_id: "testnet".into(),
        module_address: [0xAB; 32],
        deployment_id: "closure-module-1".into(),
    }
}

fn source() -> ConsumedStateRef {
    ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
}

fn successor() -> Hash {
    Hash::new([5; 32])
}

struct Fixture {
    material: AptosClosureMaterial,
    checkpoint: FinalizedCheckpoint,
}

fn build_closure(
    deployment: &AptosClosureDeployment,
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
) -> Fixture {
    let record = AptosClosureRecord {
        nullifier: *SourceNullifier::derive(consumed).as_bytes(),
        binding: *deployment
            .expected_binding(consumed, successor_commitment)
            .as_bytes(),
        module_address: deployment.module_address,
        ledger_version: VERSION,
    };
    let entries = vec![[0x22; 32], record.digest(), [0x33; 32]];
    let ledger_info = AptosLedgerInfo {
        version: VERSION,
        epoch: 9,
        accumulator_root: aptos_digest(&encode_entries(&entries)),
    };
    let checkpoint = FinalizedCheckpoint {
        chain_id: "aptos".into(),
        network_id: deployment.network_id.clone(),
        block_height: VERSION,
        block_id: ledger_info.digest().to_vec(),
        finality_policy: FinalityPolicy::Deterministic("validator-committed".into()),
    };
    Fixture {
        material: AptosClosureMaterial {
            record,
            accumulator_entries: entries,
            ledger_info,
        },
        checkpoint,
    }
}

fn proof_for(
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
    material: &AptosClosureMaterial,
) -> ClosureProof {
    ClosureProof {
        consumed_state: *consumed,
        successor_commitment: *successor_commitment,
        proof_kind: ClosureProofKind::ChainSpecific(APTOS_CLOSURE_PROOF_KIND.into()),
        proof_material: material.encode(),
    }
}

fn verify_with(
    deployment: &AptosClosureDeployment,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    committed_version: u64,
    trust_mode: ClosureTrustMode,
) -> Result<csv_protocol::ClosureVerificationResult, AptosClosureVerificationError> {
    verify_aptos_closure(AptosClosureVerificationInput {
        proof,
        deployment,
        checkpoint,
        observed_committed_version: committed_version,
        max_checkpoint_age: Some(10_000),
        proof_provider_id: "vectors",
        trust_mode,
    })
}

fn verify(
    deployment: &AptosClosureDeployment,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    committed_version: u64,
) -> Result<csv_protocol::ClosureVerificationResult, AptosClosureVerificationError> {
    verify_with(
        deployment,
        proof,
        checkpoint,
        committed_version,
        ClosureTrustMode::FullNode,
    )
}

#[test]
fn vector_positive_closure_verifies() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, VERSION).unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Satisfied
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
    assert_eq!(result.reason_codes, vec!["APTOS.CLOSURE.VERIFIED"]);
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
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify_with(
        &deployment,
        &proof,
        &fixture.checkpoint,
        VERSION,
        ClosureTrustMode::RpcQuorum,
    )
    .unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Indeterminate
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);
}

#[test]
fn vector_replay_across_deployments_fails() {
    let first = deployment();
    let mut second = deployment();
    second.module_address = [0xCD; 32];
    second.deployment_id = "closure-module-2".into();

    let fixture = build_closure(&first, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    assert_eq!(
        verify(&second, &proof, &fixture.checkpoint, VERSION).unwrap_err(),
        AptosClosureVerificationError::WrongDeployment
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
        verify(&mainnet, &proof, &fixture.checkpoint, VERSION).unwrap_err(),
        AptosClosureVerificationError::WrongNetwork
    );
}

#[test]
fn vector_replay_across_proof_kinds_fails() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_kind = ClosureProofKind::BitcoinTransactionInclusion;

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, VERSION).unwrap_err(),
        AptosClosureVerificationError::WrongProofKind
    );
}

#[test]
fn vector_wrong_domain_second_successor_is_not_proven() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &Hash::new([6; 32]), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, VERSION).unwrap();
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

    let result = verify(&deployment, &proof, &fixture.checkpoint, VERSION).unwrap();
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
}

#[test]
fn vector_insufficient_finality_is_not_closure() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &fixture.checkpoint, VERSION - 1).unwrap();
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
        verify(&deployment, &proof, &orphaned, VERSION).unwrap_err(),
        AptosClosureVerificationError::WrongCheckpointDigest
    );
}

#[test]
fn a_tampered_accumulator_root_is_rejected() {
    let deployment = deployment();
    let mut fixture = build_closure(&deployment, &source(), &successor());
    fixture.material.ledger_info.accumulator_root[0] ^= 0xFF;
    let checkpoint = FinalizedCheckpoint {
        block_id: fixture.material.ledger_info.digest().to_vec(),
        ..fixture.checkpoint.clone()
    };
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&deployment, &proof, &checkpoint, VERSION).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
}

#[test]
fn random_bytes_are_not_a_proof() {
    let deployment = deployment();
    let fixture = build_closure(&deployment, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_material = vec![0xAB; 256];

    assert_eq!(
        verify(&deployment, &proof, &fixture.checkpoint, VERSION).unwrap_err(),
        AptosClosureVerificationError::MalformedProofMaterial
    );
}
