//! Versioned Ethereum closure vectors (PAR-EVM-001).
//!
//! Every vector is built from a **real** Merkle-Patricia trie: the state and
//! storage tries are constructed with `alloy-trie`'s hash builder, proofs are
//! retained from that construction, and the block header is RLP-encoded and
//! re-hashed. Nothing here asserts a proof is valid; the verifier reconstructs
//! each proof from bytes, exactly as a recipient would.
//!
//! The five required vectors are:
//!
//! | Vector | What it pins |
//! |---|---|
//! | positive | An honest closure verifies and reports `Satisfied` closure. |
//! | replay | A proof from one deployment fails against another. |
//! | wrong domain | A second successor of the same source is not proven. |
//! | insufficient finality | A valid proof under a non-final checkpoint is not closure. |
//! | reorganization | A checkpoint orphaned by a reorg loses closure. |

use alloy_consensus::Header;
use alloy_primitives::{B256, U256, keccak256};
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use csv_ethereum::closure::{
    ETHEREUM_CLOSURE_PROOF_KIND, EthereumClosureMaterial, EthereumClosureRegistry,
    expected_binding, storage_value_rlp,
};
use csv_ethereum::closure_verifier::{
    EthereumClosureVerificationError, EthereumClosureVerificationInput, verify_ethereum_closure,
};
use csv_hash::Hash;
use csv_protocol::{
    ClosureDimensionStatus, ClosureProof, ClosureProofKind, ClosureTrustMode, ConsumedStateRef,
    FinalityPolicy, FinalizedCheckpoint, SourceNullifier,
};

const TOKEN: u16 = 7;
const CHECKPOINT_HEIGHT: u64 = 1_000;

fn registry() -> EthereumClosureRegistry {
    EthereumClosureRegistry {
        network_id: "sepolia".into(),
        contract_address: [0xAB; 20],
        mapping_slot: 6,
        deployment_id: "closure-registry-1".into(),
    }
}

fn source() -> ConsumedStateRef {
    ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
}

fn successor() -> Hash {
    Hash::new([5; 32])
}

/// A trie built over one target key, returning its root and retained proof.
fn build_trie(entries: &[(B256, Vec<u8>)], target: B256) -> (B256, Vec<Vec<u8>>) {
    let target_nibbles = Nibbles::unpack(target.as_slice());
    let mut builder = HashBuilder::default()
        .with_proof_retainer(ProofRetainer::new(vec![target_nibbles.clone()]));

    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, value) in &sorted {
        builder.add_leaf(Nibbles::unpack(key.as_slice()), value);
    }
    let root = builder.root();
    let proof = builder
        .take_proof_nodes()
        .matching_nodes_sorted(&target_nibbles)
        .into_iter()
        .map(|(_, node)| node.to_vec())
        .collect();
    (root, proof)
}

/// One fully-built closure fixture: proof material plus its checkpoint.
struct Fixture {
    material: EthereumClosureMaterial,
    checkpoint: FinalizedCheckpoint,
}

/// Build an honest closure of `source` in favour of `successor` under `registry`.
fn build_closure(
    registry: &EthereumClosureRegistry,
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
) -> Fixture {
    let nullifier = SourceNullifier::derive(consumed);
    let binding = expected_binding(registry, consumed, successor_commitment);
    let storage_key = registry.storage_key(&nullifier);

    // Storage trie: our binding, plus an unrelated entry so the trie branches.
    let slot_hash = keccak256(storage_key);
    let decoy_slot = keccak256([0x99u8; 32]);
    let (storage_root, storage_proof) = build_trie(
        &[
            (slot_hash, storage_value_rlp(&binding)),
            (decoy_slot, storage_value_rlp(&Hash::new([0x77; 32]))),
        ],
        slot_hash,
    );

    // Account RLP: [nonce, balance, storage_root, code_hash].
    let mut account_rlp = Vec::new();
    let payload_len = {
        let mut tmp = Vec::new();
        alloy_rlp::Encodable::encode(&0u64, &mut tmp);
        alloy_rlp::Encodable::encode(&U256::ZERO, &mut tmp);
        alloy_rlp::Encodable::encode(&storage_root, &mut tmp);
        alloy_rlp::Encodable::encode(&keccak256([] as [u8; 0]), &mut tmp);
        tmp.len()
    };
    alloy_rlp::Header {
        list: true,
        payload_length: payload_len,
    }
    .encode(&mut account_rlp);
    alloy_rlp::Encodable::encode(&0u64, &mut account_rlp);
    alloy_rlp::Encodable::encode(&U256::ZERO, &mut account_rlp);
    alloy_rlp::Encodable::encode(&storage_root, &mut account_rlp);
    alloy_rlp::Encodable::encode(&keccak256([] as [u8; 0]), &mut account_rlp);

    // State trie: our account, plus an unrelated account.
    let account_key = keccak256(registry.contract_address);
    let decoy_account = keccak256([0x55u8; 20]);
    let (state_root, account_proof) = build_trie(
        &[
            (account_key, account_rlp.clone()),
            (decoy_account, account_rlp.clone()),
        ],
        account_key,
    );

    let header = Header {
        state_root,
        number: CHECKPOINT_HEIGHT,
        ..Default::default()
    };
    let mut block_header_rlp = Vec::new();
    alloy_rlp::Encodable::encode(&header, &mut block_header_rlp);
    let block_hash = keccak256(&block_header_rlp);

    Fixture {
        material: EthereumClosureMaterial {
            block_header_rlp,
            contract_address: registry.contract_address,
            mapping_slot: registry.mapping_slot,
            account_proof,
            storage_proof,
        },
        checkpoint: FinalizedCheckpoint {
            chain_id: "ethereum".into(),
            network_id: registry.network_id.clone(),
            block_height: CHECKPOINT_HEIGHT,
            block_id: block_hash.to_vec(),
            finality_policy: FinalityPolicy::Deterministic("beacon-finalized".into()),
        },
    }
}

fn proof_for(
    consumed: &ConsumedStateRef,
    successor_commitment: &Hash,
    material: &EthereumClosureMaterial,
) -> ClosureProof {
    ClosureProof {
        consumed_state: *consumed,
        successor_commitment: *successor_commitment,
        proof_kind: ClosureProofKind::ChainSpecific(ETHEREUM_CLOSURE_PROOF_KIND.into()),
        proof_material: material.encode(),
    }
}

fn verify(
    registry: &EthereumClosureRegistry,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
    finalized_height: u64,
) -> Result<csv_protocol::ClosureVerificationResult, EthereumClosureVerificationError> {
    verify_ethereum_closure(EthereumClosureVerificationInput {
        proof,
        registry,
        checkpoint,
        observed_finalized_height: finalized_height,
        max_checkpoint_age: Some(10_000),
        proof_provider_id: "vectors",
        trust_mode: ClosureTrustMode::FullNode,
    })
}

#[test]
fn vector_positive_closure_verifies() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Satisfied
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
    assert_eq!(result.reason_codes, vec!["ETHEREUM.CLOSURE.VERIFIED"]);
    result.validate().expect("result must be self-consistent");
}

#[test]
fn vector_positive_is_deterministic() {
    let registry = registry();
    let first = build_closure(&registry, &source(), &successor());
    let second = build_closure(&registry, &source(), &successor());
    assert_eq!(first.material.encode(), second.material.encode());
    assert_eq!(first.checkpoint.block_id, second.checkpoint.block_id);
}

#[test]
fn vector_rpc_quorum_cannot_establish_closure() {
    // A state proof proves "under root R, slot S holds V" — not that R is a
    // canonical finalized root. The header comes from the same material, so an
    // endpoint can fabricate a self-consistent set. Only a full node or a
    // sync-committee light client can decide canonicity.
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    for trust_mode in [
        ClosureTrustMode::RpcQuorum,
        ClosureTrustMode::AttestedRegistry,
    ] {
        let result = verify_ethereum_closure(EthereumClosureVerificationInput {
            proof: &proof,
            registry: &registry,
            checkpoint: &fixture.checkpoint,
            observed_finalized_height: CHECKPOINT_HEIGHT,
            max_checkpoint_age: Some(10_000),
            proof_provider_id: "vectors",
            trust_mode,
        })
        .unwrap();

        assert_eq!(
            result.proof_validity,
            ClosureDimensionStatus::Satisfied,
            "inclusion is still cryptographic under {trust_mode:?}"
        );
        assert_eq!(
            result.checkpoint_finality,
            ClosureDimensionStatus::Indeterminate,
            "{trust_mode:?} must not establish Ethereum finality"
        );
        assert_eq!(
            result.source_closure,
            ClosureDimensionStatus::Indeterminate,
            "{trust_mode:?} must not report closure"
        );
        assert_eq!(
            result.reason_codes,
            vec!["ETHEREUM.FINALITY.TRUST_MODE_CANNOT_ESTABLISH"]
        );
    }
}

#[test]
fn vector_light_client_can_establish_closure() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify_ethereum_closure(EthereumClosureVerificationInput {
        proof: &proof,
        registry: &registry,
        checkpoint: &fixture.checkpoint,
        observed_finalized_height: CHECKPOINT_HEIGHT,
        max_checkpoint_age: Some(10_000),
        proof_provider_id: "vectors",
        trust_mode: ClosureTrustMode::LightClient,
    })
    .unwrap();
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
}

#[test]
fn vector_replay_across_deployments_fails() {
    // A genuine proof from deployment 1, presented as a proof for deployment 2.
    let first = registry();
    let mut second = registry();
    second.contract_address = [0xCD; 20];
    second.deployment_id = "closure-registry-2".into();

    let fixture = build_closure(&first, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    // The proof names the first registry, so the second rejects it outright.
    assert_eq!(
        verify(&second, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap_err(),
        EthereumClosureVerificationError::WrongRegistry
    );
}

#[test]
fn vector_replay_across_networks_fails() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let mut mainnet = registry.clone();
    mainnet.network_id = "mainnet".into();
    assert_eq!(
        verify(&mainnet, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap_err(),
        EthereumClosureVerificationError::WrongNetwork
    );
}

#[test]
fn vector_replay_across_proof_kinds_fails() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_kind = ClosureProofKind::BitcoinTransactionInclusion;

    assert_eq!(
        verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap_err(),
        EthereumClosureVerificationError::WrongProofKind
    );
}

#[test]
fn vector_wrong_domain_second_successor_is_not_proven() {
    // The chain closed the source in favour of successor A. A recipient is
    // shown that same proof alongside a claim of successor B. The slot holds
    // A's binding, so B is not proven — this is the equivocation attempt.
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let equivocating = Hash::new([6; 32]);
    let proof = proof_for(&source(), &equivocating, &fixture.material);

    let result = verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
    assert_eq!(
        result.reason_codes,
        vec!["ETHEREUM.CLOSURE.BINDING_NOT_PROVEN"]
    );
}

#[test]
fn vector_wrong_domain_other_source_is_not_proven() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let mut other_source = source();
    other_source.output_index += 1;
    let proof = proof_for(&other_source, &successor(), &fixture.material);

    let result = verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Failed);
}

#[test]
fn vector_insufficient_finality_is_not_closure() {
    // The proof itself is genuine; the checkpoint is above the finalized head.
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let result = verify(
        &registry,
        &proof,
        &fixture.checkpoint,
        CHECKPOINT_HEIGHT - 1,
    )
    .unwrap();

    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
    assert_eq!(result.checkpoint_finality, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);
    assert_eq!(result.reason_codes, vec!["ETHEREUM.FINALITY.INSUFFICIENT"]);
}

#[test]
fn vector_insufficient_confirmations_is_not_closure() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);
    let mut checkpoint = fixture.checkpoint.clone();
    checkpoint.finality_policy = FinalityPolicy::Confirmations(64);

    let result = verify(&registry, &proof, &checkpoint, CHECKPOINT_HEIGHT + 3).unwrap();
    assert_eq!(result.checkpoint_finality, ClosureDimensionStatus::Failed);
    assert_eq!(result.source_closure, ClosureDimensionStatus::Indeterminate);

    let result = verify(&registry, &proof, &checkpoint, CHECKPOINT_HEIGHT + 100).unwrap();
    assert_eq!(
        result.checkpoint_finality,
        ClosureDimensionStatus::Satisfied
    );
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);
}

#[test]
fn vector_reorganization_orphans_the_checkpoint() {
    // The canonical chain now has a different block at this height. The
    // recipient's checkpoint no longer matches the header it was justified by,
    // so the closure must not still read as verified.
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let mut orphaned = fixture.checkpoint.clone();
    orphaned.block_id = vec![0xEE; 32];

    assert_eq!(
        verify(&registry, &proof, &orphaned, CHECKPOINT_HEIGHT).unwrap_err(),
        EthereumClosureVerificationError::WrongBlockHeader
    );
}

#[test]
fn vector_reorganization_changes_height() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    let mut moved = fixture.checkpoint.clone();
    moved.block_height = CHECKPOINT_HEIGHT + 1;

    assert_eq!(
        verify(&registry, &proof, &moved, CHECKPOINT_HEIGHT + 1).unwrap_err(),
        EthereumClosureVerificationError::WrongCheckpoint
    );
}

#[test]
fn a_tampered_storage_proof_does_not_verify() {
    let registry = registry();
    let mut fixture = build_closure(&registry, &source(), &successor());
    if let Some(node) = fixture.material.storage_proof.last_mut() {
        let last = node.len() - 1;
        node[last] ^= 0xFF;
    }
    let proof = proof_for(&source(), &successor(), &fixture.material);
    let result = verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
}

#[test]
fn random_bytes_are_not_a_proof() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let mut proof = proof_for(&source(), &successor(), &fixture.material);
    proof.proof_material = vec![0xAB; 256];

    assert_eq!(
        verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap_err(),
        EthereumClosureVerificationError::MalformedProofMaterial
    );
}

#[test]
fn an_empty_storage_proof_does_not_verify() {
    let registry = registry();
    let mut fixture = build_closure(&registry, &source(), &successor());
    fixture.material.storage_proof.clear();
    let proof = proof_for(&source(), &successor(), &fixture.material);
    let result = verify(&registry, &proof, &fixture.checkpoint, CHECKPOINT_HEIGHT).unwrap();
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Failed);
}

#[test]
fn freshness_is_reported_separately_from_finality() {
    let registry = registry();
    let fixture = build_closure(&registry, &source(), &successor());
    let proof = proof_for(&source(), &successor(), &fixture.material);

    // No configured bound: freshness is unknown, and says so.
    let result = verify_ethereum_closure(EthereumClosureVerificationInput {
        proof: &proof,
        registry: &registry,
        checkpoint: &fixture.checkpoint,
        observed_finalized_height: CHECKPOINT_HEIGHT,
        max_checkpoint_age: None,
        proof_provider_id: "vectors",
        trust_mode: ClosureTrustMode::FullNode,
    })
    .unwrap();
    assert_eq!(
        result.checkpoint_freshness,
        ClosureDimensionStatus::Indeterminate
    );
    // Closure is still established: freshness is not a closure precondition.
    assert_eq!(result.source_closure, ClosureDimensionStatus::Satisfied);

    // A stale checkpoint under a configured bound fails freshness only.
    let result = verify_ethereum_closure(EthereumClosureVerificationInput {
        proof: &proof,
        registry: &registry,
        checkpoint: &fixture.checkpoint,
        observed_finalized_height: CHECKPOINT_HEIGHT + 5_000,
        max_checkpoint_age: Some(10),
        proof_provider_id: "vectors",
        trust_mode: ClosureTrustMode::FullNode,
    })
    .unwrap();
    assert_eq!(result.checkpoint_freshness, ClosureDimensionStatus::Failed);
    assert_eq!(result.proof_validity, ClosureDimensionStatus::Satisfied);
}
