#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use csv_hash::Hash;
use csv_hash::dag::{DAGNode, DAGSegment, DagStructureError};
use csv_protocol::{
    Citable, Consumable, ConsumedStateRef, EvidenceRef, ExclusivityClass, ExclusivityError,
    OutputUseBinding, ProofRequirement, ReferenceDecodeError, StateUseSchema,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../conformance/v2-transition-vectors.json");

#[derive(Deserialize)]
struct Corpus {
    schema: String,
    version: u32,
    wire_version: u32,
    compatibility: Compatibility,
    fixture: Fixture,
    negative_vectors: Vec<NegativeVector>,
}

#[derive(Deserialize)]
struct Compatibility {
    canonical_bytes: String,
    preserved_across_wire_changes: Vec<String>,
    change_rule: String,
}

#[derive(Deserialize)]
struct Fixture {
    root_node: NodeVector,
    child_node: NodeVector,
    segment: SegmentVector,
    consumed_state_ref: ConsumedVector,
    evidence_ref: EvidenceVector,
    output_use_binding: OutputVector,
}

#[derive(Deserialize)]
struct NodeVector {
    bytecode_hex: String,
    signatures_hex: Vec<String>,
    witnesses_hex: Vec<String>,
    node_id_hex: String,
    canonical_bytes_hex: Option<String>,
}

#[derive(Deserialize)]
struct SegmentVector {
    root_hex: String,
    canonical_bytes_hex: String,
}

#[derive(Deserialize)]
struct ConsumedVector {
    transition_id_hex: String,
    output_index: u32,
    state_type: u16,
    canonical_bytes_hex: String,
    digest_hex: String,
}

#[derive(Deserialize)]
struct EvidenceVector {
    commitment_hex: String,
    proof_requirement: String,
    canonical_bytes_hex: String,
    digest_hex: String,
}

#[derive(Deserialize)]
struct OutputVector {
    semantics_version: u16,
    state_type: u16,
    exclusivity: String,
    canonical_bytes_hex: String,
}

#[derive(Deserialize)]
struct NegativeVector {
    id: String,
    mutation: String,
    expected_reason: String,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the published V2 corpus must be valid JSON")
}

fn bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("vector hex must decode")
}

fn hash(value: &str) -> Hash {
    let value: [u8; 32] = bytes(value)
        .try_into()
        .expect("hash vector must be 32 bytes");
    Hash::new(value)
}

fn node(vector: &NodeVector, parents: Vec<Hash>) -> DAGNode {
    DAGNode::sealed(
        bytes(&vector.bytecode_hex),
        vector
            .signatures_hex
            .iter()
            .map(|value| bytes(value))
            .collect(),
        vector
            .witnesses_hex
            .iter()
            .map(|value| bytes(value))
            .collect(),
        parents,
    )
}

fn fixtures(corpus: &Corpus) -> (DAGNode, DAGNode, DAGSegment) {
    let root = node(&corpus.fixture.root_node, vec![]);
    let child = node(&corpus.fixture.child_node, vec![root.node_id]);
    let segment = DAGSegment::sealed(vec![child.clone(), root.clone()])
        .expect("published positive graph must seal");
    (root, child, segment)
}

#[test]
fn published_positive_vectors_pin_every_v2_kernel_surface() {
    let corpus = corpus();
    assert_eq!(corpus.schema, "diewan.parwana.transition-vectors");
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.wire_version, 2);
    assert_eq!(corpus.compatibility.canonical_bytes, "frozen");
    assert!(!corpus.compatibility.change_rule.is_empty());
    assert_eq!(
        corpus.compatibility.preserved_across_wire_changes,
        [
            "consumed-state-ref-v2",
            "evidence-ref-v2",
            "output-use-binding-v2"
        ]
    );

    let (root, child, segment) = fixtures(&corpus);
    assert_eq!(root.node_id, hash(&corpus.fixture.root_node.node_id_hex));
    assert_eq!(child.node_id, hash(&corpus.fixture.child_node.node_id_hex));
    assert_eq!(
        root.to_canonical_bytes(),
        bytes(
            corpus
                .fixture
                .root_node
                .canonical_bytes_hex
                .as_deref()
                .expect("root bytes are pinned")
        )
    );
    assert_eq!(
        segment.root_commitment,
        hash(&corpus.fixture.segment.root_hex)
    );
    assert_eq!(
        segment.to_canonical_bytes(),
        bytes(&corpus.fixture.segment.canonical_bytes_hex)
    );
    segment
        .validate_structure()
        .expect("positive segment validates");

    let consumed_vector = &corpus.fixture.consumed_state_ref;
    let consumed = ConsumedStateRef::new(
        hash(&consumed_vector.transition_id_hex),
        consumed_vector.output_index,
        consumed_vector.state_type,
    );
    assert_eq!(
        consumed.to_canonical_bytes(),
        bytes(&consumed_vector.canonical_bytes_hex)
    );
    assert_eq!(consumed.digest(), hash(&consumed_vector.digest_hex));

    let evidence_vector = &corpus.fixture.evidence_ref;
    assert_eq!(evidence_vector.proof_requirement, "finalized_inclusion");
    let evidence = EvidenceRef::new(
        hash(&evidence_vector.commitment_hex),
        ProofRequirement::FinalizedInclusion,
    );
    assert_eq!(
        evidence.to_canonical_bytes(),
        bytes(&evidence_vector.canonical_bytes_hex)
    );
    assert_eq!(evidence.digest(), hash(&evidence_vector.digest_hex));

    let output_vector = &corpus.fixture.output_use_binding;
    assert_eq!(output_vector.semantics_version, 2);
    assert_eq!(output_vector.exclusivity, "exclusive");
    let mut schema = StateUseSchema::new();
    schema
        .bind(output_vector.state_type, ExclusivityClass::Exclusive)
        .unwrap();
    let binding = schema.bind_output(output_vector.state_type).unwrap();
    assert_eq!(
        binding.to_canonical_bytes(),
        bytes(&output_vector.canonical_bytes_hex)
    );
}

#[test]
fn every_negative_vector_fails_for_its_documented_reason() {
    let corpus = corpus();
    let (root, child, segment) = fixtures(&corpus);

    for vector in &corpus.negative_vectors {
        assert!(
            !vector.mutation.is_empty(),
            "{} must document its mutation",
            vector.id
        );
        let actual = match vector.id.as_str() {
            "node-content-mutated" => {
                let mut mutated = root.clone();
                mutated.bytecode = vec![0xff, 0x20, 0x30];
                let hostile =
                    DAGSegment::new(vec![mutated, child.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(DagStructureError::NodeIdMismatch { .. }) => "NodeIdMismatch",
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "segment-root-substituted" => {
                let hostile = DAGSegment::new(segment.nodes.clone(), Hash::new([0x33; 32]));
                match hostile.validate_structure() {
                    Err(DagStructureError::RootMismatch { .. }) => "RootMismatch",
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "duplicate-node-identifier" => {
                let hostile =
                    DAGSegment::new(vec![root.clone(), root.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(DagStructureError::DuplicateNodeId { .. }) => "DuplicateNodeId",
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "consumed-ref-as-evidence" => {
                let mut encoded = bytes(&corpus.fixture.consumed_state_ref.canonical_bytes_hex);
                encoded.truncate(34);
                match EvidenceRef::from_canonical_bytes(&encoded) {
                    Err(ReferenceDecodeError::WrongDiscriminant { .. }) => "WrongDiscriminant",
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "unknown-output-exclusivity" => {
                let mut encoded = bytes(&corpus.fixture.output_use_binding.canonical_bytes_hex);
                *encoded.last_mut().unwrap() = 0xff;
                match OutputUseBinding::from_canonical_bytes(&encoded) {
                    Err(ExclusivityError::UnknownClass(_)) => "UnknownClass",
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            unknown => panic!("negative vector {unknown} has no conformance executor"),
        };
        assert_eq!(
            actual, vector.expected_reason,
            "{} reason drifted",
            vector.id
        );
    }
}

#[test]
fn the_authoritative_package_is_target_neutral_and_directly_embeddable() {
    // `include_str!` works for native and wasm targets and embeds the exact
    // language-neutral package; no filesystem API or repackaging is involved.
    assert!(CORPUS.is_ascii());
    assert!(CORPUS.contains("\"wire_version\": 2"));
}
