#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use csv_hash::Hash;
use csv_hash::dag::{DAGNode, DAGSegment, DagStructureError};
use csv_hash::seal::SealPoint;
use csv_protocol::resolution::{ParentOutput, ResolutionError, resolve_input};
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
    reason_codes: ReasonCodes,
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
struct ReasonCodes {
    registry: String,
    rule: String,
}

#[derive(Deserialize)]
struct Fixture {
    root_node: NodeVector,
    child_node: NodeVector,
    segment: SegmentVector,
    consumed_state_ref: ConsumedVector,
    evidence_ref: EvidenceVector,
    output_use_binding: OutputVector,
    parent_output: ParentOutputVector,
}

#[derive(Deserialize)]
struct ParentOutputVector {
    transition_id_hex: String,
    output_index: u32,
    state_type: u16,
    seal_id_hex: String,
    seal_nonce: u64,
    data_hex: String,
    authorized_consumers_hex: Vec<String>,
    content_commitment_hex: String,
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
    /// Stable identifier from the published reason-code registry. This is what
    /// a downstream consumer routes on; `expected_reason` names the Rust
    /// variant and exists so the executor below can be precise about which
    /// rejection path ran.
    expected_reason_code: String,
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

/// The published parent output, built through the honest constructor so its
/// recorded commitment always describes its content.
fn parent_output(vector: &ParentOutputVector, schema: &StateUseSchema) -> ParentOutput {
    ParentOutput::sealed(
        hash(&vector.transition_id_hex),
        vector.output_index,
        schema
            .bind_output(vector.state_type)
            .expect("published state type is bound"),
        SealPoint::new(bytes(&vector.seal_id_hex), Some(vector.seal_nonce), None)
            .expect("published seal point is well-formed"),
        bytes(&vector.data_hex),
        vector
            .authorized_consumers_hex
            .iter()
            .map(|value| bytes(value))
            .collect(),
    )
}

/// The schema the published parent output was created under.
fn published_schema(state_type: u16) -> StateUseSchema {
    let mut schema = StateUseSchema::new();
    schema
        .bind(state_type, ExclusivityClass::Exclusive)
        .expect("published state type binds once");
    schema
}

#[test]
fn published_positive_vectors_pin_every_v2_kernel_surface() {
    let corpus = corpus();
    assert_eq!(corpus.schema, "diewan.parwana.transition-vectors");
    assert_eq!(corpus.version, 2);
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
    let schema = published_schema(corpus.fixture.parent_output.state_type);
    let parent = parent_output(&corpus.fixture.parent_output, &schema);

    for vector in &corpus.negative_vectors {
        assert!(
            !vector.mutation.is_empty(),
            "{} must document its mutation",
            vector.id
        );
        // Every executor below returns the registry identifier the rejection
        // actually carries. Matching it against the vector's declaration is
        // what stops the published vocabulary from drifting away from the
        // code that emits it.
        let (actual, actual_code) = match vector.id.as_str() {
            "node-content-mutated" => {
                let mut mutated = root.clone();
                mutated.bytecode = vec![0xff, 0x20, 0x30];
                let hostile =
                    DAGSegment::new(vec![mutated, child.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::NodeIdMismatch { .. }) => {
                        ("NodeIdMismatch", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "segment-root-substituted" => {
                let hostile = DAGSegment::new(segment.nodes.clone(), Hash::new([0x33; 32]));
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::RootMismatch { .. }) => {
                        ("RootMismatch", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            // Distinct from `segment-root-substituted`: the declared root is
            // untouched and the node set is what changed, so the canonical root
            // no longer reproduces it. Both mutations must land on one code,
            // because a consumer cannot tell them apart and must not be told it
            // can.
            "canonical-root-recomputed" => {
                let hostile = DAGSegment::new(vec![root.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::RootMismatch { .. }) => {
                        ("RootMismatch", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "duplicate-node-identifier" => {
                let hostile =
                    DAGSegment::new(vec![root.clone(), root.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::DuplicateNodeId { .. }) => {
                        ("DuplicateNodeId", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            // A cycle among content-derived identifiers cannot arise honestly —
            // it would require a hash cycle — so it is declared, using the
            // unchecked constructor that exists for exactly this purpose.
            "graph-cycle" => {
                let cyclic_root = DAGNode::new(
                    root.node_id,
                    root.bytecode.clone(),
                    root.signatures.clone(),
                    root.witnesses.clone(),
                    vec![child.node_id],
                );
                let hostile =
                    DAGSegment::new(vec![cyclic_root, child.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::Cycle { .. }) => ("Cycle", error.registry_id()),
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "graph-self-parent" => {
                let self_parent = DAGNode::new(
                    root.node_id,
                    root.bytecode.clone(),
                    root.signatures.clone(),
                    root.witnesses.clone(),
                    vec![root.node_id],
                );
                let hostile = DAGSegment::new(vec![self_parent], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::SelfParent { .. }) => {
                        ("SelfParent", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "graph-missing-parent" => {
                let hostile = DAGSegment::new(vec![child.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::MissingParent { .. }) => {
                        ("MissingParent", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "graph-noncanonical-order" => {
                let hostile =
                    DAGSegment::new(vec![child.clone(), root.clone()], segment.root_commitment);
                match hostile.validate_structure() {
                    Err(error @ DagStructureError::NonCanonicalOrder { .. }) => {
                        ("NonCanonicalOrder", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            // A reference naming an index the transition does not have must not
            // be answered with "no such transition": the two say different
            // things about what the presenter knows.
            "parent-output-index-absent" => {
                let source = vec![parent.clone()];
                let reference = ConsumedStateRef::new(
                    parent.transition_id,
                    parent.output_index + 2,
                    parent.state_type,
                );
                match resolve_input(
                    &reference,
                    &source,
                    &schema,
                    &corpus
                        .fixture
                        .parent_output
                        .authorized_consumers_hex
                        .iter()
                        .map(|value| bytes(value))
                        .collect::<Vec<_>>(),
                ) {
                    Err(error @ ResolutionError::WrongOutputIndex { .. }) => {
                        ("WrongOutputIndex", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "parent-commitment-mutated" => {
                let mut mutated = parent.clone();
                mutated.data = vec![0x99];
                let source = vec![mutated];
                match resolve_input(
                    &parent.reference(),
                    &source,
                    &schema,
                    &corpus
                        .fixture
                        .parent_output
                        .authorized_consumers_hex
                        .iter()
                        .map(|value| bytes(value))
                        .collect::<Vec<_>>(),
                ) {
                    Err(error @ ResolutionError::CommitmentMismatch { .. }) => {
                        ("CommitmentMismatch", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "consumed-ref-as-evidence" => {
                let mut encoded = bytes(&corpus.fixture.consumed_state_ref.canonical_bytes_hex);
                encoded.truncate(34);
                match EvidenceRef::from_canonical_bytes(&encoded) {
                    Err(error @ ReferenceDecodeError::WrongDiscriminant { .. }) => {
                        ("WrongDiscriminant", error.registry_id())
                    }
                    other => panic!("{} failed incidentally: {other:?}", vector.id),
                }
            }
            "unknown-output-exclusivity" => {
                let mut encoded = bytes(&corpus.fixture.output_use_binding.canonical_bytes_hex);
                *encoded.last_mut().unwrap() = 0xff;
                match OutputUseBinding::from_canonical_bytes(&encoded) {
                    Err(error @ ExclusivityError::UnknownClass(_)) => {
                        ("UnknownClass", error.registry_id())
                    }
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
        assert_eq!(
            actual_code, vector.expected_reason_code,
            "{} publishes a reason code its rejection path does not emit",
            vector.id
        );
    }
}

/// The published parent output must be the one the fixture pins, so a consumer
/// reproducing the resolution vectors starts from the same bytes.
#[test]
fn the_published_parent_output_pins_its_content_commitment() {
    let corpus = corpus();
    let schema = published_schema(corpus.fixture.parent_output.state_type);
    let parent = parent_output(&corpus.fixture.parent_output, &schema);
    assert_eq!(
        parent.recorded_commitment,
        parent.content_commitment(),
        "the honest constructor must record what the content produces"
    );
    assert_eq!(
        hex::encode(parent.content_commitment().as_bytes()),
        corpus.fixture.parent_output.content_commitment_hex
    );
}

/// The vector package names the registry it draws from and states the rule the
/// portable conformance package's gate enforces.
#[test]
fn the_package_names_the_registry_its_codes_come_from() {
    let corpus = corpus();
    assert_eq!(
        corpus.reason_codes.registry,
        "conformance/v2-reason-code-registry.toml"
    );
    assert!(!corpus.reason_codes.rule.is_empty());
    let published = include_str!("../../conformance/v2-reason-code-registry.toml");
    for vector in &corpus.negative_vectors {
        assert!(
            published.contains(&format!("\"{}\"", vector.expected_reason_code)),
            "{} declares {}, which the published registry does not contain",
            vector.id,
            vector.expected_reason_code
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
