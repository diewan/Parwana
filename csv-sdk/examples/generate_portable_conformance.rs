// A build-time generator over fixed constants. A malformed constant is a bug
// in this file, and panicking loudly is the correct response: the alternative
// is writing a package whose material silently does not match its declaration.
#![allow(clippy::expect_used)]

//! Generate the portable V2 hostile-conformance package.
//!
//! This is the one designated command that writes
//! `csv-testkit/corpus/v2/manifest.json`. The file is never hand-edited.
//!
//! The generator deliberately imports **only** `csv_sdk`. Every byte it
//! distributes is therefore reachable by any downstream consumer holding the
//! published SDK, which is the property the package exists to guarantee. A
//! case whose material cannot be produced that way declares that plainly
//! instead of shipping filler.
//!
//! ```text
//! cargo run -p csv-sdk --example generate_portable_conformance
//! cargo run -p csv-sdk --example generate_portable_conformance -- --check
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use csv_sdk::protocol::exclusivity::{ConsumptionMode, ExclusivityClass};
use csv_sdk::protocol::state::StateAssignment;
use csv_sdk::v2::{
    ClosureProof, ClosureProofKind, ConsignmentAuthorization, ConsignmentProofRequirements,
    ConsignmentV2, ConsignmentV2Payload, ConsumedStateRef, FinalityPolicy, FinalizedCheckpoint,
    Invoice, ParentOutput, ResolvedInput, ResolvedTransition, SealDefinition, SignatureScheme,
    StateUseSchema,
};
use csv_sdk::{Hash, SealPoint};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Contract version every case in this package pins.
const CONTRACT_VERSION: &str = "0.1.10";

/// Package version. Bumped whenever distributed material or the consumer
/// contract changes, never for an editorial change.
const PACKAGE_VERSION: &str = "stage5-v1";

/// Proof material the runtime's positive path treats as a satisfied closure.
const VALID_PROOF_BYTE: u8 = 0x77;

/// Proof material that is well-formed in length but is not a real inclusion
/// proof, used by the forged-proof case.
const GARBAGE_PROOF_BYTE: u8 = 0xFA;

/// Build one canonical, signed V2 consignment through the public facade.
///
/// The inputs are fixed constants, so the bytes are byte-identical on every
/// run and every platform. This mirrors the runtime fixture that establishes
/// the positive acceptance path.
fn consignment(output_byte: u8, proof_byte: u8) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let invoice = Invoice::new(
        SealDefinition::sui(vec![0xCD; 32], 7).expect("seal definition is well-formed"),
        vec![1; 32],
        9,
    )
    .expect("invoice is well-formed");
    let destination = invoice
        .bound_seal_point()
        .expect("invoice binds a seal point");
    let source = ConsumedStateRef::new(Hash::new([0x11; 32]), 0, 7);

    let mut schema = StateUseSchema::new();
    schema
        .bind(7, ExclusivityClass::Exclusive)
        .expect("state type 7 binds once");
    let parent = ParentOutput::sealed(
        source.transition_id,
        source.output_index,
        schema.bind_output(7).expect("bound output"),
        SealPoint::new(vec![0x22; 36], None, None).expect("seal point is well-formed"),
        vec![0x33],
        vec![signing_key.verifying_key().to_bytes().to_vec()],
    );
    let successor = ResolvedTransition {
        transition_id: 9,
        inputs: vec![ResolvedInput {
            reference: source,
            parent,
            mode: ConsumptionMode::Exclusive,
        }],
        outputs: vec![StateAssignment::new(7, destination, vec![output_byte])],
        validation_script: vec![0x66],
    };
    let payload = ConsignmentV2Payload::new(
        source,
        successor.clone(),
        ClosureProof {
            consumed_state: source,
            successor_commitment: successor.commitment(),
            proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
            proof_material: vec![proof_byte; 64],
        },
        invoice,
        ConsignmentProofRequirements {
            checkpoint: FinalizedCheckpoint {
                chain_id: "bitcoin".into(),
                network_id: "signet".into(),
                block_height: 100,
                block_id: vec![0x88; 32],
                finality_policy: FinalityPolicy::Confirmations(6),
            },
            trust_mode: csv_sdk::v2::ClosureTrustMode::LightClient,
            proof_provider_id: "bitcoin-spv-v1".into(),
            verification_context: Hash::new([0x99; 32]),
            maximum_checkpoint_age: 12,
        },
    );
    let unsigned = ConsignmentV2::new(payload).expect("payload is internally consistent");
    let commitment = unsigned.commitment;
    let signature = signing_key.sign(commitment.as_bytes());
    unsigned
        .with_authorizations(vec![ConsignmentAuthorization {
            scheme: SignatureScheme::Ed25519,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
            signed_commitment: commitment,
        }])
        .expect("authorization binds the commitment")
        .canonical_cbor()
        .expect("a valid consignment encodes canonically")
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_of(&Sha256::digest(bytes))
}

/// Distributed material for one case.
enum Material {
    /// Canonical V2 consignment bytes any consumer can decode with
    /// `csv_sdk::v2::inspect`.
    ConsignmentV2(Vec<u8>),
    /// The case's executable material lives in the separately versioned
    /// transition-vector package, under the named vector identifier.
    TransitionVector(&'static str),
    /// No material is distributed. The reason is recorded verbatim.
    None(&'static str),
}

impl Material {
    fn to_json(&self) -> Value {
        match self {
            Material::ConsignmentV2(bytes) => json!({
                "kind": "consignment-v2",
                "bytes_hex": hex_of(bytes),
                "sha256": sha256_hex(bytes),
                "entry_point": "csv_sdk::v2::inspect",
            }),
            Material::TransitionVector(id) => json!({
                "kind": "transition-vector-ref",
                "package": "v2-transition-vectors",
                "vector_id": id,
                "entry_point": "csv_protocol negative-vector executor (Parwana-internal)",
            }),
            Material::None(reason) => json!({
                "kind": "none",
                "not_distributed_because": reason,
            }),
        }
    }

    fn structure_reproducible(&self) -> &'static str {
        match self {
            Material::ConsignmentV2(_) => "yes",
            Material::TransitionVector(_) => "only-with-the-transition-vector-package",
            Material::None(_) => "no",
        }
    }
}

struct Case {
    id: &'static str,
    category: &'static str,
    reason: &'static str,
    dimensions: Value,
    source: &'static str,
    material: Material,
}

impl Case {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "category": self.category,
            "wire_version": 2,
            "contract_version": CONTRACT_VERSION,
            "material": self.material.to_json(),
            "reproducible_by_sdk_consumer": {
                "canonical_structure": self.material.structure_reproducible(),
                "aggregate": "no",
                "aggregate_requires": [
                    "a closure proof provider for the declared proof kind",
                    "a finalized checkpoint and finality policy",
                    "recipient-owned verification context and authorized signers",
                ],
            },
            "expected_dimensions": self.dimensions,
            "expected_reason_code": self.reason,
            "source": self.source,
        })
    }
}

fn failed_proof() -> Value {
    json!({
        "proof": "failed",
        "inclusion": "failed",
        "finality": "indeterminate",
        "freshness": "indeterminate",
        "closure": "failed",
        "aggregate": "rejected",
    })
}

fn failed_proof_with(overrides: &[(&str, &str)]) -> Value {
    let mut value = failed_proof();
    let map = value.as_object_mut().expect("object");
    for (key, status) in overrides {
        map.insert((*key).to_string(), json!(status));
    }
    value
}

const GRAPH_SOURCE: &str = "csv-protocol/tests/v2_transition_vectors.rs::every_negative_vector_fails_for_its_documented_reason";
const DIMENSION_SOURCE: &str =
    "csv-runtime/src/recipient_acceptance.rs::every_native_dimension_has_a_distinct_stable_failure";

/// A malicious-graph case whose behaviour no published vector exercises.
const NO_VECTOR: &str = "No vector in the published transition-vector package exercises this mutation. The case records \
     an expected reason code that Parwana's kernel enforces; it is not executable by a consumer.";

/// A closure case distinguished by recipient-owned inputs rather than bytes.
const CONTEXT_VARIED: &str = "This case varies recipient-owned acceptance context (checkpoint, finality policy, network, or \
     freshness bound), not distributed consignment bytes. A consumer reproduces it by supplying \
     that context to its own proof provider.";

/// A closure case that needs a real proof encoding this package does not ship.
const NEEDS_REAL_PROOF: &str = "Distinguishing this failure from other closure failures requires a real bitcoin-spv-v1 proof \
     encoding. Parwana's own test exercises it through a proof provider; the package distributes no \
     encoded SPV proof, and shipping opaque bytes labelled as one would misrepresent it.";

fn cases() -> Vec<Case> {
    let mut cases = vec![
        Case {
            id: "valid-v2",
            category: "positive",
            reason: "ACCEPT.V2.ACCEPTED",
            dimensions: json!({
                "proof": "satisfied", "inclusion": "satisfied", "finality": "satisfied",
                "freshness": "satisfied", "closure": "satisfied", "aggregate": "accepted",
            }),
            source: "csv-runtime/src/recipient_acceptance.rs::success_returns_full_typed_report_and_is_idempotent",
            material: Material::ConsignmentV2(consignment(0x55, VALID_PROOF_BYTE)),
        },
        Case {
            id: "legacy-v1",
            category: "legacy",
            reason: "WIRE.V1.PORTABLE_NON_EQUIVOCATION_UNAVAILABLE",
            dimensions: json!({
                "proof": "indeterminate", "inclusion": "indeterminate", "finality": "indeterminate",
                "freshness": "indeterminate", "closure": "indeterminate", "aggregate": "unsupported",
            }),
            source: "csv-wire/src/consignment.rs::v1_inspection_reports_unavailable_v2_integrity",
            material: Material::None(
                "A V1 artifact carries no portable-closure evidence. The package distributes no V1 \
                 bytes because a V1 envelope must never be presented beside V2 material as though \
                 the two were interchangeable.",
            ),
        },
    ];

    let graph: [(&str, &str, Material); 11] = [
        (
            "graph-cycle",
            "PROTOCOL.DAG.CYCLE",
            Material::None(NO_VECTOR),
        ),
        (
            "graph-duplicate-node",
            "PROTOCOL.DAG.DUPLICATE_NODE",
            Material::TransitionVector("duplicate-node-identifier"),
        ),
        (
            "graph-self-parent",
            "PROTOCOL.DAG.SELF_PARENT",
            Material::None(NO_VECTOR),
        ),
        (
            "graph-missing-parent",
            "PROTOCOL.DAG.MISSING_PARENT",
            Material::None(NO_VECTOR),
        ),
        (
            "graph-root-substitution",
            "PROTOCOL.DAG.ROOT_MISMATCH",
            Material::TransitionVector("segment-root-substituted"),
        ),
        (
            "graph-noncanonical-order",
            "PROTOCOL.DAG.NON_CANONICAL_ORDER",
            Material::None(NO_VECTOR),
        ),
        (
            "state-content-mutation",
            "PROTOCOL.STATE.COMMITMENT_MISMATCH",
            Material::TransitionVector("node-content-mutated"),
        ),
        (
            "state-output-index-mutation",
            "PROTOCOL.STATE.OUTPUT_NOT_FOUND",
            Material::None(NO_VECTOR),
        ),
        (
            "transition-commitment-mutation",
            "PROTOCOL.TRANSITION.COMMITMENT_MISMATCH",
            Material::None(NO_VECTOR),
        ),
        (
            "canonical-root-mutation",
            "PROTOCOL.DAG.ROOT_MISMATCH",
            Material::None(NO_VECTOR),
        ),
        (
            "consumed-evidence-substitution",
            "PROTOCOL.REFERENCE.WRONG_DISCRIMINANT",
            Material::TransitionVector("consumed-ref-as-evidence"),
        ),
    ];
    for (id, reason, material) in graph {
        let source = if id == "consumed-evidence-substitution" {
            "csv-protocol/src/reference.rs::consumption_bytes_do_not_decode_as_evidence"
        } else {
            GRAPH_SOURCE
        };
        cases.push(Case {
            id,
            category: "malicious-graph",
            reason,
            dimensions: json!({"structure": "failed", "aggregate": "rejected"}),
            source,
            material,
        });
    }

    let closure: [(&str, &str, Value, Material); 9] = [
        (
            "proof-nonempty-garbage",
            "ACCEPT.V2.SOURCE_CLOSURE",
            failed_proof(),
            Material::ConsignmentV2(consignment(0x55, GARBAGE_PROOF_BYTE)),
        ),
        (
            "proof-wrong-header",
            "ACCEPT.V2.INCLUSION",
            failed_proof(),
            Material::None(NEEDS_REAL_PROOF),
        ),
        (
            "proof-wrong-merkle-path",
            "ACCEPT.V2.INCLUSION",
            failed_proof(),
            Material::None(NEEDS_REAL_PROOF),
        ),
        (
            "proof-wrong-outpoint",
            "ACCEPT.V2.SOURCE_CLOSURE",
            failed_proof(),
            Material::None(NEEDS_REAL_PROOF),
        ),
        (
            "proof-wrong-transition-commitment",
            "ACCEPT.V2.SOURCE_CLOSURE",
            failed_proof(),
            Material::None(NEEDS_REAL_PROOF),
        ),
        (
            "checkpoint-insufficient-finality",
            "ACCEPT.V2.FINALITY",
            failed_proof_with(&[
                ("proof", "satisfied"),
                ("inclusion", "satisfied"),
                ("finality", "failed"),
            ]),
            Material::None(CONTEXT_VARIED),
        ),
        (
            "checkpoint-stale",
            "ACCEPT.V2.FRESHNESS",
            failed_proof_with(&[
                ("proof", "satisfied"),
                ("inclusion", "satisfied"),
                ("finality", "satisfied"),
                ("freshness", "failed"),
            ]),
            Material::None(CONTEXT_VARIED),
        ),
        (
            "checkpoint-wrong-network",
            "ACCEPT.V2.VERIFICATION_CONTEXT",
            failed_proof(),
            Material::None(CONTEXT_VARIED),
        ),
        (
            "checkpoint-orphaned",
            "ACCEPT.V2.SOURCE_CLOSURE",
            failed_proof_with(&[
                ("proof", "satisfied"),
                ("inclusion", "failed"),
                ("finality", "failed"),
            ]),
            Material::None(CONTEXT_VARIED),
        ),
    ];
    for (id, reason, dimensions, material) in closure {
        let source = if id == "proof-nonempty-garbage" {
            "csv-runtime/src/recipient_acceptance.rs::forged_nonempty_proof_cannot_upgrade_assurance"
        } else {
            DIMENSION_SOURCE
        };
        cases.push(Case {
            id,
            category: "bitcoin-closure",
            reason,
            dimensions,
            source,
            material,
        });
    }

    cases.push(Case {
        id: "losing-conflict",
        category: "conflict",
        reason: "ACCEPT.V2.CONFLICT",
        dimensions: json!({"closure": "failed", "aggregate": "rejected"}),
        source: "csv-runtime/src/recipient_acceptance.rs::isolated_recipients_cannot_both_accept_one_source",
        material: Material::None(
            "A conflict is a property of two successors racing for one source against a shared \
             accepted-state store, not of any single distributed artifact.",
        ),
    });
    cases.push(Case {
        id: "reorganization",
        category: "reorganization",
        reason: "STORAGE.CHECKPOINT.ORPHANED",
        dimensions: json!({"closure": "failed", "aggregate": "revoked"}),
        source: "csv-storage/src/accepted_state.rs::orphaning_checkpoint_revokes_root_and_downgrades_descendants_idempotently",
        material: Material::None(
            "A reorganization is a checkpoint transition applied to already-accepted state, not a \
             distributable artifact.",
        ),
    });
    cases.push(Case {
        id: "crash-recovery",
        category: "crash",
        reason: "RUNTIME.SEND.RECOVERED",
        dimensions: json!({"aggregate": "accepted"}),
        source: "csv-runtime/src/transfer_coordinator.rs::send_resume_after_emit_interrupt_never_recloses_source_seal",
        material: Material::None(
            "Crash recovery is a sequence of interrupted runtime phases, not a distributable \
             artifact.",
        ),
    });
    cases
}

fn render() -> Vec<u8> {
    let cases = cases();
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for case in &cases {
        let kind = match case.material {
            Material::ConsignmentV2(_) => "consignment-v2",
            Material::TransitionVector(_) => "transition-vector-ref",
            Material::None(_) => "none",
        };
        *by_kind.entry(kind).or_default() += 1;
    }
    let mut census = Map::new();
    for (kind, count) in &by_kind {
        census.insert((*kind).to_string(), json!(count));
    }

    let payload = json!({
        "schema_version": 2,
        "package": "parwana-portable-conformance",
        "version": PACKAGE_VERSION,
        "platforms": {
            "native": {"verification": "supported", "persistent_store": "supported"},
            "wasm32": {"verification": "supported", "persistent_store": "unsupported"},
        },
        "consumer_contract": {
            "generated_by": "cargo run -p csv-sdk --example generate_portable_conformance",
            "generator_imports": "csv_sdk only",
            "material_census": census,
            "executable_by_an_sdk_only_consumer":
                by_kind.get("consignment-v2").copied().unwrap_or_default(),
            "what_a_consumer_can_reproduce":
                "The canonical-structure dimension of every case that distributes consignment-v2 \
                 material, by decoding it with csv_sdk::v2::inspect.",
            "what_a_consumer_cannot_reproduce":
                "Any aggregate outcome. Every aggregate in this package depends on a closure proof \
                 provider, a finalized checkpoint, and recipient-owned verification context that \
                 this package does not and cannot supply. Structural decoding is never \
                 cryptographic verification.",
            "expected_dimensions_are":
                "The outcome Parwana's named source test observes under its own inputs — a \
                 declared expectation, not an outcome this package produces on its own.",
            "source_pointers_are":
                "Parwana-internal test locations, provided so a reader can audit the claim in the \
                 Parwana tree. They are not runnable by a downstream consumer.",
            "do_not_manufacture_fixtures":
                "A consumer that needs material this package does not distribute must request it \
                 through a Parwana ticket rather than constructing its own 'valid' artifact.",
        },
        "cases": cases.iter().map(Case::to_json).collect::<Vec<_>>(),
    });
    let mut rendered = serde_json::to_string_pretty(&payload).expect("manifest serializes");
    rendered.push('\n');
    rendered.into_bytes()
}

fn output_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../csv-testkit/corpus/v2/manifest.json")
        .canonicalize()
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../csv-testkit/corpus/v2/manifest.json")
        })
}

fn main() -> std::process::ExitCode {
    let check = std::env::args().any(|argument| argument == "--check");
    let expected = render();
    let path = output_path();
    if check {
        let current = std::fs::read(&path).unwrap_or_default();
        if current != expected {
            eprintln!("csv-testkit/corpus/v2/manifest.json is stale");
            return std::process::ExitCode::FAILURE;
        }
        println!("portable conformance package is current ({PACKAGE_VERSION})");
    } else {
        std::fs::write(&path, &expected).expect("manifest is writable");
        println!(
            "wrote {} ({PACKAGE_VERSION}, sha256 {})",
            path.display(),
            sha256_hex(&expected)
        );
    }
    std::process::ExitCode::SUCCESS
}
