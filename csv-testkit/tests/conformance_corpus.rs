//! Release-corpus checks.
//!
//! Semantic behavior is exercised by the source tests each case names; these
//! checks establish that the package is honest about itself — that every named
//! source exists, and that no case ships material it does not declare.

use csv_accountability::{EvidenceSourceClass, github_deployment_descriptor};
use serde_json::Value;

#[test]
fn v1_manifest_covers_required_security_cases() {
    let manifest = include_str!("../corpus/v1/manifest.toml");
    for required in [
        "canonical_cbor",
        "typed_hash_replay",
        "proof_bundle_negative",
        "authorization_negative",
        "replay_negative",
        "finality_negative",
        "crash_resume",
    ] {
        assert!(
            manifest.contains(required),
            "missing corpus case: {required}"
        );
    }
    assert!(manifest.contains("corpus_version = 1"));
}

#[test]
fn portable_v2_manifest_covers_every_hostile_campaign() {
    let manifest: Value = serde_json::from_str(include_str!("../corpus/v2/manifest.json")).unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    let required = [
        "graph-cycle",
        "graph-duplicate-node",
        "graph-self-parent",
        "graph-missing-parent",
        "graph-root-substitution",
        "graph-noncanonical-order",
        "state-content-mutation",
        "state-output-index-mutation",
        "transition-commitment-mutation",
        "canonical-root-mutation",
        "consumed-evidence-substitution",
        "proof-nonempty-garbage",
        "proof-wrong-header",
        "proof-wrong-merkle-path",
        "proof-wrong-outpoint",
        "proof-wrong-transition-commitment",
        "checkpoint-insufficient-finality",
        "checkpoint-stale",
        "checkpoint-wrong-network",
        "checkpoint-orphaned",
        "losing-conflict",
        "reorganization",
        "crash-recovery",
    ];
    for id in required {
        let case = cases
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("missing portable conformance case {id}"));
        assert_eq!(case["wire_version"], 2);
        assert_eq!(case["contract_version"], "0.1.10");
        assert!(
            case["expected_reason_code"]
                .as_str()
                .is_some_and(|code| !code.is_empty())
        );
        assert!(
            case["expected_dimensions"]
                .as_object()
                .is_some_and(|map| !map.is_empty())
        );
    }
}

/// Every `source` pointer must name a test that exists in this tree.
///
/// The package's remaining claim to substance is that a reader can audit each
/// case at the named Parwana test. In `stage4-v1` four of eight pointers named
/// functions that did not exist, so the claim was unauditable.
#[test]
fn every_source_pointer_names_a_test_that_exists() {
    let manifest: Value = serde_json::from_str(include_str!("../corpus/v2/manifest.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    for case in manifest["cases"].as_array().unwrap() {
        let pointer = case["source"].as_str().expect("every case names a source");
        let (path, function) = pointer
            .split_once("::")
            .unwrap_or_else(|| panic!("{pointer} is not a file::function pointer"));
        let file = root.join(path);
        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{pointer} names a missing file: {error}"));
        assert!(
            contents.contains(&format!("fn {function}(")),
            "{pointer} names a function that does not exist"
        );
    }
}

/// A case may only carry bytes under a declared, executable material kind.
#[test]
fn no_case_ships_material_it_does_not_declare() {
    let manifest: Value = serde_json::from_str(include_str!("../corpus/v2/manifest.json")).unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let material = &case["material"];
        let kind = material["kind"].as_str().expect("material declares a kind");
        match kind {
            "consignment-v2" => {
                assert!(!material["bytes_hex"].as_str().unwrap().is_empty());
                assert!(!material["sha256"].as_str().unwrap().is_empty());
            }
            "transition-vector-ref" => {
                assert!(
                    material["bytes_hex"].is_null(),
                    "{id} duplicates vector bytes"
                );
                assert!(!material["vector_id"].as_str().unwrap().is_empty());
            }
            "none" => {
                assert!(
                    material["bytes_hex"].is_null(),
                    "{id} ships undeclared bytes"
                );
                assert!(
                    !material["not_distributed_because"]
                        .as_str()
                        .unwrap()
                        .is_empty(),
                    "{id} must say why it distributes nothing"
                );
            }
            other => panic!("{id} declares an unknown material kind {other}"),
        }
    }
}

#[test]
fn hostile_vectors_do_not_encode_success_for_failed_proof_material() {
    let manifest: Value = serde_json::from_str(include_str!("../corpus/v2/manifest.json")).unwrap();
    for case in manifest["cases"].as_array().unwrap() {
        if case["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("proof-"))
        {
            assert_ne!(case["expected_dimensions"]["proof"], "satisfied");
            assert_ne!(case["expected_dimensions"]["closure"], "satisfied");
            assert_eq!(case["expected_dimensions"]["aggregate"], "rejected");
        }
    }
}

#[test]
fn published_github_profile_descriptor_matches_code() {
    let published = include_str!("../corpus/v1/profiles/github-deployment.intent.v1.toml");
    let descriptor = github_deployment_descriptor();
    assert!(published.contains(descriptor.profile_id.as_str()));
    assert!(published.contains(&descriptor.action_type));
    assert!(published.contains(&descriptor.parameters_media_type));
    // Every declared evidence source, with a matching class, must be published.
    for source in &descriptor.evidence_sources {
        assert!(
            published.contains(source.id.as_str()),
            "published descriptor missing evidence source {}",
            source.id.as_str()
        );
        let class = match source.class {
            EvidenceSourceClass::Executor => "executor",
            EvidenceSourceClass::ProviderCorroborating => "provider_corroborating",
            EvidenceSourceClass::ExternalAnchor => "external_anchor",
        };
        assert!(
            published.contains(class),
            "published descriptor missing class {class}"
        );
    }
}

/// ANCHOR-01: the published on-chain commitment-anchor contract must match the
/// `csv_accountability::anchor::ChainCommitmentAnchorEvidence` code — the same golden bytes decode,
/// re-encode, and hash to the published digest, and the string constants agree.
#[test]
fn published_chain_anchor_contract_matches_code() {
    use csv_accountability::{
        CHAIN_ANCHOR_DOMAIN_TAG, CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE, ChainCommitmentAnchorEvidence,
        EVIDENCE_CHAIN_COMMITMENT_ANCHOR,
    };

    let published = include_str!("../corpus/v1/anchors/chain-commitment-anchor.v1.toml");

    // String constants are owned by code; the published projection must match.
    assert!(published.contains(EVIDENCE_CHAIN_COMMITMENT_ANCHOR));
    assert!(published.contains(CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE));
    assert!(published.contains(core::str::from_utf8(CHAIN_ANCHOR_DOMAIN_TAG).unwrap()));

    // Extract a quoted value for a key from the simple TOML.
    let value = |key: &str| -> String {
        let line = published
            .lines()
            .find(|line| line.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("missing key {key}"));
        let start = line.find('"').expect("open quote") + 1;
        let end = line.rfind('"').expect("close quote");
        line[start..end].to_string()
    };

    let canonical = hex::decode(value("canonical_bytes_hex")).expect("hex bytes");
    let published_digest = value("digest_hex");

    // The published golden bytes decode to valid chain-anchor evidence, re-encode
    // byte-for-byte, and hash to the published digest under the domain tag.
    let anchor =
        ChainCommitmentAnchorEvidence::from_canonical_bytes(&canonical).expect("golden decodes");
    assert_eq!(anchor.canonical_bytes().unwrap(), canonical, "round-trips");
    assert_eq!(
        hex::encode(anchor.digest().unwrap()),
        published_digest,
        "digest"
    );
    assert!(anchor.finality.is_final());
    assert_eq!(anchor.chain_id, "ethereum-sepolia");
}

/// PROFILE-02: the published database-migration descriptor must match
/// `csv_accountability::db_migration_descriptor()` — same profile id, action
/// type, media type, and complete evidence-source inventory with classes.
#[test]
fn published_db_migration_profile_descriptor_matches_code() {
    use csv_accountability::{EvidenceSourceClass, db_migration_descriptor};

    let published = include_str!("../corpus/v1/profiles/db-migration.intent.v1.toml");
    let descriptor = db_migration_descriptor();
    // The descriptor itself must be well-formed (executor + corroborating source).
    descriptor.validate().expect("descriptor is well-formed");

    assert!(published.contains(descriptor.profile_id.as_str()));
    assert!(published.contains(&descriptor.action_type));
    assert!(published.contains(&descriptor.parameters_media_type));

    for source in &descriptor.evidence_sources {
        assert!(
            published.contains(source.id.as_str()),
            "published descriptor missing evidence source {}",
            source.id.as_str()
        );
        let class = match source.class {
            EvidenceSourceClass::Executor => "executor",
            EvidenceSourceClass::ProviderCorroborating => "provider_corroborating",
            EvidenceSourceClass::ExternalAnchor => "external_anchor",
        };
        assert!(
            published.contains(class),
            "published descriptor missing class {class}"
        );
    }
}
