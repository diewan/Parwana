#![cfg(feature = "client")]

use csv_sdk::v2::{
    self, Capability, ClosureProof, ClosureVerificationProvider, ClosureVerificationProviderError,
    ClosureVerificationResult, FinalizedCheckpoint,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[test]
fn malformed_v2_error_crosses_the_sdk_boundary_unchanged() {
    let error = v2::inspect(b"not canonical cbor").unwrap_err();
    assert_eq!(error.code, v2::ConsignmentV2ErrorCode::MalformedEncoding);
}

#[test]
fn native_capabilities_are_explicit() {
    let result = v2::require_capability(Capability::NativePersistence);
    if cfg!(target_arch = "wasm32") {
        assert!(result.is_err());
    } else {
        assert!(result.is_ok());
    }
}

#[test]
fn supported_example_imports_only_csv_sdk() {
    let readme = include_str!("../README.md");
    assert!(readme.contains("use csv_sdk::v2;"));
    for internal in [
        "use csv_wire",
        "use csv_runtime",
        "use csv_verifier",
        "use csv_protocol",
    ] {
        assert!(
            !readme.contains(internal),
            "consumer documentation imported internal crate: {internal}"
        );
    }
}

#[test]
fn facade_has_no_authoritative_validation_boolean() {
    let facade = include_str!("../src/v2.rs");
    assert!(!facade.contains("proof_valid: bool"));
    assert!(!facade.contains("proof_is_valid: bool"));
}

#[test]
fn embedded_conformance_package_is_content_addressed_and_complete() {
    let bytes = v2::conformance_manifest();
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        v2::CONFORMANCE_MANIFEST_SHA256
    );
    let manifest: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(manifest["version"], v2::CONFORMANCE_PACKAGE_VERSION);
    assert_eq!(
        manifest["platforms"]["wasm32"]["persistent_store"],
        "unsupported"
    );
    let cases = manifest["cases"].as_array().unwrap();
    for category in [
        "positive",
        "legacy",
        "malicious-graph",
        "bitcoin-closure",
        "conflict",
        "reorganization",
        "crash",
    ] {
        assert!(cases.iter().any(|case| case["category"] == category));
    }
    assert!(cases.iter().all(|case| {
        case["wire_version"] == 2
            && case["contract_version"] == "0.1.10"
            && case["expected_reason_code"]
                .as_str()
                .is_some_and(|code| !code.is_empty())
    }));
}

/// Every byte the package distributes as a consignment must actually be one.
///
/// This is the gate that the `stage4-v1` package failed: it carried patterned
/// filler in a field named `bytes_hex`, so a consumer that fed the material to
/// the facade was rejected for a reason that had nothing to do with the case.
#[test]
fn distributed_consignment_material_decodes_through_the_facade() {
    let manifest: serde_json::Value = serde_json::from_slice(v2::conformance_manifest()).unwrap();
    let mut decoded = 0;
    for case in manifest["cases"].as_array().unwrap() {
        let material = &case["material"];
        let id = case["id"].as_str().unwrap();
        if material["kind"] != "consignment-v2" {
            assert!(
                material["bytes_hex"].is_null(),
                "{id} distributes bytes without declaring consignment material"
            );
            continue;
        }
        let bytes = hex::decode(material["bytes_hex"].as_str().unwrap())
            .unwrap_or_else(|error| panic!("{id} material must be hex: {error}"));
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            material["sha256"].as_str().unwrap(),
            "{id} material digest disagrees with its bytes"
        );
        v2::inspect(&bytes).unwrap_or_else(|error| {
            panic!(
                "{id} declares consignment material that the facade \
                 rejects: {error:?}"
            )
        });
        assert_eq!(material["entry_point"], "csv_sdk::v2::inspect");
        decoded += 1;
    }
    assert_eq!(
        decoded,
        manifest["consumer_contract"]["executable_by_an_sdk_only_consumer"]
            .as_u64()
            .unwrap(),
        "the declared executable-case count must equal the cases that actually decode"
    );
    assert!(
        decoded > 0,
        "the package must distribute executable material"
    );
}

/// The package must never imply that a consumer can reach an aggregate verdict.
///
/// Every aggregate depends on a closure proof provider and recipient-owned
/// context the package cannot supply; saying so is part of the contract.
#[test]
fn the_package_never_claims_a_consumer_can_reach_an_aggregate_verdict() {
    let manifest: serde_json::Value = serde_json::from_slice(v2::conformance_manifest()).unwrap();
    let contract = &manifest["consumer_contract"];
    for field in [
        "what_a_consumer_can_reproduce",
        "what_a_consumer_cannot_reproduce",
        "expected_dimensions_are",
        "do_not_manufacture_fixtures",
    ] {
        assert!(
            contract[field]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "consumer contract is missing {field}"
        );
    }
    for case in manifest["cases"].as_array().unwrap() {
        assert_eq!(
            case["reproducible_by_sdk_consumer"]["aggregate"],
            "no",
            "{} claims a consumer can reproduce an aggregate outcome",
            case["id"].as_str().unwrap()
        );
    }
}

#[test]
fn verification_report_decodes_to_an_immutable_typed_view() {
    #[derive(Serialize)]
    struct Reading<'a> {
        dimension: &'a str,
        status: &'a str,
        reason_codes: [&'a str; 1],
        provider: &'a str,
        trust_mode: &'a str,
        limitations: [&'a str; 0],
    }
    #[derive(Serialize)]
    struct Report<'a> {
        verification_context_digest: &'a str,
        assurance_report_digest: &'a str,
        dimensions: [Reading<'a>; 1],
        errors: [serde_json::Value; 0],
        foundational_shortfalls: [&'a str; 0],
    }

    let bytes = csv_sdk::canonical::to_canonical_cbor(&Report {
        verification_context_digest: "context",
        assurance_report_digest: "report",
        dimensions: [Reading {
            dimension: "PROTOCOL.DIMENSION.CANONICAL_STRUCTURE",
            status: "satisfied",
            reason_codes: ["PROTOCOL.STRUCTURE.VALIDATED"],
            provider: "local",
            trust_mode: "local",
            limitations: [],
        }],
        errors: [],
        foundational_shortfalls: [],
    })
    .unwrap();

    let decoded = v2::decode_verification_report(&bytes).unwrap();
    assert_eq!(decoded.verification_context_digest(), "context");
    assert_eq!(decoded.dimensions()[0].status, "satisfied");
}

// This signature is the regression: an external consumer can name the complete
// provider boundary without importing csv-chain-ports or another Parwana crate.
fn consumer_provider_boundary(
    provider: &dyn ClosureVerificationProvider,
    proof: &ClosureProof,
    checkpoint: &FinalizedCheckpoint,
) {
    let future: std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<ClosureVerificationResult, ClosureVerificationProviderError>,
                > + Send
                + '_,
        >,
    > = provider.verify_closure(proof, checkpoint);
    drop(future);
}

#[test]
fn v2_provider_boundary_is_reachable_through_csv_sdk_alone() {
    let boundary = consumer_provider_boundary;
    let _ = boundary;
}
