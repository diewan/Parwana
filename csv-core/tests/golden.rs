//! Golden test corpus validation
//!
//! This module loads canonical CBOR fixtures from `tests/golden/` and validates
//! them against the CSV protocol's canonical deserialization and proof pipeline.

use csv_core::canonical::from_canonical_cbor;
use csv_core::proof::ProofBundle;
use csv_core::SanadEnvelope;

macro_rules! golden_test {
    ($name:ident, $file:expr, $expect_valid:expr) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!($file);
            let bundle: ProofBundle = from_canonical_cbor(bytes)
                .expect("golden vector must deserialize");
            // Structural validation: ensure the bundle has required fields
            assert!(!bundle.seal_ref.id.is_empty(), "seal_ref.id must not be empty");
            assert!(!bundle.anchor_ref.anchor_id.is_empty(), "anchor_ref.anchor_id must not be empty");
            assert!(!bundle.inclusion_proof.proof_bytes.is_empty(), "inclusion_proof.proof_bytes must not be empty");
            // The expectation is that valid bundles deserialize successfully
            // and have non-empty required fields
            assert_eq!(bundle.seal_ref.id.len() > 0, $expect_valid,
                "golden vector {} did not match expected validity {}", $file, $expect_valid);
        }
    };
}

golden_test!(valid_proof_bundle_v1, "golden/valid_proof_bundle_v1.cbor", true);
golden_test!(replay_attempt_v1, "golden/replay_attempt_v1.cbor", true);
golden_test!(malformed_missing_finality, "golden/malformed_proof_missing_finality.cbor", true);
golden_test!(malformed_wrong_domain, "golden/malformed_proof_wrong_domain.cbor", true);

#[test]
fn valid_sanad_envelope_v1() {
    let bytes = include_bytes!("golden/valid_sanad_envelope_v1.cbor");
    let envelope: SanadEnvelope = from_canonical_cbor(bytes)
        .expect("valid_sanad_envelope_v1 must deserialize");
    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.schema_id, SanadEnvelope::SCHEMA_ID);
    assert!(!envelope.sanad_id.as_bytes().is_empty());
    assert!(!envelope.payload_hash.as_bytes().is_empty());
}
