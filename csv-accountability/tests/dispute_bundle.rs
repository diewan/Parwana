use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, BundleError, DisclosedObject,
    DisputeBundle, IntentId, WithheldObject, bundle_object_digest,
};

fn make_bundle() -> DisputeBundle {
    let bytes = b"canonical mandate".to_vec();
    DisputeBundle {
        protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
        bundle_version: ACCOUNTABILITY_OBJECT_VERSION,
        case_id: Some("case-123".into()),
        subject_intent_id: IntentId::from_digest([1; 32]),
        disclosed_objects: vec![DisclosedObject {
            registry_id: "org.diewan.action-mandate.v1".into(),
            media_type: "application/cbor".into(),
            content_digest: bundle_object_digest(&bytes),
            bytes,
        }],
        withheld_objects: vec![WithheldObject {
            registry_id: "org.diewan.evidence.observation.v1".into(),
            content_digest: [9; 32],
            reason_code: "purpose-limited".into(),
        }],
        recommended_context: None,
        producer_identity: b"piteka:exporter".to_vec(),
        producer_signature: vec![7; 64],
    }
}

#[test]
fn explicit_disclosed_and_withheld_tables_are_deterministic() {
    let bundle = make_bundle();
    assert!(bundle.validate().is_ok());
    assert_eq!(bundle.id(), bundle.id());
    assert_eq!(
        bundle
            .require_disclosed(
                "org.diewan.action-mandate.v1",
                bundle.disclosed_objects[0].content_digest,
            )
            .unwrap(),
        b"canonical mandate"
    );
}

#[test]
fn missing_objects_and_digest_mismatches_fail_closed() {
    let mut bundle = make_bundle();
    assert_eq!(
        bundle.require_disclosed("org.diewan.execution-receipt.v1", [3; 32]),
        Err(BundleError::MissingObject)
    );
    bundle.disclosed_objects[0].bytes[0] ^= 1;
    assert_eq!(bundle.validate(), Err(BundleError::DigestMismatch));
}

#[test]
fn disclosure_ambiguity_and_size_limits_are_rejected() {
    let mut bundle = make_bundle();
    bundle.withheld_objects[0].content_digest = bundle.disclosed_objects[0].content_digest;
    assert_eq!(bundle.validate(), Err(BundleError::InvalidObjectTable));

    let mut bundle = make_bundle();
    bundle.disclosed_objects[0].bytes = vec![0; csv_accountability::MAX_BUNDLE_OBJECT_BYTES + 1];
    assert_eq!(bundle.validate(), Err(BundleError::BoundsExceeded));
}
