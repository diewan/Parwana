//! Release-corpus shape checks. Semantic behavior is exercised by the source
//! tests named in the immutable manifest.

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
