//! Release-corpus shape checks. Semantic behavior is exercised by the source
//! tests named in the immutable manifest.

use csv_accountability::{EvidenceSourceClass, github_deployment_descriptor};

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
