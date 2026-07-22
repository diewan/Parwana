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

/// ANCHOR-01: the published on-chain commitment-anchor contract must match the
/// `csv_accountability::anchor::ChainAnchor` code — the same golden bytes decode,
/// re-encode, and hash to the published digest, and the string constants agree.
#[test]
fn published_chain_anchor_contract_matches_code() {
    use csv_accountability::{
        CHAIN_ANCHOR_DOMAIN_TAG, CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE, ChainAnchor,
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

    // The published golden bytes decode to a valid ChainAnchor, re-encode
    // byte-for-byte, and hash to the published digest under the domain tag.
    let anchor = ChainAnchor::from_canonical_bytes(&canonical).expect("golden decodes");
    assert_eq!(anchor.canonical_bytes().unwrap(), canonical, "round-trips");
    assert_eq!(hex::encode(anchor.digest().unwrap()), published_digest, "digest");
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
