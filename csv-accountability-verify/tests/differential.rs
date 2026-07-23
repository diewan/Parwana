use std::{fs, path::PathBuf, process::Command};

use csv_accountability::{ACCOUNTABILITY_OBJECT_VERSION, MandateSignatureEnvelope};
use csv_accountability_verify::{
    AlgorithmStatus, AuthenticityStatus, ReasonCode, ReplayStatus, RevocationStatus, Stage,
    StageDisposition, VerificationInput, verify,
};
use csv_testkit::AccountabilityFixture;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

fn vector(fixture: &AccountabilityFixture) -> Value {
    let signing_key = SigningKey::from_bytes(&[41; 32]);
    let mandate_id = fixture.mandate.id().expect("fixture mandate is valid");
    let signature = signing_key.sign(mandate_id.as_bytes());
    let envelope = MandateSignatureEnvelope {
        version: ACCOUNTABILITY_OBJECT_VERSION,
        algorithm: fixture.mandate.signature_requirements.algorithm.clone(),
        key_id: fixture.mandate.signature_requirements.key_id.clone(),
        signature: signature.to_bytes().to_vec(),
    };
    envelope
        .validate_for(&fixture.mandate)
        .expect("fixture envelope is structurally bound");
    json!({
        "profile": "github-deployment-v1",
        "algorithm": envelope.algorithm,
        "mandate_canonical_hex": hex::encode(fixture.mandate.canonical_bytes().expect("canonical mandate")),
        "mandate_id": hex::encode(mandate_id.as_bytes()),
        "intent_id": hex::encode(fixture.intent.id().expect("fixture intent").as_bytes()),
        "mandate_intent_id": hex::encode(fixture.mandate.intent_id.as_bytes()),
        "public_key": hex::encode(signing_key.verifying_key().as_bytes()),
        "signature": hex::encode(envelope.signature),
        "consumed_mandate_ids": [],
    })
}

fn run_checker(value: &Value) -> (bool, String) {
    let directory =
        std::env::temp_dir().join(format!("parwana-differential-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("temporary differential directory");
    let path = directory.join("vector.json");
    fs::write(&path, serde_json::to_vec(value).expect("serialize vector")).expect("write vector");
    let checker =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools/independent-checker/check.py");
    let output = Command::new("python3")
        .arg(checker)
        .arg(path)
        .output()
        .expect("run independent checker");
    let body: Value = serde_json::from_slice(&output.stdout).expect("checker JSON output");
    (
        output.status.success(),
        body["reason"].as_str().expect("checker reason").to_owned(),
    )
}

fn rust_replay_reason(fixture: &AccountabilityFixture, replay: ReplayStatus) -> Option<ReasonCode> {
    let authenticity: Vec<_> = fixture
        .evidence
        .iter()
        .filter(|(_, node)| node.authenticity.is_some())
        .map(|(id, _)| (*id, AuthenticityStatus::Verified))
        .collect();
    let report = verify(
        &fixture.context,
        VerificationInput {
            intent: &fixture.intent,
            mandate: &fixture.mandate,
            attempt: &fixture.attempt,
            receipt: &fixture.receipt,
            evidence: &fixture.evidence,
            evidence_authenticity: &authenticity,
            expected_executor: &fixture.executor,
            revocation_status: RevocationStatus::NotRevoked,
            algorithm_status: AlgorithmStatus::Allowed,
            replay_status: replay,
            single_use_anchor: None,
            preservation_envelopes: &[],
            preservation_authenticity: &[],
            preservation_algorithm_statuses: &[],
        },
    )
    .expect("valid context")
    .result;
    report.stages.into_iter().find_map(|result| match result {
        csv_accountability_verify::StageResult {
            stage: Stage::Replay,
            disposition: StageDisposition::Fail(reason),
        } => Some(reason),
        _ => None,
    })
}

#[test]
fn independent_checker_matches_digest_signature_intent_and_replay_semantics() {
    let fixture = AccountabilityFixture::valid();
    let valid = vector(&fixture);
    assert_eq!(run_checker(&valid), (true, "Valid".into()));

    let mut digest = valid.clone();
    let canonical = digest["mandate_canonical_hex"].as_str().expect("hex");
    let replacement = if canonical.ends_with("00") {
        "01"
    } else {
        "00"
    };
    digest["mandate_canonical_hex"] = json!(format!(
        "{}{}",
        &canonical[..canonical.len() - 2],
        replacement
    ));
    assert_eq!(
        run_checker(&digest),
        (false, "CanonicalDigestMismatch".into())
    );

    let mut signature = valid.clone();
    signature["signature"] = json!("00".repeat(64));
    assert_eq!(
        run_checker(&signature),
        (false, "MandateSignatureInvalid".into())
    );

    let mut intent = valid.clone();
    intent["mandate_intent_id"] = json!("00".repeat(32));
    assert_eq!(run_checker(&intent), (false, "IntentMismatch".into()));

    let mut replay = valid.clone();
    replay["consumed_mandate_ids"] = json!([replay["mandate_id"].clone()]);
    assert_eq!(run_checker(&replay), (false, "ReplayDetected".into()));
    assert_eq!(
        rust_replay_reason(&fixture, ReplayStatus::Replayed),
        Some(ReasonCode::ReplayDetected)
    );

    let mut unknown = valid;
    unknown["consumed_mandate_ids"] = Value::Null;
    assert_eq!(run_checker(&unknown), (false, "ReplayStatusUnknown".into()));
}
