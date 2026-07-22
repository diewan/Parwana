//! DEMO-03 (Scenario B) — the independent overreach verdict.
//!
//! When an agent executes parameters its mandate never authorized (a changed
//! commit SHA / extra environment), the exported bundle carries an executed
//! intent that no longer hashes to the mandate's authorized intent id. The
//! *independent* Parwana verifier — not Piteka — must reach a fail-closed
//! verdict: the Authority assurance dimension is `NotSatisfied` and carries the
//! `ACCOUNTABILITY.AUTHORITY.INTENT_MISMATCH` reason code. This is the
//! accountability loop's teeth, and it is reproducible offline with no I/O.

use csv_sdk::accountability::{
    ActionIntent, AssuranceDimension, DimensionStatus, GitHubDeploymentIntentV1, RequiredContexts,
};
use csv_sdk::accountability_verification::{
    AlgorithmStatus, AuthenticityStatus, ReplayStatus, RevocationStatus, VerificationDisposition,
    VerificationInput, assurance_profile, verify,
};
use csv_testkit::accountability::AccountabilityFixture;

const INTENT_MISMATCH: &str = "ACCOUNTABILITY.AUTHORITY.INTENT_MISMATCH";

/// Builds an intent for the *overreached* deployment: the same target repo, but
/// a different commit SHA/ref than the mandate authorized. Its canonical id
/// therefore differs from the fixture mandate's `intent_id`.
fn overreach_intent() -> ActionIntent {
    let required_contexts = RequiredContexts::explicit(vec!["build".into(), "security".into()])
        .expect("static required contexts are valid");
    let profile = GitHubDeploymentIntentV1 {
        repository_id: 42,
        repository_owner: "diewan".into(),
        repository_name: "piteka".into(),
        // Overreach: a SHA the approver never reviewed.
        commit_sha: "ffffffffffffffffffffffffffffffffffffffff".into(),
        exact_ref: "ffffffffffffffffffffffffffffffffffffffff".into(),
        environment_id: 7,
        environment_name: "production".into(),
        deployment_gate_policy_digest: required_contexts
            .gate_policy_id()
            .expect("static gate policy is valid"),
        required_contexts,
        payload_commitment: [3; 32],
        artifact_digest: Some([4; 32]),
    };
    ActionIntent::github_deployment(b"requester:alice".to_vec(), 90, [6; 32], vec![[7; 32]], profile)
        .expect("overreach intent is structurally valid")
}

#[test]
fn overreach_yields_independent_intent_mismatch_verdict() {
    let mut fixture = AccountabilityFixture::valid();

    // Sanity: the untouched fixture is a clean, valid authorization.
    let authorized = overreach_intent().id().expect("intent id");
    assert_ne!(
        authorized, fixture.mandate.intent_id,
        "overreach intent must differ from the authorized intent id"
    );

    // Swap in the overreached intent the agent actually executed. The mandate,
    // attempt, and receipt still reference the authorized intent id — exactly
    // the shape of a bundle exported from a rejected/overreaching attempt.
    fixture.intent = overreach_intent();

    let authenticity = fixture
        .evidence
        .iter()
        .filter(|(_, node)| node.authenticity.is_some())
        .map(|(id, _)| (*id, AuthenticityStatus::Verified))
        .collect::<Vec<_>>();

    let output = verify(
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
            replay_status: ReplayStatus::Fresh,
            single_use_anchor: None,
        },
    )
    .expect("fixture context is supported");

    // The overall verdict is fail-closed — never "authorized".
    assert_eq!(
        output.result.disposition,
        VerificationDisposition::Invalid,
        "an overreach must not verify as valid"
    );

    // The independent assurance profile pins the failure to the Authority
    // dimension with the intent-mismatch reason code.
    let assurance = assurance_profile(output.verification_context_id, &output.result);
    let authority = assurance
        .dimensions
        .iter()
        .find(|dimension| dimension.dimension == AssuranceDimension::Authority)
        .expect("authority dimension is evaluated");

    assert_eq!(
        authority.status,
        DimensionStatus::NotSatisfied,
        "authority must be NotSatisfied for an overreach"
    );
    assert!(
        authority.reason_codes.iter().any(|code| code == INTENT_MISMATCH),
        "authority reason codes must include {INTENT_MISMATCH}, got {:?}",
        authority.reason_codes
    );
    // Reconstructed authority is never "Authorized": the dimension keeps its
    // hash-bound limitation note.
    assert!(
        !authority.limitations.is_empty(),
        "the verdict must carry its context limitation"
    );
}

#[test]
fn untouched_fixture_still_satisfies_authority() {
    // Guards the negative control: the same machinery passes Authority when the
    // executed intent matches the mandate, so the mismatch above is meaningful.
    let fixture = AccountabilityFixture::valid();
    let authenticity = fixture
        .evidence
        .iter()
        .filter(|(_, node)| node.authenticity.is_some())
        .map(|(id, _)| (*id, AuthenticityStatus::Verified))
        .collect::<Vec<_>>();
    let output = verify(
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
            replay_status: ReplayStatus::Fresh,
            single_use_anchor: None,
        },
    )
    .expect("fixture context is supported");
    let assurance = assurance_profile(output.verification_context_id, &output.result);
    let authority = assurance
        .dimensions
        .iter()
        .find(|dimension| dimension.dimension == AssuranceDimension::Authority)
        .expect("authority dimension");
    assert_eq!(authority.status, DimensionStatus::Satisfied);
}
