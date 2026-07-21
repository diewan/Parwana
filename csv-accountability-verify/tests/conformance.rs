use csv_accountability::{
    ActionIntent, DimensionStatus, EvidenceKind, ExecutionAttemptState, ExecutionOutcome,
    SealConsumptionRecord, SourceLocator,
};
use csv_accountability_verify::{
    AlgorithmStatus, AuthenticityStatus, ReasonCode, ReplayStatus, RevocationStatus, Stage,
    StageDisposition, VerificationDisposition, VerificationInput, assurance_profile, verify,
};
use csv_testkit::AccountabilityFixture;

fn authenticity(
    fixture: &AccountabilityFixture,
) -> Vec<(csv_accountability::EvidenceNodeId, AuthenticityStatus)> {
    fixture
        .evidence
        .iter()
        .filter(|(_, node)| node.authenticity.is_some())
        .map(|(id, _)| (*id, AuthenticityStatus::Verified))
        .collect()
}

fn run(
    fixture: &AccountabilityFixture,
    authenticity: &[(csv_accountability::EvidenceNodeId, AuthenticityStatus)],
    revocation_status: RevocationStatus,
    replay_status: ReplayStatus,
) -> csv_accountability_verify::VerificationReport {
    verify(
        &fixture.context,
        VerificationInput {
            intent: &fixture.intent,
            mandate: &fixture.mandate,
            attempt: &fixture.attempt,
            receipt: &fixture.receipt,
            evidence: &fixture.evidence,
            evidence_authenticity: authenticity,
            expected_executor: &fixture.executor,
            revocation_status,
            algorithm_status: AlgorithmStatus::Allowed,
            replay_status,
            single_use_anchor: None,
        },
    )
    .expect("fixture context is valid")
    .result
}

fn has_reason(
    report: &csv_accountability_verify::VerificationReport,
    stage: Stage,
    disposition: StageDisposition,
) -> bool {
    report
        .stages
        .iter()
        .any(|result| result.stage == stage && result.disposition == disposition)
}

#[test]
fn valid_vector_is_ordered_context_bound_and_dimension_preserving() {
    let fixture = AccountabilityFixture::valid();
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert_eq!(report.disposition, VerificationDisposition::Valid);
    assert_eq!(
        report
            .stages
            .iter()
            .map(|result| result.stage)
            .collect::<Vec<_>>(),
        vec![
            Stage::Structure,
            Stage::Intent,
            Stage::Authority,
            Stage::Executor,
            Stage::Temporal,
            Stage::Replay,
            Stage::Evidence,
            Stage::Receipt,
            Stage::ExternalCorroboration,
            Stage::DeferredPreservation,
        ]
    );
    assert_eq!(report.evidence_summary.claims, 1);
    assert_eq!(report.evidence_summary.observations, 1);
    assert_eq!(report.evidence_summary.attestations, 1);
    assert_eq!(
        report.temporal_context.revocation_snapshot_digest,
        fixture.context.revocation_snapshot_digest
    );
    assert_eq!(
        report.temporal_context.algorithm_policy_digest,
        fixture.context.algorithm_policy_digest
    );
    assert!(has_reason(
        &report,
        Stage::DeferredPreservation,
        StageDisposition::Unsupported(ReasonCode::PreservationSemanticsDeferred)
    ));
}

#[test]
fn assurance_projection_is_complete_non_scalar_and_context_bound() {
    let fixture = AccountabilityFixture::valid();
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    let context_id = fixture.context.id().unwrap();
    let assurance = assurance_profile(context_id, &report);
    assurance.validate().expect("projection remains canonical");
    assert_eq!(assurance.verification_context_id, context_id);
    assert_eq!(assurance.dimensions.len(), 11);
    assert!(assurance.dimensions.iter().all(|dimension| {
        !dimension.reason_codes.is_empty() && !dimension.limitations.is_empty()
    }));
    assert_eq!(
        assurance.dimensions[1].limitations,
        ["Not evaluated by accountability profile v0.1"]
    );
    assert!(
        assurance
            .dimensions
            .iter()
            .all(|dimension| dimension.assurance_level.is_none())
    );
}

#[test]
fn assurance_projection_preserves_failure_and_uncertainty() {
    let mut fixture = AccountabilityFixture::valid();
    mutate_commit(&mut fixture.intent);
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Unknown,
    );
    let assurance = assurance_profile(fixture.context.id().unwrap(), &report);
    assert_eq!(
        assurance.dimensions[3].status,
        csv_accountability::DimensionStatus::NotSatisfied
    );
    assert!(
        assurance.dimensions[3]
            .reason_codes
            .contains(&"ACCOUNTABILITY.AUTHORITY.INTENT_MISMATCH".into())
    );
    assert_eq!(
        assurance.dimensions[5].status,
        csv_accountability::DimensionStatus::Indeterminate
    );
}

#[test]
fn wrong_commit_and_environment_do_not_match_the_mandate() {
    for mutate in [mutate_commit as fn(&mut ActionIntent), mutate_environment] {
        let mut fixture = AccountabilityFixture::valid();
        mutate(&mut fixture.intent);
        let report = run(
            &fixture,
            &authenticity(&fixture),
            RevocationStatus::NotRevoked,
            ReplayStatus::Fresh,
        );
        assert!(has_reason(
            &report,
            Stage::Intent,
            StageDisposition::Fail(ReasonCode::IntentMismatch)
        ));
    }
}

#[test]
fn wrong_subject_expiry_revocation_and_replay_fail_closed() {
    let mut wrong_subject = AccountabilityFixture::valid();
    wrong_subject.executor = b"executor:other".to_vec();
    let report = run(
        &wrong_subject,
        &authenticity(&wrong_subject),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Executor,
        StageDisposition::Fail(ReasonCode::WrongExecutor)
    ));

    let mut expired = AccountabilityFixture::valid();
    expired.context.evaluation_time = expired.mandate.expires_at;
    let report = run(
        &expired,
        &authenticity(&expired),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Temporal,
        StageDisposition::Fail(ReasonCode::MandateExpired)
    ));

    let fixture = AccountabilityFixture::valid();
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::Revoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Temporal,
        StageDisposition::Fail(ReasonCode::MandateRevoked)
    ));
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Replayed,
    );
    assert!(has_reason(
        &report,
        Stage::Replay,
        StageDisposition::Fail(ReasonCode::ReplayDetected)
    ));
}

#[test]
fn forged_source_is_invalid_and_unknown_authenticity_is_indeterminate() {
    let fixture = AccountabilityFixture::valid();
    let mut assessments = authenticity(&fixture);
    assessments[0].1 = AuthenticityStatus::Rejected;
    let report = run(
        &fixture,
        &assessments,
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Evidence,
        StageDisposition::Fail(ReasonCode::EvidenceAuthenticityRejected)
    ));

    assessments[0].1 = AuthenticityStatus::Unknown;
    let report = run(
        &fixture,
        &assessments,
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert_eq!(report.disposition, VerificationDisposition::Indeterminate);
}

#[test]
fn ambiguous_outcome_selective_disclosure_and_missing_evidence_remain_indeterminate() {
    let mut ambiguous = AccountabilityFixture::valid();
    ambiguous.attempt.state = ExecutionAttemptState::OutcomeAmbiguous;
    ambiguous.attempt.provider_response_digest = None;
    ambiguous.receipt.outcome = ExecutionOutcome::Unknown;
    ambiguous.receipt.completed_at = None;
    ambiguous.receipt.result_commitment = None;
    ambiguous.receipt.attempt_id = ambiguous
        .attempt
        .id(&ambiguous.mandate)
        .expect("ambiguous attempt remains valid");
    let report = run(
        &ambiguous,
        &authenticity(&ambiguous),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Receipt,
        StageDisposition::Indeterminate(ReasonCode::OutcomeAmbiguous)
    ));

    let mut selective = AccountabilityFixture::valid();
    selective.evidence[0].1.source_locator = SourceLocator::Withheld([31; 32]);
    selective.evidence[0].0 = selective.evidence[0]
        .1
        .id()
        .expect("withheld evidence remains valid");
    selective.evidence.sort_by_key(|(id, _)| *id);
    rebind_evidence_refs(&mut selective);
    let report = run(
        &selective,
        &authenticity(&selective),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Evidence,
        StageDisposition::Indeterminate(ReasonCode::SelectiveDisclosureLimitsEvaluation)
    ));

    let mut missing = AccountabilityFixture::valid();
    missing.receipt.evidence_requirements_status[0].satisfied = false;
    missing.receipt.evidence_requirements_status[0]
        .evidence_refs
        .clear();
    let report = run(
        &missing,
        &authenticity(&missing),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &report,
        Stage::Evidence,
        StageDisposition::Indeterminate(ReasonCode::RequiredEvidenceMissing)
    ));
}

#[test]
fn claim_observation_attestation_and_gap_are_counted_without_conflation() {
    let mut fixture = AccountabilityFixture::valid();
    let mut gap = fixture.evidence[0].1.clone();
    gap.kind = EvidenceKind::EvidenceGap {
        missing_registry_id: "org.diewan.evidence.provider-status.v1".into(),
        reason_digest: [30; 32],
    };
    gap.authenticity = None;
    gap.source_locator = SourceLocator::Disclosed("piteka:gap:1".into());
    let gap_id = gap.id().expect("gap is valid");
    fixture.evidence.push((gap_id, gap));
    fixture.evidence.sort_by_key(|(id, _)| *id);
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert_eq!(report.evidence_summary.gaps, 1);
    assert!(has_reason(
        &report,
        Stage::Evidence,
        StageDisposition::Indeterminate(ReasonCode::RequiredEvidenceMissing)
    ));
}

fn github_profile(intent: &ActionIntent) -> csv_accountability::GitHubDeploymentIntentV1 {
    csv_accountability::GitHubDeploymentIntentV1::from_canonical_bytes(&intent.profile_bytes)
        .expect("intent carries a canonical github profile")
}

fn mutate_commit(intent: &mut ActionIntent) {
    let mut profile = github_profile(intent);
    profile.commit_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    profile.exact_ref = profile.commit_sha.clone();
    *intent = rebuild_intent(intent, profile);
}

fn mutate_environment(intent: &mut ActionIntent) {
    let mut profile = github_profile(intent);
    profile.environment_id += 1;
    *intent = rebuild_intent(intent, profile);
}

fn rebuild_intent(
    original: &ActionIntent,
    profile: csv_accountability::GitHubDeploymentIntentV1,
) -> ActionIntent {
    ActionIntent::github_deployment(
        original.requested_by.clone(),
        original.requested_at,
        original.request_nonce,
        original.context_commitments.clone(),
        profile,
    )
    .expect("mutated profile remains structurally valid")
}

fn rebind_evidence_refs(fixture: &mut AccountabilityFixture) {
    let ids: Vec<_> = fixture.evidence.iter().map(|(id, _)| *id).collect();
    fixture.receipt.dispatch_evidence_refs = ids.clone();
    fixture.receipt.target_evidence_refs = ids.clone();
    fixture.receipt.evidence_requirements_status[0].evidence_refs = ids;
}

#[test]
fn released_corpus_indexes_every_required_v01_vector() {
    let manifest = include_str!("../../csv-testkit/corpus/accountability-v0.1/manifest.toml");
    for required in [
        "id = \"valid\"",
        "id = \"expired\"",
        "id = \"replayed\"",
        "id = \"mutated-intent\"",
        "id = \"forged-source\"",
        "id = \"ambiguous-outcome\"",
        "id = \"selectively-disclosed\"",
        "id = \"missing-required-evidence\"",
    ] {
        assert!(
            manifest.contains(required),
            "missing corpus vector: {required}"
        );
    }
    assert!(manifest.contains("id = \"contradiction\""));
    assert!(manifest.contains("id = \"preservation-renewal\""));
}

/// The Phase-B single-use anchoring loop: a preserved seal-consumption record that binds
/// exactly this mandate's reservation-token digest (nullifier) and authorized intent id
/// (commitment) re-checks offline as independent single-use enforcement, surfacing the
/// affirmative registered codes on the external-corroboration dimension.
#[test]
fn preserved_seal_consumption_corroborates_single_use_offline() {
    let fixture = AccountabilityFixture::valid();
    let matching = SealConsumptionRecord {
        seal_id: [42u8; 32],
        nullifier: fixture.attempt.reservation_token_digest,
        commitment: *fixture.mandate.intent_id.as_bytes(),
        anchor_backend: "csv-seal.local.v1".into(),
    };
    let build = |anchor: Option<&SealConsumptionRecord>| {
        verify(
            &fixture.context,
            VerificationInput {
                intent: &fixture.intent,
                mandate: &fixture.mandate,
                attempt: &fixture.attempt,
                receipt: &fixture.receipt,
                evidence: &fixture.evidence,
                evidence_authenticity: &authenticity(&fixture),
                expected_executor: &fixture.executor,
                revocation_status: RevocationStatus::NotRevoked,
                algorithm_status: AlgorithmStatus::Allowed,
                replay_status: ReplayStatus::Fresh,
                single_use_anchor: anchor,
            },
        )
        .expect("fixture context is valid")
        .result
    };

    // Matching record → Satisfied external corroboration with the affirmative codes.
    let report = build(Some(&matching));
    assert_eq!(report.disposition, VerificationDisposition::Valid);
    assert!(has_reason(
        &report,
        Stage::ExternalCorroboration,
        StageDisposition::Pass
    ));
    let assurance = assurance_profile(fixture.context.id().unwrap(), &report);
    let external = &assurance.dimensions[7];
    assert_eq!(
        external.dimension,
        csv_accountability::AssuranceDimension::ExternalCorroboration
    );
    assert_eq!(external.status, DimensionStatus::Satisfied);
    assert!(
        external
            .reason_codes
            .contains(&"ACCOUNTABILITY.SINGLE_USE.INDEPENDENTLY_ENFORCED".into())
    );
    assert!(
        external
            .reason_codes
            .contains(&"ACCOUNTABILITY.EVIDENCE.CSV_SEAL_CONSUMPTION_VALID".into())
    );

    // Absent record → NotApplicable limitation, never a failure; disposition unchanged.
    let absent = build(None);
    assert_eq!(absent.disposition, VerificationDisposition::Valid);
    let absent_dim = &assurance_profile(fixture.context.id().unwrap(), &absent).dimensions[7];
    assert_eq!(absent_dim.status, DimensionStatus::NotApplicable);
    assert!(
        absent_dim
            .reason_codes
            .contains(&"ACCOUNTABILITY.EXTERNAL_CORROBORATION.ANCHOR_ABSENT".into())
    );

    // Inconsistent record (wrong nullifier) → Indeterminate corroboration, still not a fail.
    let mut mismatched = matching.clone();
    mismatched.nullifier = [7u8; 32];
    let report = build(Some(&mismatched));
    assert_eq!(report.disposition, VerificationDisposition::Indeterminate);
    let dim = &assurance_profile(fixture.context.id().unwrap(), &report).dimensions[7];
    assert_eq!(dim.status, DimensionStatus::Indeterminate);
    assert!(
        dim.reason_codes
            .contains(&"ACCOUNTABILITY.EXTERNAL_CORROBORATION.ANCHOR_INCONSISTENT".into())
    );
}
