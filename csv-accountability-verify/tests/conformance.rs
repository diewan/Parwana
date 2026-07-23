use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ALGORITHM_SHA256_TAGGED_V1,
    ActionIntent, AlgorithmPolicyStatus, AlgorithmStatusEntry, DimensionStatus, DisclosedObject,
    DisputeBundle, EvidenceKind, EvidenceNode, EvidenceNodeId, ExecutionAttemptState,
    ExecutionOutcome, PreservationEnvelope, SealConsumptionRecord, SourceLocator,
    bundle_object_digest,
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
            preservation_envelopes: &[],
            preservation_authenticity: &[],
            preservation_algorithm_statuses: &[],
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
            Stage::ContradictionAndGap,
            Stage::Receipt,
            Stage::ExternalCorroboration,
            Stage::Custody,
            Stage::Preservation,
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
        Stage::Preservation,
        StageDisposition::Unsupported(ReasonCode::PreservationEvidenceAbsent)
    ));
}

#[test]
fn database_migration_receipt_and_portable_bundle_verify_offline() {
    let fixture = AccountabilityFixture::valid_db_migration();

    // Preserve the exact canonical objects an independent verifier needs. No
    // network, database, product projection, or provider API participates in
    // either bundle construction or the verification below.
    let mut disclosed_objects = vec![
        disclosed(
            "org.diewan.accountability.action-intent.v1",
            fixture.intent.canonical_bytes().unwrap(),
        ),
        disclosed(
            "org.diewan.accountability.action-mandate.v1",
            fixture.mandate.canonical_bytes().unwrap(),
        ),
        disclosed(
            "org.diewan.accountability.execution-attempt.v1",
            fixture.attempt.canonical_bytes(&fixture.mandate).unwrap(),
        ),
        disclosed(
            "org.diewan.accountability.execution-receipt.v1",
            fixture
                .receipt
                .canonical_bytes(&fixture.mandate, &fixture.attempt)
                .unwrap(),
        ),
    ];
    disclosed_objects.sort_by(|left, right| {
        (&left.registry_id, left.content_digest).cmp(&(&right.registry_id, right.content_digest))
    });
    let bundle = DisputeBundle {
        protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
        bundle_version: ACCOUNTABILITY_OBJECT_VERSION,
        case_id: Some("case:db-migration:20260723".into()),
        subject_intent_id: fixture.intent.id().unwrap(),
        disclosed_objects,
        withheld_objects: vec![],
        recommended_context: Some(fixture.context.id().unwrap()),
        producer_identity: b"piteka:bundle-export".to_vec(),
        producer_signature: vec![35; 64],
    };
    bundle.validate().expect("portable bundle is canonical");
    let canonical_bundle = bundle.canonical_bytes().unwrap();
    let bundle_id = bundle.id().unwrap();
    assert!(!canonical_bundle.is_empty());
    assert_ne!(bundle_id.as_bytes(), &[0; 32]);
    println!(
        "profile02_bundle_evidence bundle_id={} canonical_bytes={} disclosed_objects={}",
        hex::encode(bundle_id.as_bytes()),
        canonical_bundle.len(),
        bundle.disclosed_objects.len(),
    );

    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert_eq!(report.disposition, VerificationDisposition::Valid);
    assert!(has_reason(&report, Stage::Receipt, StageDisposition::Pass,));

    // Corruption of retained receipt bytes fails at the bundle boundary before
    // the semantic verifier can consume the artifact.
    let mut corrupted = bundle.clone();
    let receipt = corrupted
        .disclosed_objects
        .iter_mut()
        .find(|object| object.registry_id.ends_with("execution-receipt.v1"))
        .unwrap();
    receipt.bytes[0] ^= 0x80;
    assert!(corrupted.validate().is_err());
}

fn disclosed(registry_id: &str, bytes: Vec<u8>) -> DisclosedObject {
    DisclosedObject {
        registry_id: registry_id.into(),
        media_type: "application/vnd.diewan.accountability-object-v1+csv-binary".into(),
        content_digest: bundle_object_digest(&bytes),
        bytes,
    }
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

fn v02_node(kind: EvidenceKind, relationships: Vec<EvidenceNodeId>) -> EvidenceNode {
    EvidenceNode {
        kind,
        producer_identity: b"investigator:1".to_vec(),
        collected_at: 20,
        asserted_event_at: Some(10),
        content_digest: [91; 32],
        media_type: "application/cbor".into(),
        source_locator: SourceLocator::Disclosed("case:evidence:1".into()),
        authenticity: None,
        disclosure_classification: "case-parties".into(),
        relationships,
    }
}

#[test]
fn stage_12_preserves_conflicts_and_flags_an_omitted_contradiction() {
    let mut fixture = AccountabilityFixture::valid();
    let subject_id = fixture.evidence[0].0;
    let counterclaim = v02_node(
        EvidenceKind::Counterclaim {
            subject_evidence_id: subject_id,
            proposition_digest: [92; 32],
        },
        vec![subject_id],
    );
    let counterclaim_id = counterclaim.id().unwrap();
    fixture.evidence.push((counterclaim_id, counterclaim));
    let omitted = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &omitted,
        Stage::ContradictionAndGap,
        StageDisposition::Indeterminate(ReasonCode::ContradictoryEvidenceOmitted)
    ));

    let mut relationships = vec![subject_id, counterclaim_id];
    relationships.sort_unstable();
    let contradiction = v02_node(
        EvidenceKind::Contradiction {
            left_evidence_id: subject_id,
            right_evidence_id: counterclaim_id,
            analysis_digest: [93; 32],
        },
        relationships,
    );
    fixture
        .evidence
        .push((contradiction.id().unwrap(), contradiction));
    let preserved = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(
        &preserved,
        Stage::ContradictionAndGap,
        StageDisposition::Indeterminate(ReasonCode::ConflictingEvidencePreserved)
    ));
    assert_eq!(preserved.evidence_summary.counterclaims, 1);
    assert_eq!(preserved.evidence_summary.contradictions, 1);
}

#[test]
fn stage_14_reports_disclosed_custody_and_absent_preservation_separately() {
    let mut fixture = AccountabilityFixture::valid();
    let subject_id = fixture.evidence[0].0;
    let custody = v02_node(
        EvidenceKind::CustodyRecord {
            subject_evidence_id: subject_id,
            previous_custody_id: None,
            custodian_identity: b"custodian:1".to_vec(),
        },
        vec![subject_id],
    );
    fixture.evidence.push((custody.id().unwrap(), custody));
    let report = run(
        &fixture,
        &authenticity(&fixture),
        RevocationStatus::NotRevoked,
        ReplayStatus::Fresh,
    );
    assert!(has_reason(&report, Stage::Custody, StageDisposition::Pass));
    assert!(has_reason(
        &report,
        Stage::Preservation,
        StageDisposition::Unsupported(ReasonCode::PreservationEvidenceAbsent)
    ));
    assert_eq!(report.evidence_summary.custody_records, 1);
}

#[test]
fn preservation_policy_is_explicit_and_renewal_cannot_rewrite_history() {
    let fixture = AccountabilityFixture::valid();
    let first = PreservationEnvelope {
        version: csv_accountability::ACCOUNTABILITY_OBJECT_VERSION,
        object_registry_id: "org.diewan.accountability.bundle.v1".into(),
        original_canonical_bytes: fixture.intent.canonical_bytes().unwrap(),
        algorithm_ids: vec![ALGORITHM_SHA256_TAGGED_V1.into()],
        preserved_at: 1,
        previous_envelope_id: None,
        renewal_material_digest: [71; 32],
    };
    let first_id = first.id().unwrap();
    let policy = [AlgorithmStatusEntry {
        algorithm_id: ALGORITHM_SHA256_TAGGED_V1.into(),
        status: AlgorithmPolicyStatus::Allowed,
    }];
    let evaluate = |envelopes: &[(
        csv_accountability::PreservationEnvelopeId,
        PreservationEnvelope,
    )],
                    preservation_authenticity: &[(
        csv_accountability::PreservationEnvelopeId,
        AuthenticityStatus,
    )],
                    statuses: &[AlgorithmStatusEntry]| {
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
                single_use_anchor: None,
                preservation_envelopes: envelopes,
                preservation_authenticity,
                preservation_algorithm_statuses: statuses,
            },
        )
        .unwrap()
        .result
    };

    let verified = [(first_id, AuthenticityStatus::Verified)];
    let allowed = evaluate(&[(first_id, first.clone())], &verified, &policy);
    assert!(has_reason(
        &allowed,
        Stage::Preservation,
        StageDisposition::Pass
    ));

    for (status, expected) in [
        (
            AlgorithmPolicyStatus::Deprecated,
            StageDisposition::Indeterminate(ReasonCode::PreservationAlgorithmDeprecated),
        ),
        (
            AlgorithmPolicyStatus::Unknown,
            StageDisposition::Indeterminate(ReasonCode::PreservationAlgorithmUnknown),
        ),
        (
            AlgorithmPolicyStatus::Disallowed,
            StageDisposition::Fail(ReasonCode::PreservationAlgorithmDisallowed),
        ),
    ] {
        let report = evaluate(
            &[(first_id, first.clone())],
            &verified,
            &[AlgorithmStatusEntry {
                algorithm_id: ALGORITHM_SHA256_TAGGED_V1.into(),
                status,
            }],
        );
        assert!(has_reason(&report, Stage::Preservation, expected));
    }

    let rejected_authenticity = evaluate(
        &[(first_id, first.clone())],
        &[(first_id, AuthenticityStatus::Rejected)],
        &policy,
    );
    assert!(has_reason(
        &rejected_authenticity,
        Stage::Preservation,
        StageDisposition::Fail(ReasonCode::PreservationAuthenticityRejected)
    ));
    let missing_authenticity = evaluate(&[(first_id, first.clone())], &[], &policy);
    assert!(has_reason(
        &missing_authenticity,
        Stage::Preservation,
        StageDisposition::Indeterminate(ReasonCode::PreservationAuthenticityUnknown)
    ));

    let mut rewritten = first.clone();
    rewritten.previous_envelope_id = Some(first_id);
    rewritten.preserved_at = 2;
    rewritten.original_canonical_bytes.push(0xff);
    rewritten.renewal_material_digest = [72; 32];
    let rewritten_id = rewritten.id().unwrap();
    let mut renewal_authenticity = vec![
        (first_id, AuthenticityStatus::Verified),
        (rewritten_id, AuthenticityStatus::Verified),
    ];
    renewal_authenticity.sort_unstable_by_key(|(id, _)| *id);
    let rejected = evaluate(
        &[(first_id, first), (rewritten_id, rewritten)],
        &renewal_authenticity,
        &policy,
    );
    assert!(has_reason(
        &rejected,
        Stage::Preservation,
        StageDisposition::Fail(ReasonCode::PreservationEvidenceInvalid)
    ));
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
    assert!(manifest.contains("id = \"counterclaim-with-omitted-contradiction\""));
    assert!(manifest.contains("id = \"preserved-contradiction\""));
    assert!(manifest.contains("id = \"disclosed-custody\""));
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
                preservation_envelopes: &[],
                preservation_authenticity: &[],
                preservation_algorithm_statuses: &[],
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
