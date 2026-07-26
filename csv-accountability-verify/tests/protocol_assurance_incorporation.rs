//! PAR-VERIFY-001: the accountability verification report must be able to carry
//! a protocol assurance result without collapsing contextual readings into
//! cryptographic facts.
//!
//! The accountability verifier and the protocol verifier answer different
//! questions — "was this action authorized and evidenced?" versus "does this
//! bundle's cryptography and chain grounding hold?" — over the same four-valued
//! dimension vocabulary. This test drives the real projection end to end:
//! fixture → accountability report → assurance profile → folded protocol report.

use csv_accountability::{
    AssuranceDimension, AssuranceProfile, DimensionStatus, VerificationContextId,
};
use csv_accountability_verify::{
    AlgorithmStatus, AuthenticityStatus, ReplayStatus, RevocationStatus, VerificationInput,
    assurance_profile, verify,
};
use csv_testkit::AccountabilityFixture;
use csv_verifier::{
    ChainNativeClaim, ChainNativeProofAssessment, ChainNativeProofAttestation, ProofKind,
    ProofProvider, ProtocolAssuranceDimension, ProtocolAssuranceReport,
    ProtocolAssuranceReportBuilder, ProtocolReasonCode, TrustMode,
};

/// Run the real accountability verifier over a valid fixture and project its
/// report onto the v0.1 assurance profile.
fn accountability_profile() -> (AssuranceProfile, VerificationContextId) {
    let fixture = AccountabilityFixture::valid();
    let authenticity: Vec<_> = fixture
        .evidence
        .iter()
        .filter(|(_, node)| node.authenticity.is_some())
        .map(|(id, _)| (*id, AuthenticityStatus::Verified))
        .collect();
    let bound = verify(
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
            preservation_envelopes: &[],
            preservation_authenticity: &[],
            preservation_algorithm_statuses: &[],
        },
    )
    .expect("fixture context is valid");
    let context_id = bound.verification_context_id;
    (assurance_profile(context_id, &bound.result), context_id)
}

/// A protocol report whose inclusion reading is asserted by a named chain
/// adapter rather than recomputed — the contextual case the fold must preserve.
fn provider_attested_report() -> ProtocolAssuranceReport {
    let attestation = ChainNativeProofAttestation::new(
        "parwana.test.bitcoin-adapter",
        "bitcoin",
        [ChainNativeClaim::AnchorInclusion],
    );
    let mut builder = ProtocolAssuranceReportBuilder::new(
        csv_verifier::ContextDigestWriter::new("test.incorporation").finish(),
    );
    builder.record(csv_verifier::DimensionAssurance::new(
        ProtocolAssuranceDimension::AnchorInclusion,
        DimensionStatus::Satisfied,
        [ProtocolReasonCode::InclusionAttestedByProvider],
        attestation.provider(ProofKind::MerkleInclusion),
        [],
    ));
    builder.record(csv_verifier::DimensionAssurance::new(
        ProtocolAssuranceDimension::Authorization,
        DimensionStatus::Satisfied,
        [ProtocolReasonCode::SignaturesVerified],
        ProofProvider::local(ProofKind::DigitalSignature),
        [],
    ));
    // Left unrecorded on purpose: source closure and the rest fall back to the
    // fail-closed Indeterminate default.
    let _ = ChainNativeProofAssessment::NotSupplied;
    builder.build()
}

fn dimension(
    profile: &AssuranceProfile,
    dimension: AssuranceDimension,
) -> &csv_accountability::DimensionResult {
    profile
        .dimensions
        .iter()
        .find(|result| result.dimension == dimension)
        .expect("a validated profile carries every dimension")
}

#[test]
fn the_accountability_profile_carries_a_protocol_report_and_stays_canonical() {
    let (mut profile, context_id) = accountability_profile();
    profile
        .validate()
        .expect("the accountability projection is canonical to begin with");
    let before = profile.id().expect("a canonical profile has an id");

    provider_attested_report().incorporate_into(&mut profile);

    profile
        .validate()
        .expect("folding a protocol report must leave the profile canonical");
    assert_eq!(
        profile.verification_context_id, context_id,
        "the fold must not rewrite which context the profile was evaluated under"
    );
    assert_ne!(
        before,
        profile.id().expect("still canonical"),
        "the fold must be visible in the profile identity, not silent"
    );
}

#[test]
fn a_provider_attested_reading_stays_contextual_in_the_accountability_profile() {
    let (mut profile, _) = accountability_profile();
    provider_attested_report().incorporate_into(&mut profile);

    let corroboration = dimension(&profile, AssuranceDimension::ExternalCorroboration);
    assert!(
        corroboration.limitations.iter().any(|limitation| {
            limitation.contains("parwana.test.bitcoin-adapter")
                && limitation.contains(TrustMode::ProviderAttested.registry_id())
        }),
        "the adapter that asserted inclusion must be named in the limitations: {:?}",
        corroboration.limitations
    );
    assert!(
        corroboration
            .reason_codes
            .iter()
            .any(|code| code == ProtocolReasonCode::InclusionAttestedByProvider.registry_id()),
        "the protocol reason code must survive the fold: {:?}",
        corroboration.reason_codes
    );
}

#[test]
fn folding_never_reports_a_dimension_as_stronger_than_its_weakest_reading() {
    let (mut profile, _) = accountability_profile();
    provider_attested_report().incorporate_into(&mut profile);

    // AnchorInclusion is Satisfied but FinalityCheckpoint was never evaluated;
    // both fold into ExternalCorroboration, so the pair must read Indeterminate.
    assert_eq!(
        dimension(&profile, AssuranceDimension::ExternalCorroboration).status,
        DimensionStatus::Indeterminate,
        "a satisfied reading must not mask an unevaluated one sharing its dimension"
    );
    // Source closure is not externally grounded, so single-use cannot read as met.
    assert_ne!(
        dimension(&profile, AssuranceDimension::SingleUse).status,
        DimensionStatus::Satisfied,
        "portable non-equivocation is not established until Stage 2"
    );
}

#[test]
fn a_failed_protocol_dimension_propagates_into_the_accountability_profile() {
    let (mut profile, _) = accountability_profile();
    let cryptographic_before = dimension(&profile, AssuranceDimension::Cryptographic).status;

    let mut builder = ProtocolAssuranceReportBuilder::new(
        csv_verifier::ContextDigestWriter::new("test.incorporation").finish(),
    );
    builder.record(csv_verifier::DimensionAssurance::new(
        ProtocolAssuranceDimension::Authorization,
        DimensionStatus::NotSatisfied,
        [ProtocolReasonCode::SignatureInvalid],
        ProofProvider::local(ProofKind::DigitalSignature),
        [],
    ));
    builder.build().incorporate_into(&mut profile);

    assert_eq!(
        dimension(&profile, AssuranceDimension::Cryptographic).status,
        DimensionStatus::NotSatisfied,
        "an invalid signature must not be absorbed (was {cryptographic_before:?})"
    );
    profile.validate().expect("still canonical after a failure");
}
