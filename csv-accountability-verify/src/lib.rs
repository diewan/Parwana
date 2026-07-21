//! Deterministic verification of the accountability vertical slice.
//!
//! The verifier performs no I/O and treats all live-state observations as
//! explicit inputs committed by [`VerificationContext`].

#![forbid(unsafe_code)]

pub mod reason_codes;

use csv_accountability::{
    ActionIntent, ActionMandate, AssuranceDimension, AssuranceProfile, ContextBoundOutput,
    DimensionResult, DimensionStatus, EvidenceKind, EvidenceNode, EvidenceNodeId, ExecutionAttempt,
    ExecutionOutcome, ExecutionReceipt, MandateSubject, SourceLocator, VerificationContext,
    VerificationContextId, validate_evidence_graph,
};

/// Stable verification stage ordering for protocol version 0.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Structure,
    Intent,
    Authority,
    Executor,
    Temporal,
    Replay,
    Evidence,
    Receipt,
    DeferredPreservation,
}

/// Result of one verification stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageDisposition {
    Pass,
    Fail(ReasonCode),
    Indeterminate(ReasonCode),
    Unsupported(ReasonCode),
}

/// Machine-readable reason codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonCode {
    MalformedStructure,
    IntentMismatch,
    MandateInvalid,
    WrongExecutor,
    MandateNotYetValid,
    MandateExpired,
    MandateRevoked,
    RevocationStatusUnknown,
    AlgorithmDisallowed,
    AlgorithmStatusUnknown,
    ReplayDetected,
    ReplayStatusUnknown,
    EvidenceInvalid,
    EvidenceReferenceMissing,
    EvidenceAuthenticityRejected,
    EvidenceAuthenticityUnknown,
    RequiredEvidenceMissing,
    SelectiveDisclosureLimitsEvaluation,
    ReceiptInvalid,
    OutcomeAmbiguous,
    PreservationSemanticsDeferred,
}

impl ReasonCode {
    /// Stable registry identifier suitable for machine output and UI display.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::MalformedStructure => "ACCOUNTABILITY.STRUCTURE.MALFORMED",
            Self::IntentMismatch => "ACCOUNTABILITY.AUTHORITY.INTENT_MISMATCH",
            Self::MandateInvalid => "ACCOUNTABILITY.AUTHORITY.MANDATE_INVALID",
            Self::WrongExecutor => "ACCOUNTABILITY.AUTHORITY.WRONG_EXECUTOR",
            Self::MandateNotYetValid => "ACCOUNTABILITY.TEMPORAL.NOT_YET_VALID",
            Self::MandateExpired => "ACCOUNTABILITY.TEMPORAL.EXPIRED",
            Self::MandateRevoked => "ACCOUNTABILITY.TEMPORAL.REVOKED",
            Self::RevocationStatusUnknown => "ACCOUNTABILITY.TEMPORAL.REVOCATION_UNKNOWN",
            Self::AlgorithmDisallowed => "ACCOUNTABILITY.TEMPORAL.ALGORITHM_DISALLOWED",
            Self::AlgorithmStatusUnknown => "ACCOUNTABILITY.TEMPORAL.ALGORITHM_UNKNOWN",
            Self::ReplayDetected => "ACCOUNTABILITY.SINGLE_USE.REPLAY_DETECTED",
            Self::ReplayStatusUnknown => "ACCOUNTABILITY.SINGLE_USE.REPLAY_UNKNOWN",
            Self::EvidenceInvalid => "ACCOUNTABILITY.EVIDENCE.INVALID",
            Self::EvidenceReferenceMissing => "ACCOUNTABILITY.EVIDENCE.REFERENCE_MISSING",
            Self::EvidenceAuthenticityRejected => "ACCOUNTABILITY.EVIDENCE.AUTHENTICITY_REJECTED",
            Self::EvidenceAuthenticityUnknown => "ACCOUNTABILITY.EVIDENCE.AUTHENTICITY_UNKNOWN",
            Self::RequiredEvidenceMissing => {
                "ACCOUNTABILITY.COMPLETENESS.REQUIRED_EVIDENCE_MISSING"
            }
            Self::SelectiveDisclosureLimitsEvaluation => {
                "ACCOUNTABILITY.COMPLETENESS.DISCLOSURE_LIMITED"
            }
            Self::ReceiptInvalid => "ACCOUNTABILITY.EXECUTION.RECEIPT_INVALID",
            Self::OutcomeAmbiguous => "ACCOUNTABILITY.EXECUTION.OUTCOME_AMBIGUOUS",
            Self::PreservationSemanticsDeferred => "ACCOUNTABILITY.PRESERVATION.NOT_EVALUATED_V0_1",
        }
    }
}

/// A deterministic stage result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageResult {
    pub stage: Stage,
    pub disposition: StageDisposition,
}

/// Overall verification disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationDisposition {
    Valid,
    Invalid,
    Indeterminate,
}

/// Complete ordered verification report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    pub disposition: VerificationDisposition,
    pub stages: Vec<StageResult>,
    pub evidence_summary: EvidenceSummary,
    pub temporal_context: TemporalContext,
}

/// Convert an ordered verifier report into the complete v0.1 assurance model.
///
/// This projection lives beside the verifier so applications cannot invent a
/// second mapping from verification stages to protocol assurance dimensions.
pub fn assurance_profile(
    verification_context_id: VerificationContextId,
    report: &VerificationReport,
) -> AssuranceProfile {
    use AssuranceDimension as Dimension;

    AssuranceProfile {
        verification_context_id,
        dimensions: vec![
            evaluated_dimension(Dimension::Structural, report, &[Stage::Structure]),
            deferred_dimension(Dimension::Cryptographic),
            deferred_dimension(Dimension::Identity),
            evaluated_dimension(
                Dimension::Authority,
                report,
                &[Stage::Intent, Stage::Authority, Stage::Executor],
            ),
            evaluated_dimension(Dimension::Temporal, report, &[Stage::Temporal]),
            evaluated_dimension(Dimension::SingleUse, report, &[Stage::Replay]),
            evaluated_dimension(Dimension::Execution, report, &[Stage::Receipt]),
            deferred_dimension(Dimension::ExternalCorroboration),
            evaluated_dimension(Dimension::Completeness, report, &[Stage::Evidence]),
            deferred_dimension(Dimension::Custody),
            evaluated_dimension(
                Dimension::Preservation,
                report,
                &[Stage::DeferredPreservation],
            ),
        ],
    }
}

fn evaluated_dimension(
    dimension: AssuranceDimension,
    report: &VerificationReport,
    stages: &[Stage],
) -> DimensionResult {
    let results = report
        .stages
        .iter()
        .filter(|result| stages.contains(&result.stage))
        .collect::<Vec<_>>();
    let status = if results
        .iter()
        .any(|result| matches!(result.disposition, StageDisposition::Fail(_)))
    {
        DimensionStatus::NotSatisfied
    } else if results
        .iter()
        .any(|result| matches!(result.disposition, StageDisposition::Indeterminate(_)))
    {
        DimensionStatus::Indeterminate
    } else if results.is_empty()
        || results
            .iter()
            .any(|result| matches!(result.disposition, StageDisposition::Unsupported(_)))
    {
        DimensionStatus::NotApplicable
    } else {
        DimensionStatus::Satisfied
    };
    let mut reason_codes = results
        .iter()
        .filter_map(|result| match result.disposition {
            StageDisposition::Fail(reason)
            | StageDisposition::Indeterminate(reason)
            | StageDisposition::Unsupported(reason) => Some(reason.registry_id().to_owned()),
            StageDisposition::Pass => None,
        })
        .collect::<Vec<_>>();
    if status == DimensionStatus::Satisfied {
        reason_codes.push(reason_codes::REQUIREMENT_MET.into());
    }
    reason_codes.sort();
    reason_codes.dedup();
    DimensionResult {
        dimension,
        status,
        assurance_level: None,
        reason_codes,
        supporting_evidence_refs: Vec::new(),
        limitations: if status == DimensionStatus::NotApplicable {
            vec!["Not evaluated by accountability profile v0.1".into()]
        } else {
            vec!["Conclusion is limited to the selected, hash-bound verification context".into()]
        },
    }
}

fn deferred_dimension(dimension: AssuranceDimension) -> DimensionResult {
    DimensionResult {
        dimension,
        status: DimensionStatus::NotApplicable,
        assurance_level: None,
        reason_codes: vec!["ACCOUNTABILITY.PROFILE_V0_1.NOT_EVALUATED".into()],
        supporting_evidence_refs: Vec::new(),
        limitations: vec!["Not evaluated by accountability profile v0.1".into()],
    }
}

/// Explicit temporal policy material used by the evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporalContext {
    pub evaluation_time: u64,
    pub revocation_snapshot_digest: [u8; 32],
    pub algorithm_policy_digest: [u8; 32],
}

/// Deterministic counts that preserve evidence-kind distinctions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub claims: u32,
    pub observations: u32,
    pub attestations: u32,
    pub gaps: u32,
    pub withheld_locators: u32,
}

/// Result supplied by the hash-addressed revocation snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationStatus {
    NotRevoked,
    Revoked,
    Unknown,
}

/// Result supplied by the hash-addressed algorithm policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmStatus {
    Allowed,
    Disallowed,
    Unknown,
}

/// Result supplied by the single-use journal evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStatus {
    Fresh,
    Replayed,
    Unknown,
}

/// Authenticity conclusion for one evidence node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticityStatus {
    Verified,
    Rejected,
    Unknown,
}

/// All inputs required by the pure verifier.
pub struct VerificationInput<'a> {
    pub intent: &'a ActionIntent,
    pub mandate: &'a ActionMandate,
    pub attempt: &'a ExecutionAttempt,
    pub receipt: &'a ExecutionReceipt,
    pub evidence: &'a [(csv_accountability::EvidenceNodeId, EvidenceNode)],
    /// Canonically sorted authenticity conclusions for evidence nodes that
    /// carry authenticity material.
    pub evidence_authenticity: &'a [(EvidenceNodeId, AuthenticityStatus)],
    pub expected_executor: &'a [u8],
    pub revocation_status: RevocationStatus,
    pub algorithm_status: AlgorithmStatus,
    pub replay_status: ReplayStatus,
}

/// Verify in a stable, fail-closed order without network or storage access.
pub fn verify(
    context: &VerificationContext,
    input: VerificationInput<'_>,
) -> Result<ContextBoundOutput<VerificationReport>, csv_accountability::ContextError> {
    let mut stages = Vec::with_capacity(9);
    let structure = if input.intent.validate().is_ok()
        && input.mandate.validate().is_ok()
        && input.attempt.validate(input.mandate).is_ok()
    {
        StageDisposition::Pass
    } else {
        StageDisposition::Fail(ReasonCode::MalformedStructure)
    };
    stages.push(result(Stage::Structure, structure));

    let intent = match input.intent.id() {
        Ok(id) if id == input.mandate.intent_id && id == input.attempt.intent_id => {
            StageDisposition::Pass
        }
        _ => StageDisposition::Fail(ReasonCode::IntentMismatch),
    };
    stages.push(result(Stage::Intent, intent));

    let authority = if input.mandate.validate().is_ok() {
        StageDisposition::Pass
    } else {
        StageDisposition::Fail(ReasonCode::MandateInvalid)
    };
    stages.push(result(Stage::Authority, authority));

    let subject_matches = match &input.mandate.subject {
        MandateSubject::Identity(identity) => identity.as_slice() == input.expected_executor,
        MandateSubject::ExecutorClass(_) => {
            input.attempt.executor_identity == input.expected_executor
        }
    };
    let executor = if subject_matches
        && input.attempt.executor_identity.as_slice() == input.expected_executor
    {
        StageDisposition::Pass
    } else {
        StageDisposition::Fail(ReasonCode::WrongExecutor)
    };
    stages.push(result(Stage::Executor, executor));

    let temporal = if context.evaluation_time < input.mandate.valid_from {
        StageDisposition::Fail(ReasonCode::MandateNotYetValid)
    } else if context.evaluation_time >= input.mandate.expires_at {
        StageDisposition::Fail(ReasonCode::MandateExpired)
    } else {
        match (input.revocation_status, input.algorithm_status) {
            (RevocationStatus::Revoked, _) => StageDisposition::Fail(ReasonCode::MandateRevoked),
            (_, AlgorithmStatus::Disallowed) => {
                StageDisposition::Fail(ReasonCode::AlgorithmDisallowed)
            }
            (RevocationStatus::Unknown, _) => {
                StageDisposition::Indeterminate(ReasonCode::RevocationStatusUnknown)
            }
            (_, AlgorithmStatus::Unknown) => {
                StageDisposition::Indeterminate(ReasonCode::AlgorithmStatusUnknown)
            }
            (RevocationStatus::NotRevoked, AlgorithmStatus::Allowed) => StageDisposition::Pass,
        }
    };
    stages.push(result(Stage::Temporal, temporal));

    stages.push(result(
        Stage::Replay,
        match input.replay_status {
            ReplayStatus::Fresh => StageDisposition::Pass,
            ReplayStatus::Replayed => StageDisposition::Fail(ReasonCode::ReplayDetected),
            ReplayStatus::Unknown => {
                StageDisposition::Indeterminate(ReasonCode::ReplayStatusUnknown)
            }
        },
    ));

    let evidence_summary = summarize_evidence(input.evidence);
    let evidence = if validate_evidence_graph(input.evidence).is_err()
        || !authenticity_assessments_are_canonical(input.evidence, input.evidence_authenticity)
    {
        StageDisposition::Fail(ReasonCode::EvidenceInvalid)
    } else if receipt_references_missing(input.receipt, input.evidence) {
        StageDisposition::Fail(ReasonCode::EvidenceReferenceMissing)
    } else if input
        .evidence_authenticity
        .iter()
        .any(|(_, status)| *status == AuthenticityStatus::Rejected)
    {
        StageDisposition::Fail(ReasonCode::EvidenceAuthenticityRejected)
    } else if input
        .receipt
        .evidence_requirements_status
        .iter()
        .any(|status| !status.satisfied)
        || input
            .evidence
            .iter()
            .any(|(_, node)| matches!(node.kind, EvidenceKind::EvidenceGap { .. }))
    {
        StageDisposition::Indeterminate(ReasonCode::RequiredEvidenceMissing)
    } else if input
        .evidence_authenticity
        .iter()
        .any(|(_, status)| *status == AuthenticityStatus::Unknown)
        || input.evidence.iter().any(|(id, node)| {
            node.authenticity.is_some()
                && !input
                    .evidence_authenticity
                    .iter()
                    .any(|(assessed_id, _)| assessed_id == id)
        })
    {
        StageDisposition::Indeterminate(ReasonCode::EvidenceAuthenticityUnknown)
    } else if evidence_summary.withheld_locators > 0 {
        StageDisposition::Indeterminate(ReasonCode::SelectiveDisclosureLimitsEvaluation)
    } else {
        StageDisposition::Pass
    };
    stages.push(result(Stage::Evidence, evidence));

    stages.push(result(
        Stage::Receipt,
        if input
            .receipt
            .validate(input.mandate, input.attempt)
            .is_err()
        {
            StageDisposition::Fail(ReasonCode::ReceiptInvalid)
        } else if input.receipt.outcome == ExecutionOutcome::Unknown {
            StageDisposition::Indeterminate(ReasonCode::OutcomeAmbiguous)
        } else {
            StageDisposition::Pass
        },
    ));
    stages.push(result(
        Stage::DeferredPreservation,
        StageDisposition::Unsupported(ReasonCode::PreservationSemanticsDeferred),
    ));

    let disposition = if stages
        .iter()
        .any(|stage| matches!(stage.disposition, StageDisposition::Fail(_)))
    {
        VerificationDisposition::Invalid
    } else if stages
        .iter()
        .any(|stage| matches!(stage.disposition, StageDisposition::Indeterminate(_)))
    {
        VerificationDisposition::Indeterminate
    } else {
        VerificationDisposition::Valid
    };
    ContextBoundOutput::new(
        context,
        VerificationReport {
            disposition,
            stages,
            evidence_summary,
            temporal_context: TemporalContext {
                evaluation_time: context.evaluation_time,
                revocation_snapshot_digest: context.revocation_snapshot_digest,
                algorithm_policy_digest: context.algorithm_policy_digest,
            },
        },
    )
}

const fn result(stage: Stage, disposition: StageDisposition) -> StageResult {
    StageResult { stage, disposition }
}

fn summarize_evidence(evidence: &[(EvidenceNodeId, EvidenceNode)]) -> EvidenceSummary {
    let mut summary = EvidenceSummary::default();
    for (_, node) in evidence {
        match node.kind {
            EvidenceKind::Claim { .. } => summary.claims += 1,
            EvidenceKind::Observation { .. } => summary.observations += 1,
            EvidenceKind::Attestation { .. } => summary.attestations += 1,
            EvidenceKind::EvidenceGap { .. } => summary.gaps += 1,
        }
        if matches!(node.source_locator, SourceLocator::Withheld(_)) {
            summary.withheld_locators += 1;
        }
    }
    summary
}

fn authenticity_assessments_are_canonical(
    evidence: &[(EvidenceNodeId, EvidenceNode)],
    assessments: &[(EvidenceNodeId, AuthenticityStatus)],
) -> bool {
    assessments.windows(2).all(|pair| pair[0].0 < pair[1].0)
        && assessments.iter().all(|(id, _)| {
            evidence
                .iter()
                .any(|(evidence_id, node)| evidence_id == id && node.authenticity.is_some())
        })
}

fn receipt_references_missing(
    receipt: &ExecutionReceipt,
    evidence: &[(EvidenceNodeId, EvidenceNode)],
) -> bool {
    receipt
        .dispatch_evidence_refs
        .iter()
        .chain(&receipt.target_evidence_refs)
        .chain(
            receipt
                .evidence_requirements_status
                .iter()
                .flat_map(|status| &status.evidence_refs),
        )
        .any(|reference| !evidence.iter().any(|(id, _)| id == reference))
}
