//! Deterministic verification of the accountability vertical slice.
//!
//! The verifier performs no I/O and treats all live-state observations as
//! explicit inputs committed by [`VerificationContext`].

#![forbid(unsafe_code)]

use csv_accountability::{
    ActionIntent, ActionMandate, ContextBoundOutput, EvidenceKind, EvidenceNode, ExecutionAttempt,
    ExecutionReceipt, MandateSubject, VerificationContext, validate_evidence_graph,
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
    ReplayDetected,
    EvidenceInvalid,
    RequiredEvidenceMissing,
    SelectiveDisclosureLimitsEvaluation,
    ReceiptInvalid,
    PreservationSemanticsDeferred,
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
}

/// All inputs required by the pure verifier.
pub struct VerificationInput<'a> {
    pub intent: &'a ActionIntent,
    pub mandate: &'a ActionMandate,
    pub attempt: &'a ExecutionAttempt,
    pub receipt: &'a ExecutionReceipt,
    pub evidence: &'a [(csv_accountability::EvidenceNodeId, EvidenceNode)],
    pub expected_executor: &'a [u8],
    pub revoked: bool,
    pub replayed: bool,
    pub selectively_disclosed: bool,
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
    } else if input.revoked {
        StageDisposition::Fail(ReasonCode::MandateRevoked)
    } else {
        StageDisposition::Pass
    };
    stages.push(result(Stage::Temporal, temporal));

    stages.push(result(
        Stage::Replay,
        if input.replayed {
            StageDisposition::Fail(ReasonCode::ReplayDetected)
        } else {
            StageDisposition::Pass
        },
    ));

    let evidence = if validate_evidence_graph(input.evidence).is_err() {
        StageDisposition::Fail(ReasonCode::EvidenceInvalid)
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
    } else if input.selectively_disclosed {
        StageDisposition::Indeterminate(ReasonCode::SelectiveDisclosureLimitsEvaluation)
    } else {
        StageDisposition::Pass
    };
    stages.push(result(Stage::Evidence, evidence));

    stages.push(result(
        Stage::Receipt,
        if input.receipt.validate(input.mandate, input.attempt).is_ok() {
            StageDisposition::Pass
        } else {
            StageDisposition::Fail(ReasonCode::ReceiptInvalid)
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
        },
    )
}

const fn result(stage: Stage, disposition: StageDisposition) -> StageResult {
    StageResult { stage, disposition }
}
