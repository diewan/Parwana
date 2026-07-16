//! Canonical execution-receipt semantics.

use alloc::{string::String, vec::Vec};

use csv_hash::{DomainSeparatedHash, ExecutionReceiptDomain};

use crate::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionMandate, AttemptId,
    EvidenceNodeId, ExecutionAttempt, ExecutionAttemptState, ExecutionError, IntentId, MandateId,
    ObjectVersion, ProtocolVersion, ReceiptId,
};

/// Maximum evidence references or requirement-status entries on one receipt.
pub const MAX_RECEIPT_EVIDENCE_ITEMS: usize = 128;
/// Maximum registered requirement identifier length.
pub const MAX_RECEIPT_REGISTRY_ID_BYTES: usize = 128;
/// Maximum producer signature length.
pub const MAX_RECEIPT_SIGNATURE_BYTES: usize = 8_192;

/// Best available reported outcome. `Unknown` is never inferred as success or failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// The target action completed successfully.
    Succeeded,
    /// The target accepted the action but it completed unsuccessfully.
    Failed,
    /// The provider definitely rejected before acceptance.
    Rejected,
    /// Available evidence cannot establish a success, failure, or rejection.
    Unknown,
}

/// Exported mandate-consumption journal commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumptionRecord {
    /// Revision at which consumption or terminal closure was recorded.
    pub mandate_revision: u64,
    /// Digest of the immutable journal entry.
    pub journal_entry_digest: [u8; 32],
}

/// Whether one mandate evidence requirement was satisfied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRequirementStatus {
    /// Registered requirement identifier copied from the mandate.
    pub registry_id: String,
    /// Exact requirement-parameters commitment.
    pub parameters_digest: [u8; 32],
    /// Whether the producer reports the requirement as satisfied.
    pub satisfied: bool,
    /// Evidence nodes supporting the report.
    pub evidence_refs: Vec<EvidenceNodeId>,
}

/// A malformed or inconsistently bound execution receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    /// The protocol or object version is unsupported.
    UnsupportedVersion,
    /// Attempt validation failed.
    InvalidAttempt,
    /// The receipt names another mandate, intent, or attempt.
    BindingMismatch,
    /// Outcome, attempt state, or timestamps disagree.
    OutcomeMismatch,
    /// A bounded field or collection is malformed.
    InvalidField(&'static str),
    /// Requirement statuses do not exactly cover the mandate requirements.
    InvalidEvidenceRequirements,
}

/// Signed producer report binding authority, dispatch, evidence, and outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionReceipt {
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Schema version of this receipt.
    pub receipt_version: ObjectVersion,
    /// Mandate under which dispatch occurred.
    pub mandate_id: MandateId,
    /// Digest of the exact canonical mandate.
    pub mandate_digest: [u8; 32],
    /// Exact intent authorized and dispatched.
    pub intent_id: IntentId,
    /// Exact attempt being reported.
    pub attempt_id: AttemptId,
    /// Stable executor identity copied from the attempt.
    pub executor_identity: Vec<u8>,
    /// Commitment to the terminal mandate journal entry.
    pub consumption_record: ConsumptionRecord,
    /// Evidence originating at dispatch/executor boundaries.
    pub dispatch_evidence_refs: Vec<EvidenceNodeId>,
    /// Evidence originating at the target/provider boundary.
    pub target_evidence_refs: Vec<EvidenceNodeId>,
    /// Attempt start time.
    pub started_at: u64,
    /// Completion time, absent when outcome remains unknown.
    pub completed_at: Option<u64>,
    /// Best available reported outcome.
    pub outcome: ExecutionOutcome,
    /// Optional commitment to result data; raw result data is not embedded.
    pub result_commitment: Option<[u8; 32]>,
    /// Exact status of every mandate evidence requirement.
    pub evidence_requirements_status: Vec<EvidenceRequirementStatus>,
    /// Stable identity of the receipt producer.
    pub producer_identity: Vec<u8>,
    /// Detached producer signature bytes.
    pub producer_signature: Vec<u8>,
}

impl ExecutionReceipt {
    /// Validates binding, outcome semantics, bounds, and requirement coverage.
    pub fn validate(
        &self,
        mandate: &ActionMandate,
        attempt: &ExecutionAttempt,
    ) -> Result<(), ReceiptError> {
        if self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION
            || self.receipt_version != ACCOUNTABILITY_OBJECT_VERSION
        {
            return Err(ReceiptError::UnsupportedVersion);
        }
        attempt.validate(mandate).map_err(map_execution_error)?;
        if self.mandate_id != attempt.mandate_id
            || self.mandate_digest != attempt.mandate_digest
            || self.intent_id != attempt.intent_id
            || self.attempt_id
                != attempt
                    .id(mandate)
                    .map_err(|_| ReceiptError::InvalidAttempt)?
            || self.executor_identity != attempt.executor_identity
            || self.started_at != attempt.started_at
        {
            return Err(ReceiptError::BindingMismatch);
        }
        validate_bytes(&self.producer_identity, "producer_identity", 512)?;
        validate_bytes(
            &self.producer_signature,
            "producer_signature",
            MAX_RECEIPT_SIGNATURE_BYTES,
        )?;
        if self.consumption_record.journal_entry_digest == [0; 32]
            || self
                .completed_at
                .is_some_and(|completed| completed < self.started_at)
            || self
                .result_commitment
                .is_some_and(|commitment| commitment == [0; 32])
        {
            return Err(ReceiptError::InvalidField("receipt"));
        }
        let outcome_valid = match self.outcome {
            ExecutionOutcome::Succeeded | ExecutionOutcome::Failed => {
                matches!(
                    attempt.state,
                    ExecutionAttemptState::Accepted | ExecutionAttemptState::ReconciledAccepted
                ) && self.completed_at.is_some()
            }
            ExecutionOutcome::Rejected => {
                attempt.state == ExecutionAttemptState::Rejected
                    && self.completed_at.is_some()
                    && self.result_commitment.is_none()
            }
            ExecutionOutcome::Unknown => matches!(
                attempt.state,
                ExecutionAttemptState::OutcomeAmbiguous | ExecutionAttemptState::AbandonedAmbiguous
            ),
        };
        if !outcome_valid {
            return Err(ReceiptError::OutcomeMismatch);
        }
        validate_refs(&self.dispatch_evidence_refs)?;
        validate_refs(&self.target_evidence_refs)?;
        validate_requirement_statuses(self, mandate)?;
        Ok(())
    }

    /// Returns deterministic canonical bytes used for signing and identification.
    pub fn canonical_bytes(
        &self,
        mandate: &ActionMandate,
        attempt: &ExecutionAttempt,
    ) -> Result<Vec<u8>, ReceiptError> {
        self.validate(mandate, attempt)?;
        let mut out = Vec::new();
        push_u16(&mut out, self.protocol_version.major());
        push_u16(&mut out, self.protocol_version.minor());
        push_u16(&mut out, self.receipt_version.get());
        out.extend_from_slice(self.mandate_id.as_bytes());
        out.extend_from_slice(&self.mandate_digest);
        out.extend_from_slice(self.intent_id.as_bytes());
        out.extend_from_slice(self.attempt_id.as_bytes());
        push_bytes(&mut out, &self.executor_identity);
        push_u64(&mut out, self.consumption_record.mandate_revision);
        out.extend_from_slice(&self.consumption_record.journal_entry_digest);
        push_refs(&mut out, &self.dispatch_evidence_refs);
        push_refs(&mut out, &self.target_evidence_refs);
        push_u64(&mut out, self.started_at);
        push_option_u64(&mut out, self.completed_at);
        out.push(outcome_tag(self.outcome));
        push_option_digest(&mut out, self.result_commitment);
        push_u32(&mut out, self.evidence_requirements_status.len() as u32);
        for status in &self.evidence_requirements_status {
            push_bytes(&mut out, status.registry_id.as_bytes());
            out.extend_from_slice(&status.parameters_digest);
            out.push(u8::from(status.satisfied));
            push_refs(&mut out, &status.evidence_refs);
        }
        push_bytes(&mut out, &self.producer_identity);
        push_bytes(&mut out, &self.producer_signature);
        Ok(out)
    }

    /// Derives the domain-separated identifier of this exact signed receipt.
    pub fn id(
        &self,
        mandate: &ActionMandate,
        attempt: &ExecutionAttempt,
    ) -> Result<ReceiptId, ReceiptError> {
        let bytes = self.canonical_bytes(mandate, attempt)?;
        Ok(ReceiptId::from_digest(
            DomainSeparatedHash::<ExecutionReceiptDomain>::hash(&bytes).into_inner(),
        ))
    }
}

fn map_execution_error(_: ExecutionError) -> ReceiptError {
    ReceiptError::InvalidAttempt
}

fn validate_bytes(value: &[u8], field: &'static str, maximum: usize) -> Result<(), ReceiptError> {
    if value.is_empty() || value.len() > maximum {
        Err(ReceiptError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_refs(refs: &[EvidenceNodeId]) -> Result<(), ReceiptError> {
    if refs.len() > MAX_RECEIPT_EVIDENCE_ITEMS || refs.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(ReceiptError::InvalidField("evidence_refs"))
    } else {
        Ok(())
    }
}

fn validate_requirement_statuses(
    receipt: &ExecutionReceipt,
    mandate: &ActionMandate,
) -> Result<(), ReceiptError> {
    let statuses = &receipt.evidence_requirements_status;
    if statuses.len() != mandate.evidence_requirements.len()
        || statuses.len() > MAX_RECEIPT_EVIDENCE_ITEMS
    {
        return Err(ReceiptError::InvalidEvidenceRequirements);
    }
    for (status, requirement) in statuses.iter().zip(&mandate.evidence_requirements) {
        if status.registry_id != requirement.registry_id
            || status.parameters_digest != requirement.parameters_digest
            || status.registry_id.is_empty()
            || status.registry_id.len() > MAX_RECEIPT_REGISTRY_ID_BYTES
            || (status.satisfied && status.evidence_refs.is_empty())
            || (!status.satisfied && !status.evidence_refs.is_empty())
        {
            return Err(ReceiptError::InvalidEvidenceRequirements);
        }
        validate_refs(&status.evidence_refs)?;
    }
    Ok(())
}

fn outcome_tag(outcome: ExecutionOutcome) -> u8 {
    match outcome {
        ExecutionOutcome::Succeeded => 0,
        ExecutionOutcome::Failed => 1,
        ExecutionOutcome::Rejected => 2,
        ExecutionOutcome::Unknown => 3,
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn push_refs(out: &mut Vec<u8>, refs: &[EvidenceNodeId]) {
    push_u32(out, refs.len() as u32);
    for reference in refs {
        out.extend_from_slice(reference.as_bytes());
    }
}

fn push_option_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            push_u64(out, value);
        }
        None => out.push(0),
    }
}

fn push_option_digest(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}
