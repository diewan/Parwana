//! Dimensioned assurance and gate-profile semantics.

use alloc::{string::String, vec::Vec};

use csv_hash::{AssuranceProfileDomain, DomainSeparatedHash, GateProfileDomain};

use crate::{AssuranceProfileId, EvidenceNodeId, GateProfileId, VerificationContextId};

/// Maximum reason codes, evidence references, or limitations per dimension.
pub const MAX_ASSURANCE_ITEMS: usize = 128;
/// Maximum reason-code or limitation byte length.
pub const MAX_ASSURANCE_TEXT_BYTES: usize = 512;

/// Independent assurance dimension. Declaration order is canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceDimension {
    /// Schema, canonical encoding, bounds, and references.
    Structural,
    /// Hashes, signatures, and algorithm policy.
    Cryptographic,
    /// Binding of keys to claimed identities.
    Identity,
    /// Pre-action mandate matching.
    Authority,
    /// Time, expiry, revocation, and algorithm status.
    Temporal,
    /// Reservation, consumption, and replay safety.
    SingleUse,
    /// Evidence of target acceptance or completion.
    Execution,
    /// Corroboration outside the reporting executor.
    ExternalCorroboration,
    /// Required evidence presence and assessability.
    Completeness,
    /// Collection, transfer, storage, and disclosure history.
    Custody,
    /// Continued verifiability under current policy.
    Preservation,
}

/// Complete canonical dimension list.
pub const ASSURANCE_DIMENSIONS: &[AssuranceDimension] = &[
    AssuranceDimension::Structural,
    AssuranceDimension::Cryptographic,
    AssuranceDimension::Identity,
    AssuranceDimension::Authority,
    AssuranceDimension::Temporal,
    AssuranceDimension::SingleUse,
    AssuranceDimension::Execution,
    AssuranceDimension::ExternalCorroboration,
    AssuranceDimension::Completeness,
    AssuranceDimension::Custody,
    AssuranceDimension::Preservation,
];

/// Four-valued result preserving uncertainty and applicability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DimensionStatus {
    /// Requirements for the dimension were met.
    Satisfied,
    /// Evidence establishes that requirements were not met.
    NotSatisfied,
    /// Available evidence or context cannot decide the dimension.
    Indeterminate,
    /// The selected profile declares the dimension inapplicable.
    NotApplicable,
}

/// Result for one independent assurance dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionResult {
    /// Dimension being evaluated.
    pub dimension: AssuranceDimension,
    /// Four-valued conclusion.
    pub status: DimensionStatus,
    /// Optional policy-defined level; never a universal score.
    pub assurance_level: Option<String>,
    /// Stable, canonically sorted reason codes.
    pub reason_codes: Vec<String>,
    /// Canonically sorted supporting evidence nodes.
    pub supporting_evidence_refs: Vec<EvidenceNodeId>,
    /// Explicit limitations on the conclusion.
    pub limitations: Vec<String>,
}

/// Complete non-scalar assurance result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssuranceProfile {
    /// Effective verification context.
    pub verification_context_id: VerificationContextId,
    /// Exactly one result for every dimension in canonical order.
    pub dimensions: Vec<DimensionResult>,
}

/// Invalid assurance or gate policy data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceError {
    /// Dimensions are missing, duplicated, or out of canonical order.
    InvalidDimensions,
    /// A bounded field or collection is malformed.
    InvalidField,
    /// A gate rule set is missing, duplicated, or out of canonical order.
    InvalidGateProfile,
}

impl AssuranceProfile {
    /// Validates complete dimension coverage and bounded reason material.
    pub fn validate(&self) -> Result<(), AssuranceError> {
        if self.dimensions.len() != ASSURANCE_DIMENSIONS.len()
            || self
                .dimensions
                .iter()
                .zip(ASSURANCE_DIMENSIONS)
                .any(|(result, expected)| result.dimension != *expected)
            || self.dimensions.iter().any(invalid_dimension)
        {
            return Err(AssuranceError::InvalidDimensions);
        }
        Ok(())
    }

    /// Returns deterministic canonical bytes without collapsing dimensions.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AssuranceError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(self.verification_context_id.as_bytes());
        push_u32(&mut out, self.dimensions.len() as u32);
        for result in &self.dimensions {
            out.push(dimension_tag(result.dimension));
            out.push(status_tag(result.status));
            push_option_text(&mut out, result.assurance_level.as_deref());
            push_texts(&mut out, &result.reason_codes);
            push_u32(&mut out, result.supporting_evidence_refs.len() as u32);
            for reference in &result.supporting_evidence_refs {
                out.extend_from_slice(reference.as_bytes());
            }
            push_texts(&mut out, &result.limitations);
        }
        Ok(out)
    }

    /// Derives the domain-separated identifier of the full dimensioned profile.
    pub fn id(&self) -> Result<AssuranceProfileId, AssuranceError> {
        let bytes = self.canonical_bytes()?;
        Ok(AssuranceProfileId::from_digest(
            DomainSeparatedHash::<AssuranceProfileDomain>::hash(&bytes).into_inner(),
        ))
    }
}

/// Gate handling for one dimension status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDisposition {
    /// This status does not prevent a pass.
    Allow,
    /// This status requires operator attention.
    Attention,
    /// This status blocks the gated operation.
    Block,
}

/// Hash-bound gate rule for one dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DimensionGateRule {
    /// Dimension controlled by this rule.
    pub dimension: AssuranceDimension,
    /// Handling of `Satisfied`.
    pub satisfied: GateDisposition,
    /// Handling of `NotSatisfied`.
    pub not_satisfied: GateDisposition,
    /// Handling of `Indeterminate`.
    pub indeterminate: GateDisposition,
    /// Handling of `NotApplicable`.
    pub not_applicable: GateDisposition,
}

/// Named policy mapping a dimensioned profile to an operator outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateProfile {
    /// Stable gate profile name.
    pub registry_id: String,
    /// Policy version.
    pub version: u16,
    /// Exactly one rule per assurance dimension.
    pub rules: Vec<DimensionGateRule>,
}

/// Operator-facing policy result. It never replaces the assurance dimensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateOutcome {
    /// All rules allow the observed statuses.
    Pass,
    /// No rule blocks, but at least one requires attention.
    AttentionRequired,
    /// At least one rule blocks.
    Block,
}

/// Gate result binding policy, context, and full assurance profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateResult {
    /// Exact gate policy.
    pub gate_profile_id: GateProfileId,
    /// Exact effective verification context.
    pub verification_context_id: VerificationContextId,
    /// Exact dimensioned assurance result.
    pub assurance_profile_id: AssuranceProfileId,
    /// Derived operator outcome.
    pub outcome: GateOutcome,
}

impl GateProfile {
    /// Validates complete rule coverage.
    pub fn validate(&self) -> Result<(), AssuranceError> {
        if self.registry_id.is_empty()
            || self.registry_id.len() > MAX_ASSURANCE_TEXT_BYTES
            || self.version == 0
            || self.rules.len() != ASSURANCE_DIMENSIONS.len()
            || self
                .rules
                .iter()
                .zip(ASSURANCE_DIMENSIONS)
                .any(|(rule, expected)| rule.dimension != *expected)
        {
            Err(AssuranceError::InvalidGateProfile)
        } else {
            Ok(())
        }
    }

    /// Derives the domain-separated identifier of the exact gate rules.
    pub fn id(&self) -> Result<GateProfileId, AssuranceError> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_text(&mut bytes, &self.registry_id);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        for rule in &self.rules {
            bytes.push(dimension_tag(rule.dimension));
            bytes.push(disposition_tag(rule.satisfied));
            bytes.push(disposition_tag(rule.not_satisfied));
            bytes.push(disposition_tag(rule.indeterminate));
            bytes.push(disposition_tag(rule.not_applicable));
        }
        Ok(GateProfileId::from_digest(
            DomainSeparatedHash::<GateProfileDomain>::hash(&bytes).into_inner(),
        ))
    }

    /// Applies rules without mutating or hiding the dimensioned profile.
    pub fn evaluate(&self, profile: &AssuranceProfile) -> Result<GateResult, AssuranceError> {
        self.validate()?;
        profile.validate()?;
        let mut outcome = GateOutcome::Pass;
        for (rule, result) in self.rules.iter().zip(&profile.dimensions) {
            let disposition = match result.status {
                DimensionStatus::Satisfied => rule.satisfied,
                DimensionStatus::NotSatisfied => rule.not_satisfied,
                DimensionStatus::Indeterminate => rule.indeterminate,
                DimensionStatus::NotApplicable => rule.not_applicable,
            };
            outcome = match (outcome, disposition) {
                (_, GateDisposition::Block) => GateOutcome::Block,
                (GateOutcome::Pass, GateDisposition::Attention) => GateOutcome::AttentionRequired,
                (current, _) => current,
            };
        }
        Ok(GateResult {
            gate_profile_id: self.id()?,
            verification_context_id: profile.verification_context_id,
            assurance_profile_id: profile.id()?,
            outcome,
        })
    }
}

fn invalid_dimension(result: &DimensionResult) -> bool {
    result.reason_codes.len() > MAX_ASSURANCE_ITEMS
        || result.supporting_evidence_refs.len() > MAX_ASSURANCE_ITEMS
        || result.limitations.len() > MAX_ASSURANCE_ITEMS
        || result
            .assurance_level
            .as_ref()
            .is_some_and(|value| invalid_text(value))
        || result.reason_codes.iter().any(|value| invalid_text(value))
        || result.limitations.iter().any(|value| invalid_text(value))
        || result
            .reason_codes
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || result.limitations.windows(2).any(|pair| pair[0] >= pair[1])
        || result
            .supporting_evidence_refs
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
}

fn invalid_text(value: &str) -> bool {
    value.is_empty()
        || value.len() > MAX_ASSURANCE_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
}

fn dimension_tag(value: AssuranceDimension) -> u8 {
    value as u8
}
fn status_tag(value: DimensionStatus) -> u8 {
    match value {
        DimensionStatus::Satisfied => 0,
        DimensionStatus::NotSatisfied => 1,
        DimensionStatus::Indeterminate => 2,
        DimensionStatus::NotApplicable => 3,
    }
}
fn disposition_tag(value: GateDisposition) -> u8 {
    match value {
        GateDisposition::Allow => 0,
        GateDisposition::Attention => 1,
        GateDisposition::Block => 2,
    }
}
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_text(out: &mut Vec<u8>, value: &str) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}
fn push_option_text(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            push_text(out, value);
        }
        None => out.push(0),
    }
}
fn push_texts(out: &mut Vec<u8>, values: &[String]) {
    push_u32(out, values.len() as u32);
    for value in values {
        push_text(out, value);
    }
}
