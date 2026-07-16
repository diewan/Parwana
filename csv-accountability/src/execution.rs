//! Canonical execution-attempt semantics.

use alloc::vec::Vec;

use csv_hash::{DomainSeparatedHash, ExecutionAttemptDomain};

use crate::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionMandate, AttemptId,
    ExecutionAttemptState, IntentId, MandateId, ObjectVersion, ProtocolVersion,
};

/// Maximum exported executor identity or provider correlation-key length.
pub const MAX_EXECUTION_IDENTITY_BYTES: usize = 512;
/// Maximum exported provider correlation-key length.
pub const MAX_CORRELATION_KEY_BYTES: usize = 1_024;

/// A malformed or inconsistently bound execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    /// The protocol or object version is unsupported.
    UnsupportedVersion,
    /// A required field is absent or outside its protocol bound.
    InvalidField(&'static str),
    /// The attempt names a different mandate or intent.
    BindingMismatch,
    /// Dispatch timestamps or state are inconsistent.
    InvalidState,
}

/// Export-safe record binding one reservation to one provider dispatch.
///
/// Only the reservation-token digest is present. The raw bearer token is not a
/// field of this protocol object and therefore cannot enter canonical exports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttempt {
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Schema version of this attempt.
    pub attempt_version: ObjectVersion,
    /// Reserved mandate.
    pub mandate_id: MandateId,
    /// Digest of the exact canonical mandate.
    pub mandate_digest: [u8; 32],
    /// Exact intent authorized by the mandate.
    pub intent_id: IntentId,
    /// Digest of the secret reservation token.
    pub reservation_token_digest: [u8; 32],
    /// Stable executor identity.
    pub executor_identity: Vec<u8>,
    /// Provider-visible or locally committed idempotency/correlation key.
    pub correlation_key: Vec<u8>,
    /// Attempt creation time in Unix seconds.
    pub started_at: u64,
    /// Time the request crossed the provider dispatch boundary, if it did.
    pub dispatch_boundary_at: Option<u64>,
    /// Digest of the exact provider request.
    pub provider_request_digest: [u8; 32],
    /// Digest of the provider response, when one was received.
    pub provider_response_digest: Option<[u8; 32]>,
    /// Current exported attempt projection.
    pub state: ExecutionAttemptState,
}

impl ExecutionAttempt {
    /// Validates bounds, timestamps, state consistency, and mandate binding.
    pub fn validate(&self, mandate: &ActionMandate) -> Result<(), ExecutionError> {
        if self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION
            || self.attempt_version != ACCOUNTABILITY_OBJECT_VERSION
        {
            return Err(ExecutionError::UnsupportedVersion);
        }
        if self.mandate_id != mandate.id().map_err(|_| ExecutionError::BindingMismatch)?
            || self.mandate_digest != *self.mandate_id.as_bytes()
            || self.intent_id != mandate.intent_id
        {
            return Err(ExecutionError::BindingMismatch);
        }
        validate_bytes(
            &self.executor_identity,
            "executor_identity",
            MAX_EXECUTION_IDENTITY_BYTES,
        )?;
        validate_bytes(
            &self.correlation_key,
            "correlation_key",
            MAX_CORRELATION_KEY_BYTES,
        )?;
        if self.reservation_token_digest == [0; 32] || self.provider_request_digest == [0; 32] {
            return Err(ExecutionError::InvalidField("digest"));
        }
        if self
            .dispatch_boundary_at
            .is_some_and(|timestamp| timestamp < self.started_at)
        {
            return Err(ExecutionError::InvalidState);
        }
        let dispatched = self.dispatch_boundary_at.is_some();
        let state_valid = match self.state {
            ExecutionAttemptState::Prepared => {
                !dispatched && self.provider_response_digest.is_none()
            }
            ExecutionAttemptState::Dispatching | ExecutionAttemptState::OutcomeAmbiguous => {
                dispatched && self.provider_response_digest.is_none()
            }
            ExecutionAttemptState::Accepted
            | ExecutionAttemptState::Rejected
            | ExecutionAttemptState::ReconciledAccepted
            | ExecutionAttemptState::ReconciledNotAccepted => {
                dispatched && self.provider_response_digest.is_some()
            }
            ExecutionAttemptState::AbandonedAmbiguous => dispatched,
        };
        if !state_valid {
            return Err(ExecutionError::InvalidState);
        }
        Ok(())
    }

    /// Returns deterministic canonical bytes used for the attempt identifier.
    pub fn canonical_bytes(&self, mandate: &ActionMandate) -> Result<Vec<u8>, ExecutionError> {
        self.validate(mandate)?;
        let mut out = Vec::new();
        push_u16(&mut out, self.protocol_version.major());
        push_u16(&mut out, self.protocol_version.minor());
        push_u16(&mut out, self.attempt_version.get());
        out.extend_from_slice(self.mandate_id.as_bytes());
        out.extend_from_slice(&self.mandate_digest);
        out.extend_from_slice(self.intent_id.as_bytes());
        out.extend_from_slice(&self.reservation_token_digest);
        push_bytes(&mut out, &self.executor_identity);
        push_bytes(&mut out, &self.correlation_key);
        push_u64(&mut out, self.started_at);
        push_option_u64(&mut out, self.dispatch_boundary_at);
        out.extend_from_slice(&self.provider_request_digest);
        push_option_digest(&mut out, self.provider_response_digest);
        out.push(state_tag(self.state));
        Ok(out)
    }

    /// Derives the domain-separated identifier of this exact attempt.
    pub fn id(&self, mandate: &ActionMandate) -> Result<AttemptId, ExecutionError> {
        let bytes = self.canonical_bytes(mandate)?;
        Ok(AttemptId::from_digest(
            DomainSeparatedHash::<ExecutionAttemptDomain>::hash(&bytes).into_inner(),
        ))
    }
}

fn validate_bytes(value: &[u8], field: &'static str, maximum: usize) -> Result<(), ExecutionError> {
    if value.is_empty() || value.len() > maximum {
        Err(ExecutionError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn state_tag(state: ExecutionAttemptState) -> u8 {
    match state {
        ExecutionAttemptState::Prepared => 0,
        ExecutionAttemptState::Dispatching => 1,
        ExecutionAttemptState::Accepted => 2,
        ExecutionAttemptState::Rejected => 3,
        ExecutionAttemptState::OutcomeAmbiguous => 4,
        ExecutionAttemptState::ReconciledAccepted => 5,
        ExecutionAttemptState::ReconciledNotAccepted => 6,
        ExecutionAttemptState::AbandonedAmbiguous => 7,
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
