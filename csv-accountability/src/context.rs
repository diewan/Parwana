//! Hash-bound verification-context semantics.

use alloc::{string::String, vec::Vec};

use csv_hash::{DomainSeparatedHash, VerificationContextDomain};

use crate::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ObjectVersion, ProtocolVersion,
    VerificationContextId,
};

/// Maximum context extensions.
pub const MAX_CONTEXT_EXTENSIONS: usize = 64;
/// Maximum extension registry identifier length.
pub const MAX_CONTEXT_EXTENSION_ID_BYTES: usize = 128;

/// Hash-bound extension to the verification rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextExtension {
    /// Stable namespaced extension identifier.
    pub registry_id: String,
    /// Commitment to exact extension parameters.
    pub parameters_digest: [u8; 32],
}

/// Complete deterministic input controlling one verification evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationContext {
    /// Context schema version.
    pub context_version: ObjectVersion,
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Fixed evaluation time in Unix seconds.
    pub evaluation_time: u64,
    /// Commitment to verifier policy and enabled rules.
    pub verifier_policy_digest: [u8; 32],
    /// Commitment to trusted identities and keys.
    pub trust_package_digest: [u8; 32],
    /// Commitment to the revocation snapshot used.
    pub revocation_snapshot_digest: [u8; 32],
    /// Commitment to allowed cryptographic algorithms and status.
    pub algorithm_policy_digest: [u8; 32],
    /// Commitment to rules for external evidence.
    pub external_evidence_policy_digest: [u8; 32],
    /// Commitment to dimension-specific assurance thresholds.
    pub assurance_thresholds_digest: [u8; 32],
    /// Canonically sorted additional rule commitments.
    pub extensions: Vec<ContextExtension>,
}

/// Invalid verification-context data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextError {
    /// Context or protocol version is unsupported.
    UnsupportedVersion,
    /// A required digest is zero.
    MissingPolicyDigest,
    /// Extensions are malformed, duplicated, unsorted, or excessive.
    InvalidExtensions,
}

impl VerificationContext {
    /// Validates all hash-bound verification inputs.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.context_version != ACCOUNTABILITY_OBJECT_VERSION
            || self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION
        {
            return Err(ContextError::UnsupportedVersion);
        }
        if [
            self.verifier_policy_digest,
            self.trust_package_digest,
            self.revocation_snapshot_digest,
            self.algorithm_policy_digest,
            self.external_evidence_policy_digest,
            self.assurance_thresholds_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(ContextError::MissingPolicyDigest);
        }
        if self.extensions.len() > MAX_CONTEXT_EXTENSIONS
            || self.extensions.iter().any(|extension| {
                extension.registry_id.is_empty()
                    || extension.registry_id.len() > MAX_CONTEXT_EXTENSION_ID_BYTES
                    || extension.registry_id.trim() != extension.registry_id
                    || !extension.registry_id.is_ascii()
                    || extension.parameters_digest == [0; 32]
            })
            || self
                .extensions
                .windows(2)
                .any(|pair| pair[0].registry_id >= pair[1].registry_id)
        {
            return Err(ContextError::InvalidExtensions);
        }
        Ok(())
    }

    /// Returns deterministic canonical bytes for independent implementations.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContextError> {
        self.validate()?;
        let mut out = Vec::new();
        push_u16(&mut out, self.context_version.get());
        push_u16(&mut out, self.protocol_version.major());
        push_u16(&mut out, self.protocol_version.minor());
        push_u64(&mut out, self.evaluation_time);
        for digest in [
            self.verifier_policy_digest,
            self.trust_package_digest,
            self.revocation_snapshot_digest,
            self.algorithm_policy_digest,
            self.external_evidence_policy_digest,
            self.assurance_thresholds_digest,
        ] {
            out.extend_from_slice(&digest);
        }
        push_u32(&mut out, self.extensions.len() as u32);
        for extension in &self.extensions {
            push_bytes(&mut out, extension.registry_id.as_bytes());
            out.extend_from_slice(&extension.parameters_digest);
        }
        Ok(out)
    }

    /// Derives the domain-separated identifier of the effective context.
    pub fn id(&self) -> Result<VerificationContextId, ContextError> {
        let bytes = self.canonical_bytes()?;
        Ok(VerificationContextId::from_digest(
            DomainSeparatedHash::<VerificationContextDomain>::hash(&bytes).into_inner(),
        ))
    }
}

/// Verification output envelope that always echoes its effective context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextBoundOutput<T> {
    /// Digest of the exact effective context.
    pub verification_context_id: VerificationContextId,
    /// Deterministic verifier result.
    pub result: T,
}

impl<T> ContextBoundOutput<T> {
    /// Constructs an output only from a valid effective context.
    pub fn new(context: &VerificationContext, result: T) -> Result<Self, ContextError> {
        Ok(Self {
            verification_context_id: context.id()?,
            result,
        })
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
