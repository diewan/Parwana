//! Canonical pre-action authority and its detached signature envelope.

use alloc::{string::String, vec::Vec};

use csv_codec::manual_encoder::ManualEncoder;
use csv_hash::{ActionMandateDomain, DomainSeparatedHash};

use crate::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, IntentId, MandateId,
    ObjectVersion, ProtocolVersion,
};

/// Maximum encoded identity or authority-domain length.
pub const MAX_MANDATE_IDENTITY_BYTES: usize = 512;
/// Maximum number of registered constraints or evidence requirements.
pub const MAX_MANDATE_REQUIREMENTS: usize = 64;
/// Maximum registered identifier length.
pub const MAX_REGISTRY_ID_BYTES: usize = 128;
/// Maximum detached signature length.
pub const MAX_SIGNATURE_BYTES: usize = 8192;
/// Maximum signer key identifier length.
pub const MAX_KEY_ID_BYTES: usize = 512;
/// Algorithm identifier for the first supported mandate signature envelope.
pub const ED25519_SIGNATURE_ALGORITHM: &str = "org.diewan.signature.ed25519.v1";

/// A failure to construct, decode, or validate an action mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MandateError {
    /// The protocol, object, policy, or envelope version is unsupported.
    UnsupportedVersion,
    /// A required field is empty or exceeds its bound.
    InvalidField(&'static str),
    /// The validity interval or issue time is inconsistent.
    InvalidValidity,
    /// First-slice mandates must permit exactly one dispatch.
    InvalidDispatchLimit,
    /// A collection is empty, too large, duplicated, or not canonically ordered.
    InvalidRequirements,
    /// The signature envelope is malformed or uses an unsupported algorithm.
    InvalidSignatureEnvelope,
    /// Canonical bytes are truncated, malformed, or have trailing data.
    InvalidEncoding,
}

/// The executor to whom authority is granted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MandateSubject {
    /// One stable executor identity.
    Identity(Vec<u8>),
    /// A registered executor class controlled by the issuing authority.
    ExecutorClass(String),
}

/// A registered, hash-bound mandate condition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateRequirement {
    /// Stable namespaced requirement identifier.
    pub registry_id: String,
    /// Commitment to the exact requirement parameters.
    pub parameters_digest: [u8; 32],
}

/// A registered policy controlling execution of the authorized action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPolicy {
    /// Stable namespaced policy identifier.
    pub registry_id: String,
    /// Commitment to the exact policy parameters.
    pub parameters_digest: [u8; 32],
}

/// Requirements that a valid signature envelope must satisfy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureRequirements {
    /// Registered signature algorithm.
    pub algorithm: String,
    /// Stable issuer-controlled verification-key identifier.
    pub key_id: Vec<u8>,
}

/// Canonical pre-action authority for one exact intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionMandate {
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Schema version of this mandate.
    pub mandate_version: ObjectVersion,
    /// Exact canonical intent digest being authorized.
    pub intent_id: IntentId,
    /// Stable issuing identity.
    pub issuer_identity: Vec<u8>,
    /// Exact identity or registered executor class allowed to execute.
    pub subject: MandateSubject,
    /// Tenant or authority domain within which this authority is valid.
    pub authority_domain: Vec<u8>,
    /// Inclusive first valid Unix timestamp in seconds.
    pub valid_from: u64,
    /// Exclusive expiry Unix timestamp in seconds.
    pub expires_at: u64,
    /// Maximum dispatch count; fixed to one in the first slice.
    pub maximum_dispatches: u32,
    /// Canonically ordered, registered constraints.
    pub constraints: Vec<MandateRequirement>,
    /// Canonically ordered evidence requirements.
    pub evidence_requirements: Vec<MandateRequirement>,
    /// Exact execution policy.
    pub execution_policy: ExecutionPolicy,
    /// Optional parent authority.
    pub parent_mandate: Option<MandateId>,
    /// Optional commitment to a revocation registry or snapshot reference.
    pub revocation_reference: Option<[u8; 32]>,
    /// Unix timestamp at which the authority was issued.
    pub issued_at: u64,
    /// Issuer-generated anti-replay nonce.
    pub nonce: [u8; 32],
    /// Required algorithm and verification key.
    pub signature_requirements: SignatureRequirements,
}

impl ActionMandate {
    /// Validates every mandate invariant without consulting live state.
    pub fn validate(&self) -> Result<(), MandateError> {
        if self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION
            || self.mandate_version != ACCOUNTABILITY_OBJECT_VERSION
        {
            return Err(MandateError::UnsupportedVersion);
        }
        validate_bytes(
            &self.issuer_identity,
            "issuer_identity",
            MAX_MANDATE_IDENTITY_BYTES,
        )?;
        validate_bytes(
            &self.authority_domain,
            "authority_domain",
            MAX_MANDATE_IDENTITY_BYTES,
        )?;
        match &self.subject {
            MandateSubject::Identity(identity) => {
                validate_bytes(identity, "subject_identity", MAX_MANDATE_IDENTITY_BYTES)?;
            }
            MandateSubject::ExecutorClass(class) => validate_registry_id(class)?,
        }
        if self.valid_from >= self.expires_at || self.issued_at > self.valid_from {
            return Err(MandateError::InvalidValidity);
        }
        if self.maximum_dispatches != 1 {
            return Err(MandateError::InvalidDispatchLimit);
        }
        validate_requirements(&self.constraints, false)?;
        validate_requirements(&self.evidence_requirements, true)?;
        validate_registry_id(&self.execution_policy.registry_id)?;
        if self.signature_requirements.algorithm != ED25519_SIGNATURE_ALGORITHM
            || self.signature_requirements.key_id.is_empty()
            || self.signature_requirements.key_id.len() > MAX_KEY_ID_BYTES
        {
            return Err(MandateError::InvalidSignatureEnvelope);
        }
        Ok(())
    }

    /// Returns whether `timestamp` is inside the half-open validity interval.
    pub fn is_valid_at(&self, timestamp: u64) -> Result<bool, MandateError> {
        self.validate()?;
        Ok(timestamp >= self.valid_from && timestamp < self.expires_at)
    }

    /// Returns canonical bytes that are hashed and signed.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MandateError> {
        self.validate()?;
        let mut out = Vec::new();
        push_u16(&mut out, self.protocol_version.major());
        push_u16(&mut out, self.protocol_version.minor());
        push_u16(&mut out, self.mandate_version.get());
        out.extend_from_slice(self.intent_id.as_bytes());
        push_bytes(&mut out, &self.issuer_identity);
        match &self.subject {
            MandateSubject::Identity(identity) => {
                out.push(0);
                push_bytes(&mut out, identity);
            }
            MandateSubject::ExecutorClass(class) => {
                out.push(1);
                push_string(&mut out, class);
            }
        }
        push_bytes(&mut out, &self.authority_domain);
        push_u64(&mut out, self.valid_from);
        push_u64(&mut out, self.expires_at);
        push_u32(&mut out, self.maximum_dispatches);
        push_requirements(&mut out, &self.constraints);
        push_requirements(&mut out, &self.evidence_requirements);
        push_string(&mut out, &self.execution_policy.registry_id);
        out.extend_from_slice(&self.execution_policy.parameters_digest);
        push_optional_id(&mut out, self.parent_mandate);
        push_optional_digest(&mut out, self.revocation_reference);
        push_u64(&mut out, self.issued_at);
        out.extend_from_slice(&self.nonce);
        push_string(&mut out, &self.signature_requirements.algorithm);
        push_bytes(&mut out, &self.signature_requirements.key_id);
        Ok(out)
    }

    /// Decodes and validates the unique canonical representation.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, MandateError> {
        let mut cursor = Cursor::new(bytes);
        let protocol_version = ProtocolVersion::new(cursor.u16()?, cursor.u16()?);
        let mandate_version =
            ObjectVersion::try_new(cursor.u16()?).map_err(|_| MandateError::UnsupportedVersion)?;
        let intent_id = IntentId::from_digest(cursor.digest()?);
        let issuer_identity = cursor.bytes()?;
        let subject = match cursor.byte()? {
            0 => MandateSubject::Identity(cursor.bytes()?),
            1 => MandateSubject::ExecutorClass(cursor.string()?),
            _ => return Err(MandateError::InvalidEncoding),
        };
        let authority_domain = cursor.bytes()?;
        let valid_from = cursor.u64()?;
        let expires_at = cursor.u64()?;
        let maximum_dispatches = cursor.u32()?;
        let constraints = cursor.requirements()?;
        let evidence_requirements = cursor.requirements()?;
        let execution_policy = ExecutionPolicy {
            registry_id: cursor.string()?,
            parameters_digest: cursor.digest()?,
        };
        let parent_mandate = cursor.optional_id()?;
        let revocation_reference = cursor.optional_digest()?;
        let issued_at = cursor.u64()?;
        let nonce = cursor.digest()?;
        let signature_requirements = SignatureRequirements {
            algorithm: cursor.string()?,
            key_id: cursor.bytes()?,
        };
        cursor.finish()?;
        let mandate = Self {
            protocol_version,
            mandate_version,
            intent_id,
            issuer_identity,
            subject,
            authority_domain,
            valid_from,
            expires_at,
            maximum_dispatches,
            constraints,
            evidence_requirements,
            execution_policy,
            parent_mandate,
            revocation_reference,
            issued_at,
            nonce,
            signature_requirements,
        };
        mandate.validate()?;
        Ok(mandate)
    }

    /// Returns the domain-separated content identifier of the unsigned mandate body.
    pub fn id(&self) -> Result<MandateId, MandateError> {
        let canonical = self.canonical_bytes()?;
        Ok(MandateId::from_digest(
            DomainSeparatedHash::<ActionMandateDomain>::hash_multiple([
                b"action-mandate-v1".as_slice(),
                canonical.as_slice(),
            ])
            .into_inner(),
        ))
    }

    /// Returns the exact message a signature envelope must authenticate.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, MandateError> {
        Ok(self.id()?.into_bytes().to_vec())
    }
}

/// Detached signature over an [`ActionMandate`]'s signing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateSignatureEnvelope {
    /// Envelope schema version.
    pub version: ObjectVersion,
    /// Registered signature algorithm.
    pub algorithm: String,
    /// Stable key identifier, which must match the mandate requirement.
    pub key_id: Vec<u8>,
    /// Algorithm-specific detached signature bytes.
    pub signature: Vec<u8>,
}

impl MandateSignatureEnvelope {
    /// Validates structural binding to a mandate's signature requirements.
    pub fn validate_for(&self, mandate: &ActionMandate) -> Result<(), MandateError> {
        mandate.validate()?;
        if self.version != ACCOUNTABILITY_OBJECT_VERSION {
            return Err(MandateError::UnsupportedVersion);
        }
        if self.algorithm != mandate.signature_requirements.algorithm
            || self.key_id != mandate.signature_requirements.key_id
            || self.algorithm != ED25519_SIGNATURE_ALGORITHM
            || self.signature.len() != 64
            || self.signature.len() > MAX_SIGNATURE_BYTES
        {
            return Err(MandateError::InvalidSignatureEnvelope);
        }
        Ok(())
    }

    /// Encodes the detached envelope canonically after validating its mandate binding.
    pub fn canonical_bytes(&self, mandate: &ActionMandate) -> Result<Vec<u8>, MandateError> {
        self.validate_for(mandate)?;
        let mut out = Vec::new();
        push_u16(&mut out, self.version.get());
        push_string(&mut out, &self.algorithm);
        push_bytes(&mut out, &self.key_id);
        push_bytes(&mut out, &self.signature);
        Ok(out)
    }

    /// Decodes and validates an envelope for the supplied mandate.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        mandate: &ActionMandate,
    ) -> Result<Self, MandateError> {
        let mut cursor = Cursor::new(bytes);
        let version =
            ObjectVersion::try_new(cursor.u16()?).map_err(|_| MandateError::UnsupportedVersion)?;
        let envelope = Self {
            version,
            algorithm: cursor.string()?,
            key_id: cursor.bytes()?,
            signature: cursor.bytes()?,
        };
        cursor.finish()?;
        envelope.validate_for(mandate)?;
        Ok(envelope)
    }
}

fn validate_bytes(value: &[u8], field: &'static str, maximum: usize) -> Result<(), MandateError> {
    if value.is_empty() || value.len() > maximum {
        Err(MandateError::InvalidField(field))
    } else {
        Ok(())
    }
}
fn validate_registry_id(value: &str) -> Result<(), MandateError> {
    if value.is_empty()
        || value.len() > MAX_REGISTRY_ID_BYTES
        || value.trim() != value
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(MandateError::InvalidField("registry_id"))
    } else {
        Ok(())
    }
}
fn validate_requirements(
    values: &[MandateRequirement],
    require_nonempty: bool,
) -> Result<(), MandateError> {
    if values.len() > MAX_MANDATE_REQUIREMENTS || (require_nonempty && values.is_empty()) {
        return Err(MandateError::InvalidRequirements);
    }
    for value in values {
        validate_registry_id(&value.registry_id)?;
    }
    if values
        .windows(2)
        .any(|pair| pair[0].registry_id >= pair[1].registry_id)
    {
        return Err(MandateError::InvalidRequirements);
    }
    Ok(())
}
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&ManualEncoder::encode_u32_le(value));
}
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&ManualEncoder::encode_u64_le(value));
}
fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&ManualEncoder::encode_bytes(value));
}
fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}
fn push_requirements(out: &mut Vec<u8>, values: &[MandateRequirement]) {
    push_u32(out, values.len() as u32);
    for value in values {
        push_string(out, &value.registry_id);
        out.extend_from_slice(&value.parameters_digest);
    }
}
fn push_optional_id(out: &mut Vec<u8>, value: Option<MandateId>) {
    match value {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(id.as_bytes());
        }
        None => out.push(0),
    }
}
fn push_optional_digest(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(&digest);
        }
        None => out.push(0),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], MandateError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(MandateError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MandateError::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, MandateError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, MandateError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| MandateError::InvalidEncoding)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, MandateError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| MandateError::InvalidEncoding)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, MandateError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| MandateError::InvalidEncoding)?,
        ))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, MandateError> {
        let length = self.u32()? as usize;
        if length > MAX_SIGNATURE_BYTES {
            return Err(MandateError::InvalidEncoding);
        }
        Ok(self.take(length)?.to_vec())
    }
    fn string(&mut self) -> Result<String, MandateError> {
        String::from_utf8(self.bytes()?).map_err(|_| MandateError::InvalidEncoding)
    }
    fn digest(&mut self) -> Result<[u8; 32], MandateError> {
        self.take(32)?
            .try_into()
            .map_err(|_| MandateError::InvalidEncoding)
    }
    fn requirements(&mut self) -> Result<Vec<MandateRequirement>, MandateError> {
        let count = self.u32()? as usize;
        if count > MAX_MANDATE_REQUIREMENTS {
            return Err(MandateError::InvalidRequirements);
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(MandateRequirement {
                registry_id: self.string()?,
                parameters_digest: self.digest()?,
            });
        }
        Ok(values)
    }
    fn optional_id(&mut self) -> Result<Option<MandateId>, MandateError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(MandateId::from_digest(self.digest()?))),
            _ => Err(MandateError::InvalidEncoding),
        }
    }
    fn optional_digest(&mut self) -> Result<Option<[u8; 32]>, MandateError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.digest()?)),
            _ => Err(MandateError::InvalidEncoding),
        }
    }
    fn finish(self) -> Result<(), MandateError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MandateError::InvalidEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn mandate() -> ActionMandate {
        ActionMandate {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            mandate_version: ACCOUNTABILITY_OBJECT_VERSION,
            intent_id: IntentId::from_digest([1; 32]),
            issuer_identity: vec![2; 32],
            subject: MandateSubject::Identity(vec![3; 32]),
            authority_domain: b"tenant:acme".to_vec(),
            valid_from: 100,
            expires_at: 200,
            maximum_dispatches: 1,
            constraints: vec![MandateRequirement {
                registry_id: "org.diewan.constraint.exact-target.v1".to_string(),
                parameters_digest: [4; 32],
            }],
            evidence_requirements: vec![MandateRequirement {
                registry_id: "org.diewan.evidence.github-deployment.v1".to_string(),
                parameters_digest: [5; 32],
            }],
            execution_policy: ExecutionPolicy {
                registry_id: "org.diewan.execution.single-dispatch.v1".to_string(),
                parameters_digest: [6; 32],
            },
            parent_mandate: None,
            revocation_reference: Some([7; 32]),
            issued_at: 90,
            nonce: [8; 32],
            signature_requirements: SignatureRequirements {
                algorithm: ED25519_SIGNATURE_ALGORITHM.to_string(),
                key_id: b"issuer-key-1".to_vec(),
            },
        }
    }

    #[test]
    fn canonical_mandate_and_signature_envelope_round_trip() {
        let mandate = mandate();
        let encoded = mandate.canonical_bytes().unwrap();
        assert_eq!(
            ActionMandate::from_canonical_bytes(&encoded).unwrap(),
            mandate
        );
        let envelope = MandateSignatureEnvelope {
            version: ACCOUNTABILITY_OBJECT_VERSION,
            algorithm: ED25519_SIGNATURE_ALGORITHM.to_string(),
            key_id: b"issuer-key-1".to_vec(),
            signature: vec![9; 64],
        };
        let encoded = envelope.canonical_bytes(&mandate).unwrap();
        assert_eq!(
            MandateSignatureEnvelope::from_canonical_bytes(&encoded, &mandate).unwrap(),
            envelope
        );
    }

    #[test]
    fn validity_uses_inclusive_start_and_exclusive_expiry() {
        let mandate = mandate();
        assert!(!mandate.is_valid_at(99).unwrap());
        assert!(mandate.is_valid_at(100).unwrap());
        assert!(mandate.is_valid_at(199).unwrap());
        assert!(!mandate.is_valid_at(200).unwrap());
    }

    #[test]
    fn malformed_and_unsupported_inputs_fail_closed() {
        let mandate = mandate();
        let mut unsupported = mandate.canonical_bytes().unwrap();
        unsupported[0] = 1;
        assert_eq!(
            ActionMandate::from_canonical_bytes(&unsupported),
            Err(MandateError::UnsupportedVersion)
        );
        let mut invalid = mandate.clone();
        invalid.maximum_dispatches = 2;
        assert_eq!(invalid.validate(), Err(MandateError::InvalidDispatchLimit));
        let mut invalid = mandate.clone();
        invalid.evidence_requirements.clear();
        assert_eq!(invalid.validate(), Err(MandateError::InvalidRequirements));
        let mut trailing = mandate.canonical_bytes().unwrap();
        trailing.push(0);
        assert_eq!(
            ActionMandate::from_canonical_bytes(&trailing),
            Err(MandateError::InvalidEncoding)
        );
    }

    #[test]
    fn every_authority_dimension_is_hash_bound() {
        let base = mandate().id().unwrap();
        let mut changed = mandate();
        changed.subject = MandateSubject::Identity(vec![10; 32]);
        assert_ne!(changed.id().unwrap(), base);
        let mut changed = mandate();
        changed.expires_at += 1;
        assert_ne!(changed.id().unwrap(), base);
        let mut changed = mandate();
        changed.constraints[0].parameters_digest[0] ^= 1;
        assert_ne!(changed.id().unwrap(), base);
        let mut changed = mandate();
        changed.evidence_requirements[0].parameters_digest[0] ^= 1;
        assert_ne!(changed.id().unwrap(), base);
    }
}
