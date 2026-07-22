//! Historical authority reconstruction without creating execution authority.

use alloc::{string::String, vec::Vec};

use csv_hash::{AuthorityReconstructionDomain, DomainSeparatedHash};

use crate::{AuthorityReconstructionId, EvidenceNodeId, MandateId};

/// Registry identity of the first authority-reconstruction object.
pub const AUTHORITY_RECONSTRUCTION_REGISTRY_ID: &str = "org.diewan.authority-reconstruction.v1";
/// Maximum links evaluated in one reconstruction.
pub const MAX_AUTHORITY_LINKS: usize = 256;
/// Maximum contradiction references retained by one reconstruction.
pub const MAX_AUTHORITY_CONTRADICTIONS: usize = 64;
/// Maximum bytes in an identity, authority domain, or method identifier.
pub const MAX_AUTHORITY_FIELD_BYTES: usize = 512;

/// Whether the reconstruction's source set claims complete coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoritySourceCompleteness {
    /// A verified completeness mechanism covers the declared source window.
    Complete,
    /// At least one expected source or link is missing.
    Incomplete,
    /// At least one source or link exists but was deliberately withheld.
    Withheld,
}

/// Authenticity assessment for a historical snapshot or delegation link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityAuthenticity {
    /// Authenticity material verified under the bound context.
    Verified,
    /// Authenticity material was present and rejected.
    Rejected,
    /// Authenticity could not be established from disclosed material.
    Unknown,
}

/// One reconstructed delegation edge derived from historical evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityLink {
    /// Content identifier of the mandate or mandate-shaped historical record.
    pub mandate_id: MandateId,
    /// Parent link, absent only for a root authority record.
    pub parent_mandate_id: Option<MandateId>,
    /// Identity that purportedly issued this link.
    pub issuer_identity: Vec<u8>,
    /// Identity to which this link purportedly delegated.
    pub subject_identity: Vec<u8>,
    /// Authority domain in which the link was effective.
    pub authority_domain: Vec<u8>,
    /// Inclusive beginning of the historical effective interval.
    pub effective_from: u64,
    /// Exclusive end of the historical effective interval.
    pub effective_until: u64,
    /// Commitment to the exact reconstructed scope.
    pub scope_digest: [u8; 32],
    /// Result of evaluating the link's signature material.
    pub authenticity: AuthorityAuthenticity,
}

/// Canonical input to historical authority evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReconstruction {
    /// Stable reconstruction registry identifier.
    pub registry_id: String,
    /// Time at which compatibility is evaluated.
    pub evaluation_time: u64,
    /// Digest of the exact source snapshot used for reconstruction.
    pub source_snapshot_digest: [u8; 32],
    /// Authenticity assessment for that source snapshot.
    pub snapshot_authenticity: AuthorityAuthenticity,
    /// Coverage claim for the source set.
    pub source_completeness: AuthoritySourceCompleteness,
    /// Registered deterministic inference method.
    pub inference_method: String,
    /// Canonically ordered reconstructed links.
    pub links: Vec<AuthorityLink>,
    /// Canonically ordered disclosed contradiction nodes.
    pub contradiction_refs: Vec<EvidenceNodeId>,
}

/// The only conclusions historical reconstruction can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityConclusion {
    /// Disclosed, verified evidence is compatible with the reconstructed chain.
    Compatible,
    /// Disclosed evidence conflicts with the reconstructed chain.
    Incompatible,
    /// Missing, withheld, conflicting, or unverifiable evidence prevents a conclusion.
    Indeterminate,
}

/// Stable reason for a reconstruction conclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityReason {
    /// Every disclosed link is compatible under a complete verified snapshot.
    ChainCompatible,
    /// Source coverage is incomplete or withheld.
    SourceIncomplete,
    /// The source snapshot or a link has unknown authenticity.
    AuthenticityUnknown,
    /// A signature or snapshot authenticity assessment was rejected.
    AuthenticityRejected,
    /// A parent link is not disclosed.
    ParentMissing,
    /// The delegation graph contains a cycle.
    Cycle,
    /// One mandate identifier claims more than one parent.
    ConflictingParents,
    /// The disclosed graph claims zero or multiple independent roots.
    ConflictingRoots,
    /// A child exceeds or conflicts with its parent identity, domain, interval, or scope.
    DelegationMismatch,
    /// Disclosed contradiction evidence prevents a definitive compatibility conclusion.
    ContradictionPresent,
    /// The canonical object is structurally invalid.
    MalformedReconstruction,
}

/// Complete stable reason-code registry for historical authority reconstruction.
pub const AUTHORITY_RECONSTRUCTION_REASON_CODES: &[AuthorityReason] = &[
    AuthorityReason::ChainCompatible,
    AuthorityReason::SourceIncomplete,
    AuthorityReason::AuthenticityUnknown,
    AuthorityReason::AuthenticityRejected,
    AuthorityReason::ParentMissing,
    AuthorityReason::Cycle,
    AuthorityReason::ConflictingParents,
    AuthorityReason::ConflictingRoots,
    AuthorityReason::DelegationMismatch,
    AuthorityReason::ContradictionPresent,
    AuthorityReason::MalformedReconstruction,
];

impl AuthorityReason {
    /// Stable namespaced reason-code identifier.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::ChainCompatible => "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.COMPATIBLE",
            Self::SourceIncomplete => "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.SOURCE_INCOMPLETE",
            Self::AuthenticityUnknown => {
                "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.AUTHENTICITY_UNKNOWN"
            }
            Self::AuthenticityRejected => {
                "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.AUTHENTICITY_REJECTED"
            }
            Self::ParentMissing => "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.PARENT_MISSING",
            Self::Cycle => "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.CYCLE",
            Self::ConflictingParents => {
                "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.CONFLICTING_PARENTS"
            }
            Self::ConflictingRoots => "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.CONFLICTING_ROOTS",
            Self::DelegationMismatch => {
                "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.DELEGATION_MISMATCH"
            }
            Self::ContradictionPresent => {
                "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.CONTRADICTION_PRESENT"
            }
            Self::MalformedReconstruction => "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.MALFORMED",
        }
    }
}

/// Deterministic reconstruction result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityEvaluation {
    /// Three-state conclusion; this is evidence analysis, never permission.
    pub conclusion: AuthorityConclusion,
    /// Primary stable reason for the conclusion.
    pub reason: AuthorityReason,
}

/// Invalid reconstruction structure or canonical bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    /// A required field is absent, zero, or out of bounds.
    InvalidField(&'static str),
    /// Links or contradiction references are not canonically ordered.
    NonCanonicalOrder,
    /// Canonical bytes are malformed, truncated, or have trailing data.
    InvalidEncoding,
}

impl AuthorityReconstruction {
    /// Validates local bounds and canonical ordering without interpreting authority.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self.registry_id != AUTHORITY_RECONSTRUCTION_REGISTRY_ID
            || self.evaluation_time == 0
            || self.source_snapshot_digest == [0; 32]
        {
            return Err(AuthorityError::InvalidField("header"));
        }
        validate_text(&self.inference_method, "inference_method")?;
        if self.links.is_empty() || self.links.len() > MAX_AUTHORITY_LINKS {
            return Err(AuthorityError::InvalidField("links"));
        }
        for link in &self.links {
            validate_bytes(&link.issuer_identity, "issuer_identity")?;
            validate_bytes(&link.subject_identity, "subject_identity")?;
            validate_bytes(&link.authority_domain, "authority_domain")?;
            if link.effective_from >= link.effective_until || link.scope_digest == [0; 32] {
                return Err(AuthorityError::InvalidField("link_interval_or_scope"));
            }
        }
        if self
            .links
            .windows(2)
            .any(|pair| link_key(&pair[0]) >= link_key(&pair[1]))
        {
            return Err(AuthorityError::NonCanonicalOrder);
        }
        if self.contradiction_refs.len() > MAX_AUTHORITY_CONTRADICTIONS
            || self
                .contradiction_refs
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(AuthorityError::NonCanonicalOrder);
        }
        Ok(())
    }

    /// Encodes the complete reconstruction deterministically.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        self.validate()?;
        let mut out = Vec::new();
        push_text(&mut out, &self.registry_id);
        push_u64(&mut out, self.evaluation_time);
        out.extend_from_slice(&self.source_snapshot_digest);
        out.push(authenticity_tag(self.snapshot_authenticity));
        out.push(completeness_tag(self.source_completeness));
        push_text(&mut out, &self.inference_method);
        push_u32(&mut out, self.links.len() as u32);
        for link in &self.links {
            out.extend_from_slice(link.mandate_id.as_bytes());
            push_optional_id(&mut out, link.parent_mandate_id);
            push_bytes(&mut out, &link.issuer_identity);
            push_bytes(&mut out, &link.subject_identity);
            push_bytes(&mut out, &link.authority_domain);
            push_u64(&mut out, link.effective_from);
            push_u64(&mut out, link.effective_until);
            out.extend_from_slice(&link.scope_digest);
            out.push(authenticity_tag(link.authenticity));
        }
        push_u32(&mut out, self.contradiction_refs.len() as u32);
        for reference in &self.contradiction_refs {
            out.extend_from_slice(reference.as_bytes());
        }
        Ok(out)
    }

    /// Decodes canonical bytes and rejects alternate encodings.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AuthorityError> {
        let mut cursor = Cursor::new(bytes);
        let registry_id = cursor.text()?;
        let evaluation_time = cursor.u64()?;
        let source_snapshot_digest = cursor.array32()?;
        let snapshot_authenticity = cursor.authenticity()?;
        let source_completeness = cursor.completeness()?;
        let inference_method = cursor.text()?;
        let link_count = cursor.u32()? as usize;
        if link_count > MAX_AUTHORITY_LINKS {
            return Err(AuthorityError::InvalidEncoding);
        }
        let mut links = Vec::with_capacity(link_count);
        for _ in 0..link_count {
            links.push(AuthorityLink {
                mandate_id: MandateId::from_digest(cursor.array32()?),
                parent_mandate_id: cursor.optional_id()?,
                issuer_identity: cursor.bytes()?,
                subject_identity: cursor.bytes()?,
                authority_domain: cursor.bytes()?,
                effective_from: cursor.u64()?,
                effective_until: cursor.u64()?,
                scope_digest: cursor.array32()?,
                authenticity: cursor.authenticity()?,
            });
        }
        let contradiction_count = cursor.u32()? as usize;
        if contradiction_count > MAX_AUTHORITY_CONTRADICTIONS {
            return Err(AuthorityError::InvalidEncoding);
        }
        let mut contradiction_refs = Vec::with_capacity(contradiction_count);
        for _ in 0..contradiction_count {
            contradiction_refs.push(EvidenceNodeId::from_digest(cursor.array32()?));
        }
        if !cursor.remaining.is_empty() {
            return Err(AuthorityError::InvalidEncoding);
        }
        let reconstruction = Self {
            registry_id,
            evaluation_time,
            source_snapshot_digest,
            snapshot_authenticity,
            source_completeness,
            inference_method,
            links,
            contradiction_refs,
        };
        reconstruction.validate()?;
        if reconstruction.canonical_bytes()?.as_slice() != bytes {
            return Err(AuthorityError::InvalidEncoding);
        }
        Ok(reconstruction)
    }

    /// Returns the domain-separated reconstruction identifier.
    pub fn id(&self) -> Result<AuthorityReconstructionId, AuthorityError> {
        Ok(AuthorityReconstructionId::from_digest(
            DomainSeparatedHash::<AuthorityReconstructionDomain>::hash(&self.canonical_bytes()?)
                .into_inner(),
        ))
    }
}

fn link_key(link: &AuthorityLink) -> ([u8; 32], [u8; 32]) {
    (
        link.mandate_id.into_bytes(),
        link.parent_mandate_id
            .map_or([0; 32], MandateId::into_bytes),
    )
}

fn validate_bytes(value: &[u8], field: &'static str) -> Result<(), AuthorityError> {
    if value.is_empty() || value.len() > MAX_AUTHORITY_FIELD_BYTES {
        Err(AuthorityError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), AuthorityError> {
    validate_bytes(value.as_bytes(), field)?;
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(AuthorityError::InvalidField(field));
    }
    Ok(())
}

const fn authenticity_tag(value: AuthorityAuthenticity) -> u8 {
    match value {
        AuthorityAuthenticity::Verified => 0,
        AuthorityAuthenticity::Rejected => 1,
        AuthorityAuthenticity::Unknown => 2,
    }
}

const fn completeness_tag(value: AuthoritySourceCompleteness) -> u8 {
    match value {
        AuthoritySourceCompleteness::Complete => 0,
        AuthoritySourceCompleteness::Incomplete => 1,
        AuthoritySourceCompleteness::Withheld => 2,
    }
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

fn push_text(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
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

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AuthorityError> {
        if len > self.remaining.len() {
            return Err(AuthorityError::InvalidEncoding);
        }
        let (value, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, AuthorityError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, AuthorityError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| AuthorityError::InvalidEncoding)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, AuthorityError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| AuthorityError::InvalidEncoding)?,
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], AuthorityError> {
        self.take(32)?
            .try_into()
            .map_err(|_| AuthorityError::InvalidEncoding)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, AuthorityError> {
        let len = self.u32()? as usize;
        if len > MAX_AUTHORITY_FIELD_BYTES {
            return Err(AuthorityError::InvalidEncoding);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn text(&mut self) -> Result<String, AuthorityError> {
        String::from_utf8(self.bytes()?).map_err(|_| AuthorityError::InvalidEncoding)
    }

    fn authenticity(&mut self) -> Result<AuthorityAuthenticity, AuthorityError> {
        match self.byte()? {
            0 => Ok(AuthorityAuthenticity::Verified),
            1 => Ok(AuthorityAuthenticity::Rejected),
            2 => Ok(AuthorityAuthenticity::Unknown),
            _ => Err(AuthorityError::InvalidEncoding),
        }
    }

    fn completeness(&mut self) -> Result<AuthoritySourceCompleteness, AuthorityError> {
        match self.byte()? {
            0 => Ok(AuthoritySourceCompleteness::Complete),
            1 => Ok(AuthoritySourceCompleteness::Incomplete),
            2 => Ok(AuthoritySourceCompleteness::Withheld),
            _ => Err(AuthorityError::InvalidEncoding),
        }
    }

    fn optional_id(&mut self) -> Result<Option<MandateId>, AuthorityError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(MandateId::from_digest(self.array32()?))),
            _ => Err(AuthorityError::InvalidEncoding),
        }
    }
}
