//! Deterministic, selectively disclosed dispute-bundle manifests.

use alloc::{string::String, vec::Vec};

use csv_hash::{DisputeBundleDomain, DomainSeparatedHash};

use crate::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, BundleId, IntentId,
    ObjectVersion, ProtocolVersion, VerificationContextId,
};

/// Maximum objects, attachments, or withheld commitments in one v0.1 bundle.
pub const MAX_BUNDLE_OBJECTS: usize = 2_048;
/// Maximum bytes of one disclosed object or attachment.
pub const MAX_BUNDLE_OBJECT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum aggregate disclosed payload bytes.
pub const MAX_BUNDLE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Maximum registry/media-type/producer identity field length.
pub const MAX_BUNDLE_TEXT_BYTES: usize = 1_024;

/// A disclosed, content-addressed protocol object or attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisclosedObject {
    /// Stable object or attachment type identifier.
    pub registry_id: String,
    /// Declared content media type.
    pub media_type: String,
    /// Digest committed by the manifest.
    pub content_digest: [u8; 32],
    /// Exact disclosed bytes.
    pub bytes: Vec<u8>,
}

/// Commitment to an intentionally undisclosed object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithheldObject {
    /// Stable object type identifier.
    pub registry_id: String,
    /// Digest of the undisclosed exact bytes.
    pub content_digest: [u8; 32],
    /// Purpose-limited reason classification; never implies non-occurrence.
    pub reason_code: String,
}

/// Deterministic portable case-file manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeBundle {
    /// Accountability protocol compatibility version.
    pub protocol_version: ProtocolVersion,
    /// Schema version of this bundle.
    pub bundle_version: ObjectVersion,
    /// Optional application case identifier, presentation-only.
    pub case_id: Option<String>,
    /// Exact subject intent.
    pub subject_intent_id: IntentId,
    /// Canonically sorted disclosed object table.
    pub disclosed_objects: Vec<DisclosedObject>,
    /// Canonically sorted withheld-object commitments.
    pub withheld_objects: Vec<WithheldObject>,
    /// Non-binding recommended verification context.
    pub recommended_context: Option<VerificationContextId>,
    /// Stable bundle producer identity.
    pub producer_identity: Vec<u8>,
    /// Detached producer signature.
    pub producer_signature: Vec<u8>,
}

/// A malformed, incomplete, oversized, or digest-inconsistent bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// Protocol or object version is unsupported.
    UnsupportedVersion,
    /// A required bounded field is malformed.
    InvalidField(&'static str),
    /// A disclosed object's bytes do not match its committed digest.
    DigestMismatch,
    /// An object commitment is duplicated, unsorted, or ambiguously both disclosed and withheld.
    InvalidObjectTable,
    /// A required object commitment is absent.
    MissingObject,
    /// Per-object, object-count, or aggregate bundle limits were exceeded.
    BoundsExceeded,
}

impl DisputeBundle {
    /// Validates deterministic tables, disclosure boundaries, digests, and size limits.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.protocol_version != ACCOUNTABILITY_PROTOCOL_VERSION
            || self.bundle_version != ACCOUNTABILITY_OBJECT_VERSION
        {
            return Err(BundleError::UnsupportedVersion);
        }
        if self
            .case_id
            .as_ref()
            .is_some_and(|value| validate_text(value).is_err())
            || self.producer_identity.is_empty()
            || self.producer_identity.len() > MAX_BUNDLE_TEXT_BYTES
            || self.producer_signature.is_empty()
            || self.producer_signature.len() > 8_192
        {
            return Err(BundleError::InvalidField("bundle_metadata"));
        }
        if self.disclosed_objects.len() + self.withheld_objects.len() > MAX_BUNDLE_OBJECTS {
            return Err(BundleError::BoundsExceeded);
        }
        let mut total = 0usize;
        for object in &self.disclosed_objects {
            validate_text(&object.registry_id)?;
            validate_text(&object.media_type)?;
            if object.bytes.is_empty() || object.bytes.len() > MAX_BUNDLE_OBJECT_BYTES {
                return Err(BundleError::BoundsExceeded);
            }
            total = total
                .checked_add(object.bytes.len())
                .ok_or(BundleError::BoundsExceeded)?;
            if total > MAX_BUNDLE_TOTAL_BYTES {
                return Err(BundleError::BoundsExceeded);
            }
            if digest(&object.bytes) != object.content_digest {
                return Err(BundleError::DigestMismatch);
            }
        }
        for object in &self.withheld_objects {
            validate_text(&object.registry_id)?;
            validate_text(&object.reason_code)?;
            if object.content_digest == [0; 32] {
                return Err(BundleError::InvalidField("withheld_digest"));
            }
        }
        if !sorted_disclosed(&self.disclosed_objects)
            || !sorted_withheld(&self.withheld_objects)
            || self.disclosed_objects.iter().any(|disclosed| {
                self.withheld_objects
                    .iter()
                    .any(|withheld| withheld.content_digest == disclosed.content_digest)
            })
        {
            return Err(BundleError::InvalidObjectTable);
        }
        Ok(())
    }

    /// Requires an exact disclosed object and returns its bytes.
    pub fn require_disclosed(
        &self,
        registry_id: &str,
        content_digest: [u8; 32],
    ) -> Result<&[u8], BundleError> {
        self.validate()?;
        self.disclosed_objects
            .iter()
            .find(|object| {
                object.registry_id == registry_id && object.content_digest == content_digest
            })
            .map(|object| object.bytes.as_slice())
            .ok_or(BundleError::MissingObject)
    }

    /// Returns deterministic canonical manifest bytes including disclosed payloads.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BundleError> {
        self.validate()?;
        let mut out = Vec::new();
        push_u16(&mut out, self.protocol_version.major());
        push_u16(&mut out, self.protocol_version.minor());
        push_u16(&mut out, self.bundle_version.get());
        push_option_text(&mut out, self.case_id.as_deref());
        out.extend_from_slice(self.subject_intent_id.as_bytes());
        push_u32(&mut out, self.disclosed_objects.len() as u32);
        for object in &self.disclosed_objects {
            push_text(&mut out, &object.registry_id);
            push_text(&mut out, &object.media_type);
            out.extend_from_slice(&object.content_digest);
            push_bytes(&mut out, &object.bytes);
        }
        push_u32(&mut out, self.withheld_objects.len() as u32);
        for object in &self.withheld_objects {
            push_text(&mut out, &object.registry_id);
            out.extend_from_slice(&object.content_digest);
            push_text(&mut out, &object.reason_code);
        }
        match self.recommended_context {
            Some(context) => {
                out.push(1);
                out.extend_from_slice(context.as_bytes());
            }
            None => out.push(0),
        }
        push_bytes(&mut out, &self.producer_identity);
        push_bytes(&mut out, &self.producer_signature);
        Ok(out)
    }

    /// Derives the domain-separated identifier of the exact bundle.
    pub fn id(&self) -> Result<BundleId, BundleError> {
        let bytes = self.canonical_bytes()?;
        Ok(BundleId::from_digest(
            DomainSeparatedHash::<DisputeBundleDomain>::hash(&bytes).into_inner(),
        ))
    }
}

/// Computes the canonical content digest used by object-table entries.
pub fn bundle_object_digest(bytes: &[u8]) -> [u8; 32] {
    digest(bytes)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    csv_hash::Hash::sha256(bytes).into_inner()
}

fn validate_text(value: &str) -> Result<(), BundleError> {
    if value.is_empty()
        || value.len() > MAX_BUNDLE_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(BundleError::InvalidField("text"))
    } else {
        Ok(())
    }
}

fn sorted_disclosed(objects: &[DisclosedObject]) -> bool {
    objects.windows(2).all(|pair| {
        (&pair[0].registry_id, pair[0].content_digest)
            < (&pair[1].registry_id, pair[1].content_digest)
    })
}

fn sorted_withheld(objects: &[WithheldObject]) -> bool {
    objects.windows(2).all(|pair| {
        (&pair[0].registry_id, pair[0].content_digest)
            < (&pair[1].registry_id, pair[1].content_digest)
    })
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}
fn push_text(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
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
