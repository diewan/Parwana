//! Canonical long-lived preservation envelopes and renewal-chain semantics.

use alloc::{string::String, vec::Vec};

use csv_hash::{DomainSeparatedHash, PreservationEnvelopeDomain};

use crate::{ACCOUNTABILITY_OBJECT_VERSION, ObjectVersion, PreservationEnvelopeId};

/// Stable registry identifier for the preservation-envelope schema.
pub const PRESERVATION_ENVELOPE_REGISTRY_ID: &str = "org.diewan.evidence.preservation-envelope.v1";
/// Currently registered integrity algorithm identifier.
pub const ALGORITHM_SHA256_TAGGED_V1: &str = "org.diewan.algorithm.sha256-tagged.v1";
/// Maximum original canonical object size retained in one envelope.
pub const MAX_PRESERVATION_BYTES: usize = 8 * 1024 * 1024;
/// Maximum registry or algorithm identifier length.
pub const MAX_PRESERVATION_TEXT_BYTES: usize = 128;
/// Maximum algorithms declared by one envelope.
pub const MAX_PRESERVATION_ALGORITHMS: usize = 32;
/// Maximum renewal depth accepted in one verification input.
pub const MAX_PRESERVATION_CHAIN: usize = 64;

/// Policy conclusion for a registered algorithm at the evaluation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmPolicyStatus {
    /// Algorithm remains acceptable for verification.
    Allowed,
    /// Historical evidence remains inspectable but should be renewed.
    Deprecated,
    /// Algorithm is prohibited by policy and cannot support assurance.
    Disallowed,
    /// The effective policy has no conclusion for this identifier.
    Unknown,
}

/// One algorithm conclusion supplied by the hash-addressed policy package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmStatusEntry {
    /// Stable algorithm identifier.
    pub algorithm_id: String,
    /// Effective policy conclusion.
    pub status: AlgorithmPolicyStatus,
}

/// An immutable copy of historical canonical bytes plus renewal metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservationEnvelope {
    /// Preservation-envelope schema version.
    pub version: ObjectVersion,
    /// Registry identifier of the historical object schema.
    pub object_registry_id: String,
    /// Exact original canonical bytes. Renewals must retain these unchanged.
    pub original_canonical_bytes: Vec<u8>,
    /// Algorithms required to evaluate this preservation generation.
    pub algorithm_ids: Vec<String>,
    /// Fixed time at which this generation was created.
    pub preserved_at: u64,
    /// Previous generation, absent only for the first envelope.
    pub previous_envelope_id: Option<PreservationEnvelopeId>,
    /// Commitment to external renewal material (signature, timestamp, or anchor).
    pub renewal_material_digest: [u8; 32],
}

/// Invalid preservation data or renewal history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreservationError {
    /// Schema version is unsupported.
    UnsupportedVersion,
    /// A required field is malformed or outside its bound.
    InvalidField,
    /// Canonical encoding is truncated, ambiguous, or has trailing bytes.
    MalformedEncoding,
    /// Supplied identifier does not match canonical content.
    IdentifierMismatch,
    /// Renewal predecessor is missing, duplicated, cyclic, or unordered.
    InvalidRenewalChain,
    /// A renewal attempted to replace historical bytes or remove algorithm history.
    HistoricalRewrite,
}

impl PreservationEnvelope {
    /// Validates local envelope invariants without interpreting algorithm policy.
    pub fn validate(&self) -> Result<(), PreservationError> {
        if self.version != ACCOUNTABILITY_OBJECT_VERSION {
            return Err(PreservationError::UnsupportedVersion);
        }
        if !valid_text(&self.object_registry_id)
            || self.original_canonical_bytes.is_empty()
            || self.original_canonical_bytes.len() > MAX_PRESERVATION_BYTES
            || self.algorithm_ids.is_empty()
            || self.algorithm_ids.len() > MAX_PRESERVATION_ALGORITHMS
            || self.algorithm_ids.iter().any(|value| !valid_text(value))
            || self.algorithm_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || self.preserved_at == 0
            || self.renewal_material_digest == [0; 32]
        {
            return Err(PreservationError::InvalidField);
        }
        Ok(())
    }

    /// Encodes the envelope deterministically while retaining the original bytes verbatim.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PreservationError> {
        self.validate()?;
        let mut out = Vec::new();
        push_u16(&mut out, self.version.get());
        push_bytes(&mut out, self.object_registry_id.as_bytes());
        push_bytes(&mut out, &self.original_canonical_bytes);
        push_u16(&mut out, self.algorithm_ids.len() as u16);
        for algorithm_id in &self.algorithm_ids {
            push_bytes(&mut out, algorithm_id.as_bytes());
        }
        push_u64(&mut out, self.preserved_at);
        match self.previous_envelope_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.renewal_material_digest);
        Ok(out)
    }

    /// Decodes canonical bytes and rejects non-canonical alternatives.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PreservationError> {
        let mut cursor = Cursor::new(bytes);
        let version = ObjectVersion::try_new(cursor.u16()?)
            .map_err(|_| PreservationError::UnsupportedVersion)?;
        let object_registry_id = cursor.text()?;
        let original_canonical_bytes = cursor.bytes(MAX_PRESERVATION_BYTES)?;
        let algorithm_count = cursor.u16()? as usize;
        if algorithm_count == 0 || algorithm_count > MAX_PRESERVATION_ALGORITHMS {
            return Err(PreservationError::InvalidField);
        }
        let mut algorithm_ids = Vec::with_capacity(algorithm_count);
        for _ in 0..algorithm_count {
            algorithm_ids.push(cursor.text()?);
        }
        let preserved_at = cursor.u64()?;
        let previous_envelope_id = match cursor.byte()? {
            0 => None,
            1 => Some(PreservationEnvelopeId::from_digest(cursor.array32()?)),
            _ => return Err(PreservationError::MalformedEncoding),
        };
        let renewal_material_digest = cursor.array32()?;
        if !cursor.is_empty() {
            return Err(PreservationError::MalformedEncoding);
        }
        let value = Self {
            version,
            object_registry_id,
            original_canonical_bytes,
            algorithm_ids,
            preserved_at,
            previous_envelope_id,
            renewal_material_digest,
        };
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(PreservationError::MalformedEncoding);
        }
        Ok(value)
    }

    /// Derives the domain-separated identifier of this immutable generation.
    pub fn id(&self) -> Result<PreservationEnvelopeId, PreservationError> {
        Ok(PreservationEnvelopeId::from_digest(
            DomainSeparatedHash::<PreservationEnvelopeDomain>::hash(&self.canonical_bytes()?)
                .into_inner(),
        ))
    }
}

/// Validates identifiers and an ordered, non-rewriting renewal chain.
pub fn validate_preservation_chain(
    envelopes: &[(PreservationEnvelopeId, PreservationEnvelope)],
) -> Result<(), PreservationError> {
    if envelopes.is_empty() || envelopes.len() > MAX_PRESERVATION_CHAIN {
        return Err(PreservationError::InvalidRenewalChain);
    }
    for (index, (id, envelope)) in envelopes.iter().enumerate() {
        if *id != envelope.id()? {
            return Err(PreservationError::IdentifierMismatch);
        }
        if envelopes[index + 1..].iter().any(|(other, _)| other == id) {
            return Err(PreservationError::InvalidRenewalChain);
        }
        match (index, envelope.previous_envelope_id) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Err(PreservationError::InvalidRenewalChain),
            (_, Some(previous_id)) => {
                let (expected_id, previous) = &envelopes[index - 1];
                if previous_id != *expected_id || envelope.preserved_at <= previous.preserved_at {
                    return Err(PreservationError::InvalidRenewalChain);
                }
                if envelope.object_registry_id != previous.object_registry_id
                    || envelope.original_canonical_bytes != previous.original_canonical_bytes
                    || !previous
                        .algorithm_ids
                        .iter()
                        .all(|id| envelope.algorithm_ids.contains(id))
                {
                    return Err(PreservationError::HistoricalRewrite);
                }
            }
        }
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PRESERVATION_TEXT_BYTES
        && value.trim() == value
        && value.is_ascii()
        && !value.chars().any(char::is_control)
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

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], PreservationError> {
        if len > self.remaining.len() {
            return Err(PreservationError::MalformedEncoding);
        }
        let (value, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, PreservationError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, PreservationError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PreservationError::MalformedEncoding)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, PreservationError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PreservationError::MalformedEncoding)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, PreservationError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PreservationError::MalformedEncoding)?,
        ))
    }
    fn array32(&mut self) -> Result<[u8; 32], PreservationError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PreservationError::MalformedEncoding)
    }
    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, PreservationError> {
        let len = self.u32()? as usize;
        if len > maximum {
            return Err(PreservationError::InvalidField);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn text(&mut self) -> Result<String, PreservationError> {
        let bytes = self.bytes(MAX_PRESERVATION_TEXT_BYTES)?;
        String::from_utf8(bytes).map_err(|_| PreservationError::MalformedEncoding)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        format,
        string::{String, ToString},
        vec,
    };

    use super::*;

    fn first() -> PreservationEnvelope {
        PreservationEnvelope {
            version: ACCOUNTABILITY_OBJECT_VERSION,
            object_registry_id: "org.diewan.accountability.bundle.v1".to_string(),
            original_canonical_bytes: vec![0xa1, 0x01, 0x02, 0x03],
            algorithm_ids: vec![ALGORITHM_SHA256_TAGGED_V1.to_string()],
            preserved_at: 10,
            previous_envelope_id: None,
            renewal_material_digest: [7; 32],
        }
    }

    #[test]
    fn canonical_round_trip_retains_original_bytes_exactly() {
        let envelope = first();
        let bytes = envelope.canonical_bytes().unwrap();
        let decoded = PreservationEnvelope::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(
            decoded.original_canonical_bytes,
            vec![0xa1, 0x01, 0x02, 0x03]
        );
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        assert_eq!(
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            concat!(
                "000100000023",
                "6f72672e64696577616e2e6163636f756e746162696c6974792e62756e646c652e7631",
                "00000004a1010203",
                "000100000025",
                "6f72672e64696577616e2e616c676f726974686d2e7368613235362d7461676765642e7631",
                "000000000000000a00",
                "0707070707070707070707070707070707070707070707070707070707070707"
            )
        );
    }

    #[test]
    fn malformed_unsorted_and_trailing_encodings_fail_closed() {
        let mut envelope = first();
        envelope.algorithm_ids = vec!["z.v1".to_string(), "a.v1".to_string()];
        assert_eq!(envelope.validate(), Err(PreservationError::InvalidField));

        let mut bytes = first().canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            PreservationEnvelope::from_canonical_bytes(&bytes),
            Err(PreservationError::MalformedEncoding)
        );
        assert_eq!(
            PreservationEnvelope::from_canonical_bytes(&bytes[..3]),
            Err(PreservationError::MalformedEncoding)
        );
    }

    #[test]
    fn renewal_adds_protection_without_rewriting_history() {
        let original = first();
        let original_id = original.id().unwrap();
        let renewal = PreservationEnvelope {
            version: ACCOUNTABILITY_OBJECT_VERSION,
            object_registry_id: original.object_registry_id.clone(),
            original_canonical_bytes: original.original_canonical_bytes.clone(),
            algorithm_ids: vec![
                "org.diewan.algorithm.future.v1".to_string(),
                ALGORITHM_SHA256_TAGGED_V1.to_string(),
            ],
            preserved_at: 20,
            previous_envelope_id: Some(original_id),
            renewal_material_digest: [8; 32],
        };
        let renewal_id = renewal.id().unwrap();
        assert!(
            validate_preservation_chain(&[
                (original_id, original.clone()),
                (renewal_id, renewal.clone())
            ])
            .is_ok()
        );

        let mut rewritten = renewal;
        rewritten.original_canonical_bytes.push(0xff);
        let rewritten_id = rewritten.id().unwrap();
        assert_eq!(
            validate_preservation_chain(&[(original_id, original), (rewritten_id, rewritten)]),
            Err(PreservationError::HistoricalRewrite)
        );
    }
}
