//! Chain-free anchor evidence carried by dispute bundles (Master Plan §5.9, §5.5).
//!
//! An anchor record is *corroborating registered evidence* that a mandate's single use
//! was enforced by something independent of the private reservation store — for the
//! first backing, a Single-Use Seal consumption. The accountability core stays
//! chain-free: these are deterministic value types with a canonical byte layout that an
//! offline verifier reconstructs from bundle bytes alone. Producing them (talking to a
//! seal store or a chain) lives outside this crate, off the dispatch hot path.
//!
//! A [`SealConsumptionRecord`] rides in a [`crate::bundle::DisputeBundle`] as a disclosed
//! object under the stable registry id [`EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD`]; the
//! reference verifier re-checks it with [`SealConsumptionRecord::assess`] and reports the
//! result on the external-corroboration assurance dimension. Its absence is a *limitation*,
//! never a failure.

use alloc::{string::String, vec::Vec};

use csv_hash::Hash;

/// Stable evidence-source identifier: an independent single-use seal consumption record.
///
/// External to both the executor and the target provider, so it is the strongest class of
/// single-use corroboration ([`crate::profile::EvidenceSourceClass::ExternalAnchor`]).
pub const EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD: &str = "evidence.csv-seal.consumption-record";

/// Stable evidence-source identifier: an external commitment anchor for a bundle digest.
pub const EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR: &str = "evidence.csv-seal.commitment-anchor";

/// Media type of a canonical [`SealConsumptionRecord`] disclosed object.
pub const CSV_SEAL_CONSUMPTION_MEDIA_TYPE: &str =
    "application/vnd.diewan.csv-seal-consumption-v1+csv-binary";

/// Media type of a canonical [`CommitmentAnchorRecord`] disclosed object.
pub const CSV_SEAL_COMMITMENT_ANCHOR_MEDIA_TYPE: &str =
    "application/vnd.diewan.csv-seal-commitment-anchor-v1+csv-binary";

/// Maximum byte length of an anchor backend identifier or opaque anchor reference.
pub const MAX_ANCHOR_FIELD_BYTES: usize = 256;

/// A malformed anchor record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorError {
    /// A required digest field was all-zero.
    ZeroDigest,
    /// A bounded text or byte field was empty, over-long, or non-canonical.
    InvalidField(&'static str),
    /// Canonical bytes were truncated, trailing, or otherwise not the exact encoding.
    MalformedBytes,
}

/// Offline conclusion of re-checking a preserved single-use anchor against a mandate.
///
/// This never invalidates an otherwise-valid mandate on its own: corroboration can only
/// *strengthen* the single-use conclusion (§5.5). A mismatch or malformed record is
/// reported as indeterminate corroboration, not as a single-use failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleUseAnchorAssessment {
    /// The record is well-formed and binds exactly the expected nullifier and commitment:
    /// the mandate's single use was independently enforced.
    IndependentlyEnforced,
    /// The record is well-formed but binds a different nullifier or commitment, so it
    /// cannot corroborate this mandate.
    Inconsistent,
    /// The record could not be re-checked because it is structurally invalid.
    Malformed,
}

/// A preserved, independently reproducible record that one seal was consumed exactly once.
///
/// The `nullifier` is the mandate's [`crate::execution::ExecutionAttempt::reservation_token_digest`];
/// the `commitment` is the value the seal bound at issue (the mandate's intent id bytes).
/// `seal_id` identifies the single-use seal, and `anchor_backend` names the backing that
/// produced the record (for example a local seal store or an on-chain CSVSeal), so a
/// verifier can weight it without this crate depending on any chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealConsumptionRecord {
    /// Identifier of the consumed single-use seal.
    pub seal_id: [u8; 32],
    /// Consumption nullifier; equals the mandate's reservation-token digest.
    pub nullifier: [u8; 32],
    /// Commitment the seal bound at issue (the authorized intent id bytes).
    pub commitment: [u8; 32],
    /// Stable identifier of the backing that produced this record.
    pub anchor_backend: String,
}

impl SealConsumptionRecord {
    /// Validates that the record is structurally well-formed.
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.seal_id == [0; 32] || self.nullifier == [0; 32] || self.commitment == [0; 32] {
            return Err(AnchorError::ZeroDigest);
        }
        validate_field(&self.anchor_backend, "anchor_backend")?;
        Ok(())
    }

    /// Returns deterministic canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.seal_id);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.commitment);
        push_text(&mut out, &self.anchor_backend);
        Ok(out)
    }

    /// Reconstructs a record from its exact canonical bytes, failing closed on any drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AnchorError> {
        let mut cursor = Cursor::new(bytes);
        let seal_id = cursor.take_array()?;
        let nullifier = cursor.take_array()?;
        let commitment = cursor.take_array()?;
        let anchor_backend = cursor.take_text()?;
        if !cursor.is_empty() {
            return Err(AnchorError::MalformedBytes);
        }
        let record = Self {
            seal_id,
            nullifier,
            commitment,
            anchor_backend,
        };
        record.validate()?;
        Ok(record)
    }

    /// Content digest of the canonical bytes, for the bundle object table.
    pub fn digest(&self) -> Result<[u8; 32], AnchorError> {
        Ok(Hash::sha256(&self.canonical_bytes()?).into_inner())
    }

    /// Re-checks the record offline against the mandate's expected nullifier and commitment.
    pub fn assess(
        &self,
        expected_nullifier: [u8; 32],
        expected_commitment: [u8; 32],
    ) -> SingleUseAnchorAssessment {
        if self.validate().is_err() {
            return SingleUseAnchorAssessment::Malformed;
        }
        if self.nullifier == expected_nullifier && self.commitment == expected_commitment {
            SingleUseAnchorAssessment::IndependentlyEnforced
        } else {
            SingleUseAnchorAssessment::Inconsistent
        }
    }
}

/// A preserved reference that a bundle digest was anchored as an external commitment.
///
/// Design-complete but not yet consumed by the reference verifier's dimensions; it lets a
/// bundle carry existence/chronology corroboration (§5.9) alongside single-use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentAnchorRecord {
    /// Digest of the anchored bundle.
    pub bundle_digest: [u8; 32],
    /// Opaque, backend-defined anchor reference (for example a seal id or a txid).
    pub anchor_ref: Vec<u8>,
    /// Stable identifier of the backing that produced this record.
    pub anchor_backend: String,
}

impl CommitmentAnchorRecord {
    /// Validates that the record is structurally well-formed.
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.bundle_digest == [0; 32] {
            return Err(AnchorError::ZeroDigest);
        }
        if self.anchor_ref.is_empty() || self.anchor_ref.len() > MAX_ANCHOR_FIELD_BYTES {
            return Err(AnchorError::InvalidField("anchor_ref"));
        }
        validate_field(&self.anchor_backend, "anchor_backend")?;
        Ok(())
    }

    /// Returns deterministic canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.bundle_digest);
        push_bytes(&mut out, &self.anchor_ref);
        push_text(&mut out, &self.anchor_backend);
        Ok(out)
    }

    /// Reconstructs a record from its exact canonical bytes, failing closed on any drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AnchorError> {
        let mut cursor = Cursor::new(bytes);
        let bundle_digest = cursor.take_array()?;
        let anchor_ref = cursor.take_bytes()?;
        let anchor_backend = cursor.take_text()?;
        if !cursor.is_empty() {
            return Err(AnchorError::MalformedBytes);
        }
        let record = Self {
            bundle_digest,
            anchor_ref,
            anchor_backend,
        };
        record.validate()?;
        Ok(record)
    }

    /// Content digest of the canonical bytes, for the bundle object table.
    pub fn digest(&self) -> Result<[u8; 32], AnchorError> {
        Ok(Hash::sha256(&self.canonical_bytes()?).into_inner())
    }
}

fn validate_field(value: &str, name: &'static str) -> Result<(), AnchorError> {
    if value.is_empty()
        || value.len() > MAX_ANCHOR_FIELD_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(AnchorError::InvalidField(name))
    } else {
        Ok(())
    }
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

/// Minimal fail-closed reader over canonical anchor bytes.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AnchorError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(AnchorError::MalformedBytes)?;
        if end > self.bytes.len() {
            return Err(AnchorError::MalformedBytes);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_array(&mut self) -> Result<[u8; 32], AnchorError> {
        let slice = self.take(32)?;
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        Ok(array)
    }

    fn take_bytes(&mut self) -> Result<Vec<u8>, AnchorError> {
        let len_bytes = self.take(4)?;
        let len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn take_text(&mut self) -> Result<String, AnchorError> {
        let bytes = self.take_bytes()?;
        String::from_utf8(bytes).map_err(|_| AnchorError::MalformedBytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> SealConsumptionRecord {
        SealConsumptionRecord {
            seal_id: [1u8; 32],
            nullifier: [2u8; 32],
            commitment: [3u8; 32],
            anchor_backend: String::from("csv-seal.local.v1"),
        }
    }

    #[test]
    fn consumption_record_round_trips_through_canonical_bytes() {
        let original = record();
        let bytes = original.canonical_bytes().unwrap();
        let decoded = SealConsumptionRecord::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn trailing_bytes_fail_closed() {
        let mut bytes = record().canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            SealConsumptionRecord::from_canonical_bytes(&bytes),
            Err(AnchorError::MalformedBytes)
        );
    }

    #[test]
    fn zero_digest_is_rejected() {
        let mut bad = record();
        bad.nullifier = [0u8; 32];
        assert_eq!(bad.validate(), Err(AnchorError::ZeroDigest));
    }

    #[test]
    fn assess_reports_independent_enforcement_on_exact_binding() {
        let record = record();
        assert_eq!(
            record.assess([2u8; 32], [3u8; 32]),
            SingleUseAnchorAssessment::IndependentlyEnforced
        );
        assert_eq!(
            record.assess([9u8; 32], [3u8; 32]),
            SingleUseAnchorAssessment::Inconsistent
        );
    }

    #[test]
    fn commitment_anchor_round_trips() {
        let original = CommitmentAnchorRecord {
            bundle_digest: [7u8; 32],
            anchor_ref: alloc::vec![1, 2, 3, 4],
            anchor_backend: String::from("csv-seal.local.v1"),
        };
        let bytes = original.canonical_bytes().unwrap();
        assert_eq!(
            CommitmentAnchorRecord::from_canonical_bytes(&bytes).unwrap(),
            original
        );
    }
}
