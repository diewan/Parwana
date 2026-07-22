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

/// Stable evidence-source identifier: an on-chain commitment anchor with finality.
///
/// External to both the executor and the target provider
/// ([`crate::profile::EvidenceSourceClass::ExternalAnchor`]). Unlike
/// [`EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR`], this carries the chain reference and a
/// finality reading, so a verifier can weight existence/chronology corroboration.
pub const EVIDENCE_CHAIN_COMMITMENT_ANCHOR: &str = "evidence.chain.commitment-anchor";

/// Media type of a canonical [`ChainAnchor`] disclosed object.
pub const CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE: &str =
    "application/vnd.diewan.chain-commitment-anchor-v1+csv-binary";

/// Domain tag separating a [`ChainAnchor`] identifier digest from every other
/// hashed protocol object. New, additive protocol bytes (experimental `0.x`).
pub const CHAIN_ANCHOR_DOMAIN_TAG: &[u8] = b"diewan.accountability.chain-anchor.v1";

/// Finality of an on-chain anchor, read from chain observations.
///
/// The only path to [`AnchorFinality::Final`] is [`AnchorFinality::from_confirmations`]
/// with a positive required depth that the observed depth meets. A shallow,
/// zero-requirement, or unknown reading is `Pending`; finality is never
/// fabricated (§5.9, threat #15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorFinality {
    /// Anchored but not yet reorg-safe. Carries the observed and required
    /// confirmation depths so the gap is explicit.
    Pending {
        /// Confirmations observed so far.
        observed_confirmations: u64,
        /// Reorg-safe confirmations required before the anchor is final.
        required_confirmations: u64,
    },
    /// Reorg-safe final at the observed depth.
    Final {
        /// The confirmation depth at which finality was reached.
        observed_confirmations: u64,
    },
}

impl AnchorFinality {
    /// Classifies a confirmation reading. `Final` requires a positive
    /// `required_confirmations` met by `observed_confirmations`; everything else
    /// is `Pending`.
    #[must_use]
    pub const fn from_confirmations(observed: u64, required: u64) -> Self {
        if required > 0 && observed >= required {
            Self::Final {
                observed_confirmations: observed,
            }
        } else {
            Self::Pending {
                observed_confirmations: observed,
                required_confirmations: required,
            }
        }
    }

    /// Whether this reading is reorg-safe final.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Final { .. })
    }

    fn push_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Pending {
                observed_confirmations,
                required_confirmations,
            } => {
                out.push(0);
                out.extend_from_slice(&observed_confirmations.to_be_bytes());
                out.extend_from_slice(&required_confirmations.to_be_bytes());
            }
            Self::Final {
                observed_confirmations,
            } => {
                out.push(1);
                out.extend_from_slice(&observed_confirmations.to_be_bytes());
                // A final reading has no distinct required field; encode zero to
                // keep the layout fixed-width and unambiguous.
                out.extend_from_slice(&0u64.to_be_bytes());
            }
        }
    }

    fn take_canonical(cursor: &mut Cursor<'_>) -> Result<Self, AnchorError> {
        let tag = cursor.take(1)?[0];
        let observed = cursor.take_u64()?;
        let required = cursor.take_u64()?;
        match tag {
            0 => {
                // A pending reading must not encode a met threshold (that would be
                // a final reading smuggled in as pending).
                if required > 0 && observed >= required {
                    return Err(AnchorError::MalformedBytes);
                }
                Ok(Self::Pending {
                    observed_confirmations: observed,
                    required_confirmations: required,
                })
            }
            1 => {
                if required != 0 {
                    return Err(AnchorError::MalformedBytes);
                }
                Ok(Self::Final {
                    observed_confirmations: observed,
                })
            }
            _ => Err(AnchorError::MalformedBytes),
        }
    }
}

/// Offline conclusion of re-checking a [`ChainAnchor`] against an expected commitment.
///
/// Corroboration only: a mismatch or malformed anchor is reported as inconsistent
/// or malformed, never as a validity failure of the mandate/receipt (§5.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainAnchorAssessment {
    /// The anchor binds the expected commitment and is reorg-safe final.
    AnchoredFinal,
    /// The anchor binds the expected commitment but is not yet final.
    AnchoredPending,
    /// Well-formed but binds a different commitment; cannot corroborate this object.
    Inconsistent,
    /// Structurally invalid; could not be re-checked.
    Malformed,
}

/// A preserved, independently reproducible on-chain commitment anchor.
///
/// Chain-free value type: it records *that* a commitment was anchored on a chain
/// and the finality read at capture time, so an offline verifier reconstructs it
/// from bundle bytes without any chain dependency. Producing it (talking to a
/// chain via [`csv_chain_ports`]-style adapters) lives outside this crate, off the
/// dispatch hot path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainAnchor {
    /// The anchored commitment digest (for example a bundle or mandate digest).
    pub commitment: [u8; 32],
    /// Canonical chain identifier (for example `ethereum-sepolia`).
    pub chain_id: String,
    /// Opaque, backend-defined anchor reference (for example a txid).
    pub anchor_ref: Vec<u8>,
    /// Height of the block the anchor was included in.
    pub block_height: u64,
    /// Hash of the including block, used to detect reorgs across observations.
    pub block_hash: [u8; 32],
    /// Finality reading at capture time.
    pub finality: AnchorFinality,
    /// Stable identifier of the backing that produced this record.
    pub anchor_backend: String,
}

impl ChainAnchor {
    /// Validates that the anchor is structurally well-formed.
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.commitment == [0; 32] || self.block_hash == [0; 32] {
            return Err(AnchorError::ZeroDigest);
        }
        if self.anchor_ref.is_empty() || self.anchor_ref.len() > MAX_ANCHOR_FIELD_BYTES {
            return Err(AnchorError::InvalidField("anchor_ref"));
        }
        validate_field(&self.chain_id, "chain_id")?;
        validate_field(&self.anchor_backend, "anchor_backend")?;
        Ok(())
    }

    /// Returns deterministic canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AnchorError> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.commitment);
        push_text(&mut out, &self.chain_id);
        push_bytes(&mut out, &self.anchor_ref);
        out.extend_from_slice(&self.block_height.to_be_bytes());
        out.extend_from_slice(&self.block_hash);
        self.finality.push_canonical(&mut out);
        push_text(&mut out, &self.anchor_backend);
        Ok(out)
    }

    /// Reconstructs an anchor from its exact canonical bytes, failing closed on
    /// any drift.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AnchorError> {
        let mut cursor = Cursor::new(bytes);
        let commitment = cursor.take_array()?;
        let chain_id = cursor.take_text()?;
        let anchor_ref = cursor.take_bytes()?;
        let block_height = cursor.take_u64()?;
        let block_hash = cursor.take_array()?;
        let finality = AnchorFinality::take_canonical(&mut cursor)?;
        let anchor_backend = cursor.take_text()?;
        if !cursor.is_empty() {
            return Err(AnchorError::MalformedBytes);
        }
        let anchor = Self {
            commitment,
            chain_id,
            anchor_ref,
            block_height,
            block_hash,
            finality,
            anchor_backend,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    /// Domain-separated content digest for the bundle object table and node id.
    pub fn digest(&self) -> Result<[u8; 32], AnchorError> {
        let mut preimage = CHAIN_ANCHOR_DOMAIN_TAG.to_vec();
        preimage.extend_from_slice(&self.canonical_bytes()?);
        Ok(Hash::sha256(&preimage).into_inner())
    }

    /// Re-checks the anchor offline against the expected commitment.
    #[must_use]
    pub fn assess(&self, expected_commitment: [u8; 32]) -> ChainAnchorAssessment {
        if self.validate().is_err() {
            return ChainAnchorAssessment::Malformed;
        }
        if self.commitment != expected_commitment {
            return ChainAnchorAssessment::Inconsistent;
        }
        if self.finality.is_final() {
            ChainAnchorAssessment::AnchoredFinal
        } else {
            ChainAnchorAssessment::AnchoredPending
        }
    }
}

/// One chain read of an anchor from a named source, for reorg/disagreement
/// reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorObservation {
    /// The observing source (for example an RPC endpoint id).
    pub source: String,
    /// The block height the source reports for the anchor.
    pub block_height: u64,
    /// The block hash the source reports at that height.
    pub block_hash: [u8; 32],
    /// The finality the source reports.
    pub finality: AnchorFinality,
}

/// The reconciliation across a set of [`AnchorObservation`]s of the same anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorReconciliation {
    /// No observations were supplied. Absence is not non-occurrence.
    NoObservations,
    /// Every source agrees on the including block; the reconciled finality is the
    /// most conservative across sources (final only if all sources report final).
    Agreed {
        /// The agreed block height.
        block_height: u64,
        /// The agreed reconciled finality.
        finality: AnchorFinality,
    },
    /// Sources disagree on the including block (a reorg or RPC disagreement). The
    /// disagreement is preserved and never collapsed into a false final.
    Disagreement {
        /// The distinct block hashes reported, sorted, for the record.
        reported_block_hashes: Vec<[u8; 32]>,
    },
}

/// Reconciles chain reads of one anchor.
///
/// If any two sources report a different block hash, the result is a
/// [`AnchorReconciliation::Disagreement`] (a reorg or RPC disagreement) — never a
/// final verdict. Only unanimous agreement on the including block yields
/// [`AnchorReconciliation::Agreed`], and then finality is `Final` only if every
/// source independently reports final.
#[must_use]
pub fn reconcile_anchor(observations: &[AnchorObservation]) -> AnchorReconciliation {
    let Some(first) = observations.first() else {
        return AnchorReconciliation::NoObservations;
    };

    let mut hashes: Vec<[u8; 32]> = observations.iter().map(|o| o.block_hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    if hashes.len() > 1 {
        return AnchorReconciliation::Disagreement {
            reported_block_hashes: hashes,
        };
    }

    // Unanimous on the block. Final only if every source reports final; otherwise
    // the most conservative reading (the minimum observed confirmations) is used.
    let all_final = observations.iter().all(|o| o.finality.is_final());
    let min_observed = observations
        .iter()
        .map(|o| match o.finality {
            AnchorFinality::Pending {
                observed_confirmations,
                ..
            }
            | AnchorFinality::Final {
                observed_confirmations,
            } => observed_confirmations,
        })
        .min()
        .unwrap_or(0);
    let finality = if all_final {
        AnchorFinality::Final {
            observed_confirmations: min_observed,
        }
    } else {
        // Preserve the largest required threshold reported among pending sources so
        // the gap remains visible; if none is pending, fall back to min_observed+1.
        let required = observations
            .iter()
            .filter_map(|o| match o.finality {
                AnchorFinality::Pending {
                    required_confirmations,
                    ..
                } => Some(required_confirmations),
                AnchorFinality::Final { .. } => None,
            })
            .max()
            .unwrap_or(min_observed.saturating_add(1));
        AnchorFinality::Pending {
            observed_confirmations: min_observed,
            required_confirmations: required,
        }
    };
    AnchorReconciliation::Agreed {
        block_height: first.block_height,
        finality,
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

    fn take_u64(&mut self) -> Result<u64, AnchorError> {
        let slice = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(slice);
        Ok(u64::from_be_bytes(array))
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

    // ── ChainAnchor (ANCHOR-01) ──────────────────────────────────────────────

    fn chain_anchor(finality: AnchorFinality) -> ChainAnchor {
        ChainAnchor {
            commitment: [5u8; 32],
            chain_id: String::from("ethereum-sepolia"),
            anchor_ref: alloc::vec![0xde, 0xad, 0xbe, 0xef],
            block_height: 1_000,
            block_hash: [6u8; 32],
            finality,
            anchor_backend: String::from("chain.ethereum-sepolia.v1"),
        }
    }

    #[test]
    fn chain_anchor_round_trips_pending_and_final() {
        for finality in [
            AnchorFinality::from_confirmations(3, 12),
            AnchorFinality::from_confirmations(12, 12),
        ] {
            let original = chain_anchor(finality);
            let bytes = original.canonical_bytes().unwrap();
            let decoded = ChainAnchor::from_canonical_bytes(&bytes).unwrap();
            assert_eq!(original, decoded);
        }
    }

    #[test]
    fn chain_anchor_domain_tag_separates_the_digest() {
        // The digest must fold in the chain-anchor domain tag, so it differs from
        // a bare sha256 of the canonical bytes (domain separation, threat #15).
        let anchor = chain_anchor(AnchorFinality::from_confirmations(12, 12));
        let bytes = anchor.canonical_bytes().unwrap();
        let bare = Hash::sha256(&bytes).into_inner();
        assert_ne!(anchor.digest().unwrap(), bare);
    }

    #[test]
    fn chain_anchor_trailing_bytes_and_zero_digest_fail_closed() {
        let mut bytes = chain_anchor(AnchorFinality::from_confirmations(1, 12))
            .canonical_bytes()
            .unwrap();
        bytes.push(0);
        assert_eq!(
            ChainAnchor::from_canonical_bytes(&bytes),
            Err(AnchorError::MalformedBytes)
        );

        let mut bad = chain_anchor(AnchorFinality::from_confirmations(1, 12));
        bad.block_hash = [0u8; 32];
        assert_eq!(bad.validate(), Err(AnchorError::ZeroDigest));
    }

    #[test]
    fn finality_gate_never_finalizes_below_required_depth() {
        assert_eq!(
            AnchorFinality::from_confirmations(3, 12),
            AnchorFinality::Pending {
                observed_confirmations: 3,
                required_confirmations: 12
            }
        );
        assert!(!AnchorFinality::from_confirmations(3, 12).is_final());
        assert!(AnchorFinality::from_confirmations(12, 12).is_final());
        // A zero requirement never finalizes.
        assert!(!AnchorFinality::from_confirmations(100, 0).is_final());
    }

    #[test]
    fn pending_finality_encoding_that_actually_meets_threshold_is_rejected() {
        // Adversarial: hand-craft a "pending" tag whose observed ≥ required. The
        // decoder must reject it rather than admit a final reading disguised as
        // pending.
        let anchor = chain_anchor(AnchorFinality::from_confirmations(3, 12));
        let mut bytes = anchor.canonical_bytes().unwrap();
        // Locate the finality block: it is 17 bytes (tag + 2×u64) followed by the
        // length-prefixed anchor_backend. Rebuild with a tampered pending block.
        // Simpler: assert the guard directly on a decode of a crafted buffer.
        let mut crafted = Vec::new();
        crafted.extend_from_slice(&anchor.commitment);
        push_text(&mut crafted, &anchor.chain_id);
        push_bytes(&mut crafted, &anchor.anchor_ref);
        crafted.extend_from_slice(&anchor.block_height.to_be_bytes());
        crafted.extend_from_slice(&anchor.block_hash);
        crafted.push(0); // pending tag
        crafted.extend_from_slice(&20u64.to_be_bytes()); // observed
        crafted.extend_from_slice(&12u64.to_be_bytes()); // required ≤ observed
        push_text(&mut crafted, &anchor.anchor_backend);
        assert_eq!(
            ChainAnchor::from_canonical_bytes(&crafted),
            Err(AnchorError::MalformedBytes)
        );
        // Sanity: the honest bytes still decode.
        assert!(ChainAnchor::from_canonical_bytes(&bytes.split_off(0)).is_ok());
    }

    #[test]
    fn assess_reports_final_pending_and_inconsistent() {
        let final_anchor = chain_anchor(AnchorFinality::from_confirmations(12, 12));
        assert_eq!(
            final_anchor.assess([5u8; 32]),
            ChainAnchorAssessment::AnchoredFinal
        );
        let pending = chain_anchor(AnchorFinality::from_confirmations(3, 12));
        assert_eq!(pending.assess([5u8; 32]), ChainAnchorAssessment::AnchoredPending);
        // A different commitment cannot corroborate this object.
        assert_eq!(
            final_anchor.assess([9u8; 32]),
            ChainAnchorAssessment::Inconsistent
        );
    }

    fn observation(source: &str, hash: [u8; 32], finality: AnchorFinality) -> AnchorObservation {
        AnchorObservation {
            source: String::from(source),
            block_height: 1_000,
            block_hash: hash,
            finality,
        }
    }

    #[test]
    fn reconcile_agrees_only_on_unanimous_block_and_finality() {
        let final_f = AnchorFinality::from_confirmations(20, 12);
        let agreed = reconcile_anchor(&[
            observation("rpc-a", [6u8; 32], final_f),
            observation("rpc-b", [6u8; 32], final_f),
        ]);
        assert_eq!(
            agreed,
            AnchorReconciliation::Agreed {
                block_height: 1_000,
                finality: AnchorFinality::Final {
                    observed_confirmations: 20
                }
            }
        );

        // One source lagging → the reconciliation is pending, not final.
        let mixed = reconcile_anchor(&[
            observation("rpc-a", [6u8; 32], final_f),
            observation("rpc-b", [6u8; 32], AnchorFinality::from_confirmations(2, 12)),
        ]);
        match mixed {
            AnchorReconciliation::Agreed { finality, .. } => assert!(!finality.is_final()),
            other => panic!("expected agreed-pending, got {other:?}"),
        }
    }

    #[test]
    fn reconcile_reports_reorg_disagreement_not_a_false_final() {
        // Two sources report different block hashes at the same height: a reorg /
        // RPC disagreement. It must never collapse into a final verdict.
        let disagreement = reconcile_anchor(&[
            observation("rpc-a", [6u8; 32], AnchorFinality::from_confirmations(20, 12)),
            observation("rpc-b", [7u8; 32], AnchorFinality::from_confirmations(20, 12)),
        ]);
        match disagreement {
            AnchorReconciliation::Disagreement {
                reported_block_hashes,
            } => {
                assert_eq!(reported_block_hashes.len(), 2);
            }
            other => panic!("expected disagreement, got {other:?}"),
        }
        assert_eq!(reconcile_anchor(&[]), AnchorReconciliation::NoObservations);
    }
}
