//! Verification of a "record → batch → checkpoint" commitment chain.
//!
//! Ethereum proves closure with a Merkle-Patricia proof against a state root.
//! Sui, Aptos, and Solana instead commit a closure record into a batch
//! (checkpoint contents, a transaction accumulator, a slot's entries), and
//! commit that batch into a checkpoint. The shape is identical on all three, so
//! the walk lives here once and each adapter supplies its own hash function and
//! record layout.
//!
//! # What this establishes, and what it does not
//!
//! A successful [`verify_commitment_chain`] means: *the supplied record is
//! committed, by hash, under the supplied checkpoint digest.* That is a
//! statement about **inclusion**, and nothing more.
//!
//! It is emphatically **not** a statement that the checkpoint is canonical,
//! final, or agreed by a validator set. Anyone can build a checkpoint containing
//! any record; the digest chain only proves internal consistency. Establishing
//! that a checkpoint is the one consensus actually produced is a separate
//! question, answered by the caller's [`crate::ClosureTrustMode`], and reported
//! on a separate dimension. Conflating the two would let a fabricated checkpoint
//! read as closure, which is precisely the failure the split exists to prevent.
//!
//! Callers must therefore not promote an `Included` result to
//! `ClosureDimensionStatus::Satisfied` on the closure dimension unless finality
//! was independently established.

use crate::ClosureMaterialError;

/// A 32-byte digest produced by a chain's native hash function.
pub type ChainDigest = [u8; 32];

/// A chain's native 32-byte hash function over arbitrary bytes.
pub type ChainHasher = fn(&[u8]) -> ChainDigest;

/// The chain of commitments a closure record must satisfy.
#[derive(Clone, Debug)]
pub struct CommitmentChain<'a> {
    /// Canonical bytes of the closure record itself.
    pub record_bytes: &'a [u8],
    /// Canonical bytes of the batch that should contain the record's digest.
    pub batch_bytes: &'a [u8],
    /// Digests listed by the batch, in the order the batch commits them.
    pub batch_entries: &'a [ChainDigest],
    /// Digest the checkpoint commits for its batch.
    pub checkpoint_batch_digest: ChainDigest,
    /// Digest identifying the checkpoint itself.
    pub checkpoint_digest: ChainDigest,
    /// Canonical bytes of the checkpoint summary.
    pub checkpoint_summary_bytes: &'a [u8],
}

/// Outcome of walking a commitment chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainInclusion {
    /// Every link re-derived: the record is committed under the checkpoint.
    Included {
        /// Position of the record's digest within the batch.
        index: usize,
    },
    /// A link did not re-derive.
    NotIncluded(ChainInclusionFailure),
}

/// Which link of the commitment chain failed to re-derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainInclusionFailure {
    /// The checkpoint summary does not hash to the checkpoint digest.
    #[error("checkpoint summary does not hash to the checkpoint digest")]
    CheckpointDigestMismatch,
    /// The batch does not hash to the digest the checkpoint commits.
    #[error("batch does not hash to the digest committed by the checkpoint")]
    BatchDigestMismatch,
    /// The batch's listed digests do not reproduce the batch bytes.
    #[error("batch entries are not the entries the batch commits")]
    BatchEntriesMismatch,
    /// The record's digest is absent from the batch.
    #[error("record digest is not committed by the batch")]
    RecordNotInBatch,
}

/// Walk the chain record → batch → checkpoint, re-deriving every link.
///
/// Each step recomputes a digest from bytes the caller supplied and compares it
/// to the digest the next level up commits. No digest is trusted because it was
/// handed over; every one is either recomputed or matched against a recomputed
/// value.
pub fn verify_commitment_chain(chain: &CommitmentChain<'_>, hash: ChainHasher) -> ChainInclusion {
    // The checkpoint must be the one its own summary describes.
    if hash(chain.checkpoint_summary_bytes) != chain.checkpoint_digest {
        return ChainInclusion::NotIncluded(ChainInclusionFailure::CheckpointDigestMismatch);
    }

    // The batch must be the one the checkpoint committed.
    if hash(chain.batch_bytes) != chain.checkpoint_batch_digest {
        return ChainInclusion::NotIncluded(ChainInclusionFailure::BatchDigestMismatch);
    }

    // The listed entries must be exactly what the batch bytes encode, so a
    // caller cannot supply a batch whose bytes commit one set of records while
    // claiming a different, more convenient list.
    if encode_entries(chain.batch_entries) != chain.batch_bytes {
        return ChainInclusion::NotIncluded(ChainInclusionFailure::BatchEntriesMismatch);
    }

    let record_digest = hash(chain.record_bytes);
    match chain
        .batch_entries
        .iter()
        .position(|entry| entry == &record_digest)
    {
        Some(index) => ChainInclusion::Included { index },
        None => ChainInclusion::NotIncluded(ChainInclusionFailure::RecordNotInBatch),
    }
}

/// Canonical encoding of a batch's entry list.
///
/// A fixed-width, length-prefixed encoding: the count cannot be inflated and no
/// two distinct entry lists share an encoding.
pub fn encode_entries(entries: &[ChainDigest]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + entries.len() * 32);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out
}

/// Decode a canonical batch entry list.
pub fn decode_entries(bytes: &[u8]) -> Result<Vec<ChainDigest>, ClosureMaterialError> {
    if bytes.len() < 4 {
        return Err(ClosureMaterialError::UnexpectedEnd {
            read: bytes.len(),
            needed: 4,
        });
    }
    let count = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let body = &bytes[4..];
    if count.saturating_mul(32) != body.len() {
        return Err(ClosureMaterialError::LengthOverrun {
            declared: count.saturating_mul(32),
            available: body.len(),
        });
    }
    let mut entries = Vec::with_capacity(count);
    for chunk in body.chunks_exact(32) {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(chunk);
        entries.push(digest);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(bytes: &[u8]) -> ChainDigest {
        // A stand-in hash for the chain walk itself; adapters pass their own.
        use std::hash::{Hash, Hasher};
        let mut out = [0u8; 32];
        for (chunk_index, chunk) in bytes.chunks(8).enumerate() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            chunk.hash(&mut hasher);
            chunk_index.hash(&mut hasher);
            bytes.len().hash(&mut hasher);
            let value = hasher.finish().to_le_bytes();
            for (i, byte) in value.iter().enumerate() {
                out[(chunk_index * 8 + i) % 32] ^= byte;
            }
        }
        out[0] ^= bytes.len() as u8;
        out
    }

    struct Fixture {
        record: Vec<u8>,
        batch: Vec<u8>,
        entries: Vec<ChainDigest>,
        summary: Vec<u8>,
        batch_digest: ChainDigest,
        checkpoint_digest: ChainDigest,
    }

    fn fixture() -> Fixture {
        let record = b"closure-record".to_vec();
        let entries = vec![test_hash(b"other"), test_hash(&record), test_hash(b"third")];
        let batch = encode_entries(&entries);
        let batch_digest = test_hash(&batch);
        let summary = b"summary-bytes".to_vec();
        let checkpoint_digest = test_hash(&summary);
        Fixture {
            record,
            batch,
            entries,
            summary,
            batch_digest,
            checkpoint_digest,
        }
    }

    fn chain(f: &Fixture) -> CommitmentChain<'_> {
        CommitmentChain {
            record_bytes: &f.record,
            batch_bytes: &f.batch,
            batch_entries: &f.entries,
            checkpoint_batch_digest: f.batch_digest,
            checkpoint_digest: f.checkpoint_digest,
            checkpoint_summary_bytes: &f.summary,
        }
    }

    #[test]
    fn an_honest_chain_is_included_at_its_position() {
        let f = fixture();
        assert_eq!(
            verify_commitment_chain(&chain(&f), test_hash),
            ChainInclusion::Included { index: 1 }
        );
    }

    #[test]
    fn a_record_absent_from_the_batch_is_not_included() {
        let f = fixture();
        let other = b"different-record".to_vec();
        let mut c = chain(&f);
        c.record_bytes = &other;
        assert_eq!(
            verify_commitment_chain(&c, test_hash),
            ChainInclusion::NotIncluded(ChainInclusionFailure::RecordNotInBatch)
        );
    }

    #[test]
    fn a_forged_checkpoint_digest_is_rejected() {
        let f = fixture();
        let mut c = chain(&f);
        c.checkpoint_digest = [0xFF; 32];
        assert_eq!(
            verify_commitment_chain(&c, test_hash),
            ChainInclusion::NotIncluded(ChainInclusionFailure::CheckpointDigestMismatch)
        );
    }

    #[test]
    fn a_batch_the_checkpoint_did_not_commit_is_rejected() {
        let f = fixture();
        let mut c = chain(&f);
        c.checkpoint_batch_digest = [0xAA; 32];
        assert_eq!(
            verify_commitment_chain(&c, test_hash),
            ChainInclusion::NotIncluded(ChainInclusionFailure::BatchDigestMismatch)
        );
    }

    #[test]
    fn entries_that_disagree_with_the_batch_bytes_are_rejected() {
        // The attack this blocks: supply real batch bytes, but claim an entry
        // list that contains your record.
        let f = fixture();
        let mut forged = f.entries.clone();
        forged.push(test_hash(b"smuggled"));
        let mut c = chain(&f);
        c.batch_entries = &forged;
        assert_eq!(
            verify_commitment_chain(&c, test_hash),
            ChainInclusion::NotIncluded(ChainInclusionFailure::BatchEntriesMismatch)
        );
    }

    #[test]
    fn entries_round_trip() {
        let f = fixture();
        assert_eq!(decode_entries(&f.batch).unwrap(), f.entries);
    }

    #[test]
    fn malformed_entry_encodings_fail_closed() {
        assert!(decode_entries(&[]).is_err());
        assert!(decode_entries(&[1, 0, 0, 0]).is_err());
        let mut truncated = encode_entries(&[[1; 32], [2; 32]]);
        truncated.pop();
        assert!(decode_entries(&truncated).is_err());
    }
}
