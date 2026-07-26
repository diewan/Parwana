//! Sui object-consumption closure: record, framing, and digest chain.
//!
//! On Sui the seal is a Move object. Closing a source means consuming that
//! object — by id **and version** — in a transaction that records the successor
//! binding. Sui's object model already gives single-use semantics: a specific
//! `(object_id, version)` can be consumed exactly once, and a second attempt
//! references a version that no longer exists.
//!
//! # Why the version is part of the record
//!
//! An object id alone is not a single-use handle: the same id survives across
//! versions. Binding the closure to `(id, version)` is what makes it a
//! consumption of one specific state rather than a statement about the object in
//! general. Omitting the version would let a later closure of the same object
//! be presented as a closure of the earlier state.
//!
//! # What is verified, and under which trust mode
//!
//! [`crate::closure_verifier`] re-derives the whole digest chain
//! record → checkpoint contents → checkpoint summary, so inclusion is
//! cryptographic. Whether that checkpoint is the one the validator committee
//! certified is a **separate** question: Sui checkpoints are certified by a
//! BLS aggregate over 2f+1 stake, and verifying it requires the epoch committee.
//! This adapter therefore reports finality from the caller's
//! [`csv_protocol::ClosureTrustMode`] and returns `Indeterminate` — never
//! `Satisfied` — when the trust mode cannot establish committee agreement. An
//! RPC's own `is_certified` flag is not evidence and is never read as such.

use blake2::{Blake2b, Digest};
use csv_chain_ports::{
    ChainDigest, ClosureMaterialError, ClosureMaterialReader, ClosureMaterialWriter, decode_entries,
};
use csv_hash::Hash;
use csv_protocol::{ClosureDomain, ClosureProofKind, ConsumedStateRef, SourceNullifier};
use serde::{Deserialize, Serialize};

/// Stable chain identifier used by this adapter.
pub const SUI_CHAIN_ID: &str = "sui";
/// Stable proof-family name for Sui object-consumption closure.
pub const SUI_CLOSURE_PROOF_KIND: &str = "sui-object-consumption-v1";
/// Stable identifier of this adapter's closure verifier.
pub const SUI_CLOSURE_VERIFIER_ID: &str = "parwana.csv-sui.closure.v2";
/// Encoding version of this adapter's closure proof material.
pub const SUI_CLOSURE_MATERIAL_VERSION: u16 = 1;
/// Domain tag separating closure records from every other digest on Sui.
pub const SUI_CLOSURE_RECORD_TAG: &[u8] = b"parwana.sui.closure.record.v1";

/// Blake2b-256, Sui's native digest function.
pub fn sui_digest(bytes: &[u8]) -> ChainDigest {
    let mut hasher = Blake2b::<blake2::digest::consts::U32>::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// A configured Sui closure deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiClosureDeployment {
    /// Network identifier, such as `testnet`.
    pub network_id: String,
    /// Move package publishing the closure module.
    pub package_id: [u8; 32],
    /// Deployment identity distinguishing two publications of the same package.
    pub deployment_id: String,
}

impl SuiClosureDeployment {
    /// The protocol-level destination domain this deployment represents.
    pub fn closure_domain(&self) -> ClosureDomain {
        ClosureDomain {
            chain_id: SUI_CHAIN_ID.to_string(),
            network_id: self.network_id.clone(),
            contract_id: self.package_id.to_vec(),
            deployment_id: self.deployment_id.clone(),
            proof_kind: ClosureProofKind::ChainSpecific(SUI_CLOSURE_PROOF_KIND.to_string()),
        }
    }

    /// The binding a valid closure record must carry.
    pub fn expected_binding(
        &self,
        consumed_state: &ConsumedStateRef,
        successor_commitment: &Hash,
    ) -> Hash {
        let nullifier = SourceNullifier::derive(consumed_state);
        self.closure_domain()
            .binding(&nullifier, successor_commitment)
    }
}

/// The on-chain record a Sui closure transaction emits.
///
/// Canonically encoded and digested under its own tag, so no other Sui object or
/// event can be reinterpreted as a closure record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiClosureRecord {
    /// Portable source-conflict identity closed by this record.
    pub nullifier: [u8; 32],
    /// Destination-domain binding selecting one successor.
    pub binding: [u8; 32],
    /// Identity of the consumed seal object.
    pub object_id: [u8; 32],
    /// Version of the consumed seal object.
    pub object_version: u64,
    /// Package that produced the record.
    pub package_id: [u8; 32],
}

impl SuiClosureRecord {
    /// Canonical, domain-separated bytes of this record.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SUI_CLOSURE_RECORD_TAG.len() + 136);
        out.extend_from_slice(SUI_CLOSURE_RECORD_TAG);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(&self.object_id);
        out.extend_from_slice(&self.object_version.to_le_bytes());
        out.extend_from_slice(&self.package_id);
        out
    }

    /// Digest of this record, as committed by checkpoint contents.
    pub fn digest(&self) -> ChainDigest {
        sui_digest(&self.canonical_bytes())
    }
}

/// A Sui checkpoint summary, in the fields this adapter verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiCheckpointSummary {
    /// Checkpoint sequence number.
    pub sequence_number: u64,
    /// Epoch the checkpoint belongs to.
    pub epoch: u64,
    /// Digest the summary commits for its contents.
    pub content_digest: ChainDigest,
}

impl SuiCheckpointSummary {
    /// Canonical bytes of the summary.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(b"parwana.sui.checkpoint.summary.v1");
        out.extend_from_slice(&self.sequence_number.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.content_digest);
        out
    }

    /// Digest identifying this checkpoint.
    pub fn digest(&self) -> ChainDigest {
        sui_digest(&self.canonical_bytes())
    }
}

/// Chain-native material a recipient needs to verify one Sui closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiClosureMaterial {
    /// The closure record claimed to be committed.
    pub record: SuiClosureRecord,
    /// Canonical checkpoint contents: the digests the checkpoint commits.
    pub checkpoint_contents: Vec<ChainDigest>,
    /// The checkpoint summary committing those contents.
    pub summary: SuiCheckpointSummary,
}

impl SuiClosureMaterial {
    /// Encode to canonical, deterministic proof-material bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = ClosureMaterialWriter::new(SUI_CLOSURE_MATERIAL_VERSION);
        writer.put_fixed(&self.record.nullifier);
        writer.put_fixed(&self.record.binding);
        writer.put_fixed(&self.record.object_id);
        writer.put_u64(self.record.object_version);
        writer.put_fixed(&self.record.package_id);
        writer.put_u64(self.summary.sequence_number);
        writer.put_u64(self.summary.epoch);
        writer.put_fixed(&self.summary.content_digest);
        writer.put_bytes(&csv_chain_ports::checkpoint_chain::encode_entries(
            &self.checkpoint_contents,
        ));
        writer.finish()
    }

    /// Decode canonical proof-material bytes, failing closed on any deviation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClosureMaterialError> {
        let mut reader = ClosureMaterialReader::new(bytes, SUI_CLOSURE_MATERIAL_VERSION)?;
        let record = SuiClosureRecord {
            nullifier: reader.take_fixed::<32>()?,
            binding: reader.take_fixed::<32>()?,
            object_id: reader.take_fixed::<32>()?,
            object_version: reader.take_u64()?,
            package_id: reader.take_fixed::<32>()?,
        };
        let summary = SuiCheckpointSummary {
            sequence_number: reader.take_u64()?,
            epoch: reader.take_u64()?,
            content_digest: reader.take_fixed::<32>()?,
        };
        let checkpoint_contents = decode_entries(reader.take_bytes()?)?;
        reader.finish()?;
        Ok(Self {
            record,
            checkpoint_contents,
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: u16 = 7;

    fn deployment() -> SuiClosureDeployment {
        SuiClosureDeployment {
            network_id: "testnet".into(),
            package_id: [0xAB; 32],
            deployment_id: "closure-package-1".into(),
        }
    }

    fn source() -> ConsumedStateRef {
        ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
    }

    fn record() -> SuiClosureRecord {
        let deployment = deployment();
        SuiClosureRecord {
            nullifier: *SourceNullifier::derive(&source()).as_bytes(),
            binding: *deployment
                .expected_binding(&source(), &Hash::new([5; 32]))
                .as_bytes(),
            object_id: [0x11; 32],
            object_version: 4,
            package_id: deployment.package_id,
        }
    }

    fn material() -> SuiClosureMaterial {
        let record = record();
        let contents = vec![[0x22; 32], record.digest(), [0x33; 32]];
        let summary = SuiCheckpointSummary {
            sequence_number: 900,
            epoch: 12,
            content_digest: sui_digest(&csv_chain_ports::checkpoint_chain::encode_entries(
                &contents,
            )),
        };
        SuiClosureMaterial {
            record,
            checkpoint_contents: contents,
            summary,
        }
    }

    #[test]
    fn record_digest_changes_with_object_version() {
        // The version is what makes this a consumption of one state.
        let mut later = record();
        later.object_version += 1;
        assert_ne!(later.digest(), record().digest());
    }

    #[test]
    fn record_digest_changes_with_every_field() {
        let base = record().digest();
        let mut changed = record();
        changed.nullifier[0] ^= 1;
        assert_ne!(changed.digest(), base);
        changed = record();
        changed.binding[0] ^= 1;
        assert_ne!(changed.digest(), base);
        changed = record();
        changed.object_id[0] ^= 1;
        assert_ne!(changed.digest(), base);
        changed = record();
        changed.package_id[0] ^= 1;
        assert_ne!(changed.digest(), base);
    }

    #[test]
    fn record_encoding_is_domain_separated() {
        assert!(
            record()
                .canonical_bytes()
                .starts_with(SUI_CLOSURE_RECORD_TAG)
        );
    }

    #[test]
    fn nullifier_is_shared_but_binding_is_deployment_specific() {
        let first = deployment();
        let mut second = deployment();
        second.package_id = [0xCD; 32];
        second.deployment_id = "closure-package-2".into();
        let successor = Hash::new([5; 32]);
        assert_ne!(
            first.expected_binding(&source(), &successor),
            second.expected_binding(&source(), &successor)
        );
    }

    #[test]
    fn material_round_trips_and_is_deterministic() {
        let material = material();
        let encoded = material.encode();
        assert_eq!(SuiClosureMaterial::decode(&encoded).unwrap(), material);
        assert_eq!(encoded, material.encode());
    }

    #[test]
    fn material_rejects_truncation_and_trailing_bytes() {
        let encoded = material().encode();
        for cut in 2..encoded.len() {
            assert!(
                SuiClosureMaterial::decode(&encoded[..cut]).is_err(),
                "truncation at {cut} must not decode"
            );
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(SuiClosureMaterial::decode(&extended).is_err());
    }

    #[test]
    fn material_rejects_a_foreign_version() {
        let mut encoded = material().encode();
        encoded[0] = 0xFE;
        assert!(matches!(
            SuiClosureMaterial::decode(&encoded),
            Err(ClosureMaterialError::UnsupportedVersion { .. })
        ));
    }
}
