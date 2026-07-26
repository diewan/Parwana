//! Aptos resource/nullifier closure: record, framing, and digest chain.
//!
//! On Aptos the closure is a **resource fact**: a Move module under a configured
//! account address holds a nullifier table, and closing a source writes one
//! entry mapping the portable [`SourceNullifier`] to the successor binding. The
//! module writes only into an absent entry, so a second successor of the same
//! source cannot be recorded.
//!
//! The record is committed into a transaction accumulator, which is committed by
//! a ledger info. This adapter re-derives that chain; it does not re-derive the
//! validator signatures over the ledger info, which is why finality is reported
//! from the caller's trust mode. See
//! [`crate::closure_verifier::finality_for_trust_mode`].

use csv_chain_ports::{
    ChainDigest, ClosureMaterialError, ClosureMaterialReader, ClosureMaterialWriter,
    decode_entries, encode_entries,
};
use csv_hash::Hash;
use csv_protocol::{ClosureDomain, ClosureProofKind, ConsumedStateRef, SourceNullifier};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Stable chain identifier used by this adapter.
pub const APTOS_CHAIN_ID: &str = "aptos";
/// Stable proof-family name for Aptos resource/nullifier closure.
pub const APTOS_CLOSURE_PROOF_KIND: &str = "aptos-resource-nullifier-v1";
/// Stable identifier of this adapter's closure verifier.
pub const APTOS_CLOSURE_VERIFIER_ID: &str = "parwana.csv-aptos.closure.v2";
/// Encoding version of this adapter's closure proof material.
pub const APTOS_CLOSURE_MATERIAL_VERSION: u16 = 1;
/// Domain tag separating closure records from every other digest on Aptos.
pub const APTOS_CLOSURE_RECORD_TAG: &[u8] = b"parwana.aptos.closure.record.v1";

/// SHA3-256, Aptos's native digest function.
pub fn aptos_digest(bytes: &[u8]) -> ChainDigest {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// A configured Aptos closure deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AptosClosureDeployment {
    /// Network identifier, such as `testnet`.
    pub network_id: String,
    /// Account address publishing the closure module.
    pub module_address: [u8; 32],
    /// Deployment identity distinguishing two publications of the same module.
    pub deployment_id: String,
}

impl AptosClosureDeployment {
    /// The protocol-level destination domain this deployment represents.
    pub fn closure_domain(&self) -> ClosureDomain {
        ClosureDomain {
            chain_id: APTOS_CHAIN_ID.to_string(),
            network_id: self.network_id.clone(),
            contract_id: self.module_address.to_vec(),
            deployment_id: self.deployment_id.clone(),
            proof_kind: ClosureProofKind::ChainSpecific(APTOS_CLOSURE_PROOF_KIND.to_string()),
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

/// The resource entry an Aptos closure transaction writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AptosClosureRecord {
    /// Portable source-conflict identity closed by this record.
    pub nullifier: [u8; 32],
    /// Destination-domain binding selecting one successor.
    pub binding: [u8; 32],
    /// Account address holding the nullifier table.
    pub module_address: [u8; 32],
    /// Ledger version at which the entry was written.
    pub ledger_version: u64,
}

impl AptosClosureRecord {
    /// Canonical, domain-separated bytes of this record.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(APTOS_CLOSURE_RECORD_TAG.len() + 104);
        out.extend_from_slice(APTOS_CLOSURE_RECORD_TAG);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(&self.module_address);
        out.extend_from_slice(&self.ledger_version.to_le_bytes());
        out
    }

    /// Digest of this record, as committed by the transaction accumulator.
    pub fn digest(&self) -> ChainDigest {
        aptos_digest(&self.canonical_bytes())
    }
}

/// An Aptos ledger info, in the fields this adapter verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AptosLedgerInfo {
    /// Ledger version this info commits.
    pub version: u64,
    /// Epoch the ledger info belongs to.
    pub epoch: u64,
    /// Root digest of the transaction accumulator.
    pub accumulator_root: ChainDigest,
}

impl AptosLedgerInfo {
    /// Canonical bytes of the ledger info.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"parwana.aptos.ledger.info.v1");
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.accumulator_root);
        out
    }

    /// Digest identifying this ledger info.
    pub fn digest(&self) -> ChainDigest {
        aptos_digest(&self.canonical_bytes())
    }
}

/// Chain-native material a recipient needs to verify one Aptos closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AptosClosureMaterial {
    /// The closure record claimed to be committed.
    pub record: AptosClosureRecord,
    /// Digests committed by the transaction accumulator.
    pub accumulator_entries: Vec<ChainDigest>,
    /// The ledger info committing that accumulator.
    pub ledger_info: AptosLedgerInfo,
}

impl AptosClosureMaterial {
    /// Encode to canonical, deterministic proof-material bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = ClosureMaterialWriter::new(APTOS_CLOSURE_MATERIAL_VERSION);
        writer.put_fixed(&self.record.nullifier);
        writer.put_fixed(&self.record.binding);
        writer.put_fixed(&self.record.module_address);
        writer.put_u64(self.record.ledger_version);
        writer.put_u64(self.ledger_info.version);
        writer.put_u64(self.ledger_info.epoch);
        writer.put_fixed(&self.ledger_info.accumulator_root);
        writer.put_bytes(&encode_entries(&self.accumulator_entries));
        writer.finish()
    }

    /// Decode canonical proof-material bytes, failing closed on any deviation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClosureMaterialError> {
        let mut reader = ClosureMaterialReader::new(bytes, APTOS_CLOSURE_MATERIAL_VERSION)?;
        let record = AptosClosureRecord {
            nullifier: reader.take_fixed::<32>()?,
            binding: reader.take_fixed::<32>()?,
            module_address: reader.take_fixed::<32>()?,
            ledger_version: reader.take_u64()?,
        };
        let ledger_info = AptosLedgerInfo {
            version: reader.take_u64()?,
            epoch: reader.take_u64()?,
            accumulator_root: reader.take_fixed::<32>()?,
        };
        let accumulator_entries = decode_entries(reader.take_bytes()?)?;
        reader.finish()?;
        Ok(Self {
            record,
            accumulator_entries,
            ledger_info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: u16 = 7;

    fn deployment() -> AptosClosureDeployment {
        AptosClosureDeployment {
            network_id: "testnet".into(),
            module_address: [0xAB; 32],
            deployment_id: "closure-module-1".into(),
        }
    }

    fn source() -> ConsumedStateRef {
        ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
    }

    fn record() -> AptosClosureRecord {
        let deployment = deployment();
        AptosClosureRecord {
            nullifier: *SourceNullifier::derive(&source()).as_bytes(),
            binding: *deployment
                .expected_binding(&source(), &Hash::new([5; 32]))
                .as_bytes(),
            module_address: deployment.module_address,
            ledger_version: 4_200,
        }
    }

    fn material() -> AptosClosureMaterial {
        let record = record();
        let entries = vec![[0x22; 32], record.digest(), [0x33; 32]];
        AptosClosureMaterial {
            record,
            ledger_info: AptosLedgerInfo {
                version: 4_200,
                epoch: 9,
                accumulator_root: aptos_digest(&encode_entries(&entries)),
            },
            accumulator_entries: entries,
        }
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
        changed.module_address[0] ^= 1;
        assert_ne!(changed.digest(), base);
        changed = record();
        changed.ledger_version += 1;
        assert_ne!(changed.digest(), base);
    }

    #[test]
    fn record_encoding_is_domain_separated() {
        assert!(
            record()
                .canonical_bytes()
                .starts_with(APTOS_CLOSURE_RECORD_TAG)
        );
    }

    #[test]
    fn nullifier_is_shared_but_binding_is_deployment_specific() {
        let first = deployment();
        let mut second = deployment();
        second.module_address = [0xCD; 32];
        second.deployment_id = "closure-module-2".into();
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
        assert_eq!(AptosClosureMaterial::decode(&encoded).unwrap(), material);
        assert_eq!(encoded, material.encode());
    }

    #[test]
    fn material_rejects_truncation_and_trailing_bytes() {
        let encoded = material().encode();
        for cut in 2..encoded.len() {
            assert!(
                AptosClosureMaterial::decode(&encoded[..cut]).is_err(),
                "truncation at {cut} must not decode"
            );
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(AptosClosureMaterial::decode(&extended).is_err());
    }

    #[test]
    fn material_rejects_a_foreign_version() {
        let mut encoded = material().encode();
        encoded[0] = 0xFE;
        assert!(matches!(
            AptosClosureMaterial::decode(&encoded),
            Err(ClosureMaterialError::UnsupportedVersion { .. })
        ));
    }
}
