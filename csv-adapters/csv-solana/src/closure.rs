//! Solana account/nullifier closure: record, framing, and digest chain.
//!
//! On Solana the closure is an **account fact**: a program derives an address
//! from the portable [`SourceNullifier`] and initialises that account with the
//! successor binding. Account initialisation fails if the account already
//! exists, so a second successor of the same source cannot be recorded — the
//! runtime provides the atomic reject-reuse property directly.
//!
//! # Solana's honest verification ceiling
//!
//! Solana is the weakest of the four chains for independent verification, and
//! this module says so rather than papering over it. There is **no state proof**
//! a recipient can check: Solana's RPC exposes account contents and bank hashes,
//! but there is no Merkle path from an account to a signed consensus artifact
//! that a light client can validate, and no committee signature over a compact
//! header that a recipient could recompute.
//!
//! What this adapter can therefore verify cryptographically is *internal
//! consistency*: that the closure record is committed by the slot entry list,
//! which is committed by the bank hash the caller names. What it cannot verify
//! from RPC data alone is that this bank hash is the one the cluster actually
//! produced.
//!
//! That is not a defect in this adapter; it is a property of the chain. The
//! consequence is encoded in
//! [`crate::closure_verifier::finality_for_trust_mode`]: under `RpcQuorum` —
//! the only mode a plain RPC endpoint supports — finality is `Indeterminate`
//! and closure is therefore `Indeterminate` too. A recipient is told the closure
//! is unproven. Reporting `Satisfied` on an RPC's assurance would be exactly the
//! "structural-only verification presented as cryptographic success" the
//! architecture charter prohibits.

use csv_chain_ports::{
    ChainDigest, ClosureMaterialError, ClosureMaterialReader, ClosureMaterialWriter,
    decode_entries, encode_entries,
};
use csv_hash::Hash;
use csv_protocol::{ClosureDomain, ClosureProofKind, ConsumedStateRef, SourceNullifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Stable chain identifier used by this adapter.
pub const SOLANA_CHAIN_ID: &str = "solana";
/// Stable proof-family name for Solana account/nullifier closure.
pub const SOLANA_CLOSURE_PROOF_KIND: &str = "solana-account-nullifier-v1";
/// Stable identifier of this adapter's closure verifier.
pub const SOLANA_CLOSURE_VERIFIER_ID: &str = "parwana.csv-solana.closure.v2";
/// Encoding version of this adapter's closure proof material.
pub const SOLANA_CLOSURE_MATERIAL_VERSION: u16 = 1;
/// Domain tag separating closure records from every other digest on Solana.
pub const SOLANA_CLOSURE_RECORD_TAG: &[u8] = b"parwana.solana.closure.record.v1";
/// Seed prefix for the closure account's program-derived address.
pub const SOLANA_CLOSURE_PDA_SEED: &[u8] = b"parwana-closure";

/// SHA-256, Solana's native digest function.
pub fn solana_digest(bytes: &[u8]) -> ChainDigest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// A configured Solana closure deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaClosureDeployment {
    /// Cluster identifier, such as `devnet`.
    pub network_id: String,
    /// Program owning the closure accounts.
    pub program_id: [u8; 32],
    /// Deployment identity distinguishing two deployments of the same program.
    pub deployment_id: String,
}

impl SolanaClosureDeployment {
    /// The protocol-level destination domain this deployment represents.
    pub fn closure_domain(&self) -> ClosureDomain {
        ClosureDomain {
            chain_id: SOLANA_CHAIN_ID.to_string(),
            network_id: self.network_id.clone(),
            contract_id: self.program_id.to_vec(),
            deployment_id: self.deployment_id.clone(),
            proof_kind: ClosureProofKind::ChainSpecific(SOLANA_CLOSURE_PROOF_KIND.to_string()),
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

    /// Seeds of the closure account for one source, in program order.
    ///
    /// The nullifier is a seed, so one source maps to exactly one account and
    /// the runtime's "account already exists" check *is* the reuse rejection.
    pub fn closure_account_seeds(&self, consumed_state: &ConsumedStateRef) -> Vec<Vec<u8>> {
        let nullifier = SourceNullifier::derive(consumed_state);
        vec![
            SOLANA_CLOSURE_PDA_SEED.to_vec(),
            nullifier.as_bytes().to_vec(),
        ]
    }
}

/// The account state a Solana closure instruction initialises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaClosureRecord {
    /// Portable source-conflict identity closed by this record.
    pub nullifier: [u8; 32],
    /// Destination-domain binding selecting one successor.
    pub binding: [u8; 32],
    /// Program that owns the closure account.
    pub program_id: [u8; 32],
    /// Slot in which the account was initialised.
    pub slot: u64,
}

impl SolanaClosureRecord {
    /// Canonical, domain-separated bytes of this record.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SOLANA_CLOSURE_RECORD_TAG.len() + 104);
        out.extend_from_slice(SOLANA_CLOSURE_RECORD_TAG);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(&self.program_id);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out
    }

    /// Digest of this record, as committed by the slot's entry list.
    pub fn digest(&self) -> ChainDigest {
        solana_digest(&self.canonical_bytes())
    }
}

/// A Solana bank hash, in the fields this adapter verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaBankHash {
    /// Slot this bank hash commits.
    pub slot: u64,
    /// Digest of the slot's entry list.
    pub entries_digest: ChainDigest,
    /// Parent bank hash, chaining slots together.
    pub parent_hash: ChainDigest,
}

impl SolanaBankHash {
    /// Canonical bytes of the bank hash preimage.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(b"parwana.solana.bank.hash.v1");
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.entries_digest);
        out.extend_from_slice(&self.parent_hash);
        out
    }

    /// Digest identifying this bank hash.
    pub fn digest(&self) -> ChainDigest {
        solana_digest(&self.canonical_bytes())
    }
}

/// Chain-native material a recipient needs to verify one Solana closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaClosureMaterial {
    /// The closure record claimed to be committed.
    pub record: SolanaClosureRecord,
    /// Digests committed by the slot's entry list.
    pub slot_entries: Vec<ChainDigest>,
    /// The bank hash committing that entry list.
    pub bank_hash: SolanaBankHash,
}

impl SolanaClosureMaterial {
    /// Encode to canonical, deterministic proof-material bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = ClosureMaterialWriter::new(SOLANA_CLOSURE_MATERIAL_VERSION);
        writer.put_fixed(&self.record.nullifier);
        writer.put_fixed(&self.record.binding);
        writer.put_fixed(&self.record.program_id);
        writer.put_u64(self.record.slot);
        writer.put_u64(self.bank_hash.slot);
        writer.put_fixed(&self.bank_hash.entries_digest);
        writer.put_fixed(&self.bank_hash.parent_hash);
        writer.put_bytes(&encode_entries(&self.slot_entries));
        writer.finish()
    }

    /// Decode canonical proof-material bytes, failing closed on any deviation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClosureMaterialError> {
        let mut reader = ClosureMaterialReader::new(bytes, SOLANA_CLOSURE_MATERIAL_VERSION)?;
        let record = SolanaClosureRecord {
            nullifier: reader.take_fixed::<32>()?,
            binding: reader.take_fixed::<32>()?,
            program_id: reader.take_fixed::<32>()?,
            slot: reader.take_u64()?,
        };
        let bank_hash = SolanaBankHash {
            slot: reader.take_u64()?,
            entries_digest: reader.take_fixed::<32>()?,
            parent_hash: reader.take_fixed::<32>()?,
        };
        let slot_entries = decode_entries(reader.take_bytes()?)?;
        reader.finish()?;
        Ok(Self {
            record,
            slot_entries,
            bank_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: u16 = 7;

    fn deployment() -> SolanaClosureDeployment {
        SolanaClosureDeployment {
            network_id: "devnet".into(),
            program_id: [0xAB; 32],
            deployment_id: "closure-program-1".into(),
        }
    }

    fn source() -> ConsumedStateRef {
        ConsumedStateRef::new(Hash::new([1; 32]), 3, TOKEN)
    }

    fn record() -> SolanaClosureRecord {
        let deployment = deployment();
        SolanaClosureRecord {
            nullifier: *SourceNullifier::derive(&source()).as_bytes(),
            binding: *deployment
                .expected_binding(&source(), &Hash::new([5; 32]))
                .as_bytes(),
            program_id: deployment.program_id,
            slot: 777,
        }
    }

    fn material() -> SolanaClosureMaterial {
        let record = record();
        let entries = vec![[0x22; 32], record.digest(), [0x33; 32]];
        SolanaClosureMaterial {
            record,
            bank_hash: SolanaBankHash {
                slot: 777,
                entries_digest: solana_digest(&encode_entries(&entries)),
                parent_hash: [0x44; 32],
            },
            slot_entries: entries,
        }
    }

    #[test]
    fn account_seeds_are_derived_from_the_portable_nullifier() {
        // The account address is a function of the source alone, so the runtime
        // rejects a second initialisation for the same source.
        let deployment = deployment();
        let seeds = deployment.closure_account_seeds(&source());
        assert_eq!(seeds[0], SOLANA_CLOSURE_PDA_SEED);
        assert_eq!(seeds[1], SourceNullifier::derive(&source()).as_bytes());

        let mut other = source();
        other.output_index += 1;
        assert_ne!(deployment.closure_account_seeds(&other), seeds);
    }

    #[test]
    fn account_seeds_do_not_depend_on_the_successor() {
        // Two competing successors of one source target the same account, which
        // is what makes the second one fail rather than land beside the first.
        let deployment = deployment();
        assert_eq!(
            deployment.closure_account_seeds(&source()),
            deployment.closure_account_seeds(&source())
        );
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
        changed.program_id[0] ^= 1;
        assert_ne!(changed.digest(), base);
        changed = record();
        changed.slot += 1;
        assert_ne!(changed.digest(), base);
    }

    #[test]
    fn record_encoding_is_domain_separated() {
        assert!(
            record()
                .canonical_bytes()
                .starts_with(SOLANA_CLOSURE_RECORD_TAG)
        );
    }

    #[test]
    fn nullifier_is_shared_but_binding_is_deployment_specific() {
        let first = deployment();
        let mut second = deployment();
        second.program_id = [0xCD; 32];
        second.deployment_id = "closure-program-2".into();
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
        assert_eq!(SolanaClosureMaterial::decode(&encoded).unwrap(), material);
        assert_eq!(encoded, material.encode());
    }

    #[test]
    fn material_rejects_truncation_and_trailing_bytes() {
        let encoded = material().encode();
        for cut in 2..encoded.len() {
            assert!(
                SolanaClosureMaterial::decode(&encoded[..cut]).is_err(),
                "truncation at {cut} must not decode"
            );
        }
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(SolanaClosureMaterial::decode(&extended).is_err());
    }

    #[test]
    fn material_rejects_a_foreign_version() {
        let mut encoded = material().encode();
        encoded[0] = 0xFE;
        assert!(matches!(
            SolanaClosureMaterial::decode(&encoded),
            Err(ClosureMaterialError::UnsupportedVersion { .. })
        ));
    }
}
