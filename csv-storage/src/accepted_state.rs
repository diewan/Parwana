//! Atomic cache of verified accepted transition history.
//!
//! Conflict identity is derived exclusively from [`ConsumedStateRef`]. Transfer
//! or envelope identifiers are audit metadata and cannot bypass the CAS key.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use csv_hash::Hash;
use csv_protocol::{ClosureVerificationResult, Consumable, ConsumedStateRef};
#[cfg(feature = "redb")]
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

/// One typed assurance reading persisted with an accepted transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedAssuranceReading {
    /// Stable assurance-dimension registry identifier.
    pub dimension: String,
    /// Stable four-valued status identifier.
    pub status: String,
    /// Stable reason-code identifiers.
    pub reason_codes: Vec<String>,
    /// Verifier/provider that established this reading.
    pub provider_id: String,
    /// Explicit limitations retained from verification.
    pub limitations: Vec<String>,
}

/// Complete assurance report captured at acceptance time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedAssuranceReport {
    /// Digest of the exact verification context.
    pub verification_context_digest: Hash,
    /// Digest of the complete source assurance report.
    pub report_digest: Hash,
    /// Every reading in canonical dimension order.
    pub readings: Vec<AcceptedAssuranceReading>,
}

/// Atomically persisted accepted successor and its verification evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedStateRecord {
    /// Accepted transition commitment.
    pub transition_id: Hash,
    /// State whose successor this transition claims to be.
    pub consumed_state: ConsumedStateRef,
    /// Commitments of outputs created by the transition.
    pub created_outputs: Vec<Hash>,
    /// Domain-separated identity of the closure proof.
    pub closure_id: Hash,
    /// Full typed chain-native closure result, including checkpoint and policy.
    pub closure: ClosureVerificationResult,
    /// Full typed assurance report used by the acceptance policy.
    pub assurance: AcceptedAssuranceReport,
    /// Non-authoritative transfer identifier retained only for audit lookup.
    pub transfer_id: Option<String>,
}

impl AcceptedStateRecord {
    /// Canonical conflict key. Deliberately excludes `transfer_id`.
    pub fn conflict_key(&self) -> [u8; 32] {
        *self.consumed_state.digest().as_bytes()
    }

    /// Validate mandatory evidence before beginning a storage transaction.
    pub fn validate(&self) -> Result<(), AcceptedStateError> {
        self.closure
            .validate()
            .map_err(|error| AcceptedStateError::InvalidRecord(error.to_string()))?;
        if self.transition_id == Hash::new([0; 32])
            || self.closure_id == Hash::new([0; 32])
            || self.assurance.verification_context_digest == Hash::new([0; 32])
            || self.assurance.report_digest == Hash::new([0; 32])
        {
            return Err(AcceptedStateError::InvalidRecord(
                "mandatory commitment uses the zero sentinel".into(),
            ));
        }
        if self.created_outputs.is_empty() || self.assurance.readings.is_empty() {
            return Err(AcceptedStateError::InvalidRecord(
                "outputs and assurance readings must be retained".into(),
            ));
        }
        Ok(())
    }
}

/// Stable accepted-state storage failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AcceptedStateError {
    /// Another transition already consumed this exact state.
    #[error("consumed state already has successor {existing_transition}")]
    Conflict {
        /// Transition that won the atomic acceptance race.
        existing_transition: Hash,
    },
    /// Record omitted or contradicted mandatory verification evidence.
    #[error("invalid accepted-state record: {0}")]
    InvalidRecord(String),
    /// Backend could not complete the atomic operation.
    #[error("accepted-state storage failure: {0}")]
    Storage(String),
}

/// Atomic accepted-state cache.
///
/// This cache records verified history; it is not authority for global
/// uniqueness. Global uniqueness comes from the closure domain/checkpoint.
#[async_trait]
pub trait AcceptedStateStore: Send + Sync {
    /// Atomically accept a successor if no different successor owns the consumed state.
    ///
    /// Repeating the identical record is idempotent.
    async fn accept(&self, record: AcceptedStateRecord) -> Result<(), AcceptedStateError>;

    /// Load the currently accepted successor for a consumed state.
    async fn get(
        &self,
        consumed_state: &ConsumedStateRef,
    ) -> Result<Option<AcceptedStateRecord>, AcceptedStateError>;
}

/// In-memory accepted-state implementation with one lock covering check and insert.
#[derive(Clone, Default)]
pub struct InMemoryAcceptedStateStore {
    records: Arc<RwLock<HashMap<[u8; 32], AcceptedStateRecord>>>,
}

/// Durable redb accepted-state cache.
#[cfg(feature = "redb")]
pub struct RedbAcceptedStateStore {
    database: redb::Database,
}

#[cfg(feature = "redb")]
const ACCEPTED_STATES: redb::TableDefinition<&[u8], &[u8]> =
    redb::TableDefinition::new("accepted_states_v2");

#[cfg(feature = "redb")]
impl RedbAcceptedStateStore {
    /// Open or create a durable accepted-state cache.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, AcceptedStateError> {
        let database = redb::Database::create(path)
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        let write = database
            .begin_write()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        write
            .open_table(ACCEPTED_STATES)
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        write
            .commit()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        Ok(Self { database })
    }
}

#[cfg(feature = "redb")]
#[async_trait]
impl AcceptedStateStore for RedbAcceptedStateStore {
    async fn accept(&self, record: AcceptedStateRecord) -> Result<(), AcceptedStateError> {
        record.validate()?;
        let key = record.conflict_key();
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        let write = self
            .database
            .begin_write()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        {
            let mut table = write
                .open_table(ACCEPTED_STATES)
                .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
            if let Some(existing) = table
                .get(key.as_slice())
                .map_err(|error| AcceptedStateError::Storage(error.to_string()))?
            {
                let existing: AcceptedStateRecord = serde_json::from_slice(existing.value())
                    .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
                if existing == record {
                    return Ok(());
                }
                return Err(AcceptedStateError::Conflict {
                    existing_transition: existing.transition_id,
                });
            }
            table
                .insert(key.as_slice(), encoded.as_slice())
                .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        }
        write
            .commit()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))
    }

    async fn get(
        &self,
        consumed_state: &ConsumedStateRef,
    ) -> Result<Option<AcceptedStateRecord>, AcceptedStateError> {
        let read = self
            .database
            .begin_read()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        let table = read
            .open_table(ACCEPTED_STATES)
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        let key = *consumed_state.digest().as_bytes();
        table
            .get(key.as_slice())
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?
            .map(|value| {
                serde_json::from_slice(value.value())
                    .map_err(|error| AcceptedStateError::Storage(error.to_string()))
            })
            .transpose()
    }
}

#[async_trait]
impl AcceptedStateStore for InMemoryAcceptedStateStore {
    async fn accept(&self, record: AcceptedStateRecord) -> Result<(), AcceptedStateError> {
        record.validate()?;
        let key = record.conflict_key();
        let mut records = self
            .records
            .write()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))?;
        match records.get(&key) {
            Some(existing) if existing == &record => Ok(()),
            Some(existing) => Err(AcceptedStateError::Conflict {
                existing_transition: existing.transition_id,
            }),
            None => {
                records.insert(key, record);
                Ok(())
            }
        }
    }

    async fn get(
        &self,
        consumed_state: &ConsumedStateRef,
    ) -> Result<Option<AcceptedStateRecord>, AcceptedStateError> {
        let key = *consumed_state.digest().as_bytes();
        self.records
            .read()
            .map_err(|error| AcceptedStateError::Storage(error.to_string()))
            .map(|records| records.get(&key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_protocol::{
        ClosureDimensionStatus, ClosureProofKind, ClosureTrustMode, FinalityPolicy,
        FinalizedCheckpoint,
    };

    fn record(transition_byte: u8, transfer_id: &str) -> AcceptedStateRecord {
        let checkpoint = FinalizedCheckpoint {
            chain_id: "bitcoin".into(),
            network_id: "signet".into(),
            block_height: 100,
            block_id: vec![8; 32],
            finality_policy: FinalityPolicy::Confirmations(6),
        };
        AcceptedStateRecord {
            transition_id: Hash::new([transition_byte; 32]),
            consumed_state: ConsumedStateRef::new(Hash::new([1; 32]), 0, 7),
            created_outputs: vec![Hash::new([3; 32])],
            closure_id: Hash::new([4; 32]),
            closure: ClosureVerificationResult {
                chain_id: "bitcoin".into(),
                network_id: "signet".into(),
                proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
                checkpoint,
                proof_validity: ClosureDimensionStatus::Satisfied,
                checkpoint_finality: ClosureDimensionStatus::Satisfied,
                checkpoint_freshness: ClosureDimensionStatus::Satisfied,
                source_closure: ClosureDimensionStatus::Satisfied,
                trust_mode: ClosureTrustMode::FullNode,
                verifier_id: "csv-bitcoin.v2".into(),
                proof_provider_id: "local-bitcoin-node".into(),
                reason_codes: vec!["BITCOIN.CLOSURE.VERIFIED".into()],
            },
            assurance: AcceptedAssuranceReport {
                verification_context_digest: Hash::new([5; 32]),
                report_digest: Hash::new([6; 32]),
                readings: vec![AcceptedAssuranceReading {
                    dimension: "source-closure".into(),
                    status: "satisfied".into(),
                    reason_codes: vec!["BITCOIN.CLOSURE.VERIFIED".into()],
                    provider_id: "csv-bitcoin.v2".into(),
                    limitations: vec![],
                }],
            },
            transfer_id: Some(transfer_id.into()),
        }
    }

    #[tokio::test]
    async fn transfer_id_cannot_bypass_consumed_state_conflict() {
        let store = InMemoryAcceptedStateStore::default();
        store.accept(record(2, "first")).await.unwrap();
        let error = store.accept(record(9, "different")).await.unwrap_err();
        assert_eq!(
            error,
            AcceptedStateError::Conflict {
                existing_transition: Hash::new([2; 32])
            }
        );
    }

    #[tokio::test]
    async fn identical_acceptance_is_idempotent() {
        let store = InMemoryAcceptedStateStore::default();
        let record = record(2, "same");
        store.accept(record.clone()).await.unwrap();
        store.accept(record.clone()).await.unwrap();
        assert_eq!(
            store.get(&record.consumed_state).await.unwrap(),
            Some(record)
        );
    }

    #[tokio::test]
    async fn concurrent_conflicting_accepts_have_one_winner() {
        let store = InMemoryAcceptedStateStore::default();
        let (left, right) = tokio::join!(
            store.accept(record(2, "left")),
            store.accept(record(9, "right"))
        );
        assert_ne!(left.is_ok(), right.is_ok());
    }

    #[cfg(feature = "redb")]
    #[tokio::test]
    async fn redb_reopens_with_exactly_one_accepted_successor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("accepted.redb");
        {
            let store = RedbAcceptedStateStore::open(&path).unwrap();
            store.accept(record(2, "first")).await.unwrap();
            assert!(matches!(
                store.accept(record(9, "other")).await,
                Err(AcceptedStateError::Conflict { .. })
            ));
        }
        let store = RedbAcceptedStateStore::open(&path).unwrap();
        assert_eq!(
            store
                .get(&record(2, "ignored").consumed_state)
                .await
                .unwrap()
                .unwrap()
                .transition_id,
            Hash::new([2; 32])
        );
    }
}
