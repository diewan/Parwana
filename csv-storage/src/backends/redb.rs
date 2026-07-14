//! redb-backed replay database with CAS semantics.

use async_trait::async_trait;
use csv_protocol::cross_chain::HashEntry as CrossChainRegistryEntry;
use csv_protocol::proof_taxonomy::ReplayId;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition, TableError};
use std::sync::Arc;

use crate::errors::ReplayDbError;
use crate::traits::{ReplayDatabase, ReplayEntryState};

const REPLAY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("replay_entries");
const CONFLICT_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("replay_conflicts");
const TRANSFERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transfer_entries");

/// redb-backed replay database with compare-and-swap semantics.
///
/// All mutations run inside a single serialized write transaction, so the
/// check-then-insert in [`ReplayDatabase::insert_if_absent`] is atomic —
/// unlike a read-then-batch-write against a concurrent-writer store.
pub struct RedbReplayDb {
    db: Arc<Database>,
}

impl RedbReplayDb {
    /// Open or create the redb database file at the given path.
    pub fn open(path: &str) -> Result<Self, ReplayDbError> {
        let db = Database::create(path)
            .map_err(|e| ReplayDbError::Storage(format!("Failed to open redb: {e}")))?;
        // Commits are Durability::Immediate by default (fsync before commit
        // returns); replay entries guard against double-spend so they must
        // survive a crash. Create the tables up front so read transactions
        // never race table creation.
        let txn = db
            .begin_write()
            .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        txn.open_table(REPLAY_TABLE)
            .and_then(|_| txn.open_table(CONFLICT_TABLE))
            .and_then(|_| txn.open_table(TRANSFERS_TABLE))
            .map_err(|e| ReplayDbError::Storage(format!("redb table error: {e}")))?;
        txn.commit()
            .map_err(|e| ReplayDbError::Storage(format!("redb commit error: {e}")))?;
        Ok(Self { db: Arc::new(db) })
    }

    fn encode_state(state: ReplayEntryState) -> &'static [u8] {
        match state {
            ReplayEntryState::Pending => b"PENDING",
            ReplayEntryState::Consumed => b"CONSUMED",
            ReplayEntryState::RolledBack => b"ROLLED_BACK",
        }
    }

    fn decode_state(bytes: &[u8]) -> Option<ReplayEntryState> {
        match bytes {
            b"PENDING" => Some(ReplayEntryState::Pending),
            b"CONSUMED" => Some(ReplayEntryState::Consumed),
            b"ROLLED_BACK" => Some(ReplayEntryState::RolledBack),
            _ => None,
        }
    }

    fn read_state(&self, key: &[u8]) -> Result<Option<ReplayEntryState>, ReplayDbError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| ReplayDbError::Storage(format!("redb read error: {e}")))?;
        let table = match txn.open_table(REPLAY_TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(ReplayDbError::Storage(format!("redb table error: {e}"))),
        };
        match table.get(key) {
            Ok(Some(val)) => Ok(Self::decode_state(val.value())),
            Ok(None) => Ok(None),
            Err(e) => Err(ReplayDbError::Storage(format!("redb read error: {e}"))),
        }
    }

    /// Atomically transition `key` to `next` if the current state passes
    /// `admit`. `admit` returns the outcome for the observed state: `Ok(true)`
    /// to write `next`, `Ok(false)` to leave the entry unchanged (idempotent
    /// success), `Err` to reject.
    fn transition(
        &self,
        key: &[u8],
        next: ReplayEntryState,
        admit: impl Fn(Option<ReplayEntryState>) -> Result<bool, ReplayDbError>,
    ) -> Result<(), ReplayDbError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        {
            let mut table = txn
                .open_table(REPLAY_TABLE)
                .map_err(|e| ReplayDbError::Storage(format!("redb table error: {e}")))?;
            let current = table
                .get(key)
                .map_err(|e| ReplayDbError::Storage(format!("redb read error: {e}")))?
                .and_then(|val| Self::decode_state(val.value()));
            if !admit(current)? {
                return Ok(());
            }
            table
                .insert(key, Self::encode_state(next))
                .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        }
        txn.commit()
            .map_err(|e| ReplayDbError::Storage(format!("redb commit error: {e}")))?;
        Ok(())
    }

    fn cas_insert(&self, key: &[u8], state: ReplayEntryState) -> Result<(), ReplayDbError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        {
            let mut conflict = txn
                .open_table(CONFLICT_TABLE)
                .map_err(|e| ReplayDbError::Storage(format!("redb table error: {e}")))?;
            let exists = conflict
                .get(key)
                .map_err(|e| ReplayDbError::Storage(format!("redb read error: {e}")))?
                .is_some();
            if exists {
                return Err(ReplayDbError::AlreadyExists);
            }
            conflict
                .insert(key, b"1".as_slice())
                .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
            let mut replay = txn
                .open_table(REPLAY_TABLE)
                .map_err(|e| ReplayDbError::Storage(format!("redb table error: {e}")))?;
            replay
                .insert(key, Self::encode_state(state))
                .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        }
        txn.commit()
            .map_err(|e| ReplayDbError::Storage(format!("redb commit error: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl ReplayDatabase for RedbReplayDb {
    async fn contains(&self, id: &[u8]) -> Result<bool, ReplayDbError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| ReplayDbError::Storage(format!("redb read error: {e}")))?;
        let table = match txn.open_table(CONFLICT_TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(ReplayDbError::Storage(format!("redb table error: {e}"))),
        };
        match table.get(id) {
            Ok(entry) => Ok(entry.is_some()),
            Err(e) => Err(ReplayDbError::Storage(format!("redb read error: {e}"))),
        }
    }

    async fn insert_if_absent(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        self.cas_insert(id, ReplayEntryState::Pending)
    }

    async fn consume_if_unconsumed(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        match self.read_state(id)? {
            Some(ReplayEntryState::Consumed) => Ok(()),
            // RolledBack means the previous attempt definitively did not
            // complete (lock/mint failed and was rolled back). Re-arming the
            // slot lets the transfer be retried; on-chain replay guards and
            // idempotent adapter locks prevent duplicate effects.
            Some(ReplayEntryState::RolledBack) => {
                self.transition(id, ReplayEntryState::Pending, |current| match current {
                    Some(ReplayEntryState::RolledBack) => Ok(true),
                    Some(ReplayEntryState::Consumed) | Some(ReplayEntryState::Pending) => {
                        Err(ReplayDbError::AlreadyExists)
                    }
                    None => Err(ReplayDbError::NotFound),
                })
            }
            Some(_) => Err(ReplayDbError::AlreadyExists),
            None => self.cas_insert(id, ReplayEntryState::Pending),
        }
    }

    async fn confirm_consumed_replay_id(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        self.transition(
            id.as_bytes(),
            ReplayEntryState::Consumed,
            |current| match current {
                Some(ReplayEntryState::Pending) => Ok(true),
                Some(ReplayEntryState::Consumed) => Ok(false),
                Some(_) => Err(ReplayDbError::Storage(
                    "Entry is not in Pending or Consumed state".to_string(),
                )),
                None => Err(ReplayDbError::NotFound),
            },
        )
    }

    async fn mark_rolled_back(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        self.transition(
            id.as_bytes(),
            ReplayEntryState::RolledBack,
            |current| match current {
                Some(ReplayEntryState::Pending) => Ok(true),
                Some(ReplayEntryState::RolledBack) => Ok(false),
                Some(_) => Err(ReplayDbError::Storage(
                    "Entry is not in Pending state".to_string(),
                )),
                None => Err(ReplayDbError::NotFound),
            },
        )
    }

    async fn store_transfer_entry(
        &self,
        entry: &CrossChainRegistryEntry,
    ) -> Result<(), ReplayDbError> {
        let key = entry.sanad_id.as_bytes();
        let val = entry
            .to_canonical_bytes()
            .map_err(|e| ReplayDbError::Storage(format!("Serialization error: {e}")))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        {
            let mut table = txn
                .open_table(TRANSFERS_TABLE)
                .map_err(|e| ReplayDbError::Storage(format!("redb table error: {e}")))?;
            table
                .insert(key.as_slice(), val.as_slice())
                .map_err(|e| ReplayDbError::Storage(format!("redb write error: {e}")))?;
        }
        txn.commit()
            .map_err(|e| ReplayDbError::Storage(format!("redb commit error: {e}")))?;
        Ok(())
    }

    async fn load_all_transfers(&self) -> Result<Vec<CrossChainRegistryEntry>, ReplayDbError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| ReplayDbError::Storage(format!("redb read error: {e}")))?;
        let table = match txn.open_table(TRANSFERS_TABLE) {
            Ok(table) => table,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(ReplayDbError::Storage(format!("redb table error: {e}"))),
        };
        let mut transfers = Vec::new();
        for result in table
            .range::<&[u8]>(..)
            .map_err(|e| ReplayDbError::Storage(format!("redb iterator error: {e}")))?
        {
            let (_key, value) =
                result.map_err(|e| ReplayDbError::Storage(format!("redb iterator error: {e}")))?;
            let entry = CrossChainRegistryEntry::from_canonical_bytes(value.value())
                .map_err(|e| ReplayDbError::Storage(format!("Deserialization error: {e}")))?;
            transfers.push(entry);
        }
        Ok(transfers)
    }
}
