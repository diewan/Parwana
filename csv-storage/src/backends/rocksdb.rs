//! RocksDB-backed replay database with CAS semantics.

use async_trait::async_trait;
use csv_protocol::cross_chain::HashEntry as CrossChainRegistryEntry;
use csv_protocol::proof_taxonomy::ReplayId;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType, Options};
use std::sync::Arc;

use crate::errors::ReplayDbError;
use crate::traits::{ReplayDatabase, ReplayEntryState};

const CF_REPLAY: &str = "replay_entries";
const CF_CONFLICT: &str = "replay_conflicts";
const CF_TRANSFERS: &str = "transfer_entries";

/// RocksDB-backed replay database with compare-and-swap semantics.
pub struct RocksDbReplayDb {
    db: Arc<DB>,
}

impl RocksDbReplayDb {
    /// Open or create the RocksDB database at the given path.
    pub fn open(path: &str) -> Result<Self, ReplayDbError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_opts = || {
            let mut opts = Options::default();
            opts.set_compression_type(DBCompressionType::Lz4);
            opts
        };

        let db = DB::open_cf_descriptors(
            &opts,
            path,
            vec![
                ColumnFamilyDescriptor::new(CF_REPLAY, cf_opts()),
                ColumnFamilyDescriptor::new(CF_CONFLICT, cf_opts()),
                ColumnFamilyDescriptor::new(CF_TRANSFERS, cf_opts()),
            ],
        )
        .map_err(|e| ReplayDbError::Storage(format!("Failed to open RocksDB: {e}")))?;

        Ok(Self { db: Arc::new(db) })
    }

    fn cf_replay(&self) -> Result<&ColumnFamily, ReplayDbError> {
        self.db.cf_handle(CF_REPLAY).ok_or_else(|| {
            ReplayDbError::Storage("replay_entries column family not found".to_string())
        })
    }

    fn cf_conflict(&self) -> Result<&ColumnFamily, ReplayDbError> {
        self.db.cf_handle(CF_CONFLICT).ok_or_else(|| {
            ReplayDbError::Storage("replay_conflicts column family not found".to_string())
        })
    }

    fn cf_transfers(&self) -> Result<&ColumnFamily, ReplayDbError> {
        self.db.cf_handle(CF_TRANSFERS).ok_or_else(|| {
            ReplayDbError::Storage("transfer_entries column family not found".to_string())
        })
    }

    fn encode_state(state: ReplayEntryState) -> Vec<u8> {
        match state {
            ReplayEntryState::Pending => b"PENDING".to_vec(),
            ReplayEntryState::Consumed => b"CONSUMED".to_vec(),
            ReplayEntryState::RolledBack => b"ROLLED_BACK".to_vec(),
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

    fn key_exists_in_conflict_cf(&self, key: &[u8]) -> Result<bool, ReplayDbError> {
        match self.db.get_cf(self.cf_conflict()?, key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(ReplayDbError::Storage(format!("RocksDB error: {e}"))),
        }
    }

    fn read_state(&self, key: &[u8]) -> Result<Option<ReplayEntryState>, ReplayDbError> {
        match self.db.get_cf(self.cf_replay()?, key) {
            Ok(Some(val)) => Ok(Self::decode_state(&val)),
            Ok(None) => Ok(None),
            Err(e) => Err(ReplayDbError::Storage(format!("RocksDB read error: {e}"))),
        }
    }

    fn cas_insert(&self, key: &[u8], state: ReplayEntryState) -> Result<(), ReplayDbError> {
        if self.key_exists_in_conflict_cf(key)? {
            return Err(ReplayDbError::AlreadyExists);
        }
        let val = Self::encode_state(state);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(self.cf_replay()?, key, &val);
        batch.put_cf(self.cf_conflict()?, key, b"1");
        self.db
            .write(batch)
            .map_err(|e| ReplayDbError::Storage(format!("RocksDB write error: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl ReplayDatabase for RocksDbReplayDb {
    async fn contains(&self, id: &[u8]) -> Result<bool, ReplayDbError> {
        self.key_exists_in_conflict_cf(id)
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
                let val = Self::encode_state(ReplayEntryState::Pending);
                self.db
                    .put_cf(self.cf_replay()?, id, val)
                    .map_err(|e| ReplayDbError::Storage(format!("RocksDB error: {e}")))?;
                Ok(())
            }
            Some(_) => Err(ReplayDbError::AlreadyExists),
            None => self.cas_insert(id, ReplayEntryState::Pending),
        }
    }

    async fn confirm_consumed_replay_id(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let key = id.as_bytes();
        let state = match self.read_state(key)? {
            Some(ReplayEntryState::Pending) => ReplayEntryState::Consumed,
            Some(ReplayEntryState::Consumed) => return Ok(()),
            Some(_) => {
                return Err(ReplayDbError::Storage(
                    "Entry is not in Pending or Consumed state".to_string(),
                ));
            }
            None => return Err(ReplayDbError::NotFound),
        };
        let val = Self::encode_state(state);
        self.db
            .put_cf(self.cf_replay()?, key, val)
            .map_err(|e| ReplayDbError::Storage(format!("RocksDB error: {e}")))?;
        Ok(())
    }

    async fn mark_rolled_back(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let key = id.as_bytes();
        let state = match self.read_state(key)? {
            Some(ReplayEntryState::Pending) => ReplayEntryState::RolledBack,
            Some(ReplayEntryState::RolledBack) => return Ok(()),
            Some(_) => {
                return Err(ReplayDbError::Storage(
                    "Entry is not in Pending state".to_string(),
                ));
            }
            None => return Err(ReplayDbError::NotFound),
        };
        let val = Self::encode_state(state);
        self.db
            .put_cf(self.cf_replay()?, key, val)
            .map_err(|e| ReplayDbError::Storage(format!("RocksDB error: {e}")))?;
        Ok(())
    }

    async fn store_transfer_entry(
        &self,
        entry: &CrossChainRegistryEntry,
    ) -> Result<(), ReplayDbError> {
        let key = entry.sanad_id.as_bytes();
        let val = entry
            .to_canonical_bytes()
            .map_err(|e| ReplayDbError::Storage(format!("Serialization error: {e}")))?;
        self.db
            .put_cf(self.cf_transfers()?, key, val)
            .map_err(|e| ReplayDbError::Storage(format!("RocksDB error: {e}")))?;
        Ok(())
    }

    async fn load_all_transfers(&self) -> Result<Vec<CrossChainRegistryEntry>, ReplayDbError> {
        let mut transfers = Vec::new();
        for result in self
            .db
            .iterator_cf(self.cf_transfers()?, rocksdb::IteratorMode::Start)
        {
            let (_key, value) = result
                .map_err(|e| ReplayDbError::Storage(format!("RocksDB iterator error: {e}")))?;
            let entry: CrossChainRegistryEntry =
                CrossChainRegistryEntry::from_canonical_bytes(&value)
                    .map_err(|e| ReplayDbError::Storage(format!("Deserialization error: {e}")))?;
            transfers.push(entry);
        }
        Ok(transfers)
    }
}
