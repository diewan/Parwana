//! In-memory replay database (testing only).

use async_trait::async_trait;
use csv_core::cross_chain::HashEntry as CrossChainRegistryEntry;
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_proof::proof::ReplayId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::errors::{ReplayDbError, StorageError};
use crate::traits::{ReplayDatabase, ReplayEntryState, StorageBackend};

/// In-memory replay database (testing only).
pub struct InMemoryReplayDb {
    entries: Arc<RwLock<HashMap<Vec<u8>, ReplayEntryState>>>,
    transfer_entries: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryReplayDb {
    /// Create a new in-memory replay database.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            transfer_entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

}

impl Default for InMemoryReplayDb {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReplayDatabase for InMemoryReplayDb {
    async fn contains(&self, id: &[u8]) -> Result<bool, ReplayDbError> {
        let entries = self.entries.read().unwrap();
        Ok(entries.contains_key(id))
    }

    async fn insert_if_absent(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        let mut entries = self.entries.write().unwrap();
        if entries.contains_key(id) {
            return Err(ReplayDbError::AlreadyExists);
        }
        entries.insert(id.to_vec(), ReplayEntryState::Pending);
        Ok(())
    }

    async fn consume_if_unconsumed(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        let mut entries = self.entries.write().unwrap();
        match entries.get(id) {
            None => {
                entries.insert(id.to_vec(), ReplayEntryState::Pending);
                Ok(())
            }
            Some(ReplayEntryState::Consumed) => Ok(()),
            Some(ReplayEntryState::Pending) | Some(ReplayEntryState::RolledBack) => {
                Err(ReplayDbError::AlreadyExists)
            }
        }
    }

    async fn confirm_consumed_replay_id(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let key = id.as_bytes().to_vec();
        let mut entries = self.entries.write().unwrap();
        match entries.get_mut(&key) {
            Some(ReplayEntryState::Pending) => {
                *entries.get_mut(&key).unwrap() = ReplayEntryState::Consumed;
                Ok(())
            }
            Some(ReplayEntryState::Consumed) => Ok(()),
            Some(_) => Err(ReplayDbError::Storage(
                "Entry is not in Pending or Consumed state".to_string(),
            )),
            None => Err(ReplayDbError::NotFound),
        }
    }

    async fn mark_rolled_back(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let key = id.as_bytes().to_vec();
        let mut entries = self.entries.write().unwrap();
        match entries.get_mut(&key) {
            Some(ReplayEntryState::Pending) => {
                *entries.get_mut(&key).unwrap() = ReplayEntryState::RolledBack;
                Ok(())
            }
            Some(_) => Err(ReplayDbError::Storage(
                "Entry is not in Pending state".to_string(),
            )),
            None => Err(ReplayDbError::NotFound),
        }
    }

    async fn store_transfer_entry(
        &self,
        entry: &CrossChainRegistryEntry,
    ) -> Result<(), ReplayDbError> {
        let key = hex::encode(entry.sanad_id.as_bytes());
        let val = to_canonical_cbor(entry)
            .map_err(|e| ReplayDbError::Storage(format!("Serialization error: {e}")))?;
        let mut entries = self.transfer_entries.write().unwrap();
        entries.insert(key, val);
        Ok(())
    }

    async fn load_all_transfers(
        &self,
    ) -> Result<Vec<CrossChainRegistryEntry>, ReplayDbError> {
        let entries = self.transfer_entries.read().unwrap();
        let mut out = Vec::new();
        for val in entries.values() {
            let entry: CrossChainRegistryEntry = from_canonical_cbor(val)
                .map_err(|e| ReplayDbError::Storage(format!("Deserialization error: {e}")))?;
            out.push(entry);
        }
        Ok(out)
    }
}

#[async_trait]
impl StorageBackend for InMemoryReplayDb {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let entries = self.transfer_entries.read().unwrap();
        Ok(entries.get(&hex::encode(key)).cloned())
    }

    async fn set(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut entries = self.transfer_entries.write().unwrap();
        entries.insert(hex::encode(key), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut entries = self.transfer_entries.write().unwrap();
        entries.remove(&hex::encode(key));
        Ok(())
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        let entries = self.transfer_entries.read().unwrap();
        Ok(entries.contains_key(&hex::encode(key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_replay_cas() {
        let db = InMemoryReplayDb::new();
        let id = b"test-replay-id-32-bytes-padding!!";
        assert!(!db.contains(&id[..32]).await.unwrap());
        db.insert_if_absent(&id[..32]).await.unwrap();
        assert!(db.contains(&id[..32]).await.unwrap());
    }
}
