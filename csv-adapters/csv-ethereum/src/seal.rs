#![allow(dead_code)]
//! Ethereum seal management
//!
//! Provides persistent tracking of used storage slot seals to prevent replay.
//! Seals are persisted in SQLite when a SqliteSealStore is attached.

use crate::error::{EthereumError, EthereumResult};
use crate::types::EthereumSealPoint;
#[cfg(feature = "rpc")]
use csv_core::Hash;
#[cfg(feature = "rpc")]
use csv_core::SealStore;
use csv_core::hardening::{BoundedQueue, MAX_SEAL_NULLIFIER_SIZE};
#[cfg(feature = "rpc")]
use csv_store::SqliteSealStore;
use std::collections::HashSet;
#[cfg(feature = "rpc")]
use std::sync::Arc;
use std::sync::Mutex;

fn lock_poisoned() -> EthereumError {
    EthereumError::SlotUsed("Lock poisoned".to_string())
}

/// Registry for tracking used storage slot seals (prevents replay)
///
/// Maintains an in-memory cache for fast lookups with optional
/// SQLite backing for persistence across restarts.
pub struct SealRegistry {
    /// Set of used seal identifiers (contract_address + slot_index)
    used_seals: Mutex<HashSet<Vec<u8>>>,
    /// Bounded queue for rate limiting
    seal_queue: Mutex<BoundedQueue<Vec<u8>>>,
    /// Optional persistent store
    #[cfg(feature = "rpc")]
    store: Option<Arc<Mutex<SqliteSealStore>>>,
    /// Maximum size of the registry
    max_size: usize,
}

impl SealRegistry {
    /// Create a new in-memory seal registry
    pub fn new() -> Self {
        Self::with_max_size(MAX_SEAL_NULLIFIER_SIZE)
    }

    /// Create a new in-memory seal registry with custom max size
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            used_seals: Mutex::new(HashSet::new()),
            seal_queue: Mutex::new(BoundedQueue::new(max_size)),
            #[cfg(feature = "rpc")]
            store: None,
            max_size,
        }
    }

    /// Create a new seal registry with SQLite persistence
    #[cfg(feature = "rpc")]
    pub fn new_with_store(store: SqliteSealStore) -> Self {
        Self {
            used_seals: Mutex::new(HashSet::new()),
            seal_queue: Mutex::new(BoundedQueue::new(MAX_SEAL_NULLIFIER_SIZE)),
            store: Some(Arc::new(Mutex::new(store))),
            max_size: MAX_SEAL_NULLIFIER_SIZE,
        }
    }

    /// Build the seal registry key
    fn seal_key(seal: &EthereumSealPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(28);
        key.extend_from_slice(&seal.contract_address);
        key.extend_from_slice(&seal.slot_index.to_le_bytes());
        key
    }

    /// Load existing seals from store into cache
    #[cfg(feature = "rpc")]
    pub fn load_cache(&self) -> EthereumResult<()> {
        if let Some(store) = &self.store {
            let store = store.lock().map_err(|_| lock_poisoned())?;
            let seals = store
                .get_seals("ethereum")
                .map_err(|e| EthereumError::SlotUsed(format!("Failed to load seals: {}", e)))?;
            drop(store);

            let mut cache = self.used_seals.lock().map_err(|_| lock_poisoned())?;
            for seal in seals {
                cache.insert(seal.seal_id);
            }
        }
        Ok(())
    }

    /// Check if a seal has been used
    pub fn is_seal_used(&self, seal: &EthereumSealPoint) -> bool {
        let key = Self::seal_key(seal);
        let cache = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
        cache.contains(&key)
    }

    /// Mark a seal as used - persists if store is attached
    pub fn mark_seal_used(&self, seal: &EthereumSealPoint) -> EthereumResult<()> {
        if self.is_seal_used(seal) {
            return Err(EthereumError::SlotUsed(format!(
                "Storage slot {} at contract {:?} has already been used",
                seal.slot_index, seal.contract_address
            )));
        }

        // Check max size before inserting
        {
            let mut cache = self.used_seals.lock().map_err(|_| lock_poisoned())?;
            let key = Self::seal_key(seal);

            if cache.len() >= self.max_size {
                return Err(EthereumError::SlotUsed(format!(
                    "Seal registry is full (max {} entries)",
                    self.max_size
                )));
            }

            cache.insert(key.clone());
            drop(cache);
        }

        {
            let mut queue = self.seal_queue.lock().unwrap_or_else(|e| e.into_inner());
            let key = Self::seal_key(seal);
            queue.push(key);
        }

        #[cfg(feature = "rpc")]
        if let Some(store) = &self.store {
            let seal_id = self.build_seal_id_bytes(seal);
            let commitment_hash = Hash::new(seal.seal_id);
            let record = csv_core::SealRecord {
                chain: "ethereum".to_string(),
                seal_id,
                consumed_at_height: seal.slot_index,
                commitment_hash,
                recorded_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };

            let mut guard = store.lock().map_err(|_| lock_poisoned())?;
            guard
                .save_seal(&record)
                .map_err(|e| EthereumError::SlotUsed(format!("Failed to persist seal: {}", e)))?;
        }

        Ok(())
    }

    /// Clear a seal from the registry (for reorg rollback)
    pub fn clear_seal(&self, seal: &EthereumSealPoint) {
        {
            let mut cache = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
            let key = Self::seal_key(seal);
            cache.remove(&key);
        }

        #[cfg(feature = "rpc")]
        if let Some(store) = &self.store {
            let seal_id = self.build_seal_id_bytes(seal);
            if let Ok(mut guard) = store.lock() {
                let _ = guard.remove_seal("ethereum", &seal_id);
            }
        }
    }

    /// Get all used seals
    pub fn get_all_seals(&self) -> Vec<EthereumSealPoint> {
        let cache = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .iter()
            .filter_map(|key| {
                if key.len() == 28 {
                    let mut address = [0u8; 20];
                    address.copy_from_slice(&key[..20]);
                    let slot_index = u64::from_le_bytes([
                        key[20], key[21], key[22], key[23], key[24], key[25], key[26], key[27],
                    ]);
                    Some(EthereumSealPoint::new(address, slot_index, 0))
                } else {
                    None
                }
            })
            .collect()
    }

    fn build_seal_id_bytes(&self, seal: &EthereumSealPoint) -> Vec<u8> {
        let mut id = Vec::with_capacity(28);
        id.extend_from_slice(&seal.contract_address);
        id.extend_from_slice(&seal.slot_index.to_le_bytes());
        id
    }

    /// Get the current number of used seals
    pub fn len(&self) -> usize {
        let cache = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
        cache.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        let cache = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
        cache.is_empty()
    }

    /// Check if the registry is full
    pub fn is_full(&self) -> bool {
        let cache = self.used_seals.lock().unwrap_or_else(|e| e.into_inner());
        cache.len() >= self.max_size
    }

    /// Get the maximum size of the registry
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl Default for SealRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_registry() {
        let registry = SealRegistry::new();
        let seal = EthereumSealPoint::new([1u8; 20], 42, 1);

        assert!(!registry.is_seal_used(&seal));
        registry.mark_seal_used(&seal).unwrap();
        assert!(registry.is_seal_used(&seal));

        let seal2 = EthereumSealPoint::new([1u8; 20], 42, 2);
        assert!(registry.mark_seal_used(&seal2).is_err());

        let seal3 = EthereumSealPoint::new([1u8; 20], 43, 1);
        assert!(registry.mark_seal_used(&seal3).is_ok());
    }

    #[test]
    fn test_seal_registry_get_all() {
        let registry = SealRegistry::new();
        let seal1 = EthereumSealPoint::new([1u8; 20], 10, 1);
        let seal2 = EthereumSealPoint::new([2u8; 20], 20, 1);

        registry.mark_seal_used(&seal1).unwrap();
        registry.mark_seal_used(&seal2).unwrap();

        let all_seals = registry.get_all_seals();
        assert_eq!(all_seals.len(), 2);
    }

    #[test]
    fn test_seal_registry_clear() {
        let registry = SealRegistry::new();
        let seal = EthereumSealPoint::new([1u8; 20], 42, 1);

        registry.mark_seal_used(&seal).unwrap();
        assert!(registry.is_seal_used(&seal));

        registry.clear_seal(&seal);
        assert!(!registry.is_seal_used(&seal));

        assert!(registry.mark_seal_used(&seal).is_ok());
    }

    #[test]
    fn test_seal_registry_size_limit() {
        let registry = SealRegistry::with_max_size(2);
        assert_eq!(registry.max_size(), 2);

        let seal1 = EthereumSealPoint::new([1u8; 20], 10, 1);
        let seal2 = EthereumSealPoint::new([2u8; 20], 20, 1);
        let seal3 = EthereumSealPoint::new([3u8; 20], 30, 1);

        registry.mark_seal_used(&seal1).unwrap();
        registry.mark_seal_used(&seal2).unwrap();

        assert!(registry.is_full());
        assert!(registry.mark_seal_used(&seal3).is_err());
        assert!(matches!(
            registry.mark_seal_used(&seal3).unwrap_err(),
            EthereumError::SlotUsed(_)
        ));
    }
}
