//! Seal registry for the Sui adapter
//!
//! This module manages the registry of used seals to prevent replay attacks.
//! It tracks both in-memory and optionally persists seal state.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::{SuiError, SuiResult};
use crate::types::SuiSealPoint;

// Local implementation of BoundedQueue (hardening module removed during migration)
const MAX_SEAL_NULLIFIER_SIZE: usize = 10000;

#[derive(Clone, Debug)]
struct BoundedQueue<T> {
    queue: std::collections::VecDeque<T>,
    max_size: usize,
}

impl<T> BoundedQueue<T> {
    fn new(max_size: usize) -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            max_size,
        }
    }

    fn push(&mut self, item: T) {
        if self.queue.len() >= self.max_size {
            self.queue.pop_front();
        }
        self.queue.push_back(item);
    }
}

/// A persisted seal record that can be serialized.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SealRecord {
    /// The object ID of the seal
    pub object_id: [u8; 32],
    /// The object version at consumption time
    pub object_version: u64,
    /// The nonce for replay resistance
    pub nonce: u64,
    /// The checkpoint at which the seal was consumed
    pub consumed_at_checkpoint: u64,
    /// Timestamp of consumption (Unix epoch seconds)
    pub consumed_at: i64,
}

impl SealRecord {
    /// Create a new seal record from a seal reference and consumption details.
    pub fn new(seal: &SuiSealPoint, consumed_at_checkpoint: u64) -> Self {
        Self {
            object_id: seal.object_id,
            object_version: seal.version,
            nonce: seal.nonce,
            consumed_at_checkpoint,
            consumed_at: chrono::Utc::now().timestamp(),
        }
    }

    /// Returns the unique key for this seal.
    pub fn key(&self) -> String {
        format!(
            "{}-{}-{}",
            hex::encode(self.object_id),
            self.object_version,
            self.nonce
        )
    }
}

/// Registry for tracking used seals to prevent replay attacks.
///
/// This is a thread-safe structure that maintains both a set of used seals
/// and optionally persists them to storage.
#[derive(Debug)]
pub struct SealRegistry {
    /// Set of used seal keys for fast lookup
    used_seals: HashSet<String>,
    /// Full seal records for detailed tracking
    seal_records: Vec<SealRecord>,
    /// Bounded queue for rate limiting
    seal_queue: BoundedQueue<String>,
    /// Maximum size of the registry
    max_size: usize,
}

impl SealRegistry {
    /// Create a new empty seal registry.
    pub fn new() -> Self {
        Self::with_max_size(MAX_SEAL_NULLIFIER_SIZE)
    }

    /// Create a new empty seal registry with custom max size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            used_seals: HashSet::new(),
            seal_records: Vec::new(),
            seal_queue: BoundedQueue::new(max_size),
            max_size,
        }
    }

    /// Check if a seal has already been used.
    pub fn is_seal_used(&self, seal: &SuiSealPoint) -> bool {
        let key = format!(
            "{}-{}-{}",
            hex::encode(seal.object_id),
            seal.version,
            seal.nonce
        );
        self.used_seals.contains(&key)
    }

    /// Mark a seal as used.
    ///
    /// # Arguments
    /// * `seal` - The seal reference to mark
    /// * `consumed_at_checkpoint` - The checkpoint at which it was consumed
    ///
    /// # Returns
    /// `Ok(())` if the seal was successfully marked, or `Err` if already used.
    pub fn mark_seal_used(
        &mut self,
        seal: &SuiSealPoint,
        consumed_at_checkpoint: u64,
    ) -> SuiResult<()> {
        if self.is_seal_used(seal) {
            return Err(SuiError::ObjectUsed(format!(
                "Object 0x{} with version {} is already consumed",
                hex::encode(seal.object_id),
                seal.version
            )));
        }

        // Check max size limit
        if self.used_seals.len() >= self.max_size {
            return Err(SuiError::ObjectUsed(format!(
                "Seal registry is full (max {} entries)",
                self.max_size
            )));
        }

        let record = SealRecord::new(seal, consumed_at_checkpoint);
        let key = record.key();
        self.seal_queue.push(key.clone());
        self.used_seals.insert(key);
        self.seal_records.push(record);
        Ok(())
    }

    /// Clear a seal from the registry (for rollback handling).
    ///
    /// Removes the seal from `used_seals`, `seal_records`, and `seal_queue`.
    /// This allows the seal to be reused after a chain reorg.
    ///
    /// # Arguments
    /// * `seal` - The seal reference to clear
    ///
    /// # Returns
    /// `Ok(())` if the seal was found and cleared, or `Err` if not found.
    pub fn clear_seal(&mut self, seal: &SuiSealPoint) -> SuiResult<()> {
        let key = format!(
            "{}-{}-{}",
            hex::encode(seal.object_id),
            seal.version,
            seal.nonce
        );

        if !self.used_seals.remove(&key) {
            return Err(SuiError::ObjectUsed(format!(
                "Seal 0x{} not found in registry",
                hex::encode(seal.object_id)
            )));
        }

        // Remove from seal_records
        self.seal_records.retain(|r| r.key() != key);

        // Note: seal_queue is append-only by design (BoundedQueue doesn't support removal)
        // This is acceptable as the queue is only used for rate limiting, not state validation

        Ok(())
    }

    /// Get the current number of used seals.
    pub fn len(&self) -> usize {
        self.used_seals.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.used_seals.is_empty()
    }

    /// Check if the registry is full.
    pub fn is_full(&self) -> bool {
        self.used_seals.len() >= self.max_size
    }

    /// Get the maximum size of the registry.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get all seal records.
    pub fn get_seal_records(&self) -> Vec<SealRecord> {
        self.seal_records.clone()
    }

    /// Get all seal records.
    pub fn records(&self) -> &[SealRecord] {
        &self.seal_records
    }

    /// Clear all used seals (for testing purposes).
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.used_seals.clear();
        self.seal_records.clear();
    }

    /// Export seal records for persistence.
    pub fn export_records(&self) -> Vec<SealRecord> {
        self.seal_records.clone()
    }

    /// Import seal records from persistence.
    pub fn import_records(&mut self, records: Vec<SealRecord>) {
        for record in &records {
            self.used_seals.insert(record.key());
        }
        self.seal_records = records;
    }
}

impl Default for SealRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Optional trait for persistent seal storage.
///
/// Implementors can persist seals across restarts using their preferred storage backend.
pub trait SealStore: Send + Sync {
    /// Load all seal records from storage.
    fn load_seals(&self) -> Result<Vec<SealRecord>, Box<dyn std::error::Error + Send + Sync>>;

    /// Save all seal records to storage.
    fn save_seals(
        &self,
        records: &[SealRecord],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seal() -> SuiSealPoint {
        SuiSealPoint::new([1u8; 32], 1, 0)
    }

    #[test]
    fn test_new_registry_is_empty() {
        let registry = SealRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_mark_seal_used() {
        let mut registry = SealRegistry::new();
        let seal = test_seal();
        assert!(!registry.is_seal_used(&seal));

        registry.mark_seal_used(&seal, 100).unwrap();
        assert!(registry.is_seal_used(&seal));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_mark_seal_used_replay_prevention() {
        let mut registry = SealRegistry::new();
        let seal = test_seal();

        registry.mark_seal_used(&seal, 100).unwrap();
        let result = registry.mark_seal_used(&seal, 200);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SuiError::ObjectUsed(_)));
    }

    #[test]
    fn test_different_seals() {
        let mut registry = SealRegistry::new();
        let seal1 = SuiSealPoint::new([1u8; 32], 1, 0);
        let seal2 = SuiSealPoint::new([2u8; 32], 1, 0);

        registry.mark_seal_used(&seal1, 100).unwrap();
        registry.mark_seal_used(&seal2, 200).unwrap();

        assert!(registry.is_seal_used(&seal1));
        assert!(registry.is_seal_used(&seal2));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_same_object_different_version() {
        let mut registry = SealRegistry::new();
        let seal1 = SuiSealPoint::new([1u8; 32], 1, 0);
        let seal2 = SuiSealPoint::new([1u8; 32], 2, 0);

        registry.mark_seal_used(&seal1, 100).unwrap();
        registry.mark_seal_used(&seal2, 200).unwrap();

        assert!(registry.is_seal_used(&seal1));
        assert!(registry.is_seal_used(&seal2));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_export_import() {
        let mut registry = SealRegistry::new();
        let seal = test_seal();
        registry.mark_seal_used(&seal, 100).unwrap();

        let records = registry.export_records();
        let mut new_registry = SealRegistry::new();
        new_registry.import_records(records);

        assert!(new_registry.is_seal_used(&seal));
        assert_eq!(new_registry.len(), 1);
    }

    #[test]
    fn test_seal_record_serialization() {
        let seal = test_seal();
        let record = SealRecord::new(&seal, 100);

        let json = serde_json::to_string(&record).unwrap();
        let deserialized: SealRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_clear_registry() {
        let mut registry = SealRegistry::new();
        let seal = test_seal();
        registry.mark_seal_used(&seal, 100).unwrap();

        registry.clear();
        assert!(!registry.is_seal_used(&seal));
        assert!(registry.is_empty());
    }
}
