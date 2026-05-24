//! Bitcoin seal management

use crate::error::{BitcoinError, BitcoinResult};
use crate::types::BitcoinSealPoint;
use crate::wallet::Bip86Path;
use csv_protocol::hardening::{BoundedQueue, MAX_SEAL_NULLIFIER_SIZE};

#[cfg(feature = "rpc")]
use csv_protocol::store::SanadStore;
#[cfg(feature = "rpc")]
use csv_store::SqliteSealStore;

/// Registry for tracking used seals (prevents replay)
pub struct SealRegistry {
    /// Set of used seal identifiers
    used_seals: std::collections::HashSet<Vec<u8>>,
    /// Set of used derivation paths (account, change, index tuples)
    used_paths: std::collections::HashSet<(u32, u32, u32)>,
    /// Bounded queue for rate limiting seal operations
    seal_queue: BoundedQueue<Vec<u8>>,
    /// Maximum size of the registry
    max_size: usize,
    /// Optional SQLite storage for persistence
    #[cfg(feature = "rpc")]
    storage: Option<SqliteSealStore>,
}

impl SealRegistry {
    /// Create a new seal registry with default max size
    pub fn new() -> Self {
        Self::with_max_size(MAX_SEAL_NULLIFIER_SIZE)
    }

    /// Create a new seal registry with configurable max size
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            used_seals: std::collections::HashSet::new(),
            used_paths: std::collections::HashSet::new(),
            seal_queue: BoundedQueue::new(max_size),
            max_size,
            #[cfg(feature = "rpc")]
            storage: None,
        }
    }

    /// Create a seal registry with SQLite persistence
    #[cfg(feature = "rpc")]
    pub fn with_storage(path: &str) -> Result<Self, BitcoinError> {
        let storage = SqliteSealStore::open(path)
            .map_err(|e| BitcoinError::StorageError(format!("Failed to open seal store: {}", e)))?;

        let mut registry = Self::new();
        registry.storage = Some(storage);

        // Load existing seals from storage
        registry.load_from_storage()?;

        Ok(registry)
    }

    /// Load used seals from storage into memory
    #[cfg(feature = "rpc")]
    fn load_from_storage(&mut self) -> BitcoinResult<()> {
        if let Some(ref storage) = self.storage {
            let records = storage
                .get_seals("bitcoin")
                .map_err(|e| BitcoinError::StorageError(format!("Failed to load seals: {}", e)))?;

            for record in records {
                self.used_seals.insert(record.seal_id);
            }
        }
        Ok(())
    }

    /// Persist a seal to storage (internal helper)
    /// Called by mark_seal_used_with_storage after marking in memory
    #[cfg(feature = "rpc")]
    fn persist_seal(&self, _seal: &BitcoinSealPoint, _height: u64) -> BitcoinResult<()> {
        // This method is kept for API compatibility
        // Actual persistence happens in mark_seal_used_with_storage which has &mut self
        Ok(())
    }

    /// Mark a seal as used and persist to storage (requires &mut self for storage)
    #[cfg(feature = "rpc")]
    pub fn mark_seal_used_with_storage(
        &mut self,
        seal: &BitcoinSealPoint,
        height: u64,
    ) -> BitcoinResult<()> {
        // First mark in memory
        self.mark_seal_used_at_height(seal, height)?;

        // Then persist if storage is configured
        if let Some(ref mut storage) = self.storage {
            let record = csv_core::SealRecord {
                chain: "bitcoin".to_string(),
                seal_id: seal.to_vec(),
                consumed_at_height: height,
                commitment_hash: csv_core::Hash::new([0u8; 32]), // Placeholder
                recorded_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };
            // Use interior mutability via the trait method
            // Since we can't mutably borrow from &self, we need a different approach
            // For now, skip persistence in this context - will be done by caller
            storage.save_seal(&record).map_err(|e| {
                BitcoinError::StorageError(format!("Failed to persist seal: {}", e))
            })?;
        }
        Ok(())
    }

    /// Check if a seal has been used
    pub fn is_seal_used(&self, seal: &BitcoinSealPoint) -> bool {
        self.used_seals.contains(&seal.to_vec())
    }

    /// Check if a seal at a specific path has been used
    pub fn is_seal_used_by_path(&self, path: &Bip86Path) -> bool {
        // Check if this specific derivation path has been used
        self.used_paths
            .contains(&(path.account, path.change, path.index))
    }

    /// Mark a seal as used with its derivation path
    pub fn mark_seal_used_with_path(
        &mut self,
        seal: &BitcoinSealPoint,
        path: &Bip86Path,
    ) -> BitcoinResult<()> {
        // First mark the seal as used
        self.mark_seal_used(seal)?;
        // Then track the path
        self.used_paths
            .insert((path.account, path.change, path.index));
        Ok(())
    }

    /// Mark a seal as used
    pub fn mark_seal_used(&mut self, seal: &BitcoinSealPoint) -> BitcoinResult<()> {
        self.mark_seal_used_at_height(seal, 0)
    }

    /// Mark a seal as used with block height tracking
    pub fn mark_seal_used_at_height(
        &mut self,
        seal: &BitcoinSealPoint,
        height: u64,
    ) -> BitcoinResult<()> {
        // Check if already used
        if self.is_seal_used(seal) {
            return Err(BitcoinError::UTXOSpent(format!(
                "Seal {:?} has already been used",
                seal
            )));
        }

        // Check registry size limit
        if self.used_seals.len() >= self.max_size {
            return Err(BitcoinError::RegistryFull(format!(
                "Seal registry is full (max {} entries)",
                self.max_size
            )));
        }

        let seal_bytes = seal.to_vec();
        self.seal_queue.push(seal_bytes.clone());
        self.used_seals.insert(seal_bytes.clone());

        // Note: To persist, use mark_seal_used_with_storage() when storage is configured
        let _ = height; // Height is tracked but not persisted in this method

        Ok(())
    }

    /// Clear a seal from the registry (for reorg rollback)
    pub fn clear_seal(&mut self, seal: &BitcoinSealPoint) {
        let seal_bytes = seal.to_vec();
        self.used_seals.remove(&seal_bytes);
    }

    /// Clear a path from the used paths set (for reorg rollback)
    pub fn clear_path(&mut self, path: &Bip86Path) {
        self.used_paths
            .remove(&(path.account, path.change, path.index));
    }

    /// Get the current number of used seals
    pub fn len(&self) -> usize {
        self.used_seals.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.used_seals.is_empty()
    }

    /// Check if the registry is full
    pub fn is_full(&self) -> bool {
        self.used_seals.len() >= self.max_size
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
        let mut registry = SealRegistry::new();
        let seal = BitcoinSealPoint::new([1u8; 32], 0, Some(42));

        assert!(!registry.is_seal_used(&seal));
        registry.mark_seal_used(&seal).unwrap();
        assert!(registry.is_seal_used(&seal));

        // Second use should fail
        assert!(registry.mark_seal_used(&seal).is_err());
    }

    #[test]
    fn test_registry_size_limit() {
        let mut registry = SealRegistry::with_max_size(3);
        assert_eq!(registry.max_size(), 3);

        let seal1 = BitcoinSealPoint::new([1u8; 32], 0, Some(1));
        let seal2 = BitcoinSealPoint::new([2u8; 32], 0, Some(2));
        let seal3 = BitcoinSealPoint::new([3u8; 32], 0, Some(3));
        let seal4 = BitcoinSealPoint::new([4u8; 32], 0, Some(4));

        registry.mark_seal_used(&seal1).unwrap();
        registry.mark_seal_used(&seal2).unwrap();
        registry.mark_seal_used(&seal3).unwrap();

        assert!(registry.is_full());
        assert!(registry.mark_seal_used(&seal4).is_err());
        assert!(matches!(
            registry.mark_seal_used(&seal4).unwrap_err(),
            BitcoinError::RegistryFull(_)
        ));
    }

    #[test]
    fn test_registry_clear() {
        let mut registry = SealRegistry::new();
        let seal = BitcoinSealPoint::new([1u8; 32], 0, Some(42));

        registry.mark_seal_used(&seal).unwrap();
        assert!(registry.is_seal_used(&seal));
        assert_eq!(registry.len(), 1);

        registry.clear_seal(&seal);
        assert!(!registry.is_seal_used(&seal));
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_with_custom_size() {
        let registry = SealRegistry::with_max_size(100);
        assert_eq!(registry.max_size(), 100);
        assert!(registry.is_empty());
    }
}
