//! Storage traits
//!
//! This module defines the canonical storage traits for the CSV protocol.
//! All implementations MUST use these traits, not custom interfaces.

use super::errors::{ReplayDbError, StorageError};
use async_trait::async_trait;
use csv_proof::proof::ReplayId;
use csv_protocol::cross_chain::HashEntry as CrossChainRegistryEntry;

/// Generic storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Get a value by key
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Set a value by key
    async fn set(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Delete a value by key
    async fn delete(&self, key: &[u8]) -> Result<(), StorageError>;

    /// Check if a key exists
    async fn exists(&self, key: &[u8]) -> Result<bool, StorageError>;
}

/// State of a replay entry (append-only; never deleted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayEntryState {
    /// Insert recorded; mint not yet confirmed on-chain.
    Pending,
    /// Mint confirmed on-chain — terminal.
    Consumed,
    /// Transfer failed after insert; recovery may retry.
    RolledBack,
}

/// Replay database trait (compare-and-swap semantics) — canonical persistence (RULE 4).
///
/// ## Concurrency
/// - `insert_if_absent` MUST provide compare-and-swap semantics
/// - `consume_if_unconsumed` MUST be idempotent
/// - Entries are append-only: never deleted, only state-changed
#[async_trait]
pub trait ReplayDatabase: Send + Sync {
    /// Check if a replay ID exists
    async fn contains(&self, id: &[u8]) -> Result<bool, ReplayDbError>;

    /// Insert a replay ID if absent (CAS semantics)
    async fn insert_if_absent(&self, id: &[u8]) -> Result<(), ReplayDbError>;

    /// Idempotent consume-if-unconsumed
    async fn consume_if_unconsumed(&self, id: &[u8]) -> Result<(), ReplayDbError>;

    /// Promote Pending → Consumed after mint is confirmed on-chain.
    async fn confirm_consumed(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        if id.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(id);
            let replay_id = ReplayId {
                version: ReplayId::CURRENT_VERSION,
                id: bytes,
            };
            self.confirm_consumed_replay_id(&replay_id).await
        } else {
            Err(ReplayDbError::Storage(
                "Invalid replay ID length (expected 32 bytes)".to_string(),
            ))
        }
    }

    /// Promote Pending → Consumed (typed ReplayId API).
    async fn confirm_consumed_replay_id(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let _ = id;
        Err(ReplayDbError::Storage(
            "confirm_consumed not implemented for this backend".to_string(),
        ))
    }

    /// Mark Pending → RolledBack. Already RolledBack entries are idempotent.
    async fn mark_rolled_back(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let _ = id;
        Err(ReplayDbError::Storage(
            "mark_rolled_back not implemented for this backend".to_string(),
        ))
    }

    /// Persist transfer registry entry.
    async fn store_transfer_entry(
        &self,
        entry: &CrossChainRegistryEntry,
    ) -> Result<(), ReplayDbError> {
        let _ = entry;
        Err(ReplayDbError::Storage(
            "store_transfer_entry not implemented for this backend".to_string(),
        ))
    }

    /// Load all persisted transfer entries.
    async fn load_all_transfers(&self) -> Result<Vec<CrossChainRegistryEntry>, ReplayDbError> {
        Err(ReplayDbError::Storage(
            "load_all_transfers not implemented for this backend".to_string(),
        ))
    }
}

/// Transfer store trait
#[async_trait]
pub trait TransferStore: Send + Sync {
    /// Get a transfer by ID
    async fn get_transfer(&self, id: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Save a transfer
    async fn save_transfer(&self, id: &[u8], data: &[u8]) -> Result<(), StorageError>;

    /// List all transfers
    async fn list_transfers(&self) -> Result<Vec<Vec<u8>>, StorageError>;
}
