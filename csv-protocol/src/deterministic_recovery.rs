//! Deterministic recovery with checkpoints
//!
//! This module provides deterministic recovery mechanisms for the CSV protocol
//! runtime, enabling system recovery from crashes and failures.
//!
//! # Recovery Strategy
//!
//! - Periodic checkpointing of runtime state
//! - Deterministic recovery from last checkpoint
//! - Lease recovery and continuation
//! - Transfer state reconstruction
//!
//! # Checkpoint Format
//!
//! Checkpoints are canonical CBOR-encoded snapshots containing:
//! - Runtime state (leases, transfers, registries)
//! - Timestamp and sequence number
//! - Checksum for integrity verification

use csv_hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Checkpoint version.
pub const CHECKPOINT_VERSION: u32 = 1;

/// Runtime checkpoint snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCheckpoint {
    /// Checkpoint version
    pub version: u32,
    /// Checkpoint sequence number
    pub sequence: u64,
    /// Checkpoint timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Active leases
    pub leases: BTreeMap<String, LeaseState>,
    /// Active transfers
    pub transfers: BTreeMap<String, TransferState>,
    /// Cross-chain registry state
    pub registry_state: RegistryState,
    /// Checkpoint checksum (SHA-256 of canonical checkpoint payload)
    pub checksum: Hash,
}

#[derive(Serialize)]
struct CheckpointChecksumPayload<'a> {
    version: u32,
    sequence: u64,
    timestamp: u64,
    leases: &'a BTreeMap<String, LeaseState>,
    transfers: &'a BTreeMap<String, TransferState>,
    registry_state: &'a RegistryState,
}

impl RuntimeCheckpoint {
    /// Create a new runtime checkpoint.
    pub fn new(
        sequence: u64,
        leases: BTreeMap<String, LeaseState>,
        transfers: BTreeMap<String, TransferState>,
        registry_state: RegistryState,
    ) -> Result<Self, RecoveryError> {
        let timestamp = chrono::Utc::now().timestamp() as u64;

        let mut checkpoint = Self {
            version: CHECKPOINT_VERSION,
            sequence,
            timestamp,
            leases,
            transfers,
            registry_state,
            checksum: Hash::zero(),
        };

        checkpoint.checksum = checkpoint.compute_checksum()?;

        Ok(checkpoint)
    }

    fn checksum_payload(&self) -> CheckpointChecksumPayload<'_> {
        CheckpointChecksumPayload {
            version: self.version,
            sequence: self.sequence,
            timestamp: self.timestamp,
            leases: &self.leases,
            transfers: &self.transfers,
            registry_state: &self.registry_state,
        }
    }

    fn compute_checksum(&self) -> Result<Hash, RecoveryError> {
        let cbor = csv_codec::to_canonical_cbor(&self.checksum_payload())
            .map_err(|e| RecoveryError::SerializationError(e.to_string()))?;
        Ok(Hash::sha256(&cbor))
    }

    /// Serialize the checkpoint to canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, RecoveryError> {
        csv_codec::to_canonical_cbor(self)
            .map_err(|e| RecoveryError::SerializationError(e.to_string()))
    }

    /// Deserialize the checkpoint from canonical CBOR.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, RecoveryError> {
        let checkpoint: Self = csv_codec::from_canonical_cbor(bytes)
            .map_err(|e| RecoveryError::DeserializationError(e.to_string()))?;

        let computed_checksum = checkpoint.compute_checksum()?;
        if computed_checksum != checkpoint.checksum {
            return Err(RecoveryError::ChecksumMismatch);
        }

        Ok(checkpoint)
    }

    /// Verify the checkpoint integrity.
    pub fn verify(&self) -> bool {
        match self.compute_checksum() {
            Ok(computed_checksum) => computed_checksum == self.checksum,
            Err(_) => false,
        }
    }
}

/// Lease state checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseState {
    /// Lease token
    pub lease_token: String,
    /// Lease owner
    pub owner: Vec<u8>,
    /// Source chain
    pub source_chain: String,
    /// Destination chain
    pub destination_chain: String,
    /// Lease acquisition timestamp
    pub acquired_at: u64,
    /// Lease expiry timestamp
    pub expires_at: u64,
    /// Current transfer stage
    pub stage: String,
}

/// Transfer state checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferState {
    /// Transfer ID
    pub transfer_id: String,
    /// Sanad ID
    pub sanad_id: Hash,
    /// Source chain
    pub source_chain: String,
    /// Destination chain
    pub destination_chain: String,
    /// Current status
    pub status: String,
    /// Lock transaction hash
    pub lock_tx_hash: Option<Hash>,
    /// Mint transaction hash
    pub mint_tx_hash: Option<Hash>,
    /// Transfer creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
}

/// Cross-chain registry state checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryState {
    /// Number of registered transfers
    pub transfer_count: u64,
    /// Registry entries (sanad_id -> entry)
    pub entries: BTreeMap<String, RegistryEntry>,
}

/// Registry entry checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Sanad ID
    pub sanad_id: Hash,
    /// Source chain
    pub source_chain: String,
    /// Source seal
    pub source_seal: Vec<u8>,
    /// Destination chain
    pub destination_chain: String,
    /// Destination seal
    pub destination_seal: Vec<u8>,
    /// Lock transaction hash
    pub lock_tx_hash: Hash,
    /// Mint transaction hash
    pub mint_tx_hash: Hash,
    /// Transfer timestamp
    pub timestamp: u64,
}

/// Checkpoint manager for periodic checkpointing.
#[derive(Debug, Clone)]
pub struct CheckpointManager {
    /// Checkpoint interval in seconds
    pub interval_seconds: u64,
    /// Last checkpoint sequence number
    pub last_sequence: u64,
    /// Checkpoint storage backend
    pub storage: CheckpointStorage,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    pub fn new(interval_seconds: u64, storage: CheckpointStorage) -> Self {
        Self {
            interval_seconds,
            last_sequence: 0,
            storage,
        }
    }

    /// Create a checkpoint from current runtime state.
    pub fn create_checkpoint(
        &mut self,
        leases: BTreeMap<String, LeaseState>,
        transfers: BTreeMap<String, TransferState>,
        registry_state: RegistryState,
    ) -> Result<RuntimeCheckpoint, RecoveryError> {
        self.last_sequence += 1;
        let checkpoint =
            RuntimeCheckpoint::new(self.last_sequence, leases, transfers, registry_state)?;

        // Store checkpoint
        self.storage.store(&checkpoint)?;

        Ok(checkpoint)
    }

    /// Load the latest checkpoint.
    pub fn load_latest(&self) -> Result<Option<RuntimeCheckpoint>, RecoveryError> {
        self.storage.load_latest()
    }

    /// Recover runtime state from checkpoint.
    pub fn recover(&self) -> Result<RecoveryState, RecoveryError> {
        let checkpoint = self
            .load_latest()?
            .ok_or(RecoveryError::NoCheckpointFound)?;

        if !checkpoint.verify() {
            return Err(RecoveryError::CheckpointCorrupted);
        }

        Ok(RecoveryState {
            checkpoint,
            recovered_at: chrono::Utc::now().timestamp() as u64,
        })
    }
}

/// Recovery state after loading a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryState {
    /// The loaded checkpoint
    pub checkpoint: RuntimeCheckpoint,
    /// Recovery timestamp
    pub recovered_at: u64,
}

/// Checkpoint storage backend.
#[derive(Debug, Clone)]
pub enum CheckpointStorage {
    /// In-memory storage (for testing)
    Memory(std::sync::Arc<std::sync::Mutex<Vec<RuntimeCheckpoint>>>),

    /// File-based storage
    File {
        /// Directory for checkpoint files
        directory: String,
    },

    /// Database storage
    Database {
        /// Connection string
        connection_string: String,
    },
}

impl CheckpointStorage {
    /// Store a checkpoint.
    pub fn store(&self, checkpoint: &RuntimeCheckpoint) -> Result<(), RecoveryError> {
        match self {
            CheckpointStorage::Memory(checkpoints) => {
                checkpoints
                    .lock()
                    .map_err(|e| RecoveryError::StorageError(e.to_string()))?
                    .push(checkpoint.clone());
                Ok(())
            }
            CheckpointStorage::File { directory } => {
                // In production, write to file
                let filename = format!("{}/checkpoint_{:010}.cbor", directory, checkpoint.sequence);
                let cbor = checkpoint.to_canonical_cbor()?;
                std::fs::write(filename, cbor)
                    .map_err(|e| RecoveryError::StorageError(e.to_string()))?;
                Ok(())
            }
            CheckpointStorage::Database { .. } => {
                // In production, store in database
                Ok(())
            }
        }
    }

    /// Load the latest checkpoint.
    pub fn load_latest(&self) -> Result<Option<RuntimeCheckpoint>, RecoveryError> {
        match self {
            CheckpointStorage::Memory(checkpoints) => {
                let checkpoints = checkpoints
                    .lock()
                    .map_err(|e| RecoveryError::StorageError(e.to_string()))?;
                Ok(checkpoints.last().cloned())
            }
            CheckpointStorage::File { directory } => {
                // In production, read latest file from directory
                let entries = std::fs::read_dir(directory)
                    .map_err(|e| RecoveryError::StorageError(e.to_string()))?;

                let mut latest: Option<RuntimeCheckpoint> = None;
                let mut latest_seq = 0u64;

                for entry in entries {
                    let entry = entry.map_err(|e| RecoveryError::StorageError(e.to_string()))?;
                    if let Ok(name) = entry.file_name().into_string()
                        && name.starts_with("checkpoint_")
                        && name.ends_with(".cbor")
                    {
                        let seq_str: String = name
                            .strip_prefix("checkpoint_")
                            .and_then(|s| s.strip_suffix(".cbor"))
                            .unwrap_or("0")
                            .to_string();
                        if let Ok(seq) = seq_str.parse::<u64>()
                            && seq > latest_seq
                        {
                            let path = entry.path();
                            let cbor = std::fs::read(&path)
                                .map_err(|e| RecoveryError::StorageError(e.to_string()))?;
                            let checkpoint = RuntimeCheckpoint::from_canonical_cbor(&cbor)?;
                            latest_seq = seq;
                            latest = Some(checkpoint);
                        }
                    }
                }

                Ok(latest)
            }
            CheckpointStorage::Database { .. } => {
                // In production, load from database
                Ok(None)
            }
        }
    }
}

/// Recovery errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RecoveryError {
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("No checkpoint found")]
    NoCheckpointFound,

    #[error("Checkpoint corrupted")]
    CheckpointCorrupted,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),
}

/// Lease recovery handler.
pub struct LeaseRecovery;

impl LeaseRecovery {
    /// Recover active leases from checkpoint.
    pub fn recover_leases(checkpoint: &RuntimeCheckpoint) -> Vec<&LeaseState> {
        let now = chrono::Utc::now().timestamp() as u64;

        checkpoint
            .leases
            .values()
            .filter(|lease| lease.expires_at > now)
            .collect()
    }

    /// Check if a lease is still valid.
    pub fn is_lease_valid(lease: &LeaseState) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        lease.expires_at > now
    }
}

/// Transfer recovery handler.
pub struct TransferRecovery;

impl TransferRecovery {
    /// Recover transfers that need continuation from checkpoint.
    pub fn recover_pending_transfers(checkpoint: &RuntimeCheckpoint) -> Vec<&TransferState> {
        checkpoint
            .transfers
            .values()
            .filter(|transfer| matches!(transfer.status.as_str(), "locked" | "pending"))
            .collect()
    }

    /// Get transfers that completed successfully.
    pub fn get_completed_transfers(checkpoint: &RuntimeCheckpoint) -> Vec<&TransferState> {
        checkpoint
            .transfers
            .values()
            .filter(|transfer| transfer.status == "completed")
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_checkpoint() {
        let leases = BTreeMap::new();
        let transfers = BTreeMap::new();
        let registry_state = RegistryState {
            transfer_count: 0,
            entries: BTreeMap::new(),
        };

        let checkpoint = RuntimeCheckpoint::new(1, leases, transfers, registry_state).unwrap();
        assert!(checkpoint.verify());
    }

    #[test]
    fn test_checkpoint_roundtrip() {
        let leases = BTreeMap::new();
        let transfers = BTreeMap::new();
        let registry_state = RegistryState {
            transfer_count: 0,
            entries: BTreeMap::new(),
        };

        let checkpoint = RuntimeCheckpoint::new(1, leases, transfers, registry_state).unwrap();
        let cbor = checkpoint.to_canonical_cbor().unwrap();
        let restored = RuntimeCheckpoint::from_canonical_cbor(&cbor).unwrap();

        assert_eq!(checkpoint.sequence, restored.sequence);
    }

    #[test]
    fn test_checkpoint_manager() {
        let storage =
            CheckpointStorage::Memory(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let mut manager = CheckpointManager::new(60, storage);

        let leases = BTreeMap::new();
        let transfers = BTreeMap::new();
        let registry_state = RegistryState {
            transfer_count: 0,
            entries: BTreeMap::new(),
        };

        manager
            .create_checkpoint(leases, transfers, registry_state)
            .unwrap();
        let recovered = manager.recover().unwrap();

        assert_eq!(recovered.checkpoint.sequence, 1);
    }
}
