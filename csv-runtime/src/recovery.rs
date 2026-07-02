//! Deterministic recovery checkpoints
//!
//! Recovery checkpoints provide explicit, deterministic recovery points.
//! No implicit reconstruction is allowed - all recovery must use explicit checkpoints.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Re-export TransferStage from csv-protocol (protocol-level type)
pub use csv_protocol::transfer_state::TransferStage;

/// Unique identifier for a recovery checkpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CheckpointId(u64);

impl CheckpointId {
    /// Create a new checkpoint ID from a timestamp
    pub fn from_timestamp(ts: SystemTime) -> Self {
        Self(
            ts.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        )
    }

    /// Create a new checkpoint ID from a raw value
    pub fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw value
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Recovery checkpoint for overall transfer state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryCheckpoint {
    /// Unique checkpoint identifier
    pub id: CheckpointId,
    /// Timestamp when checkpoint was created
    pub timestamp: SystemTime,
    /// Transfer ID being recovered
    pub transfer_id: String,
    /// Current stage of the transfer
    pub stage: TransferStage,
    /// Checkpoint data (serialized state)
    pub data: Vec<u8>,
    /// Whether this checkpoint is committed (durable) or pending
    pub committed: bool,
}

/// Replay checkpoint for replay registry state
#[derive(Debug, Clone)]
pub struct ReplayCheckpoint {
    /// Unique checkpoint identifier
    pub id: CheckpointId,
    /// Timestamp when checkpoint was created
    pub timestamp: SystemTime,
    /// Replay IDs that were consumed (stored as Hash for serialization compatibility)
    pub consumed_replay_ids: Vec<csv_hash::Hash>,
    /// Replay IDs that were pending (stored as Hash for serialization compatibility)
    pub pending_replay_ids: Vec<csv_hash::Hash>,
    /// Checkpoint data (additional state)
    pub data: Vec<u8>,
}

impl ReplayCheckpoint {
    /// Create a new replay checkpoint
    pub fn new(
        consumed: Vec<csv_hash::ReplayIdHash>,
        pending: Vec<csv_hash::ReplayIdHash>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            id: CheckpointId::from_timestamp(SystemTime::now()),
            timestamp: SystemTime::now(),
            consumed_replay_ids: consumed.into_iter().map(|h| h.0).collect(),
            pending_replay_ids: pending.into_iter().map(|h| h.0).collect(),
            data,
        }
    }

    /// Check if a replay ID was consumed at this checkpoint
    pub fn is_consumed(&self, replay_id: &csv_hash::ReplayIdHash) -> bool {
        self.consumed_replay_ids.contains(&replay_id.0)
    }

    /// Check if a replay ID was pending at this checkpoint
    pub fn is_pending(&self, replay_id: &csv_hash::ReplayIdHash) -> bool {
        self.pending_replay_ids.contains(&replay_id.0)
    }

    /// Get consumed replay IDs as ReplayIdHash
    pub fn get_consumed_as_replay_ids(&self) -> Vec<csv_hash::ReplayIdHash> {
        self.consumed_replay_ids
            .iter()
            .map(|&h| csv_hash::ReplayIdHash(h))
            .collect()
    }

    /// Get pending replay IDs as ReplayIdHash
    pub fn get_pending_as_replay_ids(&self) -> Vec<csv_hash::ReplayIdHash> {
        self.pending_replay_ids
            .iter()
            .map(|&h| csv_hash::ReplayIdHash(h))
            .collect()
    }
}

/// Verification checkpoint for verification state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationCheckpoint {
    /// Unique checkpoint identifier
    pub id: CheckpointId,
    /// Timestamp when checkpoint was created
    pub timestamp: SystemTime,
    /// Transfer ID being verified
    pub transfer_id: String,
    /// Verification results per component
    pub verification_results: HashMap<String, VerificationResult>,
    /// Whether verification passed
    pub passed: bool,
    /// Checkpoint data (additional state)
    pub data: Vec<u8>,
}

/// Verification result for a component
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    /// Component name (e.g., "inclusion", "finality", "replay")
    pub component: String,
    /// Whether verification passed
    pub passed: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Verification timestamp
    pub timestamp: SystemTime,
}

impl VerificationCheckpoint {
    /// Create a new verification checkpoint
    pub fn new(
        transfer_id: String,
        verification_results: HashMap<String, VerificationResult>,
        passed: bool,
        data: Vec<u8>,
    ) -> Self {
        Self {
            id: CheckpointId::from_timestamp(SystemTime::now()),
            timestamp: SystemTime::now(),
            transfer_id,
            verification_results,
            passed,
            data,
        }
    }

    /// Get the verification result for a specific component
    pub fn get_result(&self, component: &str) -> Option<&VerificationResult> {
        self.verification_results.get(component)
    }
}

/// Checkpoint manager for deterministic recovery
#[derive(Debug, Clone)]
pub struct CheckpointManager {
    /// Recovery checkpoints indexed by transfer ID
    recovery_checkpoints: HashMap<String, RecoveryCheckpoint>,
    /// Replay checkpoints indexed by checkpoint ID
    replay_checkpoints: HashMap<CheckpointId, ReplayCheckpoint>,
    /// Verification checkpoints indexed by transfer ID
    verification_checkpoints: HashMap<String, VerificationCheckpoint>,
}

impl CheckpointManager {
    /// Create a new checkpoint manager
    pub fn new() -> Self {
        Self {
            recovery_checkpoints: HashMap::new(),
            replay_checkpoints: HashMap::new(),
            verification_checkpoints: HashMap::new(),
        }
    }

    /// Create a recovery checkpoint
    pub fn create_recovery_checkpoint(
        &mut self,
        transfer_id: String,
        stage: TransferStage,
        data: Vec<u8>,
    ) -> CheckpointId {
        let checkpoint = RecoveryCheckpoint {
            id: CheckpointId::from_timestamp(SystemTime::now()),
            timestamp: SystemTime::now(),
            transfer_id,
            stage,
            data,
            committed: false,
        };
        let id = checkpoint.id;
        self.recovery_checkpoints
            .insert(checkpoint.transfer_id.clone(), checkpoint);
        id
    }

    /// Commit a recovery checkpoint (make it durable)
    pub fn commit_recovery_checkpoint(&mut self, transfer_id: &str) -> bool {
        if let Some(checkpoint) = self.recovery_checkpoints.get_mut(transfer_id) {
            checkpoint.committed = true;
            true
        } else {
            false
        }
    }

    /// Get the latest recovery checkpoint for a transfer
    pub fn get_recovery_checkpoint(&self, transfer_id: &str) -> Option<&RecoveryCheckpoint> {
        self.recovery_checkpoints.get(transfer_id)
    }

    /// Create a replay checkpoint
    pub fn create_replay_checkpoint(
        &mut self,
        consumed: Vec<csv_hash::ReplayIdHash>,
        pending: Vec<csv_hash::ReplayIdHash>,
        data: Vec<u8>,
    ) -> CheckpointId {
        let checkpoint = ReplayCheckpoint::new(consumed, pending, data);
        let id = checkpoint.id;
        self.replay_checkpoints.insert(id, checkpoint);
        id
    }

    /// Get a replay checkpoint by ID
    pub fn get_replay_checkpoint(&self, id: CheckpointId) -> Option<&ReplayCheckpoint> {
        self.replay_checkpoints.get(&id)
    }

    /// Create a verification checkpoint
    pub fn create_verification_checkpoint(
        &mut self,
        transfer_id: String,
        verification_results: HashMap<String, VerificationResult>,
        passed: bool,
        data: Vec<u8>,
    ) -> CheckpointId {
        let checkpoint =
            VerificationCheckpoint::new(transfer_id, verification_results, passed, data);
        let id = checkpoint.id;
        self.verification_checkpoints
            .insert(checkpoint.transfer_id.clone(), checkpoint);
        id
    }

    /// Get the verification checkpoint for a transfer
    pub fn get_verification_checkpoint(
        &self,
        transfer_id: &str,
    ) -> Option<&VerificationCheckpoint> {
        self.verification_checkpoints.get(transfer_id)
    }

    /// Clear all checkpoints for a transfer
    pub fn clear_transfer_checkpoints(&mut self, transfer_id: &str) {
        self.recovery_checkpoints.remove(transfer_id);
        self.verification_checkpoints.remove(transfer_id);
    }

    /// Clear all checkpoints
    pub fn clear_all(&mut self) {
        self.recovery_checkpoints.clear();
        self.replay_checkpoints.clear();
        self.verification_checkpoints.clear();
    }
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_id() {
        let id = CheckpointId::from_timestamp(SystemTime::now());
        assert!(id.as_raw() > 0);

        let id2 = CheckpointId::from_raw(12345);
        assert_eq!(id2.as_raw(), 12345);
    }

    #[test]
    fn test_transfer_stage() {
        assert!(!TransferStage::Initialized.is_terminal());
        assert!(TransferStage::Completed.is_terminal());
        assert!(TransferStage::RolledBack.is_terminal());
        assert!(TransferStage::Compromised.is_terminal());

        assert_eq!(
            TransferStage::Initialized.next_stage(),
            Some(TransferStage::LockSubmitted)
        );
        assert_eq!(
            TransferStage::LockSubmitted.next_stage(),
            Some(TransferStage::LockConfirmed)
        );
        assert_eq!(TransferStage::Completed.next_stage(), None);
    }

    #[test]
    fn test_replay_checkpoint() {
        let replay_id = csv_hash::ReplayIdHash(csv_hash::Hash::new([1u8; 32]));
        let checkpoint = ReplayCheckpoint::new(vec![replay_id.clone()], vec![], vec![]);

        assert!(checkpoint.is_consumed(&replay_id));
        assert!(!checkpoint.is_pending(&replay_id));
    }

    #[test]
    fn test_verification_checkpoint() {
        let mut results = HashMap::new();
        results.insert(
            "inclusion".to_string(),
            VerificationResult {
                component: "inclusion".to_string(),
                passed: true,
                error: None,
                timestamp: SystemTime::now(),
            },
        );

        let checkpoint =
            VerificationCheckpoint::new("test-transfer".to_string(), results, true, vec![]);

        assert!(checkpoint.passed);
        assert!(checkpoint.get_result("inclusion").is_some());
        assert!(checkpoint.get_result("inclusion").unwrap().passed);
    }

    #[test]
    fn test_checkpoint_manager() {
        let mut manager = CheckpointManager::new();

        // Create recovery checkpoint
        let _recovery_id = manager.create_recovery_checkpoint(
            "transfer-1".to_string(),
            TransferStage::LockConfirmed,
            vec![1, 2, 3],
        );
        assert!(manager.get_recovery_checkpoint("transfer-1").is_some());

        // Commit checkpoint
        assert!(manager.commit_recovery_checkpoint("transfer-1"));
        assert!(
            manager
                .get_recovery_checkpoint("transfer-1")
                .unwrap()
                .committed
        );

        // Create replay checkpoint
        let replay_id = manager.create_replay_checkpoint(vec![], vec![], vec![]);
        assert!(manager.get_replay_checkpoint(replay_id).is_some());

        // Create verification checkpoint
        let mut results = HashMap::new();
        results.insert(
            "test".to_string(),
            VerificationResult {
                component: "test".to_string(),
                passed: true,
                error: None,
                timestamp: SystemTime::now(),
            },
        );
        let _verification_id =
            manager.create_verification_checkpoint("transfer-1".to_string(), results, true, vec![]);
        assert!(manager.get_verification_checkpoint("transfer-1").is_some());

        // Clear transfer checkpoints
        manager.clear_transfer_checkpoints("transfer-1");
        assert!(manager.get_recovery_checkpoint("transfer-1").is_none());
        assert!(manager.get_verification_checkpoint("transfer-1").is_none());
    }
}
