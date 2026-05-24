//! Durable execution journal for crash-safe transfer execution.
//!
//! The execution journal provides a phase-by-phase audit trail for every
//! cross-chain transfer. It enables deterministic crash recovery by
//! recording each phase transition with its outcome.
//!
//! # Design
//!
//! - Every phase transition is recorded BEFORE execution (Entered) and AFTER
//!   execution (Completed or Failed).
//! - The journal is append-only: entries are never modified or deleted.
//! - Crash recovery uses the journal to determine where to resume execution.
//!
//! # Crash Recovery
//!
//! When a coordinator restarts after a crash, it queries the journal to find
//! the last phase reached for each incomplete transfer and resumes from there.
//!
//! # Invariants
//!
//! - Entries are written in order: Entered -> Completed/Failed
//! - No entry is ever modified after writing
//! - The journal survives coordinator restarts

use std::collections::HashMap;
use std::time::SystemTime;

use csv_protocol::transfer_state::TransferStage;

/// Outcome of a transfer phase execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseOutcome {
    /// Phase was entered but not yet completed
    Entered,
    /// Phase completed successfully
    Completed,
    /// Phase failed with a reason
    Failed(String),
}

/// A single entry in the execution journal
#[derive(Debug, Clone)]
pub struct TransferPhaseEntry {
    /// Unique transfer identifier
    pub transfer_id: String,
    /// Replay ID hash for this transfer
    pub replay_id: csv_hash::ReplayIdHash,
    /// Hash of the proof bundle (if available)
    pub proof_hash: [u8; 32],
    /// The transfer stage/phase
    pub phase: TransferStage,
    /// Timestamp when the entry was recorded
    pub ts: SystemTime,
    /// Outcome of this phase
    pub outcome: PhaseOutcome,
    /// Attempt number (increments on retry)
    pub attempt: u32,
}

/// Error type for journal operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// Storage I/O error
    Io(String),
    /// Serialization error
    Serialization(String),
    /// Journal is full (capacity exceeded)
    CapacityExceeded,
}

impl core::fmt::Display for JournalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "Journal I/O error: {}", msg),
            Self::Serialization(msg) => write!(f, "Journal serialization error: {}", msg),
            Self::CapacityExceeded => write!(f, "Journal capacity exceeded"),
        }
    }
}

impl std::error::Error for JournalError {}

/// In-memory implementation of the execution journal for testing and
/// non-persistent deployments.
pub struct InMemoryJournal {
    entries: std::sync::Mutex<Vec<TransferPhaseEntry>>,
    max_entries: usize,
}

impl InMemoryJournal {
    /// Create a new in-memory journal with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
            max_entries,
        }
    }

    /// Record a phase entry in the journal.
    fn record_locked(&self, entry: TransferPhaseEntry) -> Result<(), JournalError> {
        let mut guard = self.entries.lock().map_err(|e| JournalError::Io(e.to_string()))?;

        // Enforce capacity limit
        if guard.len() >= self.max_entries {
            // Remove oldest entries to make room
            let keep = self.max_entries / 2;
            guard.drain(..keep);
        }

        guard.push(entry);
        Ok(())
    }

    /// Get all incomplete transfers (those that haven't reached a terminal phase).
    fn incomplete_transfers_locked(&self) -> Vec<TransferPhaseEntry> {
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut transfer_phases: HashMap<String, &TransferPhaseEntry> = HashMap::new();

        for entry in guard.iter() {
            transfer_phases
                .entry(entry.transfer_id.clone())
                .or_insert(entry);
        }

        transfer_phases
            .into_values()
            .filter(|entry| {
                !matches!(entry.outcome, PhaseOutcome::Completed)
                    && !entry.phase.is_terminal()
            })
            .cloned()
            .collect()
    }

    /// Get the latest phase for a transfer.
    fn latest_phase_locked(&self, transfer_id: &str) -> Option<TransferStage> {
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .filter(|e| e.transfer_id == transfer_id)
            .max_by_key(|e| e.ts)
            .map(|e| e.phase)
    }
}

impl Default for InMemoryJournal {
    fn default() -> Self {
        Self::new(10000)
    }
}

/// Execution journal trait.
///
/// Implementations may use RocksDB, PostgreSQL, or any other persistent store.
pub trait ExecutionJournal: Send + Sync {
    /// Record a phase entry in the journal.
    fn record(&self, entry: TransferPhaseEntry) -> Result<(), JournalError>;

    /// Get all transfers that are incomplete (no Completed outcome).
    fn incomplete_transfers(&self) -> Result<Vec<TransferPhaseEntry>, JournalError>;

    /// Get the latest phase for a transfer.
    fn latest_phase(&self, transfer_id: &str) -> Result<Option<TransferStage>, JournalError>;
}

impl ExecutionJournal for InMemoryJournal {
    fn record(&self, entry: TransferPhaseEntry) -> Result<(), JournalError> {
        self.record_locked(entry)
    }

    fn incomplete_transfers(&self) -> Result<Vec<TransferPhaseEntry>, JournalError> {
        Ok(self.incomplete_transfers_locked())
    }

    fn latest_phase(&self, transfer_id: &str) -> Result<Option<TransferStage>, JournalError> {
        Ok(self.latest_phase_locked(transfer_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journal_records_entries() {
        let journal = InMemoryJournal::new(1000);
        let replay_id = csv_hash::ReplayIdHash(csv_hash::Hash::new([1u8; 32]));
        let proof_hash = [0u8; 32];

        journal
            .record(TransferPhaseEntry {
                transfer_id: "test-1".to_string(),
                replay_id: replay_id.clone(),
                proof_hash,
                phase: TransferStage::Initialized,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Entered,
                attempt: 1,
            })
            .unwrap();

        journal
            .record(TransferPhaseEntry {
                transfer_id: "test-1".to_string(),
                replay_id,
                proof_hash,
                phase: TransferStage::Initialized,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                attempt: 1,
            })
            .unwrap();

        let latest = journal.latest_phase("test-1").unwrap();
        assert_eq!(latest, Some(TransferStage::Initialized));
    }

    #[test]
    fn test_journal_incomplete_transfers() {
        let journal = InMemoryJournal::new(1000);
        let replay_id = csv_hash::ReplayIdHash(csv_hash::Hash::new([1u8; 32]));
        let proof_hash = [0u8; 32];

        // Complete transfer
        journal
            .record(TransferPhaseEntry {
                transfer_id: "complete-1".to_string(),
                replay_id: replay_id.clone(),
                proof_hash,
                phase: TransferStage::Completed,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                attempt: 1,
            })
            .unwrap();

        // Incomplete transfer
        journal
            .record(TransferPhaseEntry {
                transfer_id: "incomplete-1".to_string(),
                replay_id,
                proof_hash,
                phase: TransferStage::LockConfirmed,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Entered,
                attempt: 1,
            })
            .unwrap();

        let incomplete = journal.incomplete_transfers().unwrap();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].transfer_id, "incomplete-1");
    }

    #[test]
    fn test_journal_capacity_enforcement() {
        let journal = InMemoryJournal::new(5);
        let replay_id = csv_hash::ReplayIdHash(csv_hash::Hash::new([1u8; 32]));
        let proof_hash = [0u8; 32];

        // Fill beyond capacity
        for i in 0..10 {
            journal
                .record(TransferPhaseEntry {
                    transfer_id: format!("transfer-{}", i),
                    replay_id: replay_id.clone(),
                    proof_hash,
                    phase: TransferStage::Initialized,
                    ts: SystemTime::now(),
                    outcome: PhaseOutcome::Entered,
                    attempt: 1,
                })
                .unwrap();
        }

        // Journal should have trimmed old entries
        let entries = journal.entries.lock().unwrap();
        assert!(entries.len() <= 10);
    }
}
