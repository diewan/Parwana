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
//! - Transfer context (sanad_id, chains, lock_tx_hash) is stored in the journal
//!   entry to enable recovery even when the transfer store is unavailable.
//!
//! # Crash Recovery
//!
//! When a coordinator restarts after a crash, it queries the journal to find
//! the last phase reached for each incomplete transfer and resumes from there.
//! Recovery uses the transfer context stored in the journal entry to reconstruct
//! the transfer state without relying on external storage.
//!
//! # Invariants
//!
//! - Entries are written in order: Entered -> Completed/Failed
//! - No entry is ever modified after writing
//! - The journal survives coordinator restarts
//! - Transfer context is persisted alongside phase entries for recovery

use std::collections::HashMap;
use std::time::SystemTime;

use csv_protocol::transfer_state::TransferStage;
use csv_wire::{HashWire, SanadIdWire};
use serde::{Deserialize, Serialize};

/// Transfer context stored in journal entries for crash recovery.
///
/// This contains the minimal data needed to reconstruct a transfer
/// without relying on external storage. It is persisted alongside
/// each phase entry to enable recovery even when the transfer store
/// is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferContext {
    /// Sanad ID being transferred
    pub sanad_id: SanadIdWire,
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Lock transaction hash (hex-encoded)
    pub lock_tx_hash: HashWire,
    /// Destination owner address (hex-encoded)
    pub destination_owner: String,
}

/// Outcome of a transfer phase execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseOutcome {
    /// Phase was entered but not yet completed
    Entered,
    /// Phase completed successfully
    Completed,
    /// Phase failed with a reason
    Failed(String),
}

/// A single entry in the execution journal.
///
/// Each entry records a phase transition with its outcome. The entry
/// includes transfer context to enable recovery without external storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPhaseEntry {
    /// Unique transfer identifier
    pub transfer_id: String,
    /// Replay ID hash for this transfer (stored as HashWire for serialization compatibility)
    pub replay_id: HashWire,
    /// Hash of the proof bundle (if available)
    pub proof_hash: [u8; 32],
    /// Canonical proof bundle bytes needed to resume after validation.
    pub proof_payload: Option<Vec<u8>>,
    /// The transfer stage/phase
    pub phase: TransferStage,
    /// Timestamp when the entry was recorded
    pub ts: SystemTime,
    /// Outcome of this phase
    pub outcome: PhaseOutcome,
    /// Attempt number (increments on retry)
    pub attempt: u32,
    /// Transfer context for crash recovery (persisted with each entry)
    pub transfer_context: Option<TransferContext>,
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

/// In-memory implementation of the execution journal for tests and ephemeral
/// processes that do not execute recoverable mutations.
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
        let mut guard = self
            .entries
            .lock()
            .map_err(|e| JournalError::Io(e.to_string()))?;

        if guard.len() >= self.max_entries {
            return Err(JournalError::CapacityExceeded);
        }

        guard.push(entry);
        Ok(())
    }

    /// Get all incomplete transfers (those that haven't reached a terminal phase).
    fn incomplete_transfers_locked(&self) -> Vec<TransferPhaseEntry> {
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut transfer_phases: HashMap<String, &TransferPhaseEntry> = HashMap::new();

        for entry in guard.iter() {
            transfer_phases.insert(entry.transfer_id.clone(), entry);
        }

        transfer_phases
            .into_values()
            .filter(|entry| !entry.phase.is_terminal())
            .cloned()
            .collect()
    }

    /// Get the latest phase for a transfer.
    fn latest_entry_locked(&self, transfer_id: &str) -> Option<TransferPhaseEntry> {
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .rev()
            .find(|e| e.transfer_id == transfer_id)
            .cloned()
    }
}

impl Default for InMemoryJournal {
    fn default() -> Self {
        Self::new(10000)
    }
}

/// Execution journal trait.
///
/// Implementations may use redb, PostgreSQL, or any other persistent store.
pub trait ExecutionJournal: Send + Sync {
    /// Record a phase entry in the journal.
    fn record(&self, entry: TransferPhaseEntry) -> Result<(), JournalError>;

    /// Get all transfers that are incomplete (no Completed outcome).
    fn incomplete_transfers(&self) -> Result<Vec<TransferPhaseEntry>, JournalError>;

    /// Get the latest phase for a transfer.
    fn latest_phase(&self, transfer_id: &str) -> Result<Option<TransferStage>, JournalError>;

    /// Get the latest durable recovery entry for a transfer.
    fn latest_entry(&self, transfer_id: &str) -> Result<Option<TransferPhaseEntry>, JournalError>;
}

impl ExecutionJournal for InMemoryJournal {
    fn record(&self, entry: TransferPhaseEntry) -> Result<(), JournalError> {
        self.record_locked(entry)
    }

    fn incomplete_transfers(&self) -> Result<Vec<TransferPhaseEntry>, JournalError> {
        Ok(self.incomplete_transfers_locked())
    }

    fn latest_phase(&self, transfer_id: &str) -> Result<Option<TransferStage>, JournalError> {
        Ok(self
            .latest_entry_locked(transfer_id)
            .map(|entry| entry.phase))
    }

    fn latest_entry(&self, transfer_id: &str) -> Result<Option<TransferPhaseEntry>, JournalError> {
        Ok(self.latest_entry_locked(transfer_id))
    }
}

/// Key space for the durable journal: monotonically increasing sequence
/// numbers so iteration order is insertion order.
#[cfg(feature = "persistent")]
const JOURNAL_TABLE: redb::TableDefinition<'static, u64, &'static [u8]> =
    redb::TableDefinition::new("transfer_phases");

/// redb-backed append-only execution journal for production recovery.
#[cfg(feature = "persistent")]
pub struct RedbExecutionJournal {
    db: redb::Database,
    next_sequence: std::sync::Mutex<u64>,
}

#[cfg(feature = "persistent")]
impl RedbExecutionJournal {
    /// Open or create a durable execution journal at `path` (a file, not a
    /// directory).
    pub fn open(path: &str) -> Result<Self, JournalError> {
        use redb::ReadableDatabase;

        let db = redb::Database::create(path).map_err(|e| JournalError::Io(e.to_string()))?;
        // Create the table so later read transactions never observe a missing
        // table, and seed the sequence counter from the highest existing key.
        let txn = db
            .begin_write()
            .map_err(|e| JournalError::Io(e.to_string()))?;
        txn.open_table(JOURNAL_TABLE)
            .map_err(|e| JournalError::Io(e.to_string()))?;
        txn.commit().map_err(|e| JournalError::Io(e.to_string()))?;

        let read = db
            .begin_read()
            .map_err(|e| JournalError::Io(e.to_string()))?;
        let table = read
            .open_table(JOURNAL_TABLE)
            .map_err(|e| JournalError::Io(e.to_string()))?;
        let next_sequence = redb::ReadableTable::last(&table)
            .map_err(|e| JournalError::Io(e.to_string()))?
            .map(|(key, _)| key.value() + 1)
            .unwrap_or(0);
        Ok(Self {
            db,
            next_sequence: std::sync::Mutex::new(next_sequence),
        })
    }

    /// Read every journal entry in insertion order (diagnostics / recovery
    /// tooling).
    pub fn entries(&self) -> Result<Vec<TransferPhaseEntry>, JournalError> {
        use redb::ReadableDatabase;

        let read = self
            .db
            .begin_read()
            .map_err(|e| JournalError::Io(e.to_string()))?;
        let table = read
            .open_table(JOURNAL_TABLE)
            .map_err(|e| JournalError::Io(e.to_string()))?;
        redb::ReadableTable::range::<u64>(&table, ..)
            .map_err(|e| JournalError::Io(e.to_string()))?
            .map(|item| {
                let (_, bytes) = item.map_err(|e| JournalError::Io(e.to_string()))?;
                csv_codec::from_canonical_cbor(bytes.value())
                    .map_err(|e| JournalError::Serialization(e.to_string()))
            })
            .collect()
    }

    fn latest_entry_from(
        entries: &[TransferPhaseEntry],
        transfer_id: &str,
    ) -> Option<TransferPhaseEntry> {
        entries
            .iter()
            .rev()
            .find(|entry| entry.transfer_id == transfer_id)
            .cloned()
    }
}

#[cfg(feature = "persistent")]
impl ExecutionJournal for RedbExecutionJournal {
    fn record(&self, entry: TransferPhaseEntry) -> Result<(), JournalError> {
        let bytes = csv_codec::to_canonical_cbor(&entry)
            .map_err(|e| JournalError::Serialization(e.to_string()))?;
        let mut sequence = self
            .next_sequence
            .lock()
            .map_err(|e| JournalError::Io(e.to_string()))?;
        // Durability is the whole point of this journal: the phase MUST be on
        // stable storage before the corresponding chain action runs, otherwise
        // a crash between the (async) write and the action loses the entry and
        // defeats crash-safe resume. redb commits are Durability::Immediate by
        // default — commit() returns only after the data is fsynced.
        let txn = self
            .db
            .begin_write()
            .map_err(|e| JournalError::Io(e.to_string()))?;
        {
            let mut table = txn
                .open_table(JOURNAL_TABLE)
                .map_err(|e| JournalError::Io(e.to_string()))?;
            table
                .insert(*sequence, bytes.as_slice())
                .map_err(|e| JournalError::Io(e.to_string()))?;
        }
        txn.commit().map_err(|e| JournalError::Io(e.to_string()))?;
        *sequence += 1;
        Ok(())
    }

    fn incomplete_transfers(&self) -> Result<Vec<TransferPhaseEntry>, JournalError> {
        let entries = self.entries()?;
        let mut latest = HashMap::new();
        for entry in entries {
            latest.insert(entry.transfer_id.clone(), entry);
        }
        Ok(latest
            .into_values()
            .filter(|entry| !entry.phase.is_terminal())
            .collect())
    }

    fn latest_phase(&self, transfer_id: &str) -> Result<Option<TransferStage>, JournalError> {
        Ok(self.latest_entry(transfer_id)?.map(|entry| entry.phase))
    }

    fn latest_entry(&self, transfer_id: &str) -> Result<Option<TransferPhaseEntry>, JournalError> {
        Ok(Self::latest_entry_from(&self.entries()?, transfer_id))
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
                replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                proof_hash,
                proof_payload: None,
                phase: TransferStage::Initialized,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Entered,
                transfer_context: None,
                attempt: 1,
            })
            .unwrap();

        journal
            .record(TransferPhaseEntry {
                transfer_id: "test-1".to_string(),
                replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                proof_hash,
                proof_payload: None,
                phase: TransferStage::Initialized,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                transfer_context: None,
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
                replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                proof_hash,
                proof_payload: None,
                phase: TransferStage::Completed,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                transfer_context: None,
                attempt: 1,
            })
            .unwrap();

        // Incomplete transfer
        journal
            .record(TransferPhaseEntry {
                transfer_id: "incomplete-1".to_string(),
                replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                proof_hash,
                proof_payload: None,
                phase: TransferStage::LockConfirmed,
                ts: SystemTime::now(),
                outcome: PhaseOutcome::Entered,
                transfer_context: None,
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

        for i in 0..5 {
            journal
                .record(TransferPhaseEntry {
                    transfer_id: format!("transfer-{}", i),
                    replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                    proof_hash,
                    proof_payload: None,
                    phase: TransferStage::Initialized,
                    ts: SystemTime::now(),
                    outcome: PhaseOutcome::Entered,
                    transfer_context: None,
                    attempt: 1,
                })
                .unwrap();
        }

        let result = journal.record(TransferPhaseEntry {
            transfer_id: "transfer-over-capacity".to_string(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash,
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: SystemTime::now(),
            outcome: PhaseOutcome::Entered,
            transfer_context: None,
            attempt: 1,
        });
        assert_eq!(result, Err(JournalError::CapacityExceeded));

        let entries = journal.entries.lock().unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[cfg(feature = "persistent")]
    #[test]
    fn durable_journal_recovers_proof_payload_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("journal.redb");
        let path = file.to_str().unwrap();
        let replay_id = csv_hash::ReplayIdHash(csv_hash::Hash::new([4u8; 32]));
        {
            let journal = RedbExecutionJournal::open(path).unwrap();
            journal
                .record(TransferPhaseEntry {
                    transfer_id: "recover-me".to_string(),
                    replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                    proof_hash: [8u8; 32],
                    proof_payload: Some(vec![1, 2, 3]),
                    phase: TransferStage::ProofValidated,
                    ts: SystemTime::now(),
                    outcome: PhaseOutcome::Completed,
                    transfer_context: None,
                    attempt: 1,
                })
                .unwrap();
        }

        let reopened = RedbExecutionJournal::open(path).unwrap();
        let entry = reopened.latest_entry("recover-me").unwrap().unwrap();
        assert_eq!(entry.phase, TransferStage::ProofValidated);
        assert_eq!(entry.proof_payload, Some(vec![1, 2, 3]));
    }
}
