//! Replay Record Types
//!
//! This module provides replay record types for PostgreSQL storage.

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_protocol::sanad::SanadId;

/// Replay state for a record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReplayState {
    /// Pending replay
    Pending,
    /// Finalized replay
    Finalized,
    /// Rolled back replay
    RolledBack,
    /// Tombstoned replay
    Tombstoned,
}

/// Global replay record.
///
/// This type is used in csv-runtime for PostgreSQL storage.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlobalReplayRecord {
    /// Seal ID
    pub seal_id: SanadId,
    /// Originating chain
    pub originating_chain: ChainId,
    /// Consumed by transfer
    pub consumed_by_transfer: SanadId,
    /// Consumption proof hash
    pub consumption_proof_hash: Hash,
    /// Replay state
    pub state: ReplayState,
}
