//! Event types for CSV protocol

use serde::{Deserialize, Serialize};
use csv_hash::Hash;

/// A CSV protocol event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsvEvent {
    /// Event type
    pub event_type: String,
    /// Event data
    pub data: Vec<u8>,
    /// Event hash
    pub hash: Hash,
    /// Timestamp
    pub timestamp: u64,
}

impl CsvEvent {
    /// Create a reorg detected event
    pub fn reorg_detected(chain_id: String, old_hash: Hash, new_hash: Hash, depth: u64) -> Self {
        Self {
            event_type: "reorg_detected".to_string(),
            data: vec![],
            hash: Hash::default(),
            timestamp: 0,
        }
    }
}

/// Event indexer registry
#[derive(Debug, Clone, Default)]
pub struct EventIndexerRegistry {
    // Placeholder for event indexer registry
}

impl EventIndexerRegistry {
    /// Create a new event indexer registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit an event
    pub fn emit(&mut self, event: CsvEvent) {
        // Placeholder for event emission
    }
}
