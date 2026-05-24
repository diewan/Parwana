//! Reorg Detector
//!
//! Detects blockchain reorganizations by comparing current chain state
//! with previously known state.

use std::sync::Arc;
use std::sync::Mutex;

use crate::events::{CsvEvent, EventIndexerRegistry};
use csv_hash::Hash;
use csv_hash::chain_id::ChainId;

/// Reorg event
#[derive(Clone, Debug)]
pub struct ReorgEvent {
    /// Chain where reorg occurred
    pub chain: ChainId,
    /// Old block height
    pub old_height: u64,
    /// New block height
    pub new_height: u64,
    /// Old block hash
    pub old_hash: Hash,
    /// New block hash
    pub new_hash: Hash,
    /// Depth of reorg (number of blocks rolled back)
    pub depth: u64,
}

/// Reorg detector
pub struct ReorgDetector {
    /// Last known block hashes per chain
    last_known: std::collections::BTreeMap<String, (u64, Hash)>,
    /// Event registry for emitting reorg events
    event_registry: Option<Arc<Mutex<EventIndexerRegistry>>>,
}

impl ReorgDetector {
    /// Create a new reorg detector
    pub fn new() -> Self {
        Self {
            last_known: std::collections::BTreeMap::new(),
            event_registry: None,
        }
    }

    /// Create a new reorg detector with event registry
    pub fn with_event_registry(registry: Arc<Mutex<EventIndexerRegistry>>) -> Self {
        Self {
            last_known: std::collections::BTreeMap::new(),
            event_registry: Some(registry),
        }
    }

    /// Update the detector with current chain state
    ///
    /// Returns Some(ReorgEvent) if a reorg is detected, None otherwise.
    pub fn update(&mut self, chain: ChainId, height: u64, hash: Hash) -> Option<ReorgEvent> {
        let chain_str = chain.as_str().to_string();

        match self.last_known.get(&chain_str) {
            Some((last_height, last_hash)) => {
                if height < *last_height {
                    // Reorg detected - chain rolled back
                    let depth = last_height - height;
                    let event = ReorgEvent {
                        chain: chain.clone(),
                        old_height: *last_height,
                        new_height: height,
                        old_hash: *last_hash,
                        new_hash: hash,
                        depth,
                    };

                    // Emit reorg_detected event
                    if let Some(ref registry) = self.event_registry {
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let csv_event = CsvEvent::reorg_detected(
                            &chain.to_string(),
                            *last_height,
                            "",  // tx_hash - not available in this context
                            timestamp,
                            *last_height,
                            height,
                            depth,
                        );
                        if let Ok(mut guard) = registry.lock() {
                            let _ = guard.emit(csv_event);
                        }
                    }

                    Some(event)
                } else if height == *last_height && hash != *last_hash {
                    // Same height but different hash - reorg at same height
                    let event = ReorgEvent {
                        chain: chain.clone(),
                        old_height: *last_height,
                        new_height: height,
                        old_hash: *last_hash,
                        new_hash: hash,
                        depth: 0,
                    };

                    // Emit reorg_detected event
                    if let Some(ref registry) = self.event_registry {
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let csv_event = CsvEvent::reorg_detected(
                            &chain.to_string(),
                            *last_height,
                            "",  // tx_hash - not available in this context
                            timestamp,
                            *last_height,
                            height,
                            0,
                        );
                        if let Ok(mut guard) = registry.lock() {
                            let _ = guard.emit(csv_event);
                        }
                    }

                    Some(event)
                } else {
                    // Normal progression
                    self.last_known.insert(chain_str, (height, hash));
                    None
                }
            }
            None => {
                // First time seeing this chain
                self.last_known.insert(chain_str, (height, hash));
                None
            }
        }
    }

    /// Get the last known state for a chain
    pub fn get_last_known(&self, chain: &ChainId) -> Option<(u64, Hash)> {
        self.last_known.get(chain.as_str()).copied()
    }
}

impl Default for ReorgDetector {
    fn default() -> Self {
        Self::new()
    }
}
