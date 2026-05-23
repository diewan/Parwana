//! Canonical event model with causality chains.
//!
//! Every state transition MUST emit exactly one CanonicalEvent.
//! Events form a tamper-evident, causally-ordered audit log.

use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;
use csv_hash::csv_tagged_hash;
use csv_hash::canonical::to_canonical_cbor;

/// A canonical, deterministically hashable protocol event.
///
/// Every state transition MUST emit exactly one CanonicalEvent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEvent {
    /// Deterministic event identity: tagged_hash("csv-event-v1", cbor(self minus event_id))
    pub event_id: [u8; 32],

    /// Hash of the event that causally precedes this one (None = genesis).
    pub causality_parent: Option<[u8; 32]>,

    /// Transfer this event belongs to.
    pub transfer_id: [u8; 32],

    /// Monotonically increasing sequence within this transfer.
    pub sequence: u64,

    /// Unix seconds when this event was emitted.
    pub emitted_at: u64,

    /// Event variant.
    pub event_type: EventType,

    /// Tagged hash of the event-specific payload.
    pub payload_hash: [u8; 32],
}

/// Event variant types for the protocol event stream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EventType {
    SealCreated,
    SealLocked,
    InclusionVerified,
    FinalityConfirmed,
    TransferComplete,
    SealRolledBack { reorg_depth: u64 },
    ReplayRejected,
    AdapterError { retryable: bool },
}

impl CanonicalEvent {
    /// Construct and self-hash a new event.
    pub fn new(
        causality_parent: Option<[u8; 32]>,
        transfer_id: [u8; 32],
        sequence: u64,
        emitted_at: u64,
        event_type: EventType,
        payload: &[u8],
    ) -> Result<Self, ProtocolError> {
        let payload_hash = csv_tagged_hash("csv-event-payload-v1", payload);

        // Build without event_id first
        let mut event = Self {
            event_id: [0u8; 32],
            causality_parent,
            transfer_id,
            sequence,
            emitted_at,
            event_type,
            payload_hash,
        };

        // Self-hash
        let cbor = to_canonical_cbor(&event)?;
        event.event_id = csv_tagged_hash("csv-event-v1", &cbor);
        Ok(event)
    }

    /// Verify the event's own integrity (event_id matches computed hash).
    pub fn verify_integrity(&self) -> bool {
        let check = Self {
            event_id: [0u8; 32],
            causality_parent: self.causality_parent,
            transfer_id: self.transfer_id,
            sequence: self.sequence,
            emitted_at: self.emitted_at,
            event_type: self.event_type.clone(),
            payload_hash: self.payload_hash,
        };
        let cbor = match to_canonical_cbor(&check) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let computed = csv_tagged_hash("csv-event-v1", &cbor);
        computed == self.event_id
    }
}

/// Append-only event log — the single source of truth for audit reconstruction.
pub trait EventLog: Send + Sync {
    /// Append an event. Returns error if causality_parent doesn't match last event.
    fn append(&self, event: CanonicalEvent) -> Result<(), ProtocolError>;

    /// Read events for a transfer in sequence order.
    fn events_for_transfer(
        &self,
        transfer_id: &[u8; 32],
    ) -> Result<Vec<CanonicalEvent>, ProtocolError>;

    /// Verify the full causality chain for a transfer.
    fn verify_causality(&self, transfer_id: &[u8; 32]) -> Result<(), ProtocolError>;
}

/// In-memory append-only event log for testing.
pub struct InMemoryEventLog {
    events: std::sync::Arc<std::sync::RwLock<Vec<CanonicalEvent>>>,
}

impl InMemoryEventLog {
    pub fn new() -> Self {
        Self {
            events: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }
}

impl Default for InMemoryEventLog {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EventLog for InMemoryEventLog {
    fn append(&self, event: CanonicalEvent) -> Result<(), ProtocolError> {
        let mut events = self.events.write().map_err(|_| {
            ProtocolError::Generic("event log lock poisoned".to_string())
        })?;

        // Verify event integrity
        if !event.verify_integrity() {
            return Err(ProtocolError::Generic("event integrity check failed".to_string()));
        }

        // Check causality parent if not genesis
        if let Some(parent_hash) = event.causality_parent {
            if !events.is_empty() {
                let last_id = events.last().unwrap().event_id;
                if last_id != parent_hash {
                    return Err(ProtocolError::Generic(
                        "causality parent does not match last event".to_string(),
                    ));
                }
            } else if parent_hash != [0u8; 32] {
                return Err(ProtocolError::Generic(
                    "genesis event must have None causality_parent".to_string(),
                ));
            }
        }

        events.push(event);
        Ok(())
    }

    fn events_for_transfer(
        &self,
        transfer_id: &[u8; 32],
    ) -> Result<Vec<CanonicalEvent>, ProtocolError> {
        let events = self.events.read().map_err(|_| {
            ProtocolError::Generic("event log lock poisoned".to_string())
        })?;

        Ok(events
            .iter()
            .filter(|e| &e.transfer_id == transfer_id)
            .cloned()
            .collect())
    }

    fn verify_causality(&self, transfer_id: &[u8; 32]) -> Result<(), ProtocolError> {
        let events = self.events.read().map_err(|_| {
            ProtocolError::Generic("event log lock poisoned".to_string())
        })?;

        let transfer_events: Vec<_> = events
            .iter()
            .filter(|e| &e.transfer_id == transfer_id)
            .collect();

        if transfer_events.is_empty() {
            return Ok(());
        }

        // Verify sequence ordering
        for (i, event) in transfer_events.iter().enumerate() {
            if event.sequence != i as u64 {
                return Err(ProtocolError::Generic(format!(
                    "sequence mismatch at index {}: expected {}, got {}",
                    i, i, event.sequence
                )));
            }
        }

        // Verify causality chain
        for (i, event) in transfer_events.iter().enumerate() {
            match (&event.causality_parent, i) {
                (None, 0) => {} // Genesis event
                (Some(parent), _) => {
                    let expected_parent = &transfer_events[i - 1].event_id;
                    if parent != expected_parent {
                        return Err(ProtocolError::Generic(
                            "causality chain broken".to_string(),
                        ));
                    }
                }
                (None, _) => {
                    return Err(ProtocolError::Generic(
                        "non-genesis event has None causality_parent".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation_and_integrity() {
        let payload = b"seal created";
        let event = CanonicalEvent::new(
            None,
            [0x01; 32],
            0,
            1_700_000_000,
            EventType::SealCreated,
            payload,
        )
        .unwrap();

        assert!(event.verify_integrity());
        assert_ne!(event.event_id, [0u8; 32]);
    }

    #[test]
    fn test_event_causality_chain() {
        let log = InMemoryEventLog::new();

        // Genesis event
        let genesis = CanonicalEvent::new(
            None,
            [0x01; 32],
            0,
            1_700_000_000,
            EventType::SealCreated,
            b"genesis",
        )
        .unwrap();
        log.append(genesis).unwrap();

        // Second event with causality parent
        let events = log.events_for_transfer(&[0x01; 32]).unwrap();
        let parent_id = events[0].event_id;

        let second = CanonicalEvent::new(
            Some(parent_id),
            [0x01; 32],
            1,
            1_700_000_001,
            EventType::SealLocked,
            b"locked",
        )
        .unwrap();
        log.append(second).unwrap();

        // Verify causality
        assert!(log.verify_causality(&[0x01; 32]).is_ok());
    }

    #[test]
    fn test_event_rejects_broken_causality() {
        let log = InMemoryEventLog::new();

        let genesis = CanonicalEvent::new(
            None,
            [0x01; 32],
            0,
            1_700_000_000,
            EventType::SealCreated,
            b"genesis",
        )
        .unwrap();
        log.append(genesis).unwrap();

        // Try to append with wrong causality parent
        let bad = CanonicalEvent::new(
            Some([0xFF; 32]), // Wrong parent
            [0x01; 32],
            1,
            1_700_000_001,
            EventType::SealLocked,
            b"locked",
        )
        .unwrap();
        assert!(log.append(bad).is_err());
    }
}
