//! Durable event store abstraction and implementations.
//!
//! This module provides the event store trait and implementations for
//! event sourcing. Events are appended to the store and can be replayed
//! to reconstruct aggregate state.
//!
//! # Event Sourcing Pattern
//!
//! 1. **Append**: All state changes are appended as events (never mutate/delete)
//! 2. **Persist**: Events are written to durable storage before acknowledgment
//! 3. **Replay**: Aggregate state is reconstructed by replaying events
//! 4. **Subscribe**: Events are published to subscribers for observability
//!
//! # Thread Safety
//!
//! All implementations must be `Send + Sync` to support concurrent access
//! from multiple runtime threads.

use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

use crate::event_envelope::{AggregateSnapshot, EventFilter, RuntimeEventEnvelope, StreamPosition};
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_wire::SanadIdWire;

/// Synchronous event store used to persist and retrieve event envelopes.
///
/// This trait defines the interface for event sourcing storage. Implementations
/// may use SQLite, PostgreSQL, RocksDB, or any other persistent store.
///
/// # Invariants
///
/// - Events are append-only (no mutations or deletions)
/// - Versions are monotonically increasing per aggregate
/// - `append` must be idempotent for the same event_id
/// - `get_events` returns events in version order
pub trait EventStore: Send + Sync {
    /// Append an event to the store.
    ///
    /// Returns `Err` if the event violates store invariants (e.g., version gap,
    /// duplicate event_id, or aggregate version regression).
    fn append(&self, event: &RuntimeEventEnvelope) -> Result<(), EventStoreError>;

    /// Append multiple events atomically.
    ///
    /// All events must belong to the same aggregate and have contiguous versions.
    /// Returns `Err` if any event is invalid or if the batch cannot be committed.
    fn append_batch(&self, events: &[RuntimeEventEnvelope]) -> Result<(), EventStoreError>;

    /// Get all events for an aggregate, optionally filtered.
    ///
    /// Returns events in version order (ascending).
    fn get_events(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        filter: Option<&EventFilter>,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError>;

    /// Get the latest version for an aggregate.
    ///
    /// Returns `Ok(0)` if no events exist for the aggregate.
    fn get_latest_version(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<u64, EventStoreError>;

    /// Save an aggregate snapshot.
    fn save_snapshot(&self, snapshot: &AggregateSnapshot) -> Result<(), EventStoreError>;

    /// Load the latest snapshot for an aggregate.
    fn load_snapshot(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<AggregateSnapshot>, EventStoreError>;

    /// Delete snapshots older than the given version.
    fn prune_snapshots_before(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        keep_after_version: u64,
    ) -> Result<usize, EventStoreError>;

    /// Get the next events after a given position.
    ///
    /// Used by event processors to resume reading from where they left off.
    fn get_after_position(
        &self,
        position: &StreamPosition,
        limit: usize,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError>;

    /// Update the stream position after processing events.
    fn update_position(&self, position: &StreamPosition) -> Result<(), EventStoreError>;

    /// Get the current stream position for an aggregate.
    fn get_position(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<StreamPosition>, EventStoreError>;

    /// Get all aggregates that have events in the store.
    fn list_aggregates(&self) -> Result<Vec<csv_protocol::sanad::SanadId>, EventStoreError>;

    /// Count the total number of events in the store.
    fn event_count(&self) -> Result<usize, EventStoreError>;

    /// Clear all events and snapshots for an aggregate (used during rollback).
    fn clear_aggregate(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<(), EventStoreError>;
}

/// In-memory event store for non-persistent deployments and tests.
///
/// This implementation stores all events in memory and is suitable for
/// testing, development, and ephemeral deployments where durability
/// is not required.
pub struct InMemoryEventStore {
    /// Events indexed by aggregate ID.
    events: std::sync::Mutex<HashMap<SanadIdWire, Vec<RuntimeEventEnvelope>>>,
    /// Snapshots indexed by aggregate ID.
    snapshots: std::sync::Mutex<HashMap<SanadIdWire, AggregateSnapshot>>,
    /// Stream positions indexed by aggregate ID.
    positions: std::sync::Mutex<HashMap<SanadIdWire, StreamPosition>>,
}

impl InMemoryEventStore {
    /// Create a new in-memory event store.
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(HashMap::new()),
            snapshots: std::sync::Mutex::new(HashMap::new()),
            positions: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Get all events for an aggregate (internal, no locking).
    fn get_events_locked(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        filter: Option<&EventFilter>,
    ) -> Vec<RuntimeEventEnvelope> {
        let Ok(guard) = self.events.lock() else {
            return Vec::new();
        };
        let events = guard.get(aggregate_id).cloned().unwrap_or_default();

        let mut result = events;

        if let Some(f) = filter {
            if let Some(ref event_type) = f.event_type {
                result.retain(|e| &e.event_type == event_type);
            }
            if let Some(min_ver) = f.min_version {
                result.retain(|e| e.version >= min_ver);
            }
            if let Some(max_ver) = f.max_version {
                result.retain(|e| e.version <= max_ver);
            }
            if let Some(limit) = f.limit {
                result.truncate(limit);
            }
        }

        result
    }
}

impl Default for InMemoryEventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore for InMemoryEventStore {
    fn append(&self, event: &RuntimeEventEnvelope) -> Result<(), EventStoreError> {
        let mut guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        let events = guard
            .entry(event.aggregate_id.clone())
            .or_insert_with(Vec::new);

        // Check for duplicate event_id
        if events.iter().any(|e| e.event_id == event.event_id) {
            return Err(EventStoreError::DuplicateEvent(event.event_id));
        }

        // Check version ordering
        let last_version = events.last().map(|e| e.version).unwrap_or(0);
        if event.version <= last_version {
            return Err(EventStoreError::VersionRegression {
                expected_gt: last_version,
                got: event.version,
            });
        }

        events.push(event.clone());
        Ok(())
    }

    fn append_batch(&self, events: &[RuntimeEventEnvelope]) -> Result<(), EventStoreError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        let aggregate_id = &events[0].aggregate_id;
        let store_events = guard.entry(aggregate_id.clone()).or_insert_with(Vec::new);

        // Check all events belong to the same aggregate
        for event in events {
            if &event.aggregate_id != aggregate_id {
                return Err(EventStoreError::BatchError(
                    "all events in batch must belong to the same aggregate".to_string(),
                ));
            }
        }

        // Check version ordering and contiguity
        let last_version = store_events.last().map(|e| e.version).unwrap_or(0);
        for (i, event) in events.iter().enumerate() {
            let expected_version = last_version + i as u64 + 1;
            if event.version != expected_version {
                return Err(EventStoreError::VersionGap {
                    expected: expected_version,
                    got: event.version,
                });
            }
            if store_events.iter().any(|e| e.event_id == event.event_id) {
                return Err(EventStoreError::DuplicateEvent(event.event_id));
            }
        }

        store_events.extend(events.iter().cloned());
        Ok(())
    }

    fn get_events(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        filter: Option<&EventFilter>,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError> {
        Ok(self.get_events_locked(aggregate_id, filter))
    }

    fn get_latest_version(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<u64, EventStoreError> {
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard
            .get(aggregate_id)
            .and_then(|events| events.last())
            .map(|e| e.version)
            .unwrap_or(0))
    }

    fn save_snapshot(&self, snapshot: &AggregateSnapshot) -> Result<(), EventStoreError> {
        let mut guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        guard.insert(snapshot.aggregate_id.clone(), snapshot.clone());
        Ok(())
    }

    fn load_snapshot(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<AggregateSnapshot>, EventStoreError> {
        let guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard.get(aggregate_id).cloned())
    }

    fn prune_snapshots_before(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        keep_after_version: u64,
    ) -> Result<usize, EventStoreError> {
        let guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        let removed = guard
            .get(aggregate_id)
            .filter(|s| s.version < keep_after_version)
            .map(|_| 1)
            .unwrap_or(0);
        Ok(removed)
    }

    fn get_after_position(
        &self,
        position: &StreamPosition,
        limit: usize,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError> {
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        let events = guard
            .get(&position.aggregate_id)
            .cloned()
            .unwrap_or_default();

        let result: Vec<_> = events
            .into_iter()
            .filter(|e| e.version > position.last_version)
            .take(limit)
            .collect();

        Ok(result)
    }

    fn update_position(&self, position: &StreamPosition) -> Result<(), EventStoreError> {
        let mut guard = self
            .positions
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        guard.insert(position.aggregate_id.clone(), position.clone());
        Ok(())
    }

    fn get_position(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<StreamPosition>, EventStoreError> {
        let guard = self
            .positions
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard.get(aggregate_id).cloned())
    }

    fn list_aggregates(&self) -> Result<Vec<csv_protocol::sanad::SanadId>, EventStoreError> {
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard.keys().cloned().collect())
    }

    fn event_count(&self) -> Result<usize, EventStoreError> {
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard.values().map(|v| v.len()).sum())
    }

    fn clear_aggregate(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<(), EventStoreError> {
        let mut events_guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        events_guard.remove(aggregate_id);

        let mut snapshots_guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        snapshots_guard.remove(aggregate_id);

        let mut positions_guard = self
            .positions
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        positions_guard.remove(aggregate_id);

        Ok(())
    }
}

/// RocksDB-backed event store for durability when `persistent` feature is enabled.
#[cfg(feature = "persistent")]
pub struct RocksDbEventStore {
    db: rocksdb::DB,
}

#[cfg(feature = "persistent")]
impl RocksDbEventStore {
    /// Open a RocksDB-backed event store at the given filesystem path.
    pub fn open(path: &str) -> Result<Self, String> {
        let opts = rocksdb::Options::default();
        match rocksdb::DB::open(&opts, path) {
            Ok(db) => Ok(Self { db }),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Key prefix for events.
    const EVENTS_PREFIX: &'static str = "evt:";

    /// Key prefix for snapshots.
    const SNAPSHOTS_PREFIX: &'static str = "snap:";

    /// Key prefix for positions.
    const POSITIONS_PREFIX: &'static str = "pos:";

    /// Build a key for storing an event.
    /// Uses raw bytes for aggregate ID to avoid serde_json dependency.
    fn event_key(aggregate_id: &SanadIdWire, version: u64) -> String {
        format!(
            "{}{}:{:x}",
            Self::EVENTS_PREFIX,
            hex::encode(aggregate_id.bytes.as_bytes()),
            version
        )
    }

    /// Build a key for storing a snapshot.
    fn snapshot_key(aggregate_id: &SanadIdWire) -> String {
        format!(
            "{}{}",
            Self::SNAPSHOTS_PREFIX,
            hex::encode(aggregate_id.bytes.as_bytes())
        )
    }

    /// Build a key for storing a position.
    fn position_key(aggregate_id: &SanadIdWire) -> String {
        format!(
            "{}{}",
            Self::POSITIONS_PREFIX,
            hex::encode(aggregate_id.bytes.as_bytes())
        )
    }
}

#[cfg(feature = "persistent")]
impl EventStore for RocksDbEventStore {
    fn append(&self, event: &RuntimeEventEnvelope) -> Result<(), EventStoreError> {
        let key = Self::event_key(&event.aggregate_id, event.version);
        let value =
            to_canonical_cbor(event).map_err(|e| EventStoreError::Serialization(e.to_string()))?;
        self.db
            .put(key, value)
            .map_err(|e| EventStoreError::Io(e.to_string()))
    }

    fn append_batch(&self, events: &[RuntimeEventEnvelope]) -> Result<(), EventStoreError> {
        if events.is_empty() {
            return Ok(());
        }
        let mut batch = rocksdb::WriteBatch::default();
        for event in events {
            let key = Self::event_key(&event.aggregate_id, event.version);
            let value = to_canonical_cbor(event)
                .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
            batch.put(key, value);
        }
        self.db
            .write(batch)
            .map_err(|e| EventStoreError::Io(e.to_string()))
    }

    fn get_events(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        filter: Option<&EventFilter>,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError> {
        let prefix = format!("{}{:?}:", Self::EVENTS_PREFIX, aggregate_id);
        let mut result = Vec::new();

        for entry in self.db.prefix_iterator(prefix.as_bytes()) {
            let (_, value) = entry.map_err(|e| EventStoreError::Io(e.to_string()))?;
            let event: RuntimeEventEnvelope = from_canonical_cbor(&value)
                .map_err(|e| EventStoreError::Serialization(e.to_string()))?;

            if let Some(f) = filter {
                if let Some(ref event_type) = f.event_type
                    && &event.event_type != event_type
                {
                    continue;
                }
                if let Some(min_ver) = f.min_version
                    && event.version < min_ver
                {
                    continue;
                }
                if let Some(max_ver) = f.max_version
                    && event.version > max_ver
                {
                    continue;
                }
                if let Some(limit) = f.limit
                    && result.len() >= limit
                {
                    break;
                }
            }

            result.push(event);
        }

        Ok(result)
    }

    fn get_latest_version(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<u64, EventStoreError> {
        // Iterate all events for this aggregate and find the max version
        let prefix = format!("{}{:?}:", Self::EVENTS_PREFIX, aggregate_id);
        let mut max_version = 0u64;

        for result in self.db.prefix_iterator(prefix.as_bytes()) {
            let (key, _) = result.map_err(|e| EventStoreError::Io(e.to_string()))?;
            let key_str =
                String::from_utf8(key.to_vec()).map_err(|e| EventStoreError::Io(e.to_string()))?;
            if let Some(ver_str) = key_str.split(':').next_back()
                && let Ok(ver) = ver_str.parse::<u64>()
                && ver > max_version
            {
                max_version = ver;
            }
        }

        Ok(max_version)
    }

    fn save_snapshot(&self, snapshot: &AggregateSnapshot) -> Result<(), EventStoreError> {
        let key = Self::snapshot_key(&snapshot.aggregate_id);
        let value = to_canonical_cbor(snapshot)
            .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
        self.db
            .put(key, value)
            .map_err(|e| EventStoreError::Io(e.to_string()))
    }

    fn load_snapshot(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<AggregateSnapshot>, EventStoreError> {
        let aggregate_id_wire: csv_wire::SanadIdWire = aggregate_id.clone().into();
        let key = Self::snapshot_key(&aggregate_id_wire);
        match self.db.get(key) {
            Ok(Some(value)) => {
                let snapshot: AggregateSnapshot = from_canonical_cbor(&value)
                    .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                Ok(Some(snapshot))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(EventStoreError::Io(e.to_string())),
        }
    }

    fn prune_snapshots_before(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        keep_after_version: u64,
    ) -> Result<usize, EventStoreError> {
        let aggregate_id_wire: csv_wire::SanadIdWire = aggregate_id.clone().into();
        let key = Self::snapshot_key(&aggregate_id_wire);
        match self.db.get(&key) {
            Ok(Some(value)) => {
                let snapshot: AggregateSnapshot = from_canonical_cbor(&value)
                    .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                if snapshot.version < keep_after_version {
                    self.db
                        .delete(&key)
                        .map_err(|e| EventStoreError::Io(e.to_string()))?;
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
            Ok(None) => Ok(0),
            Err(e) => Err(EventStoreError::Io(e.to_string())),
        }
    }

    fn get_after_position(
        &self,
        position: &StreamPosition,
        limit: usize,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError> {
        let prefix = format!("{}{:?}:", Self::EVENTS_PREFIX, position.aggregate_id);
        let mut result = Vec::new();

        for item in self.db.prefix_iterator(prefix.as_bytes()) {
            let (_, value) = item.map_err(|e| EventStoreError::Io(e.to_string()))?;
            let event: RuntimeEventEnvelope = from_canonical_cbor(&value)
                .map_err(|e| EventStoreError::Serialization(e.to_string()))?;

            if event.version > position.last_version {
                result.push(event);
                if result.len() >= limit {
                    break;
                }
            }
        }

        Ok(result)
    }

    fn update_position(&self, position: &StreamPosition) -> Result<(), EventStoreError> {
        let key = Self::position_key(&position.aggregate_id);
        let value = to_canonical_cbor(position)
            .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
        self.db
            .put(key, value)
            .map_err(|e| EventStoreError::Io(e.to_string()))
    }

    fn get_position(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<StreamPosition>, EventStoreError> {
        let aggregate_id_wire: csv_wire::SanadIdWire = aggregate_id.clone().into();
        let key = Self::position_key(&aggregate_id_wire);
        match self.db.get(key) {
            Ok(Some(value)) => {
                let position: StreamPosition = from_canonical_cbor(&value)
                    .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                Ok(Some(position))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(EventStoreError::Io(e.to_string())),
        }
    }

    fn list_aggregates(&self) -> Result<Vec<csv_protocol::sanad::SanadId>, EventStoreError> {
        let mut aggregates = std::collections::HashSet::new();
        let prefix = Self::EVENTS_PREFIX;

        for item in self.db.prefix_iterator(prefix.as_bytes()) {
            let (key, _) = item.map_err(|e| EventStoreError::Io(e.to_string()))?;
            let key_str =
                String::from_utf8(key.to_vec()).map_err(|e| EventStoreError::Io(e.to_string()))?;
            // Extract aggregate ID from key format "evt:{hex_aggregate_id}:version"
            if let Some(rest) = key_str.strip_prefix(prefix)
                && let Some(colon_pos) = rest.find(':')
            {
                let hex_id = &rest[..colon_pos];
                if let Ok(bytes) = hex::decode(hex_id)
                    && bytes.len() == 32
                {
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&bytes);
                    aggregates.insert(csv_protocol::sanad::SanadId::new(array));
                }
            }
        }

        Ok(aggregates.into_iter().collect())
    }

    fn event_count(&self) -> Result<usize, EventStoreError> {
        // Count all events by iterating the prefix
        let mut count = 0;
        for _ in self.db.prefix_iterator(Self::EVENTS_PREFIX.as_bytes()) {
            count += 1;
        }
        Ok(count)
    }

    fn clear_aggregate(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<(), EventStoreError> {
        // Delete all events for this aggregate
        let prefix = format!("{}{:?}:", Self::EVENTS_PREFIX, aggregate_id);
        for item in self.db.prefix_iterator(prefix.as_bytes()) {
            let (key, _) = item.map_err(|e| EventStoreError::Io(e.to_string()))?;
            self.db
                .delete(key)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
        }

        // Delete snapshot
        let aggregate_id_wire: csv_wire::SanadIdWire = aggregate_id.clone().into();
        let snap_key = Self::snapshot_key(&aggregate_id_wire);
        let _ = self.db.delete(snap_key);

        // Delete position
        let aggregate_id_wire: csv_wire::SanadIdWire = aggregate_id.clone().into();
        let pos_key = Self::position_key(&aggregate_id_wire);
        let _ = self.db.delete(pos_key);

        Ok(())
    }
}

/// Error type for event store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStoreError {
    /// Database I/O error.
    Io(String),
    /// Serialization/deserialization error.
    Serialization(String),
    /// Duplicate event ID detected.
    DuplicateEvent(uuid::Uuid),
    /// Event version is not greater than the last version.
    VersionRegression {
        /// The last version in the store.
        expected_gt: u64,
        /// The version of the event being appended.
        got: u64,
    },
    /// Event version does not match the expected contiguous version.
    VersionGap {
        /// The expected version.
        expected: u64,
        /// The actual version.
        got: u64,
    },
    /// Batch error.
    BatchError(String),
    /// Lock acquisition failed.
    LockError(String),
}

impl core::fmt::Display for EventStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "Event store I/O error: {}", msg),
            Self::Serialization(msg) => write!(f, "Event serialization error: {}", msg),
            Self::DuplicateEvent(id) => write!(f, "Duplicate event ID: {}", id),
            Self::VersionRegression { expected_gt, got } => {
                write!(
                    f,
                    "Version regression: expected > {}, got {}",
                    expected_gt, got
                )
            }
            Self::VersionGap { expected, got } => {
                write!(f, "Version gap: expected {}, got {}", expected, got)
            }
            Self::BatchError(msg) => write!(f, "Batch error: {}", msg),
            Self::LockError(msg) => write!(f, "Lock error: {}", msg),
        }
    }
}

impl std::error::Error for EventStoreError {}
