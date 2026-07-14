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
        let wire_id: SanadIdWire = aggregate_id.clone().into();
        let events = guard.get(&wire_id).cloned().unwrap_or_default();

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
        let aggregate_id_wire: SanadIdWire = aggregate_id.clone().into();
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard
            .get(&aggregate_id_wire)
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
        let aggregate_id_wire: SanadIdWire = aggregate_id.clone().into();
        let guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard.get(&aggregate_id_wire).cloned())
    }

    fn prune_snapshots_before(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        keep_after_version: u64,
    ) -> Result<usize, EventStoreError> {
        let aggregate_id_wire: SanadIdWire = aggregate_id.clone().into();
        let guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        let removed = guard
            .get(&aggregate_id_wire)
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
        let aggregate_id_wire: SanadIdWire = position.aggregate_id.clone();
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        let events = guard.get(&aggregate_id_wire).cloned().unwrap_or_default();

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
        let aggregate_id_wire: SanadIdWire = aggregate_id.clone().into();
        let guard = self
            .positions
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        Ok(guard.get(&aggregate_id_wire).cloned())
    }

    fn list_aggregates(&self) -> Result<Vec<csv_protocol::sanad::SanadId>, EventStoreError> {
        let guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        guard
            .keys()
            .map(|w| {
                let wire = w.clone();
                csv_protocol::sanad::SanadId::try_from(wire).map_err(EventStoreError::Serialization)
            })
            .collect::<Result<Vec<_>, _>>()
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
        let wire_id: SanadIdWire = aggregate_id.clone().into();

        let mut events_guard = self
            .events
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        events_guard.remove(&wire_id);

        let mut snapshots_guard = self
            .snapshots
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        snapshots_guard.remove(&wire_id);

        let mut positions_guard = self
            .positions
            .lock()
            .map_err(|e| EventStoreError::LockError(e.to_string()))?;
        positions_guard.remove(&wire_id);

        Ok(())
    }
}

/// Events keyed by (aggregate id bytes, version) so per-aggregate range scans
/// come back in version order.
#[cfg(feature = "persistent")]
const EVENTS_TABLE: redb::TableDefinition<'static, (&'static [u8], u64), &'static [u8]> =
    redb::TableDefinition::new("events");

/// Latest snapshot per aggregate id.
#[cfg(feature = "persistent")]
const SNAPSHOTS_TABLE: redb::TableDefinition<'static, &'static [u8], &'static [u8]> =
    redb::TableDefinition::new("snapshots");

/// Stream position per aggregate id.
#[cfg(feature = "persistent")]
const POSITIONS_TABLE: redb::TableDefinition<'static, &'static [u8], &'static [u8]> =
    redb::TableDefinition::new("positions");

/// redb-backed event store for durability when `persistent` feature is enabled.
#[cfg(feature = "persistent")]
pub struct RedbEventStore {
    db: redb::Database,
}

#[cfg(feature = "persistent")]
impl RedbEventStore {
    /// Open a redb-backed event store at the given file path.
    pub fn open(path: &str) -> Result<Self, String> {
        let db = redb::Database::create(path).map_err(|e| e.to_string())?;
        // Create all tables up front so read transactions never observe a
        // missing table.
        let txn = db.begin_write().map_err(|e| e.to_string())?;
        txn.open_table(EVENTS_TABLE)
            .and_then(|_| txn.open_table(SNAPSHOTS_TABLE))
            .and_then(|_| txn.open_table(POSITIONS_TABLE))
            .map_err(|e| e.to_string())?;
        txn.commit().map_err(|e| e.to_string())?;
        Ok(Self { db })
    }

    fn aggregate_bytes(aggregate_id: &csv_protocol::sanad::SanadId) -> Vec<u8> {
        let wire: csv_wire::SanadIdWire = aggregate_id.clone().into();
        wire.bytes.as_bytes().to_vec()
    }

    fn put(
        &self,
        table: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), EventStoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        {
            let mut t = txn
                .open_table(table)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            t.insert(key, value)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
        }
        txn.commit().map_err(|e| EventStoreError::Io(e.to_string()))
    }

    fn get(
        &self,
        table: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, EventStoreError> {
        use redb::ReadableDatabase;
        let txn = self
            .db
            .begin_read()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let t = txn
            .open_table(table)
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        Ok(t.get(key)
            .map_err(|e| EventStoreError::Io(e.to_string()))?
            .map(|v| v.value().to_vec()))
    }

    /// Scan one aggregate's events in version order, applying `visit` until it
    /// returns `false`.
    fn scan_aggregate_events(
        &self,
        aggregate: &[u8],
        mut visit: impl FnMut(u64, &[u8]) -> Result<bool, EventStoreError>,
    ) -> Result<(), EventStoreError> {
        use redb::ReadableDatabase;
        let txn = self
            .db
            .begin_read()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let t = txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        for item in redb::ReadableTable::range(&t, (aggregate, 0u64)..=(aggregate, u64::MAX))
            .map_err(|e| EventStoreError::Io(e.to_string()))?
        {
            let (key, value) = item.map_err(|e| EventStoreError::Io(e.to_string()))?;
            let (_, version) = key.value();
            if !visit(version, value.value())? {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "persistent")]
impl EventStore for RedbEventStore {
    fn append(&self, event: &RuntimeEventEnvelope) -> Result<(), EventStoreError> {
        self.append_batch(std::slice::from_ref(event))
    }

    fn append_batch(&self, events: &[RuntimeEventEnvelope]) -> Result<(), EventStoreError> {
        if events.is_empty() {
            return Ok(());
        }
        let txn = self
            .db
            .begin_write()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        {
            let mut t = txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            for event in events {
                let value = to_canonical_cbor(event)
                    .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                t.insert(
                    (event.aggregate_id.bytes.as_bytes(), event.version),
                    value.as_slice(),
                )
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            }
        }
        txn.commit().map_err(|e| EventStoreError::Io(e.to_string()))
    }

    fn get_events(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        filter: Option<&EventFilter>,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError> {
        let aggregate = Self::aggregate_bytes(aggregate_id);
        let mut result = Vec::new();

        self.scan_aggregate_events(&aggregate, |_, value| {
            let event: RuntimeEventEnvelope = from_canonical_cbor(value)
                .map_err(|e| EventStoreError::Serialization(e.to_string()))?;

            if let Some(f) = filter {
                if let Some(ref event_type) = f.event_type
                    && &event.event_type != event_type
                {
                    return Ok(true);
                }
                if let Some(min_ver) = f.min_version
                    && event.version < min_ver
                {
                    return Ok(true);
                }
                if let Some(max_ver) = f.max_version
                    && event.version > max_ver
                {
                    return Ok(true);
                }
                if let Some(limit) = f.limit
                    && result.len() >= limit
                {
                    return Ok(false);
                }
            }

            result.push(event);
            Ok(true)
        })?;

        Ok(result)
    }

    fn get_latest_version(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<u64, EventStoreError> {
        use redb::ReadableDatabase;
        let aggregate = Self::aggregate_bytes(aggregate_id);
        let txn = self
            .db
            .begin_read()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let t = txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let last = redb::ReadableTable::range(
            &t,
            (aggregate.as_slice(), 0u64)..=(aggregate.as_slice(), u64::MAX),
        )
        .map_err(|e| EventStoreError::Io(e.to_string()))?
        .next_back()
        .transpose()
        .map_err(|e| EventStoreError::Io(e.to_string()))?;
        Ok(last.map(|(key, _)| key.value().1).unwrap_or(0))
    }

    fn save_snapshot(&self, snapshot: &AggregateSnapshot) -> Result<(), EventStoreError> {
        let value = to_canonical_cbor(snapshot)
            .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
        self.put(
            SNAPSHOTS_TABLE,
            snapshot.aggregate_id.bytes.as_bytes(),
            &value,
        )
    }

    fn load_snapshot(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<AggregateSnapshot>, EventStoreError> {
        let key = Self::aggregate_bytes(aggregate_id);
        match self.get(SNAPSHOTS_TABLE, &key)? {
            Some(value) => {
                let snapshot: AggregateSnapshot = from_canonical_cbor(&value)
                    .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    fn prune_snapshots_before(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        keep_after_version: u64,
    ) -> Result<usize, EventStoreError> {
        use redb::ReadableTable;
        let key = Self::aggregate_bytes(aggregate_id);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let pruned = {
            let mut t = txn
                .open_table(SNAPSHOTS_TABLE)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            let stale = match t
                .get(key.as_slice())
                .map_err(|e| EventStoreError::Io(e.to_string()))?
            {
                Some(value) => {
                    let snapshot: AggregateSnapshot = from_canonical_cbor(value.value())
                        .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                    snapshot.version < keep_after_version
                }
                None => false,
            };
            if stale {
                t.remove(key.as_slice())
                    .map_err(|e| EventStoreError::Io(e.to_string()))?;
                1
            } else {
                0
            }
        };
        txn.commit()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        Ok(pruned)
    }

    fn get_after_position(
        &self,
        position: &StreamPosition,
        limit: usize,
    ) -> Result<Vec<RuntimeEventEnvelope>, EventStoreError> {
        let aggregate = position.aggregate_id.bytes.as_bytes().to_vec();
        let mut result = Vec::new();

        self.scan_aggregate_events(&aggregate, |version, value| {
            if version <= position.last_version {
                return Ok(true);
            }
            let event: RuntimeEventEnvelope = from_canonical_cbor(value)
                .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
            result.push(event);
            Ok(result.len() < limit)
        })?;

        Ok(result)
    }

    fn update_position(&self, position: &StreamPosition) -> Result<(), EventStoreError> {
        let value = to_canonical_cbor(position)
            .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
        self.put(
            POSITIONS_TABLE,
            position.aggregate_id.bytes.as_bytes(),
            &value,
        )
    }

    fn get_position(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<StreamPosition>, EventStoreError> {
        let key = Self::aggregate_bytes(aggregate_id);
        match self.get(POSITIONS_TABLE, &key)? {
            Some(value) => {
                let position: StreamPosition = from_canonical_cbor(&value)
                    .map_err(|e| EventStoreError::Serialization(e.to_string()))?;
                Ok(Some(position))
            }
            None => Ok(None),
        }
    }

    fn list_aggregates(&self) -> Result<Vec<csv_protocol::sanad::SanadId>, EventStoreError> {
        use redb::ReadableDatabase;
        let mut aggregates = std::collections::HashSet::new();
        let txn = self
            .db
            .begin_read()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let t = txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        for item in redb::ReadableTable::range::<(&[u8], u64)>(&t, ..)
            .map_err(|e| EventStoreError::Io(e.to_string()))?
        {
            let (key, _) = item.map_err(|e| EventStoreError::Io(e.to_string()))?;
            let (aggregate, _) = key.value();
            if aggregate.len() == 32 {
                let mut array = [0u8; 32];
                array.copy_from_slice(aggregate);
                aggregates.insert(csv_protocol::sanad::SanadId::new(array));
            }
        }
        Ok(aggregates.into_iter().collect())
    }

    fn event_count(&self) -> Result<usize, EventStoreError> {
        use redb::ReadableDatabase;
        let txn = self
            .db
            .begin_read()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let t = txn
            .open_table(EVENTS_TABLE)
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        let count =
            redb::ReadableTableMetadata::len(&t).map_err(|e| EventStoreError::Io(e.to_string()))?;
        Ok(count as usize)
    }

    fn clear_aggregate(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<(), EventStoreError> {
        let aggregate = Self::aggregate_bytes(aggregate_id);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| EventStoreError::Io(e.to_string()))?;
        {
            let mut events = txn
                .open_table(EVENTS_TABLE)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            let versions: Vec<u64> = redb::ReadableTable::range(
                &events,
                (aggregate.as_slice(), 0u64)..=(aggregate.as_slice(), u64::MAX),
            )
            .map_err(|e| EventStoreError::Io(e.to_string()))?
            .map(|item| {
                item.map(|(key, _)| key.value().1)
                    .map_err(|e| EventStoreError::Io(e.to_string()))
            })
            .collect::<Result<_, _>>()?;
            for version in versions {
                events
                    .remove((aggregate.as_slice(), version))
                    .map_err(|e| EventStoreError::Io(e.to_string()))?;
            }

            let mut snapshots = txn
                .open_table(SNAPSHOTS_TABLE)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            snapshots
                .remove(aggregate.as_slice())
                .map_err(|e| EventStoreError::Io(e.to_string()))?;

            let mut positions = txn
                .open_table(POSITIONS_TABLE)
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
            positions
                .remove(aggregate.as_slice())
                .map_err(|e| EventStoreError::Io(e.to_string()))?;
        }
        txn.commit().map_err(|e| EventStoreError::Io(e.to_string()))
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
