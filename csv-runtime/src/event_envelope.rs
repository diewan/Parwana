//! Durable runtime event envelope with typed payloads.
//!
//! This module defines the event envelope structure used for all runtime events.
//! Each envelope carries metadata for correlation, causation, and ordering.
//!
//! # Event Sourcing Model
//!
//! Events are the sole source of truth for state changes. The runtime:
//! 1. Appends events to a durable store (never mutates or deletes)
//! 2. Replays events to reconstruct aggregate state
//! 3. Emits events to subscribers for observability
//!
//! # Envelope Structure
//!
//! - `event_id`: Unique identifier for this event
//! - `aggregate_id`: The transfer/aggregate this event belongs to
//! - `event_type`: Semantic type of the event (e.g., "TransferLocked")
//! - `version`: Monotonically increasing sequence number per aggregate
//! - `timestamp`: When the event occurred
//! - `payload`: Serialized event data
//! - `causation_id`: ID of the event that caused this event (if any)
//! - `correlation_id`: ID grouping related events across aggregates

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use csv_protocol::sanad::SanadId as TransferId;
use csv_wire::SanadIdWire;

/// Unique event type identifier.
///
/// Event types are stable strings that identify the semantic meaning of an event.
/// They follow the pattern `Domain.Action` (e.g., "Transfer.Locked", "Transfer.Minted").
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventType(pub String);

impl EventType {
    /// Transfer lifecycle events.
    pub const TRANSFER_LOCKED: &'static str = "Transfer.Locked";
    /// Transfer awaiting finality.
    pub const TRANSFER_FINALITY_AWAITED: &'static str = "Transfer.FinalityAwaited";
    /// Transfer proof built.
    pub const TRANSFER_PROOF_BUILT: &'static str = "Transfer.ProofBuilt";
    /// Transfer proof verified.
    pub const TRANSFER_PROOF_VERIFIED: &'static str = "Transfer.ProofVerified";
    /// Transfer minted.
    pub const TRANSFER_MINTED: &'static str = "Transfer.Minted";
    /// Transfer complete.
    pub const TRANSFER_COMPLETE: &'static str = "Transfer.Complete";
    /// Transfer rollback triggered.
    pub const TRANSFER_ROLLBACK_TRIGGERED: &'static str = "Transfer.RollbackTriggered";
    /// Transfer rollback completed.
    pub const TRANSFER_ROLLBACK_COMPLETED: &'static str = "Transfer.RollbackCompleted";
    /// Transfer replay detected.
    pub const TRANSFER_REPLAY_DETECTED: &'static str = "Transfer.ReplayDetected";
    /// Transfer verification downgraded.
    pub const TRANSFER_VERIFICATION_DOWNGRADED: &'static str = "Transfer.VerificationDowngraded";
    /// Settlement evidence recorded after a confirmed destination mint. Keyed for
    /// a later source-chain escrow release (TRM-ESCROW-001); this is auditable
    /// evidence, not release authority.
    pub const TRANSFER_SETTLEMENT_RECORDED: &'static str = "Transfer.SettlementRecorded";
    /// Source-chain escrow released to the operator on a verifier-signed settlement
    /// receipt (RFC-0012 §10 / TRM-ESCROW-001). DISTINCT from a destination mint
    /// (`Transfer.Minted`) and from settlement evidence; this is the terminal
    /// source-side payout and the runtime's one-release-per-`lock_event_id` guard.
    pub const TRANSFER_SETTLEMENT_RELEASED: &'static str = "Transfer.SettlementReleased";
    /// Source-chain escrow refunded to the original locker after the destination
    /// mint failed to occur within the escrow timeout (RFC-0012 §10 failure
    /// handling). Mutually exclusive with `Transfer.SettlementReleased`.
    pub const TRANSFER_SETTLEMENT_REFUNDED: &'static str = "Transfer.SettlementRefunded";

    /// Lease management events.
    pub const LEASE_ACQUIRED: &'static str = "Lease.Acquired";
    /// Lease released.
    pub const LEASE_RELEASED: &'static str = "Lease.Released";
    /// Lease expired.
    pub const LEASE_EXPIRED: &'static str = "Lease.Expired";
    /// Lease renewed.
    pub const LEASE_RENEWED: &'static str = "Lease.Renewed";

    /// Finality events.
    pub const FINALITY_ANCHORED: &'static str = "Finality.Anchored";
    /// Finality reorg detected.
    pub const FINALITY_REORG_DETECTED: &'static str = "Finality.ReorgDetected";
    /// Finality stale.
    pub const FINALITY_STALE: &'static str = "Finality.Stale";

    /// Reorg detection events.
    pub const REORG_DETECTED: &'static str = "Reorg.Detected";
    /// Reorg handled.
    pub const REORG_HANDLED: &'static str = "Reorg.Handled";

    /// Create an EventType from a static string.
    pub fn from_static(s: &'static str) -> Self {
        Self(s.to_string())
    }

    /// Query these event types as strings.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for EventType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A durable event envelope for event sourcing.
///
/// This is the core type in the event sourcing system. Every state change
/// in the runtime is represented as an event appended to a store.
///
/// # Invariants
///
/// - `version` must be monotonically increasing per aggregate
/// - `timestamp` must be after `causation_id` event's timestamp (if set)
/// - Events are immutable once persisted
/// - Events are never deleted or modified (append-only)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RuntimeEventEnvelope {
    /// Unique event identifier.
    pub event_id: Uuid,
    /// The aggregate (transfer) this event belongs to.
    pub aggregate_id: SanadIdWire,
    /// Semantic type of this event.
    pub event_type: EventType,
    /// Monotonically increasing version within the aggregate.
    pub version: u64,
    /// Optional causation event id (event that caused this one).
    pub causation_id: Option<Uuid>,
    /// Correlation id for grouping related events across aggregates.
    pub correlation_id: Uuid,
    /// Serialized event payload (JSON).
    pub payload: String,
    /// Timestamp when the event occurred.
    pub timestamp: SystemTime,
    /// Runtime instance that generated the event.
    pub runtime_id: Uuid,
}

impl RuntimeEventEnvelope {
    /// Create a new event envelope.
    ///
    /// # Arguments
    ///
    /// * `aggregate_id` - The transfer/aggregate this event belongs to
    /// * `event_type` - The semantic type of the event
    /// * `version` - The version number within the aggregate
    /// * `payload` - Serialized event data as JSON string
    /// * `causation_id` - Optional ID of the causative event
    /// * `correlation_id` - ID grouping related events
    /// * `runtime_id` - The runtime instance generating this event
    /// * `timestamp` - When the event occurred
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        aggregate_id: SanadIdWire,
        event_type: EventType,
        version: u64,
        payload: String,
        causation_id: Option<Uuid>,
        correlation_id: Uuid,
        runtime_id: Uuid,
        timestamp: SystemTime,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            aggregate_id,
            event_type,
            version,
            causation_id,
            correlation_id,
            payload,
            timestamp,
            runtime_id,
        }
    }

    /// Create a new event envelope with a generated correlation ID.
    pub fn new_with_auto_correlation(
        aggregate_id: SanadIdWire,
        event_type: EventType,
        version: u64,
        payload: String,
        causation_id: Option<Uuid>,
        runtime_id: Uuid,
        timestamp: SystemTime,
    ) -> Self {
        Self::new(
            aggregate_id,
            event_type,
            version,
            payload,
            causation_id,
            Uuid::new_v4(),
            runtime_id,
            timestamp,
        )
    }

    /// Get the event type as a string.
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Get the aggregate ID.
    pub fn aggregate_id(&self) -> &SanadIdWire {
        &self.aggregate_id
    }

    /// Get the version number.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Get the correlation ID.
    pub fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    /// Get the event ID.
    pub fn event_id(&self) -> Uuid {
        self.event_id
    }

    /// Get the payload as a string slice.
    pub fn payload(&self) -> &str {
        &self.payload
    }
}

/// Event stream position for replay.
///
/// Used to track where in an event stream a consumer is reading.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPosition {
    /// The aggregate this position belongs to.
    pub aggregate_id: SanadIdWire,
    /// The last consumed version number.
    pub last_version: u64,
    /// The event ID of the last consumed event.
    pub last_event_id: Option<Uuid>,
    /// When this position was last updated.
    pub updated_at: SystemTime,
}

impl StreamPosition {
    /// Create a new stream position.
    pub fn new(aggregate_id: SanadIdWire, last_version: u64) -> Self {
        Self {
            aggregate_id,
            last_version,
            last_event_id: None,
            updated_at: SystemTime::now(),
        }
    }

    /// Advance the position to the given version.
    pub fn advance(&mut self, version: u64, event_id: Uuid) {
        self.last_version = version;
        self.last_event_id = Some(event_id);
        self.updated_at = SystemTime::now();
    }

    /// Check if this position is before the given version.
    pub fn is_before(&self, version: u64) -> bool {
        self.last_version < version
    }
}

/// Event filtering criteria for querying streams.
#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    /// Filter by aggregate ID.
    pub aggregate_id: Option<TransferId>,
    /// Filter by event type.
    pub event_type: Option<EventType>,
    /// Filter by correlation ID.
    pub correlation_id: Option<Uuid>,
    /// Minimum version to include.
    pub min_version: Option<u64>,
    /// Maximum version to include.
    pub max_version: Option<u64>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
}

impl EventFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by aggregate ID.
    pub fn for_aggregate(mut self, aggregate_id: TransferId) -> Self {
        self.aggregate_id = Some(aggregate_id);
        self
    }

    /// Filter by event type.
    pub fn of_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    /// Filter by correlation ID.
    pub fn with_correlation(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set minimum version.
    pub fn from_version(mut self, min_version: u64) -> Self {
        self.min_version = Some(min_version);
        self
    }

    /// Set maximum version.
    pub fn up_to_version(mut self, max_version: u64) -> Self {
        self.max_version = Some(max_version);
        self
    }

    /// Set result limit.
    pub fn limit_to(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Snapshot of an aggregate's state at a given version.
///
/// Snapshots are optional performance optimizations that allow replaying
/// fewer events. The runtime can load the snapshot and then replay only
/// events after the snapshot version.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AggregateSnapshot {
    /// The aggregate this snapshot belongs to.
    pub aggregate_id: SanadIdWire,
    /// The version this snapshot represents.
    pub version: u64,
    /// Serialized aggregate state (JSON).
    pub state: String,
    /// When the snapshot was created.
    pub created_at: SystemTime,
}

impl AggregateSnapshot {
    /// Create a new aggregate snapshot.
    pub fn new(aggregate_id: SanadIdWire, version: u64, state: String) -> Self {
        Self {
            aggregate_id,
            version,
            state,
            created_at: SystemTime::now(),
        }
    }
}
