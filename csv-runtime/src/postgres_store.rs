//! PostgreSQL-backed storage for runtime coordination.
//!
//! This module provides PostgreSQL implementations for runtime coordination
//! components that require distributed consistency, including:
//! - Transfer lease coordination with FOR UPDATE SKIP LOCKED
//! - Durable event sourcing with versioned event streams
//! - Replay registry with atomic operations
//!
//! SQLite is no longer acceptable for runtime coordination in production.

#[cfg(feature = "postgres")]
use sqlx::postgres::PgPoolOptions;
#[cfg(feature = "postgres")]
use sqlx::{PgPool, Row};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::event_envelope::{AggregateSnapshot, EventFilter, RuntimeEventEnvelope, StreamPosition};
use crate::user_runtime_lease::TransferLease;
use crate::replay_record::GlobalReplayRecord;
use csv_protocol::sanad::SanadId;
use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use uuid::Uuid;

/// PostgreSQL-backed lease coordination store.
#[cfg(feature = "postgres")]
pub struct PostgresLeaseStore {
    pool: PgPool,
}

#[cfg(feature = "postgres")]
impl PostgresLeaseStore {
    /// Create a new PostgreSQL lease store.
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        // Run migrations to create tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS transfer_leases (
                transfer_id BYTEA PRIMARY KEY,
                epoch BIGINT NOT NULL,
                owner_runtime_id UUID NOT NULL,
                acquired_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_transfer_leases_expires_at ON transfer_leases(expires_at);
            "#,
        )
        .execute(&pool)
        .await?;

        let pool_for_struct = pool.clone();
        Ok(Self { pool: pool_for_struct })
    }

    /// Acquire a lease for a transfer using FOR UPDATE SKIP LOCKED.
    ///
    /// This provides distributed lease coordination across multiple runtime instances.
    pub async fn acquire_lease(
        &self,
        transfer_id: SanadId,
        runtime_id: Uuid,
        ttl_secs: u64,
    ) -> Result<TransferLease, sqlx::Error> {
        let now = SystemTime::now();
        let expires_at = now
            .checked_add(std::time::Duration::from_secs(ttl_secs))
            .unwrap_or(now);

        // Convert SystemTime to i64 timestamp for PostgreSQL
        let acquired_ts = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let expires_ts = expires_at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

        // Try to acquire lease with FOR UPDATE SKIP LOCKED
        let result = sqlx::query(
            r#"
            INSERT INTO transfer_leases (transfer_id, epoch, owner_runtime_id, acquired_at, expires_at)
            VALUES ($1, 1, $2, to_timestamp($3), to_timestamp($4))
            ON CONFLICT (transfer_id) DO NOTHING
            RETURNING transfer_id, epoch, owner_runtime_id, acquired_at, expires_at
            "#,
        )
        .bind(transfer_id.as_bytes())
        .bind(runtime_id)
        .bind(acquired_ts)
        .bind(expires_ts)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(row) => {
                // Lease acquired successfully
                Ok(TransferLease {
                    transfer_id: SanadId::new(row.get("transfer_id")),
                    epoch: row.get::<i64, _>("epoch") as u64,
                    owner_runtime_id: row.get("owner_runtime_id"),
                    acquired_at: UNIX_EPOCH + std::time::Duration::from_secs(row.get::<chrono::DateTime<chrono::Utc>, _>("acquired_at").timestamp() as u64),
                    expires_at: UNIX_EPOCH + std::time::Duration::from_secs(row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at").timestamp() as u64),
                })
            }
            None => {
                // Lease already exists, try to acquire with SKIP LOCKED
                let row = sqlx::query(
                    r#"
                    SELECT transfer_id, epoch, owner_runtime_id, acquired_at, expires_at
                    FROM transfer_leases
                    WHERE transfer_id = $1 AND expires_at > NOW()
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                    "#,
                )
                .bind(transfer_id.as_bytes())
                .fetch_one(&self.pool)
                .await?;

                // Check if we own this lease
                let owner: Uuid = row.get("owner_runtime_id");
                if owner == runtime_id {
                    Ok(TransferLease {
                        transfer_id: SanadId::new(row.get("transfer_id")),
                        epoch: row.get::<i64, _>("epoch") as u64,
                        owner_runtime_id: row.get("owner_runtime_id"),
                        acquired_at: UNIX_EPOCH + std::time::Duration::from_secs(row.get::<chrono::DateTime<chrono::Utc>, _>("acquired_at").timestamp() as u64),
                        expires_at: UNIX_EPOCH + std::time::Duration::from_secs(row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at").timestamp() as u64),
                    })
                } else {
                    Err(sqlx::Error::RowNotFound)
                }
            }
        }
    }

    /// Renew an existing lease.
    pub async fn renew_lease(
        &self,
        transfer_id: SanadId,
        runtime_id: Uuid,
        ttl_secs: u64,
    ) -> Result<TransferLease, sqlx::Error> {
        let expires_at = SystemTime::now()
            .checked_add(std::time::Duration::from_secs(ttl_secs))
            .unwrap_or(SystemTime::now());
        let expires_ts = expires_at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;

        sqlx::query(
            r#"
            UPDATE transfer_leases
            SET expires_at = to_timestamp($1), epoch = epoch + 1
            WHERE transfer_id = $2 AND owner_runtime_id = $3
            RETURNING transfer_id, epoch, owner_runtime_id, acquired_at, expires_at
            "#,
        )
        .bind(expires_ts)
        .bind(transfer_id.as_bytes())
        .bind(runtime_id)
        .fetch_one(&self.pool)
        .await
        .map(|row| TransferLease {
            transfer_id: SanadId::new(row.get("transfer_id")),
            epoch: row.get::<i64, _>("epoch") as u64,
            owner_runtime_id: row.get("owner_runtime_id"),
            acquired_at: UNIX_EPOCH + std::time::Duration::from_secs(row.get::<chrono::DateTime<chrono::Utc>, _>("acquired_at").timestamp() as u64),
            expires_at: UNIX_EPOCH + std::time::Duration::from_secs(row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at").timestamp() as u64),
        })
    }

    /// Release a lease.
    pub async fn release_lease(
        &self,
        transfer_id: SanadId,
        runtime_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM transfer_leases
            WHERE transfer_id = $1 AND owner_runtime_id = $2
            "#,
        )
        .bind(transfer_id.as_bytes())
        .bind(runtime_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// PostgreSQL-backed event store for durable event sourcing.
///
/// Implements the `EventStore` trait for PostgreSQL-backed persistence.
/// Events are stored with version ordering and can be queried with filters.
#[cfg(feature = "postgres")]
pub struct PostgresEventStore {
    pool: PgPool,
}

#[cfg(feature = "postgres")]
impl PostgresEventStore {
    /// Create a new PostgreSQL event store.
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        // Create events table with versioned event sourcing schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_events (
                event_id UUID PRIMARY KEY,
                aggregate_id BYTEA NOT NULL,
                event_type TEXT NOT NULL,
                version BIGINT NOT NULL,
                causation_id UUID,
                correlation_id UUID NOT NULL,
                payload TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                runtime_id UUID NOT NULL,
                CONSTRAINT uq_aggregate_version UNIQUE (aggregate_id, version)
            );

            CREATE INDEX IF NOT EXISTS idx_runtime_events_aggregate_id ON runtime_events(aggregate_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_correlation_id ON runtime_events(correlation_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_timestamp ON runtime_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_aggregate_version ON runtime_events(aggregate_id, version);
            "#,
        )
        .execute(&pool)
        .await?;

        // Create snapshots table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS aggregate_snapshots (
                aggregate_id BYTEA PRIMARY KEY,
                version BIGINT NOT NULL,
                state TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;

        // Create positions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS stream_positions (
                aggregate_id BYTEA PRIMARY KEY,
                last_version BIGINT NOT NULL,
                last_event_id UUID,
                updated_at TIMESTAMPTZ NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;

        let pool_for_struct = pool.clone();
        Ok(Self { pool: pool_for_struct })
    }

    /// Build the aggregate ID key for database queries.
    fn aggregate_key(&self, aggregate_id: &csv_protocol::sanad::SanadId) -> Vec<u8> {
        aggregate_id.as_bytes().to_vec()
    }
}

/// Async wrapper for PostgresEventStore that provides proper async EventStore implementation.
#[cfg(feature = "postgres")]
pub struct AsyncPostgresEventStore {
    pool: PgPool,
}

#[cfg(feature = "postgres")]
impl AsyncPostgresEventStore {
    /// Create a new async PostgreSQL event store.
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        // Create events table with versioned event sourcing schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS runtime_events (
                event_id UUID PRIMARY KEY,
                aggregate_id BYTEA NOT NULL,
                event_type TEXT NOT NULL,
                version BIGINT NOT NULL,
                causation_id UUID,
                correlation_id UUID NOT NULL,
                payload TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                runtime_id UUID NOT NULL,
                CONSTRAINT uq_aggregate_version UNIQUE (aggregate_id, version)
            );

            CREATE INDEX IF NOT EXISTS idx_runtime_events_aggregate_id ON runtime_events(aggregate_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_correlation_id ON runtime_events(correlation_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_timestamp ON runtime_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_runtime_events_aggregate_version ON runtime_events(aggregate_id, version);
            "#,
        )
        .execute(&pool)
        .await?;

        // Create snapshots table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS aggregate_snapshots (
                aggregate_id BYTEA PRIMARY KEY,
                version BIGINT NOT NULL,
                state TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;

        // Create positions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS stream_positions (
                aggregate_id BYTEA PRIMARY KEY,
                last_version BIGINT NOT NULL,
                last_event_id UUID,
                updated_at TIMESTAMPTZ NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    /// Append an event to the store.
    pub async fn append(&self, event: &RuntimeEventEnvelope) -> Result<(), crate::event_persistence::EventStoreError> {
        sqlx::query(
            r#"
            INSERT INTO runtime_events (event_id, aggregate_id, event_type, version, causation_id, correlation_id, payload, timestamp, runtime_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(event.event_id)
        .bind(event.aggregate_id.as_bytes())
        .bind(event.event_type.as_str())
        .bind(event.version as i64)
        .bind(event.causation_id)
        .bind(event.correlation_id)
        .bind(&event.payload)
        .bind(chrono::DateTime::<chrono::Utc>::from(event.timestamp))
        .bind(event.runtime_id)
        .execute(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        Ok(())
    }

    /// Append multiple events atomically.
    pub async fn append_batch(
        &self,
        events: &[RuntimeEventEnvelope],
    ) -> Result<(), crate::event_persistence::EventStoreError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await.map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        for event in events {
            sqlx::query(
                r#"
                INSERT INTO runtime_events (event_id, aggregate_id, event_type, version, causation_id, correlation_id, payload, timestamp, runtime_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(event.event_id)
            .bind(event.aggregate_id.as_bytes())
            .bind(event.event_type.as_str())
            .bind(event.version as i64)
            .bind(event.causation_id)
            .bind(event.correlation_id)
            .bind(&event.payload)
            .bind(chrono::DateTime::<chrono::Utc>::from(event.timestamp))
            .bind(event.runtime_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;
        }

        tx.commit().await.map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;
        Ok(())
    }

    /// Get all events for an aggregate, optionally filtered.
    pub async fn get_events(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        filter: Option<&EventFilter>,
    ) -> Result<Vec<RuntimeEventEnvelope>, crate::event_persistence::EventStoreError> {
        let mut query = sqlx::query_as::<_, (Uuid, Vec<u8>, String, i64, Option<Uuid>, Uuid, String, chrono::DateTime<chrono::Utc>, Uuid)>(
            r#"
            SELECT event_id, aggregate_id, event_type, version, causation_id, correlation_id, payload, timestamp, runtime_id
            FROM runtime_events
            WHERE aggregate_id = $1
            "#,
        )
        .bind(aggregate_id.as_bytes());

        if let Some(f) = filter {
            if let Some(ref event_type) = f.event_type {
                query = query.bind(event_type.as_str());
            }
            if let Some(min_ver) = f.min_version {
                query = query.bind(min_ver as i64);
            }
            if let Some(max_ver) = f.max_version {
                query = query.bind(max_ver as i64);
            }
        }

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        let events: Result<Vec<_>, _> = rows
            .into_iter()
            .map(|row| {
                Ok(RuntimeEventEnvelope {
                    event_id: row.0,
                    aggregate_id: SanadId::new(row.1.try_into().map_err(|_| crate::event_persistence::EventStoreError::Io("Invalid aggregate_id length".to_string()))?),
                    event_type: crate::event_envelope::EventType(row.2),
                    version: row.3 as u64,
                    causation_id: row.4,
                    correlation_id: row.5,
                    payload: row.6,
                    timestamp: row.7.into(),
                    runtime_id: row.8,
                })
            })
            .collect();

        events
    }

    /// Get the latest version for an aggregate.
    pub async fn get_latest_version(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<u64, crate::event_persistence::EventStoreError> {
        let version: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT MAX(version) FROM runtime_events WHERE aggregate_id = $1
            "#,
        )
        .bind(aggregate_id.as_bytes())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        Ok(version.unwrap_or(0) as u64)
    }

    /// Save an aggregate snapshot.
    pub async fn save_snapshot(&self, snapshot: &AggregateSnapshot) -> Result<(), crate::event_persistence::EventStoreError> {
        sqlx::query(
            r#"
            INSERT INTO aggregate_snapshots (aggregate_id, version, state, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (aggregate_id) DO UPDATE SET version = $2, state = $3, created_at = $4
            "#,
        )
        .bind(snapshot.aggregate_id.as_bytes())
        .bind(snapshot.version as i64)
        .bind(&snapshot.state)
        .bind(chrono::DateTime::<chrono::Utc>::from(snapshot.created_at))
        .execute(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        Ok(())
    }

    /// Load the latest snapshot for an aggregate.
    pub async fn load_snapshot(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<AggregateSnapshot>, crate::event_persistence::EventStoreError> {
        let row: Option<(Vec<u8>, i64, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            r#"
            SELECT aggregate_id, version, state, created_at FROM aggregate_snapshots WHERE aggregate_id = $1
            "#,
        )
        .bind(aggregate_id.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        match row {
            Some((agg_id, version, state, created_at)) => {
                Ok(Some(AggregateSnapshot {
                    aggregate_id: SanadId::new(agg_id.try_into().map_err(|_| crate::event_persistence::EventStoreError::Io("Invalid aggregate_id length".to_string()))?),
                    version: version as u64,
                    state,
                    created_at: created_at.into(),
                }))
            }
            None => Ok(None),
        }
    }

    /// Delete snapshots older than the given version.
    pub async fn prune_snapshots_before(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
        keep_after_version: u64,
    ) -> Result<usize, crate::event_persistence::EventStoreError> {
        let result = sqlx::query(
            r#"
            DELETE FROM aggregate_snapshots WHERE aggregate_id = $1 AND version < $2
            "#,
        )
        .bind(aggregate_id.as_bytes())
        .bind(keep_after_version as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }

    /// Get the next events after a given position.
    pub async fn get_after_position(
        &self,
        position: &StreamPosition,
        limit: usize,
    ) -> Result<Vec<RuntimeEventEnvelope>, crate::event_persistence::EventStoreError> {
        let rows = sqlx::query_as::<_, (Uuid, Vec<u8>, String, i64, Option<Uuid>, Uuid, String, chrono::DateTime<chrono::Utc>, Uuid)>(
            r#"
            SELECT event_id, aggregate_id, event_type, version, causation_id, correlation_id, payload, timestamp, runtime_id
            FROM runtime_events
            WHERE aggregate_id = $1 AND version > $2
            ORDER BY version ASC
            LIMIT $3
            "#,
        )
        .bind(position.aggregate_id.as_bytes())
        .bind(position.last_version as i64)
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        let events: Result<Vec<_>, _> = rows
            .into_iter()
            .map(|row| {
                Ok(RuntimeEventEnvelope {
                    event_id: row.0,
                    aggregate_id: SanadId::new(row.1.try_into().map_err(|_| crate::event_persistence::EventStoreError::Io("Invalid aggregate_id length".to_string()))?),
                    event_type: crate::event_envelope::EventType(row.2),
                    version: row.3 as u64,
                    causation_id: row.4,
                    correlation_id: row.5,
                    payload: row.6,
                    timestamp: row.7.into(),
                    runtime_id: row.8,
                })
            })
            .collect();

        events
    }

    /// Update the stream position after processing events.
    pub async fn update_position(&self, position: &StreamPosition) -> Result<(), crate::event_persistence::EventStoreError> {
        sqlx::query(
            r#"
            INSERT INTO stream_positions (aggregate_id, last_version, last_event_id, updated_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (aggregate_id) DO UPDATE SET last_version = $2, last_event_id = $3, updated_at = $4
            "#,
        )
        .bind(position.aggregate_id.as_bytes())
        .bind(position.last_version as i64)
        .bind(position.last_event_id)
        .bind(chrono::DateTime::<chrono::Utc>::from(position.updated_at))
        .execute(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        Ok(())
    }

    /// Get the current stream position for an aggregate.
    pub async fn get_position(
        &self,
        aggregate_id: &csv_protocol::sanad::SanadId,
    ) -> Result<Option<StreamPosition>, crate::event_persistence::EventStoreError> {
        let row: Option<(Vec<u8>, i64, Option<Uuid>, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            r#"
            SELECT aggregate_id, last_version, last_event_id, updated_at FROM stream_positions WHERE aggregate_id = $1
            "#,
        )
        .bind(aggregate_id.as_bytes())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        match row {
            Some((agg_id, last_version, last_event_id, updated_at)) => {
                Ok(Some(StreamPosition {
                    aggregate_id: SanadId::new(agg_id.try_into().map_err(|_| crate::event_persistence::EventStoreError::Io("Invalid aggregate_id length".to_string()))?),
                    last_version: last_version as u64,
                    last_event_id,
                    updated_at: updated_at.into(),
                }))
            }
            None => Ok(None),
        }
    }

    /// Get all aggregates that have events in the store.
    pub async fn list_aggregates(&self) -> Result<Vec<csv_protocol::sanad::SanadId>, crate::event_persistence::EventStoreError> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT aggregate_id FROM runtime_events ORDER BY aggregate_id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        let aggregates: Result<Vec<_>, _> = rows
            .into_iter()
            .map(|agg_id| {
                Ok(SanadId::new(agg_id.try_into().map_err(|_| crate::event_persistence::EventStoreError::Io("Invalid aggregate_id length".to_string()))?))
            })
            .collect();

        aggregates
    }

    /// Count the total number of events in the store.
    pub async fn event_count(&self) -> Result<usize, crate::event_persistence::EventStoreError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM runtime_events
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        Ok(count as usize)
    }

    /// Clear all events and snapshots for an aggregate.
    pub async fn clear_aggregate(&self, aggregate_id: &csv_protocol::sanad::SanadId) -> Result<(), crate::event_persistence::EventStoreError> {
        let mut tx = self.pool.begin().await.map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        sqlx::query("DELETE FROM runtime_events WHERE aggregate_id = $1")
            .bind(aggregate_id.as_bytes())
            .execute(&mut *tx)
            .await
            .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        sqlx::query("DELETE FROM aggregate_snapshots WHERE aggregate_id = $1")
            .bind(aggregate_id.as_bytes())
            .execute(&mut *tx)
            .await
            .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        sqlx::query("DELETE FROM stream_positions WHERE aggregate_id = $1")
            .bind(aggregate_id.as_bytes())
            .execute(&mut *tx)
            .await
            .map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;

        tx.commit().await.map_err(|e| crate::event_persistence::EventStoreError::Io(e.to_string()))?;
        Ok(())
    }
}
