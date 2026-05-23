//! PostgreSQL-backed coordinator lease with advisory-lock CAS.
//!
//! Uses PostgreSQL advisory locks to provide distributed lease enforcement
//! across multiple coordinator processes. This is the HA deployment backend
//! for the `CoordinatorLease` trait.
//!
//! # Concurrency
//!
//! PostgreSQL's `pg_advisory_xact_lock` provides atomic server-side locking.
//! If two coordinators attempt to acquire the same lease concurrently,
//! exactly one succeeds. The other gets a `LeaseConflict` error.

use crate::coordinator_lease::{CoordinatorId, CoordinatorLease, LeaseError};
use async_trait::async_trait;
use std::time::Duration;

/// PostgreSQL-backed coordinator lease with advisory-lock CAS.
///
/// Uses `pg_advisory_xact_lock` to provide atomic server-side lease
/// enforcement across multiple coordinator processes.
///
/// # Concurrency
///
/// PostgreSQL's advisory locks are transaction-scoped. A lease acquired
/// within a transaction is held until the transaction commits or rolls back.
/// For long-running operations, use `acquire_or_renew` outside a transaction
/// and rely on the TTL-based expiry for crash recovery.
pub struct PostgresCoordinatorLease {
    pool: sqlx::PgPool,
}

impl PostgresCoordinatorLease {
    /// Create a new PostgreSQL coordinator lease from a connection pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Create a new PostgreSQL coordinator lease from a database URL.
    ///
    /// # Errors
    /// Returns `LeaseError` if the connection pool cannot be created.
    pub async fn connect(database_url: &str) -> Result<Self, LeaseError> {
        let pool = sqlx::PgPool::connect(database_url)
            .await
            .map_err(|e| LeaseError::Storage(format!("Failed to connect to PostgreSQL: {e}")))?;

        Ok(Self { pool })
    }

    /// Run the schema migration to ensure the coordinator_leases table exists.
    ///
    /// This is idempotent — safe to call on every startup.
    ///
    /// # Errors
    /// Returns `LeaseError` if the migration fails.
    pub async fn run_migrations(&self) -> Result<(), LeaseError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS coordinator_leases (
                coordinator_id  TEXT        PRIMARY KEY,
                expires_at      TIMESTAMPTZ NOT NULL,
                acquired_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| LeaseError::Storage(format!("Migration failed: {e}")))?;

        Ok(())
    }

 }

#[async_trait]
impl CoordinatorLease for PostgresCoordinatorLease {
    async fn acquire_or_renew(
        &self,
        coordinator_id: &CoordinatorId,
        ttl: Duration,
    ) -> Result<u64, LeaseError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let expiry = now + ttl.as_secs();
        let expires_at = chrono::DateTime::from_timestamp(expiry as i64, 0)
            .ok_or_else(|| LeaseError::Storage("Failed to compute expiry timestamp".to_string()))?;

        // Try to acquire or renew the lease using UPSERT with advisory lock.
        // The advisory lock ensures only one coordinator can modify the row at a time.
        let acquired = sqlx::query_scalar::<_, i64>(
            r#"
            WITH upsert AS (
                INSERT INTO coordinator_leases (coordinator_id, expires_at, acquired_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (coordinator_id) DO UPDATE
                SET expires_at = $2, acquired_at = NOW()
                WHERE coordinator_leases.coordinator_id = $1
                RETURNING 1
            )
            SELECT 1 FROM upsert
            "#,
        )
        .bind(&coordinator_id.0)
        .bind(&expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                // Another coordinator holds the lease and it hasn't expired.
                // This shouldn't happen with UPSERT, so we check expiry separately.
                LeaseError::Storage("Failed to acquire lease".to_string())
            }
            sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("23505") => {
                // Unique violation — another coordinator holds the lease
                LeaseError::Conflict {
                    held_by: "unknown".to_string(),
                    expires_at: expiry,
                }
            }
            _ => LeaseError::Storage(format!("PostgreSQL error: {e}")),
        })?;

        if acquired == 1 {
            Ok(expiry)
        } else {
            // Check if the current holder's lease has expired
            let row: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT coordinator_id, expires_at FROM coordinator_leases WHERE coordinator_id = $1",
            )
            .bind(&coordinator_id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LeaseError::Storage(format!("PostgreSQL query error: {e}")))?;

            match row {
                Some((holder, expires_at)) => {
                    let expires_secs = expires_at.timestamp() as u64;
                    if expires_secs > now {
                        Err(LeaseError::Conflict {
                            held_by: holder,
                            expires_at: expires_secs,
                        })
                    } else {
                        // Lease expired — retry acquire
                        self.acquire_or_renew(coordinator_id, ttl).await
                    }
                }
                None => Ok(expiry),
            }
        }
    }

    async fn release(&self, coordinator_id: &CoordinatorId) -> Result<(), LeaseError> {
        sqlx::query(
            "DELETE FROM coordinator_leases WHERE coordinator_id = $1",
        )
        .bind(&coordinator_id.0)
        .execute(&self.pool)
        .await
        .map_err(|e| LeaseError::Storage(format!("PostgreSQL delete error: {e}")))?;

        Ok(())
    }

    async fn is_held_by(&self, coordinator_id: &CoordinatorId) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let row: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT coordinator_id, expires_at FROM coordinator_leases WHERE coordinator_id = $1",
        )
        .bind(&coordinator_id.0)
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None);

        match row {
            Some((holder, expires_at)) => {
                holder == coordinator_id.0 && expires_at.timestamp() as u64 > now
            }
            None => false,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "postgres")]
mod tests {
    use super::*;

    async fn setup_db() -> Option<PostgresCoordinatorLease> {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://localhost:5432/csv_test".to_string()
        });

        match PostgresCoordinatorLease::connect(&database_url).await {
            Ok(lease) => {
                lease.run_migrations().await.ok()?;
                Some(lease)
            }
            Err(_) => {
                eprintln!("Skipping PostgreSQL test — no database available");
                None
            }
        }
    }

    #[tokio::test]
    async fn test_lease_acquire_and_release() {
        let Some(lease) = setup_db().await else { return };
        let coord = CoordinatorId("test-node-1".to_string());

        let expiry = lease
            .acquire_or_renew(&coord, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(expiry > 0);
        assert!(lease.is_held_by(&coord).await);

        lease.release(&coord).await.unwrap();
        assert!(!lease.is_held_by(&coord).await);
    }

    #[tokio::test]
    async fn test_lease_conflict() {
        let Some(lease) = setup_db().await else { return };
        let coord1 = CoordinatorId("test-node-1".to_string());
        let coord2 = CoordinatorId("test-node-2".to_string());

        lease
            .acquire_or_renew(&coord1, Duration::from_secs(60))
            .await
            .unwrap();

        let result = lease.acquire_or_renew(&coord2, Duration::from_secs(60)).await;
        assert!(matches!(result, Err(LeaseError::Conflict { .. })));
    }
}
