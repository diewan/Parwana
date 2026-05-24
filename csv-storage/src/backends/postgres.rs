//! PostgreSQL-backed replay database with server-side CAS.

use async_trait::async_trait;
use csv_protocol::cross_chain::HashEntry as CrossChainRegistryEntry;
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_proof::proof::ReplayId;
use sqlx::PgPool;

use crate::errors::ReplayDbError;
use crate::traits::ReplayDatabase;

/// PostgreSQL-backed replay database (multi-coordinator CAS).
pub struct PostgresReplayDb {
    pool: PgPool,
}

impl PostgresReplayDb {
    /// Create from an existing connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect using a database URL.
    pub async fn connect(database_url: &str) -> Result<Self, ReplayDbError> {
        let pool = sqlx::PgPool::connect(database_url)
            .await
            .map_err(|e| ReplayDbError::Storage(format!("PostgreSQL connect failed: {e}")))?;
        Ok(Self { pool })
    }

    /// Run idempotent schema migrations.
    pub async fn run_migrations(&self) -> Result<(), ReplayDbError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS replay_entries (
                id          TEXT PRIMARY KEY,
                state       TEXT NOT NULL CHECK (state IN ('Pending', 'Consumed', 'RolledBack')),
                inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at  TIMESTAMPTZ
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(format!("Migration failed: {e}")))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_replay_state ON replay_entries (state)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(format!("Migration failed: {e}")))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cross_chain_transfers (
                sanad_id   TEXT PRIMARY KEY,
                entry_data TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(format!("Migration failed: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl ReplayDatabase for PostgresReplayDb {
    async fn contains(&self, id: &[u8]) -> Result<bool, ReplayDbError> {
        let hex_id = hex::encode(id);
        let row: Option<(String,)> =
            sqlx::query_as("SELECT id FROM replay_entries WHERE id = $1")
                .bind(&hex_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| ReplayDbError::Storage(e.to_string()))?;
        Ok(row.is_some())
    }

    async fn insert_if_absent(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        let hex_id = hex::encode(id);
        let inserted = sqlx::query_scalar::<_, String>(
            r#"
            INSERT INTO replay_entries (id, state, inserted_at)
            VALUES ($1, 'Pending', NOW())
            ON CONFLICT (id) DO NOTHING
            RETURNING id
            "#,
        )
        .bind(&hex_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(e.to_string()))?;

        match inserted {
            Some(_) => Ok(()),
            None => Err(ReplayDbError::AlreadyExists),
        }
    }

    async fn consume_if_unconsumed(&self, id: &[u8]) -> Result<(), ReplayDbError> {
        let hex_id = hex::encode(id);
        let current: Option<(String,)> =
            sqlx::query_as("SELECT state FROM replay_entries WHERE id = $1")
                .bind(&hex_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| ReplayDbError::Storage(e.to_string()))?;

        match current {
            Some((state,)) if state == "Consumed" => Ok(()),
            Some((_,)) => Err(ReplayDbError::AlreadyExists),
            None => self.insert_if_absent(id).await,
        }
    }

    async fn confirm_consumed_replay_id(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let hex_id = hex::encode(id.as_bytes());
        let result = sqlx::query(
            r#"
            UPDATE replay_entries
            SET state = 'Consumed', updated_at = NOW()
            WHERE id = $1 AND state = 'Pending'
            "#,
        )
        .bind(&hex_id)
        .execute(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(e.to_string()))?;

        if result.rows_affected() == 0 {
            let current: Option<(String,)> =
                sqlx::query_as("SELECT state FROM replay_entries WHERE id = $1")
                    .bind(&hex_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| ReplayDbError::Storage(e.to_string()))?;
            match current {
                Some((state,)) if state == "Consumed" => Ok(()),
                Some((_,)) => Err(ReplayDbError::Storage(
                    "Entry is not in Pending state".to_string(),
                )),
                None => Err(ReplayDbError::NotFound),
            }
        } else {
            Ok(())
        }
    }

    async fn mark_rolled_back(&self, id: &ReplayId) -> Result<(), ReplayDbError> {
        let hex_id = hex::encode(id.as_bytes());
        let result = sqlx::query(
            r#"
            UPDATE replay_entries
            SET state = 'RolledBack', updated_at = NOW()
            WHERE id = $1 AND state = 'Pending'
            "#,
        )
        .bind(&hex_id)
        .execute(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(e.to_string()))?;

        if result.rows_affected() == 0 {
            let current: Option<(String,)> =
                sqlx::query_as("SELECT state FROM replay_entries WHERE id = $1")
                    .bind(&hex_id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| ReplayDbError::Storage(e.to_string()))?;
            match current {
                Some((state,)) if state == "RolledBack" => Ok(()),
                Some((_,)) => Err(ReplayDbError::Storage(
                    "Entry is not in Pending state".to_string(),
                )),
                None => Err(ReplayDbError::NotFound),
            }
        } else {
            Ok(())
        }
    }

    async fn store_transfer_entry(
        &self,
        entry: &CrossChainRegistryEntry,
    ) -> Result<(), ReplayDbError> {
        let sanad_hex = hex::encode(entry.sanad_id.as_bytes());
        let entry_bytes = to_canonical_cbor(entry)
            .map_err(|e| ReplayDbError::Storage(format!("Serialization error: {e}")))?;
        let entry_hex = hex::encode(&entry_bytes);

        sqlx::query(
            "INSERT INTO cross_chain_transfers (sanad_id, entry_data) VALUES ($1, $2)
             ON CONFLICT (sanad_id) DO UPDATE SET entry_data = EXCLUDED.entry_data",
        )
        .bind(&sanad_hex)
        .bind(&entry_hex)
        .execute(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn load_all_transfers(
        &self,
    ) -> Result<Vec<CrossChainRegistryEntry>, ReplayDbError> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT sanad_id, entry_data FROM cross_chain_transfers",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ReplayDbError::Storage(e.to_string()))?;

        let mut transfers = Vec::new();
        for (_sanad_hex, entry_hex) in rows {
            let entry_bytes = hex::decode(&entry_hex)
                .map_err(|e| ReplayDbError::Storage(format!("Hex decode error: {e}")))?;
            let entry: CrossChainRegistryEntry = from_canonical_cbor(&entry_bytes)
                .map_err(|e| ReplayDbError::Storage(format!("Deserialization error: {e}")))?;
            transfers.push(entry);
        }
        Ok(transfers)
    }
}
