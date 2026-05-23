//! Replay Store for Persistent Replay Detection
//!
//! Provides SQLite-backed storage for replay detection with crash-safe persistence.

use csv_core::Hash;

/// Persistent replay store
#[cfg(feature = "sqlite")]
pub struct ReplayStore {
    /// SQLite database connection
    db: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
impl ReplayStore {
    /// Create a new replay store with the given database path
    pub async fn new(database_path: &str) -> Result<Self, sqlx::Error> {
        let db = sqlx::SqlitePool::connect(database_path).await?;
        
        // Initialize schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS replay_entries (
                key_hash BLOB PRIMARY KEY,
                proof_hash BLOB NOT NULL,
                seal_id BLOB NOT NULL,
                commitment_hash BLOB NOT NULL,
                source_chain TEXT NOT NULL,
                destination_chain TEXT NOT NULL,
                first_seen_at INTEGER NOT NULL,
                replay_attempts INTEGER NOT NULL DEFAULT 0,
                accepted BOOLEAN NOT NULL DEFAULT FALSE
            );
            
            CREATE INDEX IF NOT EXISTS idx_replay_proof ON replay_entries(proof_hash);
            CREATE INDEX IF NOT EXISTS idx_replay_seal ON replay_entries(seal_id);
            "#
        )
        .execute(&db)
        .await?;
        
        Ok(Self { db })
    }

    /// Record a proof in the replay registry using atomic consume-if-unconsumed semantics.
    ///
    /// This is an atomic operation that prevents race conditions. It uses INSERT OR IGNORE
    /// to ensure that concurrent attempts to insert the same key cannot succeed.
    ///
    /// Returns true if this is the first time seeing this proof (insert succeeded).
    /// Returns false if it's a replay attempt (key already exists).
    pub async fn record_proof(
        &self,
        key_hash: Hash,
        proof_hash: Hash,
        seal_id: Hash,
        commitment_hash: Hash,
        source_chain: &str,
        destination_chain: &str,
        timestamp: u64,
    ) -> Result<bool, sqlx::Error> {
        // Atomic insert-or-ignore: if key exists, this does nothing
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO replay_entries (
                key_hash, proof_hash, seal_id, commitment_hash,
                source_chain, destination_chain, first_seen_at, replay_attempts, accepted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, FALSE)
            "#
        )
        .bind(key_hash.as_bytes())
        .bind(proof_hash.as_bytes())
        .bind(seal_id.as_bytes())
        .bind(commitment_hash.as_bytes())
        .bind(source_chain)
        .bind(destination_chain)
        .bind(timestamp as i64)
        .execute(&self.db)
        .await?;

        // If rows_affected > 0, the insert succeeded (first time)
        // If rows_affected == 0, the key already existed (replay attempt)
        if result.rows_affected() > 0 {
            Ok(true)
        } else {
            // Replay attempt - increment counter atomically
            sqlx::query(
                "UPDATE replay_entries SET replay_attempts = replay_attempts + 1 WHERE key_hash = ?"
            )
            .bind(key_hash.as_bytes())
            .execute(&self.db)
            .await?;
            Ok(false)
        }
    }

    /// Check if a proof has been seen before
    pub async fn has_been_seen(&self, key_hash: Hash) -> Result<bool, sqlx::Error> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM replay_entries WHERE key_hash = ?"
        )
        .bind(key_hash.as_bytes())
        .fetch_one(&self.db)
        .await?;
        Ok(count > 0)
    }

    /// Get total replay attempts
    pub async fn total_replay_attempts(&self) -> Result<u64, sqlx::Error> {
        let total = sqlx::query_scalar::<_, i64>("SELECT SUM(replay_attempts) FROM replay_entries")
            .fetch_one(&self.db)
            .await?;
        Ok(total as u64)
    }

    /// Idempotent consume-if-unconsumed operation using atomic SQL.
    ///
    /// This uses INSERT OR IGNORE to ensure atomic semantics, preventing
    /// race conditions between concurrent consumers.
    ///
    /// Returns Ok(true) if the seal was successfully consumed.
    /// Returns Ok(false) if the seal was already consumed (idempotent).
    /// Returns Err if the operation failed due to a database error.
    pub async fn consume_if_unconsumed(
        &self,
        key_hash: Hash,
        proof_hash: Hash,
        seal_id: Hash,
        commitment_hash: Hash,
        source_chain: &str,
        destination_chain: &str,
        timestamp: u64,
    ) -> Result<bool, sqlx::Error> {
        // Atomic insert-or-ignore with accepted = TRUE
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO replay_entries (
                key_hash, proof_hash, seal_id, commitment_hash,
                source_chain, destination_chain, first_seen_at, replay_attempts, accepted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, TRUE)
            "#
        )
        .bind(key_hash.as_bytes())
        .bind(proof_hash.as_bytes())
        .bind(seal_id.as_bytes())
        .bind(commitment_hash.as_bytes())
        .bind(source_chain)
        .bind(destination_chain)
        .bind(timestamp as i64)
        .execute(&self.db)
        .await?;

        // If rows_affected > 0, the insert succeeded (first time)
        // If rows_affected == 0, the key already existed
        if result.rows_affected() > 0 {
            Ok(true)
        } else {
            // Check if already accepted (idempotent) or replay attack
            let accepted: bool = sqlx::query_scalar::<_, bool>(
                "SELECT accepted FROM replay_entries WHERE key_hash = ?"
            )
            .bind(key_hash.as_bytes())
            .fetch_one(&self.db)
            .await?;

            if accepted {
                Ok(false) // Already consumed - idempotent
            } else {
                // Entry exists but not accepted - replay attack
                Err(sqlx::Error::RowNotFound)
            }
        }
    }
}
