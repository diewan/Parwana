//! Persistent Replay Registry Store
//!
//! This module provides persistent storage for the replay registry using SQLite.
//! It ensures that replay protection survives across:
//! - application restart
//! - crash recovery
//! - node migration

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_protocol::replay::{ReplayEntry, ReplayKey};
use rusqlite::{Connection, Result as RusqliteResult, params};

/// Persistent replay registry store
///
/// This provides SQLite-backed persistence for replay detection using rusqlite.
/// In production, this should be used instead of the in-memory ReplayRegistry.
pub struct ReplayRegistryStore {
    /// SQLite database connection
    db: Connection,
}

impl ReplayRegistryStore {
    /// Create a new replay registry store with the given database path
    pub fn new(database_path: &str) -> RusqliteResult<Self> {
        let db = Connection::open(database_path)?;

        // Initialize schema
        db.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS replay_registry (
                key_hash BLOB PRIMARY KEY,
                proof_hash BLOB NOT NULL,
                seal_id BLOB NOT NULL,
                commitment_hash BLOB NOT NULL,
                source_chain TEXT NOT NULL,
                destination_chain TEXT NOT NULL,
                first_seen_at INTEGER NOT NULL,
                replay_attempts INTEGER NOT NULL DEFAULT 0,
                accepted BOOLEAN NOT NULL DEFAULT 0
            );
            
            CREATE INDEX IF NOT EXISTS idx_proof_hash ON replay_registry(proof_hash);
            CREATE INDEX IF NOT EXISTS idx_seal_id ON replay_registry(seal_id);
            "#,
        )?;

        Ok(Self { db })
    }

    /// Record a proof in the persistent replay registry using atomic consume-if-unconsumed semantics.
    ///
    /// This is an atomic operation that prevents race conditions. It uses INSERT OR IGNORE
    /// to ensure that concurrent attempts to insert the same key cannot succeed.
    ///
    /// Returns true if this is the first time seeing this proof (insert succeeded).
    /// Returns false if it's a replay attempt (key already exists).
    pub fn record_proof(&self, key: ReplayKey, timestamp: u64) -> RusqliteResult<bool> {
        let key_hash = key.hash();

        // Atomic insert-or-ignore: if key exists, this does nothing
        let rows_affected = self.db.execute(
            r#"
            INSERT OR IGNORE INTO replay_registry (
                key_hash, proof_hash, seal_id, commitment_hash,
                source_chain, destination_chain, first_seen_at, replay_attempts, accepted
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0)
            "#,
            params![
                key_hash.as_bytes(),
                key.proof_hash.as_bytes(),
                key.seal_id.as_bytes(),
                key.commitment_hash.as_bytes(),
                key.source_chain.as_str(),
                key.destination_chain.as_str(),
                timestamp as i64,
            ],
        )?;

        // If rows_affected > 0, the insert succeeded (first time)
        // If rows_affected == 0, the key already existed (replay attempt)
        if rows_affected > 0 {
            Ok(true)
        } else {
            // Replay attempt - increment counter atomically
            self.db.execute(
                "UPDATE replay_registry SET replay_attempts = replay_attempts + 1 WHERE key_hash = ?",
                [key_hash.as_bytes()],
            )?;
            Ok(false)
        }
    }

    /// Check if a proof has been seen before
    pub fn has_been_seen(&self, key: &ReplayKey) -> RusqliteResult<bool> {
        let key_hash = key.hash();
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM replay_registry WHERE key_hash = ?",
            [key_hash.as_bytes()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Mark a proof as accepted
    pub fn mark_accepted(&self, key: &ReplayKey) -> RusqliteResult<()> {
        let key_hash = key.hash();
        self.db.execute(
            "UPDATE replay_registry SET accepted = 1 WHERE key_hash = ?",
            [key_hash.as_bytes()],
        )?;
        Ok(())
    }

    /// Get the number of replay attempts for a proof
    pub fn replay_attempts(&self, key: &ReplayKey) -> RusqliteResult<u64> {
        let key_hash = key.hash();
        let attempts: Option<i64> = self.db.query_row(
            "SELECT replay_attempts FROM replay_registry WHERE key_hash = ?",
            [key_hash.as_bytes()],
            |row| row.get(0),
        )?;
        Ok(attempts.unwrap_or(0) as u64)
    }

    /// Get all entries
    pub fn entries(&self) -> RusqliteResult<Vec<ReplayEntry>> {
        let mut stmt = self.db.prepare(
            "SELECT proof_hash, seal_id, commitment_hash, source_chain, destination_chain, first_seen_at, replay_attempts, accepted FROM replay_registry"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ReplayEntry {
                key: ReplayKey::new(
                    Hash::new(row.get(0)?),
                    Hash::new(row.get(1)?),
                    Hash::new(row.get(2)?),
                    ChainId::new(&row.get::<_, String>(3)?),
                    ChainId::new(&row.get::<_, String>(4)?),
                ),
                first_seen_at: row.get(5)?,
                replay_attempts: row.get(6)?,
                accepted: row.get(7)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }

        Ok(entries)
    }

    /// Get the total number of tracked proofs
    pub fn total_proofs(&self) -> RusqliteResult<usize> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM replay_registry", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get the number of replay attempts detected
    pub fn total_replay_attempts(&self) -> RusqliteResult<u64> {
        let total: Option<i64> = self.db.query_row(
            "SELECT SUM(replay_attempts) FROM replay_registry",
            [],
            |row| row.get(0),
        )?;
        Ok(total.unwrap_or(0) as u64)
    }

    /// Idempotent consume-if-unconsumed operation using atomic SQL.
    ///
    /// This uses INSERT OR IGNORE to ensure atomic semantics, preventing
    /// race conditions between concurrent consumers.
    ///
    /// Returns Ok(true) if the seal was successfully consumed.
    /// Returns Ok(false) if the seal was already consumed (idempotent).
    /// Returns Err if the operation failed due to a database error.
    pub fn consume_if_unconsumed(&self, key: ReplayKey, timestamp: u64) -> RusqliteResult<bool> {
        let key_hash = key.hash();

        // Atomic insert-or-ignore with accepted = 1
        let rows_affected = self.db.execute(
            r#"
            INSERT OR IGNORE INTO replay_registry (
                key_hash, proof_hash, seal_id, commitment_hash,
                source_chain, destination_chain, first_seen_at, replay_attempts, accepted
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 1)
            "#,
            params![
                key_hash.as_bytes(),
                key.proof_hash.as_bytes(),
                key.seal_id.as_bytes(),
                key.commitment_hash.as_bytes(),
                key.source_chain.as_str(),
                key.destination_chain.as_str(),
                timestamp as i64,
            ],
        )?;

        // If rows_affected > 0, the insert succeeded (first time)
        // If rows_affected == 0, the key already existed
        if rows_affected > 0 {
            Ok(true)
        } else {
            // Check if already accepted (idempotent) or replay attack
            let accepted: i64 = self.db.query_row(
                "SELECT accepted FROM replay_registry WHERE key_hash = ?",
                [key_hash.as_bytes()],
                |row| row.get(0),
            )?;

            if accepted == 1 {
                Ok(false) // Already consumed - idempotent
            } else {
                // Entry exists but not accepted - replay attack
                Err(rusqlite::Error::QueryReturnedNoRows)
            }
        }
    }
}
