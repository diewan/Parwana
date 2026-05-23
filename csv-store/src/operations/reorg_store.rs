//! Reorg Store for Persistent Reorg Detection
//!
//! Provides SQLite-backed storage for reorg detection with crash-safe persistence.

use csv_core::Hash;

/// Persistent reorg store
#[cfg(feature = "sqlite")]
pub struct ReorgStore {
    /// SQLite database connection
    db: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
impl ReorgStore {
    /// Create a new reorg store with the given database path
    pub async fn new(database_path: &str) -> Result<Self, sqlx::Error> {
        let db = sqlx::SqlitePool::connect(database_path).await?;
        
        // Initialize schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS reorg_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                old_height INTEGER NOT NULL,
                new_height INTEGER NOT NULL,
                detected_at INTEGER NOT NULL,
                affected_transfers BLOB
            );
            
            CREATE INDEX IF NOT EXISTS idx_reorg_chain ON reorg_events(chain);
            CREATE INDEX IF NOT EXISTS idx_reorg_detected ON reorg_events(detected_at);
            "#
        )
        .execute(&db)
        .await?;
        
        Ok(Self { db })
    }

    /// Record a reorg event
    pub async fn record_reorg(
        &self,
        chain: &str,
        old_height: u64,
        new_height: u64,
        affected_transfers: &[Hash],
    ) -> Result<(), sqlx::Error> {
        let detected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let affected_bytes: Vec<u8> = affected_transfers
            .iter()
            .flat_map(|h| h.as_bytes().to_vec())
            .collect();
        
        sqlx::query(
            r#"
            INSERT INTO reorg_events (chain, old_height, new_height, detected_at, affected_transfers)
            VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(chain)
        .bind(old_height as i64)
        .bind(new_height as i64)
        .bind(detected_at as i64)
        .bind(affected_bytes)
        .execute(&self.db)
        .await?;
        
        Ok(())
    }

    /// Get recent reorg events for a chain
    pub async fn get_recent_reorgs(&self, chain: &str, limit: u32) -> Result<Vec<ReorgEvent>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (i64, String, i64, i64, i64, Vec<u8>)>(
            "SELECT id, chain, old_height, new_height, detected_at, affected_transfers FROM reorg_events WHERE chain = ? ORDER BY detected_at DESC LIMIT ?"
        )
        .bind(chain)
        .bind(limit)
        .fetch_all(&self.db)
        .await?;
        
        let mut events = Vec::new();
        for row in rows {
            events.push(ReorgEvent {
                id: row.0 as u64,
                chain: row.1,
                old_height: row.2 as u64,
                new_height: row.3 as u64,
                detected_at: row.4 as u64,
                affected_transfers: row.5,
            });
        }
        
        Ok(events)
    }
}

/// Reorg event record
#[derive(Clone, Debug)]
pub struct ReorgEvent {
    pub id: u64,
    pub chain: String,
    pub old_height: u64,
    pub new_height: u64,
    pub detected_at: u64,
    pub affected_transfers: Vec<u8>,
}
