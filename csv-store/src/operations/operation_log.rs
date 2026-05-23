//! Operation Log for Audit Trail
//!
//! Provides SQLite-backed storage for operation logging with crash-safe persistence.

/// Operation log entry
#[derive(Clone, Debug)]
pub struct OperationLogEntry {
    pub id: u64,
    pub operation_type: String,
    pub entity_id: Vec<u8>,
    pub chain: Option<String>,
    pub status: String,
    pub timestamp: u64,
    pub metadata: Option<Vec<u8>>,
}

/// Persistent operation log
#[cfg(feature = "sqlite")]
pub struct OperationLog {
    /// SQLite database connection
    db: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
impl OperationLog {
    /// Create a new operation log with the given database path
    pub async fn new(database_path: &str) -> Result<Self, sqlx::Error> {
        let db = sqlx::SqlitePool::connect(database_path).await?;
        
        // Initialize schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS operation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                entity_id BLOB NOT NULL,
                chain TEXT,
                status TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                metadata BLOB
            );
            
            CREATE INDEX IF NOT EXISTS idx_op_log_type ON operation_log(operation_type);
            CREATE INDEX IF NOT EXISTS idx_op_log_entity ON operation_log(entity_id);
            CREATE INDEX IF NOT EXISTS idx_op_log_timestamp ON operation_log(timestamp);
            "#
        )
        .execute(&db)
        .await?;
        
        Ok(Self { db })
    }

    /// Log an operation
    pub async fn log_operation(
        &self,
        operation_type: &str,
        entity_id: &[u8],
        chain: Option<&str>,
        status: &str,
        metadata: Option<&[u8]>,
    ) -> Result<u64, sqlx::Error> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let result = sqlx::query(
            r#"
            INSERT INTO operation_log (operation_type, entity_id, chain, status, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(operation_type)
        .bind(entity_id)
        .bind(chain)
        .bind(status)
        .bind(timestamp as i64)
        .bind(metadata)
        .execute(&self.db)
        .await?;
        
        Ok(result.last_insert_rowid() as u64)
    }

    /// Get recent operations
    pub async fn get_recent_operations(&self, limit: u32) -> Result<Vec<OperationLogEntry>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (i64, String, Vec<u8>, Option<String>, String, i64, Option<Vec<u8>>)>(
            "SELECT id, operation_type, entity_id, chain, status, timestamp, metadata FROM operation_log ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.db)
        .await?;
        
        let mut entries = Vec::new();
        for row in rows {
            entries.push(OperationLogEntry {
                id: row.0 as u64,
                operation_type: row.1,
                entity_id: row.2,
                chain: row.3,
                status: row.4,
                timestamp: row.5 as u64,
                metadata: row.6,
            });
        }
        
        Ok(entries)
    }
}
