//! Transfer Store for Persistent Transfer State
//!
//! Provides SQLite-backed storage for transfer states with crash-safe persistence.

use csv_core::Hash;

/// Persistent transfer store
#[cfg(feature = "sqlite")]
pub struct TransferStore {
    /// SQLite database connection
    db: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
impl TransferStore {
    /// Create a new transfer store with the given database path
    pub async fn new(database_path: &str) -> Result<Self, sqlx::Error> {
        let db = sqlx::SqlitePool::connect(database_path).await?;
        
        // Initialize schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS transfers (
                transfer_id BLOB PRIMARY KEY,
                sanad_id BLOB NOT NULL,
                source_chain TEXT NOT NULL,
                destination_chain TEXT NOT NULL,
                seal_point BLOB NOT NULL,
                commitment_hash BLOB NOT NULL,
                state TEXT NOT NULL,
                initiated_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                metadata BLOB
            );
            
            CREATE INDEX IF NOT EXISTS idx_transfers_state ON transfers(state);
            CREATE INDEX IF NOT EXISTS idx_transfers_sanad ON transfers(sanad_id);
            "#
        )
        .execute(&db)
        .await?;
        
        Ok(Self { db })
    }

    /// Save a transfer state
    pub async fn save_transfer(
        &self,
        transfer_id: Hash,
        sanad_id: Hash,
        source_chain: &str,
        destination_chain: &str,
        seal_point: &[u8],
        commitment_hash: Hash,
        state: &str,
        initiated_at: u64,
        metadata: Option<&[u8]>,
    ) -> Result<(), sqlx::Error> {
        let updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        sqlx::query(
            r#"
            INSERT INTO transfers (
                transfer_id, sanad_id, source_chain, destination_chain,
                seal_point, commitment_hash, state, initiated_at, updated_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(transfer_id) DO UPDATE SET
                state = excluded.state,
                updated_at = excluded.updated_at,
                metadata = excluded.metadata
            "#
        )
        .bind(transfer_id.as_bytes())
        .bind(sanad_id.as_bytes())
        .bind(source_chain)
        .bind(destination_chain)
        .bind(seal_point)
        .bind(commitment_hash.as_bytes())
        .bind(state)
        .bind(initiated_at as i64)
        .bind(updated_at as i64)
        .bind(metadata)
        .execute(&self.db)
        .await?;
        
        Ok(())
    }

    /// Get a transfer by ID
    pub async fn get_transfer(&self, transfer_id: Hash) -> Result<Option<TransferRecord>, sqlx::Error> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, String, Vec<u8>, Vec<u8>, String, i64, i64, Option<Vec<u8>>)>(
            "SELECT transfer_id, sanad_id, source_chain, destination_chain, seal_point, commitment_hash, state, initiated_at, updated_at, metadata FROM transfers WHERE transfer_id = ?"
        )
        .bind(transfer_id.as_bytes())
        .fetch_optional(&self.db)
        .await?;
        
        match row {
            Some(row) => {
                Ok(Some(TransferRecord {
                    transfer_id: Hash::new(row.0.try_into().unwrap_or([0u8; 32])),
                    sanad_id: Hash::new(row.1.try_into().unwrap_or([0u8; 32])),
                    source_chain: row.2,
                    destination_chain: row.3,
                    seal_point: row.4,
                    commitment_hash: Hash::new(row.5.try_into().unwrap_or([0u8; 32])),
                    state: row.6,
                    initiated_at: row.7 as u64,
                    updated_at: row.8 as u64,
                    metadata: row.9,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get transfers by state
    pub async fn get_transfers_by_state(&self, state: &str) -> Result<Vec<TransferRecord>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, String, Vec<u8>, Vec<u8>, String, i64, i64, Option<Vec<u8>>)>(
            "SELECT transfer_id, sanad_id, source_chain, destination_chain, seal_point, commitment_hash, state, initiated_at, updated_at, metadata FROM transfers WHERE state = ?"
        )
        .bind(state)
        .fetch_all(&self.db)
        .await?;
        
        let mut transfers = Vec::new();
        for row in rows {
            transfers.push(TransferRecord {
                transfer_id: Hash::new(row.0.try_into().unwrap_or([0u8; 32])),
                sanad_id: Hash::new(row.1.try_into().unwrap_or([0u8; 32])),
                source_chain: row.2,
                destination_chain: row.3,
                seal_point: row.4,
                commitment_hash: Hash::new(row.5.try_into().unwrap_or([0u8; 32])),
                state: row.6,
                initiated_at: row.7 as u64,
                updated_at: row.8 as u64,
                metadata: row.9,
            });
        }
        
        Ok(transfers)
    }
}

/// Transfer record
#[derive(Clone, Debug)]
pub struct TransferRecord {
    pub transfer_id: Hash,
    pub sanad_id: Hash,
    pub source_chain: String,
    pub destination_chain: String,
    pub seal_point: Vec<u8>,
    pub commitment_hash: Hash,
    pub state: String,
    pub initiated_at: u64,
    pub updated_at: u64,
    pub metadata: Option<Vec<u8>>,
}
