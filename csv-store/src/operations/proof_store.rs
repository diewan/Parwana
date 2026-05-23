//! Proof Store for Persistent Proof Records
//!
//! Provides SQLite-backed storage for proof records with crash-safe persistence.

use csv_core::Hash;

/// Persistent proof store
#[cfg(feature = "sqlite")]
pub struct ProofStore {
    /// SQLite database connection
    db: sqlx::SqlitePool,
}

#[cfg(feature = "sqlite")]
impl ProofStore {
    /// Create a new proof store with the given database path
    pub async fn new(database_path: &str) -> Result<Self, sqlx::Error> {
        let db = sqlx::SqlitePool::connect(database_path).await?;
        
        // Initialize schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS proofs (
                proof_id BLOB PRIMARY KEY,
                transfer_id BLOB NOT NULL,
                proof_bytes BLOB NOT NULL,
                validated BOOLEAN NOT NULL DEFAULT FALSE,
                validated_at INTEGER,
                created_at INTEGER NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_proofs_transfer ON proofs(transfer_id);
            CREATE INDEX IF NOT EXISTS idx_proofs_validated ON proofs(validated);
            "#
        )
        .execute(&db)
        .await?;
        
        Ok(Self { db })
    }

    /// Save a proof
    pub async fn save_proof(
        &self,
        proof_id: Hash,
        transfer_id: Hash,
        proof_bytes: &[u8],
    ) -> Result<(), sqlx::Error> {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        sqlx::query(
            r#"
            INSERT INTO proofs (proof_id, transfer_id, proof_bytes, validated, created_at)
            VALUES (?, ?, ?, FALSE, ?)
            ON CONFLICT(proof_id) DO UPDATE SET
                proof_bytes = excluded.proof_bytes
            "#
        )
        .bind(proof_id.as_bytes())
        .bind(transfer_id.as_bytes())
        .bind(proof_bytes)
        .bind(created_at as i64)
        .execute(&self.db)
        .await?;
        
        Ok(())
    }

    /// Mark a proof as validated
    pub async fn mark_validated(&self, proof_id: Hash) -> Result<(), sqlx::Error> {
        let validated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        sqlx::query(
            "UPDATE proofs SET validated = TRUE, validated_at = ? WHERE proof_id = ?"
        )
        .bind(validated_at as i64)
        .bind(proof_id.as_bytes())
        .execute(&self.db)
        .await?;
        
        Ok(())
    }

    /// Get a proof by ID
    pub async fn get_proof(&self, proof_id: Hash) -> Result<Option<ProofRecord>, sqlx::Error> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>, bool, Option<i64>, i64)>(
            "SELECT proof_id, transfer_id, proof_bytes, validated, validated_at, created_at FROM proofs WHERE proof_id = ?"
        )
        .bind(proof_id.as_bytes())
        .fetch_optional(&self.db)
        .await?;
        
        match row {
            Some(row) => {
                Ok(Some(ProofRecord {
                    proof_id: Hash::new(row.0.try_into().unwrap_or([0u8; 32])),
                    transfer_id: Hash::new(row.1.try_into().unwrap_or([0u8; 32])),
                    proof_bytes: row.2,
                    validated: row.3,
                    validated_at: row.4.map(|t| t as u64),
                    created_at: row.5 as u64,
                }))
            }
            None => Ok(None),
        }
    }
}

/// Proof record
#[derive(Clone, Debug)]
pub struct ProofRecord {
    pub proof_id: Hash,
    pub transfer_id: Hash,
    pub proof_bytes: Vec<u8>,
    pub validated: bool,
    pub validated_at: Option<u64>,
    pub created_at: u64,
}
