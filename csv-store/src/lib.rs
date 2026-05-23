//! SQLite persistence for CSV Adapter seals and anchors

#[cfg(feature = "sqlite")]
use csv_core::{AnchorRecord, Hash, SanadRecord, SanadStore, SealStore, StoreError};

#[cfg(feature = "sqlite")]
use rusqlite::{Connection, params};
#[cfg(feature = "sqlite")]
use std::sync::Mutex;

/// Application state module (unified storage).
pub mod state;

#[cfg(feature = "browser-storage")]
pub mod browser_storage;

#[cfg(feature = "encrypted-storage")]
pub mod encrypted_storage;

#[cfg(feature = "sqlite")]
pub mod replay_registry_store;

// TODO: Rewrite operations/*.rs to use rusqlite (currently uses sqlx which is not a dependency)
// #[cfg(feature = "sqlite")]
// pub mod operations;

// Re-exports from state module
#[allow(deprecated)]
pub use state::Chain;
pub use state::{
    ChainConfig, ChainId, ContractRecord, FaucetConfig, GasAccount, Network, ProofRecord,
    SanadStatus, SealRecord, StateStorage, StorageBackend, StorageError, TransactionRecord,
    TransactionStatus, TransactionType, TransferRecord, TransferStatus, WalletAccount,
    WalletConfig,
};

#[cfg(all(not(target_arch = "wasm32"), feature = "file-storage"))]
pub use state::FileStorage;

#[cfg(feature = "browser-storage")]
pub use browser_storage::{
    BrowserStateStorage, BrowserStorageError, LocalStorageManager, UNIFIED_STORAGE_KEY,
    WALLET_MNEMONIC_KEY, asset_storage, seal_storage, wallet_storage,
};

#[cfg(feature = "encrypted-storage")]
pub use encrypted_storage::{
    EncryptedStorageError, EncryptedStorageManager, seal_nullifier_storage,
};

/// SQLite-backed seal and anchor store
#[cfg(feature = "sqlite")]
pub struct SqliteSealStore {
    conn: Mutex<Connection>,
}

#[cfg(feature = "sqlite")]
impl SqliteSealStore {
    /// Create or open a SQLite store at the given path
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path).map_err(|e| StoreError::IoError(e.to_string()))?;
        Self::init_tables(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory store (for testing)
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(|e| StoreError::IoError(e.to_string()))?;
        Self::init_tables(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init_tables(conn: &Connection) -> Result<(), StoreError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS seals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                seal_id BLOB NOT NULL,
                consumed_at_height INTEGER NOT NULL,
                commitment_hash BLOB NOT NULL,
                recorded_at INTEGER NOT NULL,
                UNIQUE(chain, seal_id)
            );
            CREATE INDEX IF NOT EXISTS idx_seals_chain ON seals(chain);
            CREATE INDEX IF NOT EXISTS idx_seals_height ON seals(chain, consumed_at_height);

            CREATE TABLE IF NOT EXISTS anchors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain TEXT NOT NULL,
                anchor_id BLOB NOT NULL,
                block_height INTEGER NOT NULL,
                commitment_hash BLOB NOT NULL,
                is_finalized INTEGER NOT NULL DEFAULT 0,
                confirmations INTEGER NOT NULL DEFAULT 0,
                recorded_at INTEGER NOT NULL,
                UNIQUE(chain, anchor_id)
            );
            CREATE INDEX IF NOT EXISTS idx_anchors_chain ON anchors(chain);
            CREATE INDEX IF NOT EXISTS idx_anchors_height ON anchors(chain, block_height);
            CREATE INDEX IF NOT EXISTS idx_anchors_pending ON anchors(chain, is_finalized);

            CREATE TABLE IF NOT EXISTS sanads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sanad_id BLOB NOT NULL UNIQUE,
                chain TEXT NOT NULL,
                owner BLOB NOT NULL,
                sanad_data BLOB NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                recorded_at INTEGER NOT NULL,
                consumed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_sanads_chain ON sanads(chain);
            CREATE INDEX IF NOT EXISTS idx_sanads_owner ON sanads(owner);
            CREATE INDEX IF NOT EXISTS idx_sanads_consumed ON sanads(consumed);
            ",
        )
        .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
impl SealStore for SqliteSealStore {
    fn save_seal(&mut self, record: &csv_core::SealRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR IGNORE INTO seals (chain, seal_id, consumed_at_height, commitment_hash, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &record.chain,
                &record.seal_id,
                record.consumed_at_height as i64,
                record.commitment_hash.as_bytes(),
                record.recorded_at as i64,
            ],
        ).map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }

    fn is_seal_consumed(&self, chain: &str, seal_id: &[u8]) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM seals WHERE chain = ?1 AND seal_id = ?2",
                params![chain, seal_id],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(count > 0)
    }

    fn get_seals(&self, chain: &str) -> Result<Vec<csv_core::SealRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT seal_id, consumed_at_height, commitment_hash, recorded_at FROM seals WHERE chain = ?1"
        ).map_err(|e| StoreError::IoError(e.to_string()))?;

        let seals = stmt
            .query_map(params![chain], |row| {
                let seal_id: Vec<u8> = row.get(0)?;
                let consumed_at_height: i64 = row.get(1)?;
                let commitment_hash: Vec<u8> = row.get(2)?;
                let recorded_at: i64 = row.get(3)?;
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&commitment_hash);
                Ok(csv_core::SealRecord {
                    chain: chain.to_string(),
                    seal_id,
                    consumed_at_height: consumed_at_height as u64,
                    commitment_hash: Hash::new(hash_bytes),
                    recorded_at: recorded_at as u64,
                })
            })
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        seals
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    fn remove_seal(&mut self, chain: &str, seal_id: &[u8]) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "DELETE FROM seals WHERE chain = ?1 AND seal_id = ?2",
            params![chain, seal_id],
        )
        .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }

    fn remove_seals_after(&mut self, chain: &str, height: u64) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let removed = conn
            .execute(
                "DELETE FROM seals WHERE chain = ?1 AND consumed_at_height > ?2",
                params![chain, height as i64],
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(removed)
    }

    fn save_anchor(&mut self, record: &AnchorRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR IGNORE INTO anchors (chain, anchor_id, block_height, commitment_hash, is_finalized, confirmations, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.chain,
                record.anchor_id,
                record.block_height as i64,
                record.commitment_hash.as_bytes(),
                record.is_finalized as i64,
                record.confirmations as i64,
                record.recorded_at as i64,
            ],
        ).map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }

    fn has_anchor(&self, chain: &str, anchor_id: &[u8]) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM anchors WHERE chain = ?1 AND anchor_id = ?2",
                params![chain, anchor_id],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(count > 0)
    }

    fn finalize_anchor(
        &mut self,
        chain: &str,
        anchor_id: &[u8],
        confirmations: u64,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE anchors SET is_finalized = 1, confirmations = ?3
             WHERE chain = ?1 AND anchor_id = ?2",
            params![chain, anchor_id, confirmations as i64],
        )
        .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }

    fn pending_anchors(&self, chain: &str) -> Result<Vec<AnchorRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT anchor_id, block_height, commitment_hash, confirmations, recorded_at
             FROM anchors WHERE chain = ?1 AND is_finalized = 0",
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        let anchors = stmt
            .query_map(params![chain], |row| {
                let anchor_id: Vec<u8> = row.get(0)?;
                let block_height: i64 = row.get(1)?;
                let commitment_hash: Vec<u8> = row.get(2)?;
                let confirmations: i64 = row.get(3)?;
                let recorded_at: i64 = row.get(4)?;
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&commitment_hash);
                Ok(AnchorRecord {
                    chain: chain.to_string(),
                    anchor_id,
                    block_height: block_height as u64,
                    commitment_hash: Hash::new(hash_bytes),
                    is_finalized: false,
                    confirmations: confirmations as u64,
                    recorded_at: recorded_at as u64,
                })
            })
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        anchors
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    fn remove_anchors_after(&mut self, chain: &str, height: u64) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let removed = conn
            .execute(
                "DELETE FROM anchors WHERE chain = ?1 AND block_height > ?2",
                params![chain, height as i64],
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(removed)
    }

    fn highest_block(&self, chain: &str) -> Result<u64, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let max: Option<i64> = conn
            .query_row(
                "SELECT MAX(block_height) FROM anchors WHERE chain = ?1",
                params![chain],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(max.unwrap_or(0) as u64)
    }
}

#[cfg(feature = "sqlite")]
impl SanadStore for SqliteSealStore {
    fn save_sanad(&mut self, record: &SanadRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO sanads (sanad_id, chain, owner, sanad_data, consumed, recorded_at, consumed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(sanad_id) DO UPDATE SET
             chain = excluded.chain, owner = excluded.owner, sanad_data = excluded.sanad_data",
            params![
                record.sanad_id.0.as_bytes(),
                &record.chain,
                &record.owner,
                &record.sanad_data,
                record.consumed as i64,
                record.recorded_at as i64,
                record.consumed_at.map(|t| t as i64),
            ],
        )
        .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(())
    }

    fn get_sanad(&self, sanad_id: &csv_core::SanadId) -> Result<Option<SanadRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT chain, owner, sanad_data, consumed, recorded_at, consumed_at 
                 FROM sanads WHERE sanad_id = ?1",
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        let result = stmt.query_row(params![sanad_id.0.as_bytes()], |row| {
            let chain: String = row.get(0)?;
            let owner: Vec<u8> = row.get(1)?;
            let sanad_data: Vec<u8> = row.get(2)?;
            let consumed: i64 = row.get(3)?;
            let recorded_at: i64 = row.get(4)?;
            let consumed_at: Option<i64> = row.get(5)?;

            Ok(SanadRecord {
                sanad_id: sanad_id.clone(),
                chain,
                owner,
                sanad_data,
                consumed: consumed != 0,
                recorded_at: recorded_at as u64,
                consumed_at: consumed_at.map(|t| t as u64),
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::IoError(e.to_string())),
        }
    }

    fn list_sanads_by_chain(&self, chain: &str) -> Result<Vec<SanadRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT sanad_id, owner, sanad_data, consumed, recorded_at, consumed_at 
                 FROM sanads WHERE chain = ?1",
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        let sanads = stmt
            .query_map(params![chain], |row| {
                let sanad_id_bytes: Vec<u8> = row.get(0)?;
                let owner: Vec<u8> = row.get(1)?;
                let sanad_data: Vec<u8> = row.get(2)?;
                let consumed: i64 = row.get(3)?;
                let recorded_at: i64 = row.get(4)?;
                let consumed_at: Option<i64> = row.get(5)?;

                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&sanad_id_bytes);

                Ok(SanadRecord {
                    sanad_id: csv_core::SanadId(Hash::new(hash_bytes)),
                    chain: chain.to_string(),
                    owner,
                    sanad_data,
                    consumed: consumed != 0,
                    recorded_at: recorded_at as u64,
                    consumed_at: consumed_at.map(|t| t as u64),
                })
            })
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        sanads
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    fn list_sanads_by_owner(&self, owner: &[u8]) -> Result<Vec<SanadRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT sanad_id, chain, sanad_data, consumed, recorded_at, consumed_at 
                 FROM sanads WHERE owner = ?1",
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        let sanads = stmt
            .query_map(params![owner], |row| {
                let sanad_id_bytes: Vec<u8> = row.get(0)?;
                let chain: String = row.get(1)?;
                let sanad_data: Vec<u8> = row.get(2)?;
                let consumed: i64 = row.get(3)?;
                let recorded_at: i64 = row.get(4)?;
                let consumed_at: Option<i64> = row.get(5)?;

                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&sanad_id_bytes);

                Ok(SanadRecord {
                    sanad_id: csv_core::SanadId(Hash::new(hash_bytes)),
                    chain,
                    owner: owner.to_vec(),
                    sanad_data,
                    consumed: consumed != 0,
                    recorded_at: recorded_at as u64,
                    consumed_at: consumed_at.map(|t| t as u64),
                })
            })
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        sanads
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    fn consume_sanad(
        &mut self,
        sanad_id: &csv_core::SanadId,
        consumed_at: u64,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let updated = conn
            .execute(
                "UPDATE sanads SET consumed = 1, consumed_at = ?2 WHERE sanad_id = ?1 AND consumed = 0",
                params![sanad_id.0.as_bytes(), consumed_at as i64],
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        if updated == 0 {
            // Check if sanad exists and is already consumed
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM sanads WHERE sanad_id = ?1 AND consumed = 1",
                    params![sanad_id.0.as_bytes()],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if exists {
                return Err(StoreError::DuplicateRecord(format!(
                    "Sanad {:?} already consumed",
                    sanad_id
                )));
            } else {
                return Err(StoreError::NotFound(format!(
                    "Sanad {:?} not found",
                    sanad_id
                )));
            }
        }
        Ok(())
    }

    fn list_consumed_sanads(&self) -> Result<Vec<SanadRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT sanad_id, chain, owner, sanad_data, recorded_at, consumed_at 
                 FROM sanads WHERE consumed = 1",
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        let sanads = stmt
            .query_map([], |row| {
                let sanad_id_bytes: Vec<u8> = row.get(0)?;
                let chain: String = row.get(1)?;
                let owner: Vec<u8> = row.get(2)?;
                let sanad_data: Vec<u8> = row.get(3)?;
                let recorded_at: i64 = row.get(4)?;
                let consumed_at: Option<i64> = row.get(5)?;

                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&sanad_id_bytes);

                Ok(SanadRecord {
                    sanad_id: csv_core::SanadId(Hash::new(hash_bytes)),
                    chain,
                    owner,
                    sanad_data,
                    consumed: true,
                    recorded_at: recorded_at as u64,
                    consumed_at: consumed_at.map(|t| t as u64),
                })
            })
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        sanads
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    fn list_active_sanads(&self) -> Result<Vec<SanadRecord>, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT sanad_id, chain, owner, sanad_data, recorded_at 
                 FROM sanads WHERE consumed = 0",
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        let sanads = stmt
            .query_map([], |row| {
                let sanad_id_bytes: Vec<u8> = row.get(0)?;
                let chain: String = row.get(1)?;
                let owner: Vec<u8> = row.get(2)?;
                let sanad_data: Vec<u8> = row.get(3)?;
                let recorded_at: i64 = row.get(4)?;

                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&sanad_id_bytes);

                Ok(SanadRecord {
                    sanad_id: csv_core::SanadId(Hash::new(hash_bytes)),
                    chain,
                    owner,
                    sanad_data,
                    consumed: false,
                    recorded_at: recorded_at as u64,
                    consumed_at: None,
                })
            })
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        sanads
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::IoError(e.to_string()))
    }

    fn has_sanad(&self, sanad_id: &csv_core::SanadId) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sanads WHERE sanad_id = ?1",
                params![sanad_id.0.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;
        Ok(count > 0)
    }

    fn delete_sanad(&mut self, sanad_id: &csv_core::SanadId) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let deleted = conn
            .execute(
                "DELETE FROM sanads WHERE sanad_id = ?1",
                params![sanad_id.0.as_bytes()],
            )
            .map_err(|e| StoreError::IoError(e.to_string()))?;

        if deleted == 0 {
            return Err(StoreError::NotFound(format!(
                "Sanad {:?} not found",
                sanad_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_core::SealRecord;

    fn test_seal_record(chain: &str, height: u64) -> SealRecord {
        let mut seal_id = vec![0u8; 16];
        seal_id[0..8].copy_from_slice(&height.to_le_bytes());
        seal_id[8..].copy_from_slice(chain.as_bytes().get(..8).unwrap_or(&[0u8; 8]));
        SealRecord {
            chain: chain.to_string(),
            seal_id,
            consumed_at_height: height,
            commitment_hash: Hash::new([0xAA; 32]),
            recorded_at: 1700000000,
        }
    }

    fn test_anchor_record(chain: &str, height: u64) -> AnchorRecord {
        let mut anchor_id = vec![0u8; 16];
        anchor_id[0..8].copy_from_slice(&height.to_le_bytes());
        AnchorRecord {
            chain: chain.to_string(),
            anchor_id,
            block_height: height,
            commitment_hash: Hash::new([0xBB; 32]),
            is_finalized: false,
            confirmations: 0,
            recorded_at: 1700000000,
        }
    }

    #[test]
    fn test_sqlite_open_in_memory() {
        let store = SqliteSealStore::in_memory().unwrap();
        assert_eq!(store.highest_block("bitcoin").unwrap(), 0);
    }

    #[test]
    fn test_sqlite_seal_lifecycle() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        let record = test_seal_record("bitcoin", 100);
        let seal_id = record.seal_id.clone();
        store.save_seal(&record).unwrap();
        assert!(store.is_seal_consumed("bitcoin", &seal_id).unwrap());
        assert!(!store.is_seal_consumed("ethereum", &seal_id).unwrap());
    }

    #[test]
    fn test_sqlite_get_seals() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        store.save_seal(&test_seal_record("bitcoin", 100)).unwrap();
        store.save_seal(&test_seal_record("bitcoin", 200)).unwrap();
        store.save_seal(&test_seal_record("ethereum", 300)).unwrap();

        let btc_seals = store.get_seals("bitcoin").unwrap();
        assert_eq!(btc_seals.len(), 2);

        let eth_seals = store.get_seals("ethereum").unwrap();
        assert_eq!(eth_seals.len(), 1);
    }

    #[test]
    fn test_sqlite_remove_seal() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        let record = test_seal_record("bitcoin", 100);
        let seal_id = record.seal_id.clone();
        store.save_seal(&record).unwrap();
        store.remove_seal("bitcoin", &seal_id).unwrap();
        assert!(!store.is_seal_consumed("bitcoin", &seal_id).unwrap());
    }

    #[test]
    fn test_sqlite_remove_seals_after_height() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        store.save_seal(&test_seal_record("bitcoin", 100)).unwrap();
        store.save_seal(&test_seal_record("bitcoin", 150)).unwrap();
        store.save_seal(&test_seal_record("bitcoin", 200)).unwrap();
        let removed = store.remove_seals_after("bitcoin", 150).unwrap();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_sqlite_anchor_lifecycle() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        let anchor = test_anchor_record("bitcoin", 100);
        let anchor_id = anchor.anchor_id.clone();
        store.save_anchor(&anchor).unwrap();
        assert!(store.has_anchor("bitcoin", &anchor_id).unwrap());

        let pending = store.pending_anchors("bitcoin").unwrap();
        assert_eq!(pending.len(), 1);

        store.finalize_anchor("bitcoin", &anchor_id, 6).unwrap();
        let pending = store.pending_anchors("bitcoin").unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_sqlite_remove_anchors_after_height() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 100))
            .unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 200))
            .unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 300))
            .unwrap();
        let removed = store.remove_anchors_after("bitcoin", 200).unwrap();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_sqlite_highest_block() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 100))
            .unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 300))
            .unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 200))
            .unwrap();
        assert_eq!(store.highest_block("bitcoin").unwrap(), 300);
        assert_eq!(store.highest_block("ethereum").unwrap(), 0);
    }

    #[test]
    fn test_sqlite_duplicate_seal_ignored() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        let record = test_seal_record("bitcoin", 100);
        let _seal_id = record.seal_id.clone();
        store.save_seal(&record).unwrap();
        // Try to save another seal with the same seal_id but different height
        let mut dup = record.clone();
        dup.consumed_at_height = 200;
        store.save_seal(&dup).unwrap();
        let seals = store.get_seals("bitcoin").unwrap();
        // INSERT OR IGNORE means only the first one is stored
        assert_eq!(seals.len(), 1);
        assert_eq!(seals[0].consumed_at_height, 100);
    }

    #[test]
    fn test_sqlite_multi_chain_isolation() {
        let mut store = SqliteSealStore::in_memory().unwrap();
        store.save_seal(&test_seal_record("bitcoin", 100)).unwrap();
        store.save_seal(&test_seal_record("ethereum", 200)).unwrap();
        store
            .save_anchor(&test_anchor_record("bitcoin", 100))
            .unwrap();
        store
            .save_anchor(&test_anchor_record("ethereum", 200))
            .unwrap();

        assert_eq!(store.get_seals("bitcoin").unwrap().len(), 1);
        assert_eq!(store.pending_anchors("bitcoin").unwrap().len(), 1);
    }
}
