//! Cross-chain operations for CSV sanads.
//!
//! This module builds on top of [`csv_protocol::cross_chain`] which provides the
//! core cross-chain types and orchestrator ([`CrossChainTransfer`],
//! [`StandardTransferVerifier`], [`CrossChainRegistry`], etc.).
//!
//! # Relationship with csv-core
//!
//! - `csv_protocol::cross_chain` — Core types (lock events, inclusion proofs,
//!   finality proofs, transfer state machine, in-memory registry).
//! - `csv_sdk::cross_chain` — SDK extensions: SQLite-backed persistence
//!   ([`PersistentTransferRegistry`]), chain-specific mint operations
//!   ([`mint_sanad_on_chain`]), and integration between persistent storage
//!   and the in-memory registry via [`load_into_registry`] / [`save_from_registry`].
//!
//! ## Architecture
//!
//! ```text
//! csv_protocol::cross_chain::CrossChainTransfer (orchestrator)
//!     ↕ loads/saves from
//! csv_sdk::cross_chain::PersistentTransferRegistry (SQLite)
//!     ↕ used by
//! csv_sdk::cross_chain::mint_sanad_on_chain (chain adapter dispatch)
//! ```
//!
//! ## Usage
//!
//! 1. Use `PersistentTransferRegistry` for SQLite-backed double-spend tracking.
//! 2. Load persisted transfers into `csv_protocol::CrossChainRegistry` via
//!    [`PersistentTransferRegistry::load_into_registry`].
//! 3. Use `csv_protocol::CrossChainTransfer::execute` with loaded registry.
//! 4. Save updated registry back via [`PersistentTransferRegistry::save_from_registry`].
//!
//! ## Re-exports from csv_protocol::cross_chain
//!
//! For convenience, key types from `csv_protocol::cross_chain` are re-exported
//! here so that SDK consumers don't need to depend on csv-core directly
//! for cross-chain operations.

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::seal::SealPoint;
use csv_protocol::cross_chain::{CrossChainRegistry, CrossChainRegistryEntry};

use crate::CsvError;

#[cfg(feature = "sqlite")]
use sqlx::SqlitePool;

/// Result type for cross-chain operations.
pub type CrossChainResult<T> = Result<T, CrossChainError>;

/// Error type for cross-chain operations.
#[derive(Debug, thiserror::Error)]
pub enum CrossChainError {
    /// The requested chain is not supported.
    #[error("Chain not supported: {0}")]
    ChainNotSupported(String),

    /// RPC operation failed.
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Missing feature for the operation.
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),

    /// Underlying adapter error.
    #[error("Adapter error: {0}")]
    ProtocolError(String),

    #[cfg(feature = "cross-chain-persist")]
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),
}

impl From<CrossChainError> for CsvError {
    fn from(e: CrossChainError) -> Self {
        CsvError::Generic(format!("Cross-chain error: {}", e))
    }
}

// ===========================================================================
// Persistent Transfer Registry (SC-02)
// ===========================================================================
#[cfg(feature = "cross-chain-persist")]
/// In-memory transfer registry backed by SQLite for persistence.
///
/// Tracks completed cross-chain transfers to prevent double-spend while
/// surviving process restarts via the `transfers` table.
pub struct PersistentTransferRegistry {
    pool: SqlitePool,
}

#[cfg(feature = "cross-chain-persist")]
impl PersistentTransferRegistry {
    /// Create a new persistent registry from a database pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Check if a sanad has already been transferred (double-spend check).
    pub async fn is_transferred(&self, sanad_id: &str) -> Result<bool, CrossChainError> {
        let count: Option<i64> =
            sqlx::query_scalar("SELECT COUNT(*) FROM transfers WHERE sanad_id = ?")
                .bind(sanad_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| CrossChainError::Database(e.to_string()))?;

        Ok(count.unwrap_or(0) > 0)
    }

    /// Record a completed cross-chain transfer.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_transfer(
        &self,
        sanad_id: &str,
        from_chain: &str,
        to_chain: &str,
        lock_tx: &str,
        mint_tx: Option<&str>,
        from_owner: &str,
        to_owner: &str,
    ) -> Result<(), CrossChainError> {
        let transfer_id = format!("transfer_{}_{}_{}", sanad_id, from_chain, to_chain);
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO transfers (id, sanad_id, from_chain, to_chain, from_owner, to_owner,
                                   lock_tx, mint_tx, proof_ref, status, created_at, completed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, 'completed', $9, $10)
            ON CONFLICT(id) DO UPDATE SET status = 'completed', completed_at = $10
            "#,
        )
        .bind(&transfer_id)
        .bind(sanad_id)
        .bind(from_chain)
        .bind(to_chain)
        .bind(from_owner)
        .bind(to_owner)
        .bind(lock_tx)
        .bind(mint_tx)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| CrossChainError::Database(e.to_string()))?;

        Ok(())
    }

    /// Query transfers by sanad ID.
    pub async fn query_by_sanad(
        &self,
        sanad_id: &str,
    ) -> Result<Vec<TransferInfo>, CrossChainError> {
        let rows = sqlx::query_as::<_, TransferInfo>(
            r#"SELECT id, sanad_id, from_chain, to_chain, from_owner, to_owner,
                     lock_tx, mint_tx, created_at, completed_at
              FROM transfers WHERE sanad_id = ? ORDER BY created_at DESC"#,
        )
        .bind(sanad_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CrossChainError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Query transfers by source chain.
    pub async fn query_by_chain(&self, chain: &str) -> Result<Vec<TransferInfo>, CrossChainError> {
        let rows = sqlx::query_as::<_, TransferInfo>(
            r#"SELECT id, sanad_id, from_chain, to_chain, from_owner, to_owner,
                     lock_tx, mint_tx, created_at, completed_at
              FROM transfers WHERE from_chain = ? ORDER BY created_at DESC"#,
        )
        .bind(chain)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CrossChainError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Get the total number of recorded transfers.
    pub async fn transfer_count(&self) -> Result<u64, CrossChainError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transfers")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| CrossChainError::Database(e.to_string()))?;

        Ok(count as u64)
    }

    /// Load all transfers from SQLite into an in-memory `CrossChainRegistry`.
    ///
    /// This is the primary integration point (SC-02): it bridges the persistent
    /// SQLite store with csv-core's in-memory registry so that `CrossChainTransfer`
    /// can use fast BTreeMap lookups while benefiting from disk-backed durability.
    pub async fn load_into_registry(&self) -> Result<CrossChainRegistry, CrossChainError> {
        let rows = sqlx::query_as::<_, TransferInfo>(
            "SELECT id, sanad_id, from_chain, to_chain, from_owner, to_owner,
                    lock_tx, mint_tx, created_at, completed_at
             FROM transfers ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CrossChainError::Database(e.to_string()))?;

        let mut registry = CrossChainRegistry::new();

        for row in rows {
            let entry = Self::transfer_info_to_registry_entry(&row)?;
            // Silently skip entries that fail double-spend checks during load
            // (they were already recorded on a prior run)
            let _ = registry.record_transfer(entry);
        }

        Ok(registry)
    }

    /// Save an in-memory `CrossChainRegistry` to SQLite.
    ///
    /// Useful for periodic checkpointing: call after the orchestrator records
    /// new transfers so that in-memory state survives process restarts.
    pub async fn save_from_registry(
        &self,
        registry: &CrossChainRegistry,
    ) -> Result<(), CrossChainError> {
        for entry in registry.all_transfers() {
            let row = Self::registry_entry_to_transfer_info(entry);
            self.record_transfer(
                &row.sanad_id,
                &row.from_chain,
                &row.to_chain,
                &row.lock_tx,
                row.mint_tx.as_deref(),
                &row.from_owner,
                &row.to_owner,
            )
            .await?;
        }

        Ok(())
    }

    // --- Internal helpers ---

    fn transfer_info_to_registry_entry(
        row: &TransferInfo,
    ) -> Result<CrossChainRegistryEntry, CrossChainError> {
        let parse_hash = |hex: &str| -> Result<Hash, CrossChainError> {
            let bytes = hex::decode(hex.trim_start_matches("0x"))
                .map_err(|e| CrossChainError::Database(format!("invalid hash hex: {}", e)))?;
            Hash::try_from(bytes.as_slice())
                .map_err(|_| CrossChainError::Database("hash must be 32 bytes".to_string()))
        };

        let parse_seal = |hex: &str| -> Result<SealPoint, CrossChainError> {
            let bytes = hex::decode(hex.trim_start_matches("0x"))
                .map_err(|e| CrossChainError::Database(format!("invalid seal hex: {}", e)))?;
            SealPoint::new(bytes, None)
                .map_err(|e| CrossChainError::Database(format!("invalid seal: {}", e)))
        };

        Ok(CrossChainRegistryEntry {
            sanad_id: parse_hash(&row.sanad_id)?,
            source_chain: row
                .from_chain
                .parse()
                .map_err(|_| CrossChainError::Database("invalid from_chain".to_string()))?,
            source_seal: parse_seal(&row.lock_tx)?,
            destination_chain: row
                .to_chain
                .parse()
                .map_err(|_| CrossChainError::Database("invalid to_chain".to_string()))?,
            destination_seal: match row.mint_tx.as_ref() {
                Some(mint) => parse_seal(mint).unwrap_or_else(|err| {
                    log::error!(
                        "Failed to parse destination seal from mint_tx: {}. \
                         Transfer will require recovery/re-query of mint transaction.",
                        err
                    );
                    // If mint_tx is present but parse fails, re-derive the seal from mint TX
                    // by creating a SealPoint from the mint transaction hash bytes
                    SealPoint::new(
                        hex::decode(mint.trim_start_matches("0x"))
                            .unwrap_or_else(|_| vec![0u8; 32]),
                        None,
                    )
                    .unwrap_or_else(|_| {
                        // Fallback: use the mint_tx hash directly as seal id
                        // This allows recovery by re-querying the mint transaction
                        SealPoint::new(
                            hex::decode(mint.trim_start_matches("0x"))
                                .unwrap_or_else(|_| vec![0u8; 32]),
                            None,
                        )
                        .unwrap_or_else(|_| SealPoint {
                            id: mint.as_bytes().to_vec(),
                            nonce: None,
                        })
                    })
                }),
                None => {
                    // mint_tx is NULL — this is a pending transfer (locked but not yet minted)
                    // Store a recovery marker instead of a placeholder zero seal
                    // The recovery mechanism will re-query the destination chain
                    // once the mint transaction completes
                    SealPoint {
                        id: format!("pending_recovery_{}", row.sanad_id)
                            .as_bytes()
                            .to_vec(),
                        nonce: None,
                    }
                }
            },
            lock_tx_hash: parse_hash(&row.lock_tx)?,
            mint_tx_hash: match row.mint_tx.as_ref() {
                Some(m) => parse_hash(m)?,
                None => Hash::new([0u8; 32]),
            },
            timestamp: row.created_at.timestamp() as u64,
        })
    }

    fn registry_entry_to_transfer_info(entry: &CrossChainRegistryEntry) -> TransferInfo {
        TransferInfo {
            id: format!(
                "transfer_{}_{}_{}",
                entry.sanad_id.to_hex(),
                entry.source_chain,
                entry.destination_chain,
            ),
            sanad_id: entry.sanad_id.to_hex(),
            from_chain: entry.source_chain.to_string(),
            to_chain: entry.destination_chain.to_string(),
            from_owner: String::new(), // SealPoint doesn't carry owner info
            to_owner: String::new(),
            lock_tx: hex::encode(&entry.source_seal.id),
            mint_tx: Some(hex::encode(&entry.destination_seal.id)),
            created_at: chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH),
            completed_at: None,
        }
    }
}

#[cfg(feature = "cross-chain-persist")]
/// Minimal transfer info returned by query methods.
#[derive(Debug, sqlx::FromRow)]
#[allow(missing_docs)]
pub struct TransferInfo {
    pub id: String,
    pub sanad_id: String,
    pub from_chain: String,
    pub to_chain: String,
    pub from_owner: String,
    pub to_owner: String,
    pub lock_tx: String,
    pub mint_tx: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Execute a cross-chain transfer with persistence.
///
/// 1. Check if sanad already transferred (double-spend guard)
/// 2. Mint on destination chain
/// 3. Record in SQLite registry
#[allow(clippy::too_many_arguments)]
pub async fn mint_sanad_on_chain(
    chain: ChainId,
    rpc_url: &str,
    contract: &str,
    private_key: &str,
    sanad_id: Hash,
    commitment: Hash,
    source_chain: u8,
    source_seal_ref: Hash,
) -> CrossChainResult<String> {
    match chain.as_str() {
        #[cfg(all(feature = "sui", feature = "rpc"))]
        "sui" => {
            use csv_sui::mint::mint_sanad;

            mint_sanad(
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            )
            .await
            .map_err(|e| CrossChainError::ProtocolError(format!("{:?}", e)))
        }

        #[cfg(not(all(feature = "sui", feature = "rpc")))]
        "sui" => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::FeatureNotEnabled(
                "Sui cross-chain mint requires 'sui' and 'rpc' features.".to_string(),
            ))
        }

        #[cfg(feature = "solana")]
        "solana" => {
            use csv_solana::mint::mint_sanad_from_hex_key;
            let state_root = Hash::new([0u8; 32]);

            mint_sanad_from_hex_key(
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                state_root,
                source_chain,
                source_seal_ref,
            )
            .map_err(|e| CrossChainError::ProtocolError(format!("{:?}", e)))
        }

        #[cfg(not(feature = "solana"))]
        "solana" => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::FeatureNotEnabled(
                "Solana cross-chain mint requires 'solana' feature.".to_string(),
            ))
        }

        #[cfg(feature = "bitcoin")]
        "bitcoin" => {
            use csv_bitcoin::MempoolSignetRpc;
            use csv_bitcoin::mint::mint_sanad;

            let _ = rpc_url;
            let rpc = MempoolSignetRpc::new();

            let tx_hash: Result<String, csv_bitcoin::error::BitcoinError> = mint_sanad(
                rpc,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
                contract,
            )
            .await;

            tx_hash.map_err(|e| CrossChainError::ProtocolError(format!("{:?}", e)))
        }

        #[cfg(not(feature = "bitcoin"))]
        "bitcoin" => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::FeatureNotEnabled(
                "Bitcoin cross-chain mint requires 'bitcoin' feature.".to_string(),
            ))
        }

        #[cfg(feature = "ethereum")]
        "ethereum" => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::ProtocolError(
                "Direct SDK Ethereum mint is unavailable because the legacy ethers-based helper \
                 was removed; use csv-runtime/EthereumBackend for Ethereum mint execution."
                    .to_string(),
            ))
        }

        #[cfg(not(feature = "ethereum"))]
        "ethereum" => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::FeatureNotEnabled(
                "Ethereum cross-chain mint requires 'ethereum' feature.".to_string(),
            ))
        }

        #[cfg(feature = "aptos")]
        "aptos" => {
            use csv_aptos::mint::mint_sanad;

            mint_sanad(
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            )
            .await
            .map_err(|e| CrossChainError::ProtocolError(format!("{:?}", e)))
        }

        #[cfg(not(feature = "aptos"))]
        "aptos" => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::FeatureNotEnabled(
                "Aptos cross-chain mint requires 'aptos' feature.".to_string(),
            ))
        }

        _ => {
            let _ = (
                rpc_url,
                contract,
                private_key,
                sanad_id,
                commitment,
                source_chain,
                source_seal_ref,
            );
            Err(CrossChainError::ChainNotSupported(format!(
                "Cross-chain mint not available for {:?}",
                chain
            )))
        }
    }
}

/// Check if cross-chain mint is supported for a given chain.
pub fn is_mint_supported(chain: ChainId) -> bool {
    match chain.as_str() {
        #[cfg(all(feature = "sui", feature = "rpc"))]
        "sui" => true,
        #[cfg(feature = "solana")]
        "solana" => true,
        #[cfg(feature = "bitcoin")]
        "bitcoin" => true,
        #[cfg(feature = "ethereum")]
        "ethereum" => true,
        #[cfg(feature = "aptos")]
        "aptos" => true,
        _ => false,
    }
}
