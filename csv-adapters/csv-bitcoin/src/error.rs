//! Bitcoin adapter error types

use csv_core::mcp::{FixAction, HasErrorSuggestion, error_codes};
use thiserror::Error;

/// Bitcoin adapter specific errors
#[derive(Error, Debug)]
pub enum BitcoinError {
    /// Bitcoin RPC error
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    /// UTXO already spent
    #[error("UTXO already spent: {0}")]
    UTXOSpent(String),

    /// Invalid Merkle proof
    #[error("Invalid Merkle proof: {0}")]
    InvalidMerkleProof(String),

    /// Registry full (max size reached)
    #[error("Registry full: {0}")]
    RegistryFull(String),

    /// Reorg detected
    #[error("Reorg detected at height {height}, depth {depth}")]
    ReorgDetected { height: u64, depth: u64 },

    /// Insufficient confirmations
    #[error("Insufficient confirmations: got {got}, need {need}")]
    InsufficientConfirmations { got: u64, need: u64 },

    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// MPC tree/building error
    #[error("MPC error: {0}")]
    MpcError(String),

    /// Storage error (SQLite persistence)
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Transaction building/signing error
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// Insufficient funds
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),

    /// Wrapper for core adapter errors
    #[error(transparent)]
    CoreError(#[from] csv_core::ProtocolError),
}

impl From<BitcoinError> for csv_core::ProtocolError {
    fn from(err: BitcoinError) -> Self {
        match err {
            BitcoinError::CoreError(e) => e,
            BitcoinError::RpcError(msg) => csv_core::ProtocolError::NetworkError(msg),
            BitcoinError::TransactionNotFound(msg) => csv_core::ProtocolError::Generic(msg),
            BitcoinError::UTXOSpent(msg) => csv_core::ProtocolError::InvalidSeal(msg),
            BitcoinError::InvalidMerkleProof(msg) => {
                csv_core::ProtocolError::InclusionProofFailed(msg)
            }
            BitcoinError::RegistryFull(msg) => csv_core::ProtocolError::Generic(msg),
            BitcoinError::ReorgDetected { height, depth } => csv_core::ProtocolError::ReorgInvalid(
                format!("Reorg at height {}, depth {}", height, depth),
            ),
            BitcoinError::InsufficientConfirmations { got, need } => {
                csv_core::ProtocolError::FinalityNotReached(format!(
                    "Got {} confirmations, need {}",
                    got, need
                ))
            }
            BitcoinError::InvalidInput(msg) => csv_core::ProtocolError::InvalidInput(msg),
            BitcoinError::MpcError(msg) => {
                csv_core::ProtocolError::Generic(format!("MPC: {}", msg))
            }
            BitcoinError::StorageError(msg) => csv_core::ProtocolError::StorageError(msg),
            BitcoinError::TransactionError(msg) => csv_core::ProtocolError::Generic(msg),
            BitcoinError::InsufficientFunds(msg) => csv_core::ProtocolError::Generic(msg),
        }
    }
}

impl BitcoinError {
    /// Whether this error is transient and may be retried
    pub fn is_transient(&self) -> bool {
        match self {
            BitcoinError::RpcError(_) => true,
            BitcoinError::TransactionNotFound(_) => true,
            BitcoinError::InsufficientConfirmations { .. } => true,
            BitcoinError::MpcError(_) => true,
            BitcoinError::ReorgDetected { .. } => true,
            BitcoinError::InvalidInput(_) => false,
            BitcoinError::UTXOSpent(_) => false,
            BitcoinError::InvalidMerkleProof(_) => false,
            BitcoinError::RegistryFull(_) => false,
            BitcoinError::CoreError(_) => false,
            BitcoinError::StorageError(_) => false,
            BitcoinError::TransactionError(_) => false,
            BitcoinError::InsufficientFunds(_) => false,
        }
    }
}

impl HasErrorSuggestion for BitcoinError {
    fn error_code(&self) -> &'static str {
        match self {
            BitcoinError::RpcError(_) => error_codes::BTC_RPC_ERROR,
            BitcoinError::TransactionNotFound(_) => error_codes::BTC_TRANSACTION_NOT_FOUND,
            BitcoinError::UTXOSpent(_) => error_codes::BTC_UTXO_SPENT,
            BitcoinError::InvalidMerkleProof(_) => error_codes::BTC_INVALID_MERKLE_PROOF,
            BitcoinError::RegistryFull(_) => error_codes::BTC_REGISTRY_FULL,
            BitcoinError::ReorgDetected { .. } => error_codes::BTC_REORG_DETECTED,
            BitcoinError::InsufficientConfirmations { .. } => {
                error_codes::BTC_INSUFFICIENT_CONFIRMATIONS
            }
            BitcoinError::InvalidInput(_) => error_codes::BTC_RPC_ERROR,
            BitcoinError::MpcError(_) => "BTC_MPC_ERROR",
            BitcoinError::StorageError(_) => "BTC_STORAGE_ERROR",
            BitcoinError::CoreError(e) => e.error_code(),
            BitcoinError::TransactionError(_) => "BTC_TRANSACTION_ERROR",
            BitcoinError::InsufficientFunds(_) => error_codes::BTC_INSUFFICIENT_FUNDS,
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            BitcoinError::RpcError(_) => "Bitcoin RPC call failed. Check: \
                 1) Your internet connection, \
                 2) The RPC endpoint is accessible (try https://mempool.space/api), \
                 3) Rate limits haven't been exceeded. \
                 Retry with a different RPC provider if needed."
                .to_string(),
            BitcoinError::StorageError(_) => "Database storage error. Check: \
                 1) Disk space is available, \
                 2) The data directory has write permissions, \
                 3) The database file is not corrupted. \
                 Try restarting with a clean data directory."
                .to_string(),
            BitcoinError::TransactionNotFound(txid) => {
                format!(
                    "Transaction {} was not found. It may not have been broadcast yet, \
                     or it was dropped from the mempool. Wait a few minutes and retry, \
                     or rebroadcast the transaction.",
                    txid
                )
            }
            BitcoinError::UTXOSpent(outpoint) => {
                format!(
                    "The UTXO {} has already been spent. \
                     Use a different, unspent UTXO. Check your wallet balance \
                     and available UTXOs.",
                    outpoint
                )
            }
            BitcoinError::InvalidMerkleProof(_) => {
                "The Merkle proof is invalid. This may indicate: \
                 1) The transaction is not in the claimed block, \
                 2) The block hash is incorrect, or \
                 3) The proof structure is malformed. \
                 Regenerate the proof from a confirmed transaction."
                    .to_string()
            }
            BitcoinError::RegistryFull(_) => "The seal registry has reached maximum capacity. \
                 Finalize existing seals or use a different registry instance. \
                 Contact the registry operator for capacity increases."
                .to_string(),
            BitcoinError::ReorgDetected { height, depth } => {
                format!(
                    "Chain reorganization detected at height {} with depth {}. \
                     Your anchor may be invalid. Wait for the reorg to complete \
                     and republish at the new chain tip.",
                    height, depth
                )
            }
            BitcoinError::InsufficientConfirmations { got, need } => {
                format!(
                    "Insufficient confirmations: got {}, need {}. \
                     Wait for {} more block confirmations (approximately {} minutes).",
                    got,
                    need,
                    need - got,
                    (need - got) * 10
                )
            }
            BitcoinError::InvalidInput(msg) => format!("Check the input parameters: {}", msg),
            BitcoinError::MpcError(msg) => format!(
                "MPC tree operation failed: {}. Check commitment data and retry.",
                msg
            ),
            BitcoinError::CoreError(e) => e.suggested_fix(),
            BitcoinError::TransactionError(msg) => format!("Transaction building/signing failed: {}. Check input data and retry.", msg),
            BitcoinError::InsufficientFunds(msg) => format!("{} Add more Bitcoin to your wallet or use a different address with sufficient balance.", msg),
        }
    }

    fn docs_url(&self) -> String {
        match self {
            BitcoinError::CoreError(e) => e.docs_url(),
            BitcoinError::MpcError(_) => "https://docs.csv.network/errors/mpc".to_string(),
            BitcoinError::TransactionError(_) => "https://docs.csv.network/errors/bitcoin".to_string(),
            BitcoinError::InsufficientFunds(_) => "https://docs.csv.network/errors/bitcoin".to_string(),
            _ => error_codes::docs_url(self.error_code()),
        }
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            BitcoinError::RpcError(_) => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::from([(
                    "rpc_endpoint".to_string(),
                    "https://mempool.space/api".to_string(),
                )]),
            }),
            BitcoinError::InsufficientConfirmations { need, .. } => {
                Some(FixAction::WaitForConfirmations {
                    confirmations: *need as u32,
                    estimated_seconds: *need * 600,
                })
            }
            BitcoinError::ReorgDetected { .. } => Some(FixAction::CheckState {
                url: "https://mempool.space".to_string(),
                what: "Check current Bitcoin chain tip".to_string(),
            }),
            BitcoinError::TransactionNotFound(_) => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::from([(
                    "wait_seconds".to_string(),
                    "60".to_string(),
                )]),
            }),
            BitcoinError::CoreError(e) => e.fix_action(),
            BitcoinError::InvalidInput(_) => None,
            BitcoinError::TransactionError(_) => None,
            BitcoinError::InsufficientFunds(_) => None,
            _ => None,
        }
    }
}

/// Result type for Bitcoin adapter operations
pub type BitcoinResult<T> = Result<T, BitcoinError>;
