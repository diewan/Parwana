//! Storage errors
//!
//! This module defines error types for storage operations.

/// Storage error
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Key not found
    #[error("Key not found")]
    KeyNotFound,

    /// Database connection error
    #[error("Database connection error: {0}")]
    ConnectionError(String),
}

/// Replay database error
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayDbError {
    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Entry already exists (replay attempt or concurrent insert)
    #[error("Entry already exists")]
    AlreadyExists,

    /// Entry not found
    #[error("Entry not found")]
    NotFound,
}

impl From<StorageError> for ReplayDbError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e.to_string())
    }
}
