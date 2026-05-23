//! Error types for csv-protocol

use thiserror::Error;

/// Error type for protocol operations
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Invalid state transition
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    /// Replay detected
    #[error("Replay detected: {0}")]
    ReplayDetected(String),

    /// Finality error
    #[error("Finality error: {0}")]
    FinalityError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Codec error
    #[error("Codec error: {0}")]
    CodecError(String),
}

impl From<csv_codec::CodecError> for ProtocolError {
    fn from(err: csv_codec::CodecError) -> Self {
        ProtocolError::CodecError(err.to_string())
    }
}

/// Result type for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;
