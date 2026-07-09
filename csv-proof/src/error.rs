//! Error types for csv-proof

use thiserror::Error;

/// Error type for proof operations
#[derive(Debug, Error)]
pub enum ProofError {
    /// Invalid proof structure
    #[error("Invalid proof structure: {0}")]
    InvalidStructure(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    /// Requested proof system is not implemented
    #[error("Proof system not implemented: {0}")]
    NotImplemented(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Codec error
    #[error("Codec error: {0}")]
    CodecError(String),
}

impl From<csv_codec::CodecError> for ProofError {
    fn from(err: csv_codec::CodecError) -> Self {
        ProofError::CodecError(err.to_string())
    }
}

/// Result type for proof operations
pub type Result<T> = std::result::Result<T, ProofError>;
