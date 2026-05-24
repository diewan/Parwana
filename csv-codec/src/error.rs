//! Codec errors

use thiserror::Error;

/// Codec errors
#[derive(Debug, Error)]
pub enum CodecError {
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Integrity error (e.g., checksum mismatch)
    #[error("Integrity error: {0}")]
    IntegrityError(String),

    /// Schema validation error
    #[error("Schema validation error: {0}")]
    SchemaValidationError(String),
}

/// Codec result type
pub type Result<T> = std::result::Result<T, CodecError>;
