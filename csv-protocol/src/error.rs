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

    /// Seal replay detected
    #[error("Seal replay detected: {0}")]
    SealReplay(String),

    /// Invalid seal
    #[error("Invalid seal: {0}")]
    InvalidSeal(String),

    /// Finality error
    #[error("Finality error: {0}")]
    FinalityError(String),

    /// Finality not reached
    #[error("Finality not reached: {0}")]
    FinalityNotReached(String),

    /// Proof is too old (anchor buried deeper than the freshness bound).
    #[error("Proof expired: {0}")]
    ProofExpired(String),

    /// Inclusion proof failed
    #[error("Inclusion proof failed: {0}")]
    InclusionProofFailed(String),

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

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Publish failed
    #[error("Publish failed: {0}")]
    PublishFailed(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Generic error with message
    #[error("{0}")]
    Generic(String),

    /// Unsupported protocol version
    #[error("Unsupported protocol version: found {found}, max supported {max_supported}")]
    UnsupportedVersion { found: u16, max_supported: u16 },

    /// Malformed envelope
    #[error("Malformed envelope")]
    MalformedEnvelope,

    /// Reorg invalid
    #[error("Reorg invalid: {0}")]
    ReorgInvalid(String),
}

impl From<csv_codec::CodecError> for ProtocolError {
    fn from(err: csv_codec::CodecError) -> Self {
        ProtocolError::CodecError(err.to_string())
    }
}

/// Result type for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;
