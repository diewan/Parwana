//! Error types for Celestia adapter
//!
//! This module defines all error types specific to Celestia DA operations,
//! including IPFS storage errors and commitment verification failures.

use thiserror::Error;

/// Errors that can occur when interacting with Celestia DA layer
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CelestiaError {
    /// Invalid input parameter
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Namespace error - invalid or malformed namespace
    #[error("Invalid namespace: {0}")]
    InvalidNamespace(String),

    /// Blob too large for Celestia (exceeds maximum blob size)
    #[error("Blob exceeds maximum size: {size} bytes (max: {max})")]
    BlobTooLarge { size: usize, max: usize },

    /// Blob is empty
    #[error("Blob cannot be empty")]
    EmptyBlob,

    /// Commitment verification failed
    #[error("Commitment verification failed: {0}")]
    CommitmentVerificationFailed(String),

    /// Proof ID error
    #[error("Invalid proof ID: {0}")]
    InvalidProofId(String),

    /// RPC error when communicating with Celestia node
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// IPFS storage error
    #[error("IPFS error: {0}")]
    IpfsError(String),

    /// Invalid CID format
    #[error("Invalid CID: {0}")]
    InvalidCid(String),

    /// Data not found on DA layer
    #[error("Data not found: {0}")]
    DataNotFound(String),

    /// Timeout waiting for DA inclusion
    #[error("Timeout waiting for DA inclusion after {0} attempts")]
    InclusionTimeout(u32),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Seal protocol error
    #[error("Seal protocol error: {0}")]
    SealProtocolError(String),

    /// Fraud proof error
    #[error("Fraud proof error: {0}")]
    FraudProofError(String),

    /// Metadata validation failed
    #[error("Metadata validation failed: {0}")]
    MetadataValidationFailed(String),

    /// Height not found or invalid
    #[error("Invalid or unavailable height: {0}")]
    InvalidHeight(u64),

    /// Namespace mismatch
    #[error("Namespace mismatch: expected {expected}, got {actual}")]
    NamespaceMismatch { expected: String, actual: String },

    /// Feature not enabled
    #[error("Feature '{0}' is not enabled")]
    FeatureNotEnabled(String),

    /// Generic internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type alias for Celestia operations
pub type Result<T> = std::result::Result<T, CelestiaError>;

impl CelestiaError {
    /// Create a blob too large error with default max size
    pub fn blob_too_large(size: usize) -> Self {
        Self::BlobTooLarge {
            size,
            max: MAX_BLOB_SIZE,
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RpcError(_)
                | Self::NetworkError(_)
                | Self::InclusionTimeout(_)
                | Self::DataNotFound(_)
        )
    }

    /// Check if this error is related to IPFS
    pub fn is_ipfs_error(&self) -> bool {
        matches!(self, Self::IpfsError(_) | Self::InvalidCid(_))
    }
}

/// Maximum blob size for Celestia (2MB)
pub const MAX_BLOB_SIZE: usize = 2 * 1024 * 1024;

/// Maximum IPFS data size (100MB for large STARK proofs)
pub const MAX_IPFS_DATA_SIZE: usize = 100 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = CelestiaError::InvalidNamespace("test".to_string());
        assert!(err.to_string().contains("Invalid namespace"));
    }

    #[test]
    fn test_blob_too_large() {
        let err = CelestiaError::blob_too_large(3 * 1024 * 1024);
        assert!(err.to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn test_retryable_errors() {
        assert!(CelestiaError::RpcError("test".to_string()).is_retryable());
        assert!(CelestiaError::NetworkError("test".to_string()).is_retryable());
        assert!(!CelestiaError::InvalidNamespace("test".to_string()).is_retryable());
    }

    #[test]
    fn test_ipfs_errors() {
        assert!(CelestiaError::IpfsError("test".to_string()).is_ipfs_error());
        assert!(CelestiaError::InvalidCid("test".to_string()).is_ipfs_error());
        assert!(!CelestiaError::RpcError("test".to_string()).is_ipfs_error());
    }
}
