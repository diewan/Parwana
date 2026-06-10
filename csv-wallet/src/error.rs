//! Unified wallet error types

use thiserror::Error;

/// Unified error type for wallet operations
#[derive(Debug, Error)]
pub enum WalletError {
    /// Key generation error
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Key derivation error
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Signing error
    #[error("Signing failed: {0}")]
    Signing(String),

    /// Signature verification error
    #[error("Signature verification failed: {0}")]
    Verification(String),

    /// Key storage error
    #[error("Key storage error: {0}")]
    Storage(String),

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    /// Chain not supported
    #[error("Chain not supported: {0}")]
    UnsupportedChain(String),

    /// Wallet not found
    #[error("Wallet not found")]
    WalletNotFound,

    /// Invalid passphrase
    #[error("Invalid passphrase")]
    InvalidPassphrase,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for wallet operations
pub type Result<T> = std::result::Result<T, WalletError>;
