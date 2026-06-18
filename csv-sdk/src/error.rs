//! Unified error types for the CSV Adapter meta-crate.
//!
//! This module provides a single error enum that wraps all error sources
//! from the underlying crates, with integration to [`ErrorSuggestion`]
//! from agent_types for machine-actionable fix suggestions.

use thiserror::Error;

use crate::mcp::{FixAction, HasErrorSuggestion, error_codes};

use csv_hash::chain_id::ChainId;

/// Unified error type for all CSV operations.
///
/// Every variant integrates with [`ErrorSuggestion`] to provide
/// machine-actionable fix hints for autonomous agents.
#[derive(Error, Debug)]
pub enum CsvError {
    /// The requested chain is not supported or not enabled.
    #[error("Chain not supported: {0}")]
    ChainNotSupported(ChainId),

    /// The requested operation is not enabled for this chain.
    #[error("Chain operation not enabled: {0}")]
    ChainNotEnabled(String),

    /// The wallet has insufficient funds for the operation.
    #[error("Insufficient funds: available {available}, needed {needed}")]
    InsufficientFunds {
        /// Available balance (chain-specific units).
        available: String,
        /// Required balance.
        needed: String,
        /// Which chain the funds are needed on.
        chain: ChainId,
    },

    /// The specified Sanad ID is invalid or malformed.
    #[error("Invalid Sanad ID: {0}")]
    InvalidSanadId(String),

    /// Invalid input provided to an operation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// The specified Sanad was not found.
    #[error("Sanad not found: {0}")]
    SanadNotFound(String),

    /// The specified transfer was not found.
    #[error("Transfer not found: {0}")]
    TransferNotFound(String),

    /// A Sanad has already been consumed (single-use violation).
    #[error("Sanad already consumed: {0}")]
    SanadAlreadyConsumed(String),

    /// A transfer operation failed.
    #[error("Transfer failed: {error}")]
    TransferFailed {
        /// The transfer identifier.
        transfer_id: String,
        /// Human-readable error message.
        error: String,
    },

    /// The commitment hash is invalid.
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Proof verification failed.
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// The wallet operation failed.
    #[error("Wallet error: {0}")]
    WalletError(String),

    /// Network or RPC communication failed.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// The store backend operation failed.
    #[error("Store error: {0}")]
    StoreError(String),

    /// A builder validation error.
    #[error("Builder validation error: {0}")]
    BuilderError(String),

    /// A deployment error (contract/program deployment failed).
    #[error("Deployment error: {0}")]
    DeploymentError(String),

    /// An event stream error.
    #[error("Event stream error: {0}")]
    EventStreamError(String),

    /// A chain-specific adapter error wrapped from the underlying crate.
    #[error("Adapter error on {chain}: {message}")]
    ProtocolError {
        /// Which chain the error occurred on.
        chain: ChainId,
        /// Human-readable error message.
        message: String,
    },

    /// A required capability is not available on this chain.
    #[error("Capability unavailable on {chain}: {capability}")]
    CapabilityUnavailable {
        /// Which chain the capability is unavailable on.
        chain: ChainId,
        /// The unavailable capability.
        capability: String,
    },

    /// A generic error with a message.
    #[error("CSV error: {0}")]
    Generic(String),

    /// P2P proof transport error (Nostr relay communication failed).
    #[error("P2P transport error: {0}")]
    P2PError(String),

    /// Runtime execution error (from TransferCoordinator).
    #[error("Runtime execution error: {0}")]
    RuntimeError(String),

    /// Signature capability is not available (wallet feature not enabled or derivation failed).
    #[error("Signature capability unavailable: {0}")]
    SignatureCapabilityUnavailable(String),

    /// The runtime coordinator is not available (feature not enabled or not configured).
    #[error("Runtime coordinator not available: {0}")]
    CoordinatorNotAvailable(String),
}

impl CsvError {
    /// Check if this error is retryable (transient).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NetworkError(_) | Self::StoreError(_) | Self::ProtocolError { .. }
        )
    }

    /// Check if this error indicates an insufficient funds condition.
    pub fn is_insufficient_funds(&self) -> bool {
        matches!(self, Self::InsufficientFunds { .. })
    }
}

impl HasErrorSuggestion for CsvError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::ChainNotSupported(_) => error_codes::CSV_CHAIN_NOT_SUPPORTED,
            Self::ChainNotEnabled(_) => error_codes::CSV_CHAIN_NOT_ENABLED,
            Self::InsufficientFunds { .. } => error_codes::CSV_INSUFFICIENT_FUNDS,
            Self::InvalidSanadId(_) => error_codes::CSV_INVALID_SANAD_ID,
            Self::SanadNotFound(_) => error_codes::CSV_SANAD_NOT_FOUND,
            Self::TransferNotFound(_) => error_codes::CSV_TRANSFER_NOT_FOUND,
            Self::SanadAlreadyConsumed(_) => error_codes::CSV_SANAD_ALREADY_CONSUMED,
            Self::TransferFailed { .. } => error_codes::CSV_TRANSFER_FAILED,
            Self::InvalidCommitment(_) => error_codes::CSV_INVALID_COMMITMENT,
            Self::ProofVerificationFailed(_) => error_codes::CSV_PROOF_VERIFICATION_FAILED,
            Self::WalletError(_) => error_codes::CSV_WALLET_ERROR,
            Self::NetworkError(_) => error_codes::CSV_NETWORK_ERROR,
            Self::SerializationError(_) => error_codes::CSV_SERIALIZATION_ERROR,
            Self::ConfigError(_) => error_codes::CSV_CONFIG_ERROR,
            Self::StoreError(_) => error_codes::CSV_STORE_ERROR,
            Self::BuilderError(_) => error_codes::CSV_BUILDER_ERROR,
            Self::DeploymentError(_) => error_codes::CSV_DEPLOYMENT_ERROR,
            Self::EventStreamError(_) => error_codes::CSV_EVENT_STREAM_ERROR,
            Self::ProtocolError { .. } => error_codes::CSV_ADAPTER_ERROR,
            Self::CapabilityUnavailable { .. } => "CSV_CAPABILITY_UNAVAILABLE",
            Self::Generic(_) => error_codes::CSV_GENERIC,
            Self::P2PError(_) => "CSV_P2P_ERROR",
            Self::RuntimeError(_) => "CSV_RUNTIME_ERROR",
            Self::InvalidInput(_) => "CSV_INVALID_INPUT",
            Self::SignatureCapabilityUnavailable(_) => "CSV_SIGNATURE_CAPABILITY_UNAVAILABLE",
            Self::CoordinatorNotAvailable(_) => "CSV_COORDINATOR_NOT_AVAILABLE",
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            Self::ChainNotSupported(chain) => {
                format!(
                    "Chain '{}' is not supported. Supported chains: bitcoin, ethereum, sui, aptos, solana. \
                     Check for SDK updates or enable the chain in configuration.",
                    chain
                )
            }
            Self::ChainNotEnabled(msg) => {
                format!(
                    "Chain operation not enabled: {}. This feature requires RPC configuration \
                     or chain adapter setup. Enable the chain when building the client.",
                    msg
                )
            }
            Self::InsufficientFunds { chain, needed, .. } => {
                format!(
                    "Insufficient funds on {} chain. Fund your wallet before retrying. \
                     Amount needed: {}. Visit https://faucet.{}.csv.dev for testnet funds.",
                    chain, needed, chain
                )
            }
            Self::InvalidSanadId(id) => {
                format!(
                    "Sanad ID '{}' is invalid. Sanad IDs must be 32-byte hex strings (0x + 64 hex chars). \
                     Verify the ID format and try again.",
                    id
                )
            }
            Self::SanadNotFound(id) => {
                format!(
                    "Sanad '{}' not found. Sanads exist in client-side state, not on-chain. \
                     Check: 1) The ID is correct, 2) You own this sanad, 3) It wasn't already consumed.",
                    id
                )
            }
            Self::TransferNotFound(id) => {
                format!(
                    "Transfer '{}' not found. Check the transfer ID is correct \
                     and the transfer was successfully initiated.",
                    id
                )
            }
            Self::SanadAlreadyConsumed(id) => {
                format!(
                    "Sanad '{}' has already been consumed. Sanads are single-use seals. \
                     You cannot transfer or use this sanad again.",
                    id
                )
            }
            Self::TransferFailed { transfer_id, error } => {
                format!(
                    "Transfer '{}' failed: {}. Check source chain RPC connectivity, \
                     wallet funds for gas, and that the sanad exists on the source chain.",
                    transfer_id, error
                )
            }
            Self::InvalidCommitment(msg) => {
                format!(
                    "Invalid commitment: {}. Check the commitment parameters \
                     and regenerate with correct inputs.",
                    msg
                )
            }
            Self::ProofVerificationFailed(_) => {
                "Proof verification failed. Check: 1) Source chain has enough confirmations, \
                 2) The proof wasn't tampered with, 3) The anchor is still valid (no reorg)."
                    .to_string()
            }
            Self::WalletError(msg) => {
                format!(
                    "Wallet error: {}. Check wallet configuration and retry.",
                    msg
                )
            }
            Self::NetworkError(_) => {
                "Network error. Check your internet connection and RPC endpoint configuration. \
                 Try a different RPC provider if the issue persists."
                    .to_string()
            }
            Self::SerializationError(_) => {
                "Serialization error. Check data format matches expected schema.".to_string()
            }
            Self::ConfigError(_) => {
                "Configuration error. Review your config file for missing or invalid fields."
                    .to_string()
            }
            Self::StoreError(_) => {
                "Store error. Check storage is accessible and not corrupted.".to_string()
            }
            Self::BuilderError(_) => {
                "Builder validation error. Check all required fields are set correctly.".to_string()
            }
            Self::EventStreamError(_) => {
                "Event stream error. Check the stream endpoint and retry.".to_string()
            }
            Self::ProtocolError { chain, message } => {
                format!(
                    "Adapter error on {}: {}. Check chain-specific documentation.",
                    chain, message
                )
            }
            Self::CapabilityUnavailable { chain, capability } => {
                format!(
                    "Capability '{}' is not available on {} chain. \
                     This may require: 1) Enabling a feature flag, 2) Chain configuration, 3) SDK update.",
                    capability, chain
                )
            }
            Self::Generic(msg) => {
                format!(
                    "CSV error: {}. Check logs for details or contact support.",
                    msg
                )
            }
            Self::DeploymentError(msg) => {
                format!(
                    "Deployment error: {}. Check deployment configuration and contract code.",
                    msg
                )
            }
            Self::P2PError(msg) => {
                format!(
                    "P2P transport error: {}. Check Nostr relay connectivity and network access.",
                    msg
                )
            }
            Self::RuntimeError(msg) => {
                format!(
                    "Runtime execution error: {}. Check runtime configuration and retry.",
                    msg
                )
            }
            Self::InvalidInput(msg) => {
                format!(
                    "Invalid input: {}. Verify the input format and constraints.",
                    msg
                )
            }
            Self::SignatureCapabilityUnavailable(msg) => {
                format!(
                    "Signature capability unavailable: {}. This operation requires the 'wallet' feature \
                     enabled and proper key derivation. Enable the wallet feature or use a configured runtime.",
                    msg
                )
            }
            Self::CoordinatorNotAvailable(msg) => {
                format!(
                    "Runtime coordinator not available: {}. Transfer operations require the runtime-coordinator \
                     feature enabled and a configured TransferCoordinator. Enable the feature and provide a \
                     runtime instance, or use csv-runtime for production transfers.",
                    msg
                )
            }
        }
    }

    fn docs_url(&self) -> String {
        error_codes::docs_url(self.error_code())
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            Self::InsufficientFunds { chain, needed, .. } => Some(FixAction::FundFromFaucet {
                url: format!("https://faucet.{}.csv.dev", chain),
                amount: needed.clone(),
            }),
            Self::NetworkError(_) => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::new(),
            }),
            Self::ProofVerificationFailed(_) => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/proof-verification".to_string(),
                what: "Check source chain confirmations and proof format".to_string(),
            }),
            Self::CapabilityUnavailable { .. } => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/capabilities".to_string(),
                what: "Check chain capability documentation".to_string(),
            }),
            Self::CoordinatorNotAvailable(_) => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/runtime-coordinator".to_string(),
                what: "Enable runtime-coordinator feature and configure TransferCoordinator".to_string(),
            }),
            _ => None,
        }
    }
}

// Conversion from csv-adapter-core errors
impl From<csv_protocol::error::ProtocolError> for CsvError {
    fn from(err: csv_protocol::error::ProtocolError) -> Self {
        CsvError::Generic(err.to_string())
    }
}

// Conversion from common Rust errors
impl From<std::io::Error> for CsvError {
    fn from(err: std::io::Error) -> Self {
        CsvError::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for CsvError {
    fn from(err: serde_json::Error) -> Self {
        CsvError::SerializationError(err.to_string())
    }
}

impl From<toml::de::Error> for CsvError {
    fn from(err: toml::de::Error) -> Self {
        CsvError::ConfigError(err.to_string())
    }
}

impl From<hex::FromHexError> for CsvError {
    fn from(err: hex::FromHexError) -> Self {
        CsvError::Generic(format!("Hex decoding error: {}", err))
    }
}
