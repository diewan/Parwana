//! Sui adapter error types
//!
//! This module provides a comprehensive error taxonomy for the Sui adapter,
//! with chain-specific error variants and recovery guidance.

use csv_core::mcp::{FixAction, HasErrorSuggestion, error_codes};
use thiserror::Error;

/// Comprehensive error types for the Sui adapter.
///
/// Each variant includes context for debugging and recovery guidance.
#[derive(Error, Debug)]
pub enum SuiError {
    /// Error during RPC communication with Sui node.
    /// Recovery: Retry with backoff, switch to fallback RPC endpoint.
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Seal object has already been consumed.
    /// Recovery: This is a fatal error for seal replay attempts. Check object state.
    #[error("Object already used: {0}")]
    ObjectUsed(String),

    /// State proof verification failed (object existence/ownership).
    /// Recovery: Re-fetch proof from different RPC endpoint, check for reorg.
    #[error("State proof verification failed: {0}")]
    StateProofFailed(String),

    /// Event proof verification failed (event emission verification).
    /// Recovery: Re-verify transaction, check event index and data.
    #[error("Event proof verification failed: {0}")]
    EventProofFailed(String),

    /// Checkpoint certification verification failed.
    /// Recovery: Check validator signatures, verify epoch boundaries.
    #[error("Checkpoint certification failed: {0}")]
    CheckpointFailed(String),

    /// Transaction submission or execution failed.
    /// Recovery: Check transaction dry-run error, adjust gas parameters.
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    /// Error during serialization/deserialization.
    /// Recovery: This is a programming error. Check data format compatibility.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Timeout while waiting for transaction confirmation.
    /// Recovery: Resubmit transaction with higher gas, check mempool status.
    #[error("Transaction confirmation timeout after {timeout_ms}ms: {tx_digest}")]
    ConfirmationTimeout { tx_digest: String, timeout_ms: u64 },

    /// Chain reorg detected affecting anchor validity.
    /// Recovery: Re-publish commitment at new chain tip.
    #[error("Chain reorg detected at checkpoint {checkpoint}: anchor may be invalid")]
    ReorgDetected { checkpoint: u64 },

    /// Network mismatch (e.g., mainnet seal on testnet).
    /// Recovery: Ensure network configuration matches chain ID.
    #[error("Network mismatch: expected chain_id {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },

    /// Configuration error - missing or invalid configuration value.
    /// Recovery: Check configuration and set required values.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Feature not enabled - required feature is not compiled in.
    /// Recovery: Rebuild with the required feature enabled.
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),

    /// Core adapter error from csv-adapter-core.
    #[error(transparent)]
    CoreError(#[from] csv_core::ProtocolError),
}

impl SuiError {
    /// Returns true if this error is potentially transient and should be retried.
    pub fn is_transient(&self) -> bool {
        match self {
            SuiError::RpcError(_)
            | SuiError::ConfirmationTimeout { .. }
            | SuiError::TransactionFailed(_) => true,
            SuiError::ObjectUsed(_)
            | SuiError::StateProofFailed(_)
            | SuiError::EventProofFailed(_)
            | SuiError::CheckpointFailed(_)
            | SuiError::SerializationError(_)
            | SuiError::ReorgDetected { .. }
            | SuiError::NetworkMismatch { .. }
            | SuiError::ConfigurationError(_)
            | SuiError::FeatureNotEnabled(_)
            | SuiError::CoreError(_) => false,
        }
    }

    /// Construct an error for transaction timeout
    pub fn timeout(tx_digest: &str, timeout_ms: u64) -> Self {
        SuiError::ConfirmationTimeout {
            tx_digest: tx_digest.to_string(),
            timeout_ms,
        }
    }

    /// Construct an error for chain reorg
    pub fn reorg(checkpoint: u64) -> Self {
        SuiError::ReorgDetected { checkpoint }
    }
}

impl HasErrorSuggestion for SuiError {
    fn error_code(&self) -> &'static str {
        match self {
            SuiError::RpcError(_) => error_codes::SUI_RPC_ERROR,
            SuiError::ObjectUsed(_) => error_codes::SUI_OBJECT_USED,
            SuiError::StateProofFailed(_) => error_codes::SUI_STATE_PROOF_FAILED,
            SuiError::EventProofFailed(_) => error_codes::SUI_EVENT_PROOF_FAILED,
            SuiError::CheckpointFailed(_) => error_codes::SUI_CHECKPOINT_FAILED,
            SuiError::TransactionFailed(_) => error_codes::SUI_TRANSACTION_FAILED,
            SuiError::SerializationError(_) => error_codes::SUI_SERIALIZATION_ERROR,
            SuiError::ConfirmationTimeout { .. } => error_codes::SUI_CONFIRMATION_TIMEOUT,
            SuiError::ReorgDetected { .. } => error_codes::SUI_REORG_DETECTED,
            SuiError::NetworkMismatch { .. } => error_codes::SUI_NETWORK_MISMATCH,
            SuiError::ConfigurationError(_) => "SUI_CONFIGURATION_ERROR",
            SuiError::FeatureNotEnabled(_) => "SUI_FEATURE_NOT_ENABLED",
            SuiError::CoreError(e) => e.error_code(),
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            SuiError::RpcError(_) => "Sui RPC call failed. Check: \
                 1) Your internet connection, \
                 2) The RPC endpoint is accessible (try https://fullnode.mainnet.sui.io), \
                 3) Rate limits haven't been exceeded. \
                 For testnet, use https://fullnode.testnet.sui.io"
                .to_string(),
            SuiError::ObjectUsed(obj) => {
                format!(
                    "The Sui object {} has already been consumed. \
                     Objects can only be used once. Use a different object \
                     or check the object state on the Sui explorer.",
                    obj
                )
            }
            SuiError::StateProofFailed(_) => {
                "The state proof verification failed. This may indicate: \
                 1) The object doesn't exist at the claimed version, \
                 2) The proof is for a different object, or \
                 3) A chain reorganization occurred. \
                 Re-fetch the proof from a reliable RPC endpoint."
                    .to_string()
            }
            SuiError::EventProofFailed(_) => "The event proof verification failed. Check: \
                 1) The transaction digest is correct, \
                 2) The event index matches, \
                 3) The event data hasn't been pruned. \
                 Re-verify against a full node with complete history."
                .to_string(),
            SuiError::CheckpointFailed(_) => "Checkpoint certification failed. This may indicate: \
                 1) The checkpoint is not yet certified, \
                 2) Validator signatures are invalid, or \
                 3) The epoch has changed. \
                 Wait for the next checkpoint and retry."
                .to_string(),
            SuiError::TransactionFailed(_) => "Transaction execution failed. Check: \
                 1) You have sufficient gas (SUI tokens), \
                 2) The transaction inputs are valid, \
                 3) The Move contract doesn't abort. \
                 Simulate the transaction first to identify issues."
                .to_string(),
            SuiError::SerializationError(_) => {
                "BCS serialization/deserialization failed. Ensure the data \
                 structure matches the expected Move types and all required \
                 fields are present."
                    .to_string()
            }
            SuiError::ConfirmationTimeout {
                tx_digest,
                timeout_ms,
            } => {
                format!(
                    "Transaction {} did not confirm within {}ms. \
                     The transaction may still succeed. Check the transaction \
                     status on the Sui explorer before retrying.",
                    tx_digest, timeout_ms
                )
            }
            SuiError::ReorgDetected { checkpoint } => {
                format!(
                    "Chain reorganization detected at checkpoint {}. \
                     Your anchor may be invalid. Wait for the reorg to complete \
                     and republish at the new chain tip.",
                    checkpoint
                )
            }
            SuiError::NetworkMismatch { expected, actual } => {
                format!(
                    "Network mismatch: expected chain_id {}, got {}. \
                     Ensure your configuration matches the target network. \
                     For mainnet use 'mainnet', for testnet use 'testnet'.",
                    expected, actual
                )
            }
            SuiError::ConfigurationError(msg) => {
                format!(
                    "Configuration error: {}. \
                     Check your Sui adapter configuration and ensure all \
                     required fields (signer_address, signer_private_key) are set.",
                    msg
                )
            }
            SuiError::FeatureNotEnabled(feature) => {
                format!(
                    "Feature '{}' is not enabled. \
                     Rebuild with the required feature: cargo build --features {}",
                    feature, feature
                )
            }
            SuiError::CoreError(e) => e.suggested_fix(),
        }
    }

    fn docs_url(&self) -> String {
        match self {
            SuiError::CoreError(e) => e.docs_url(),
            _ => error_codes::docs_url(self.error_code()),
        }
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            SuiError::RpcError(_) => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::from([(
                    "rpc_endpoint".to_string(),
                    "https://fullnode.mainnet.sui.io".to_string(),
                )]),
            }),
            SuiError::ConfirmationTimeout { .. } => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::from([(
                    "wait_seconds".to_string(),
                    "30".to_string(),
                )]),
            }),
            SuiError::TransactionFailed(_) => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::from([
                    ("check_gas".to_string(), "true".to_string()),
                    ("dry_run_first".to_string(), "true".to_string()),
                ]),
            }),
            SuiError::ReorgDetected { .. } => Some(FixAction::CheckState {
                url: "https://suiscan.xyz".to_string(),
                what: "Check current Sui checkpoint".to_string(),
            }),
            SuiError::StateProofFailed(_) | SuiError::EventProofFailed(_) => {
                Some(FixAction::Retry {
                    parameter_changes: std::collections::HashMap::from([(
                        "rpc_endpoint".to_string(),
                        "try_alternative".to_string(),
                    )]),
                })
            }
            SuiError::ConfigurationError(_) => Some(FixAction::CheckState {
                url: "https://docs.sui.io".to_string(),
                what: "Check Sui adapter configuration documentation".to_string(),
            }),
            SuiError::FeatureNotEnabled(_) => Some(FixAction::CheckState {
                url: "https://github.com/client-side-validation/csv-adapter".to_string(),
                what: "Enable required feature in Cargo.toml".to_string(),
            }),
            SuiError::CoreError(e) => e.fix_action(),
            _ => None,
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for SuiError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        SuiError::RpcError(err.to_string())
    }
}

impl From<SuiError> for csv_core::ProtocolError {
    fn from(err: SuiError) -> Self {
        match err {
            SuiError::CoreError(e) => e,
            SuiError::RpcError(msg) | SuiError::TransactionFailed(msg) => {
                csv_core::ProtocolError::NetworkError(msg)
            }
            SuiError::ObjectUsed(msg) => csv_core::ProtocolError::InvalidSeal(msg),
            SuiError::StateProofFailed(msg) | SuiError::EventProofFailed(msg) => {
                csv_core::ProtocolError::InclusionProofFailed(msg)
            }
            SuiError::CheckpointFailed(msg) => csv_core::ProtocolError::NetworkError(msg),
            SuiError::SerializationError(msg) => csv_core::ProtocolError::InvalidSeal(msg),
            SuiError::ConfirmationTimeout {
                tx_digest,
                timeout_ms,
            } => csv_core::ProtocolError::NetworkError(format!(
                "Timeout waiting for tx {} after {}ms",
                tx_digest, timeout_ms
            )),
            SuiError::ReorgDetected { checkpoint } => {
                csv_core::ProtocolError::ReorgInvalid(format!("Reorg at checkpoint {}", checkpoint))
            }
            sui_err => csv_core::ProtocolError::NetworkError(format!("{}", sui_err)),
        }
    }
}

/// Result type for Sui adapter operations
pub type SuiResult<T> = Result<T, SuiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_errors() {
        assert!(SuiError::RpcError("connection refused".to_string()).is_transient());
        assert!(
            SuiError::ConfirmationTimeout {
                tx_digest: "abc".to_string(),
                timeout_ms: 30000
            }
            .is_transient()
        );
        assert!(SuiError::TransactionFailed("execution failed".to_string()).is_transient());
    }

    #[test]
    fn test_non_transient_errors() {
        assert!(!SuiError::ObjectUsed("object consumed".to_string()).is_transient());
        assert!(!SuiError::StateProofFailed("invalid proof".to_string()).is_transient());
        assert!(!SuiError::ReorgDetected { checkpoint: 100 }.is_transient());
    }

    #[test]
    fn test_error_conversion() {
        let sui_err = SuiError::StateProofFailed("bad proof".to_string());
        let core_err: csv_core::ProtocolError = sui_err.into();
        assert!(matches!(
            core_err,
            csv_core::ProtocolError::InclusionProofFailed(_)
        ));
    }
}
