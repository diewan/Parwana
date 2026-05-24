//! Aptos adapter error types
//!
//! This module provides a comprehensive error taxonomy for the Aptos adapter,
//! with chain-specific error variants and recovery guidance.

use thiserror::Error;

// Local implementations (mcp module removed during migration)
#[derive(Debug, Clone)]
pub enum FixAction {
    Retry { backoff_secs: u64, parameter_changes: Vec<String> },
    CheckState { check: String, url: String, what: String },
    SwitchEndpoint { endpoint: String },
}

pub trait HasErrorSuggestion {
    fn error_code(&self) -> u32;
    fn fix_action(&self) -> Option<FixAction>;
    fn description(&self) -> String;
    fn suggested_fix(&self) -> String;
    fn docs_url(&self) -> String;
}

mod error_codes {
    pub const APTOS_STATE_PROOF_FAILED: u32 = 2001;
    pub const APTOS_EVENT_PROOF_FAILED: u32 = 2002;
    pub const APTOS_RESOURCE_USED: u32 = 2003;
    pub const APTOS_TRANSACTION_FAILED: u32 = 2004;
    pub const APTOS_RPC_ERROR: u32 = 2005;
    pub const APTOS_CHECKPOINT_FAILED: u32 = 2006;

    pub fn docs_url(code: u32) -> String {
        format!("https://docs.csv-protocol.io/errors/{}", code)
    }
}

/// Comprehensive error types for the Aptos adapter.
///
/// Each variant includes context for debugging and recovery guidance.
#[derive(Error, Debug)]
pub enum AptosError {
    /// Error during RPC communication with Aptos node.
    /// Recovery: Retry with backoff, switch to fallback RPC endpoint.
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Seal resource has already been consumed.
    /// Recovery: This is a fatal error for seal replay attempts. Check seal state.
    #[error("Resource already used: {0}")]
    ResourceUsed(String),

    /// State proof verification failed (Merkle proof against accumulator root).
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
    #[error("Transaction confirmation timeout after {timeout_ms}ms: {tx_hash}")]
    ConfirmationTimeout { tx_hash: String, timeout_ms: u64 },

    /// Chain reorg detected affecting anchor validity.
    /// Recovery: Re-publish commitment at new chain tip.
    #[error("Chain reorg detected at version {version}: anchor may be invalid")]
    ReorgDetected { version: u64 },

    /// Network mismatch (e.g., mainnet seal on testnet).
    /// Recovery: Ensure network configuration matches chain ID.
    #[error("Network mismatch: expected chain_id {expected}, got {actual}")]
    NetworkMismatch { expected: u64, actual: u64 },

    /// Feature not enabled - required feature is not compiled in.
    /// Recovery: Rebuild with the required feature enabled.
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),

    /// Core adapter error from csv-adapter-core.
    #[error(transparent)]
    CoreError(#[from] csv_protocol::ProtocolError),
}

impl AptosError {
    /// Returns true if this error is potentially transient and should be retried.
    pub fn is_transient(&self) -> bool {
        match self {
            AptosError::RpcError(_)
            | AptosError::ConfirmationTimeout { .. }
            | AptosError::TransactionFailed(_) => true,
            AptosError::ResourceUsed(_)
            | AptosError::StateProofFailed(_)
            | AptosError::EventProofFailed(_)
            | AptosError::CheckpointFailed(_)
            | AptosError::SerializationError(_)
            | AptosError::ReorgDetected { .. }
            | AptosError::NetworkMismatch { .. }
            | AptosError::FeatureNotEnabled(_)
            | AptosError::CoreError(_) => false,
        }
    }

    /// Construct an error for transaction timeout
    pub fn timeout(tx_hash: &str, timeout_ms: u64) -> Self {
        AptosError::ConfirmationTimeout {
            tx_hash: tx_hash.to_string(),
            timeout_ms,
        }
    }

    /// Construct an error for chain reorg
    pub fn reorg(version: u64) -> Self {
        AptosError::ReorgDetected { version }
    }
}

impl HasErrorSuggestion for AptosError {
    fn error_code(&self) -> u32 {
        match self {
            AptosError::RpcError(_) => error_codes::APTOS_RPC_ERROR,
            AptosError::ResourceUsed(_) => error_codes::APTOS_RESOURCE_USED,
            AptosError::StateProofFailed(_) => error_codes::APTOS_STATE_PROOF_FAILED,
            AptosError::EventProofFailed(_) => error_codes::APTOS_EVENT_PROOF_FAILED,
            AptosError::CheckpointFailed(_) => error_codes::APTOS_CHECKPOINT_FAILED,
            AptosError::TransactionFailed(_) => error_codes::APTOS_TRANSACTION_FAILED,
            AptosError::SerializationError(_) => 2007,
            AptosError::ConfirmationTimeout { .. } => 2008,
            AptosError::ReorgDetected { .. } => 2009,
            AptosError::NetworkMismatch { .. } => 2010,
            AptosError::FeatureNotEnabled(_) => 2011,
            AptosError::CoreError(_) => 1,
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            AptosError::RpcError(_) => "Aptos RPC call failed. Check: \
                 1) Your internet connection, \
                 2) The RPC endpoint is accessible (try https://fullnode.mainnet.aptoslabs.com), \
                 3) Rate limits haven't been exceeded. \
                 For testnet, use https://fullnode.testnet.aptoslabs.com"
                .to_string(),
            AptosError::ResourceUsed(resource) => {
                format!(
                    "The Aptos resource {} has already been consumed. \
                     Resources can only be used once. Use a different resource \
                     or check the resource state on the Aptos explorer.",
                    resource
                )
            }
            AptosError::StateProofFailed(_) => {
                "The state proof verification failed against the accumulator root. \
                 This may indicate: \
                 1) The resource doesn't exist at the claimed version, \
                 2) The proof is for a different resource, or \
                 3) A chain reorganization occurred. \
                 Re-fetch the proof from a reliable RPC endpoint."
                    .to_string()
            }
            AptosError::EventProofFailed(_) => "The event proof verification failed. Check: \
                 1) The transaction version is correct, \
                 2) The event key matches, \
                 3) The event data hasn't been pruned. \
                 Re-verify against a full node with complete history."
                .to_string(),
            AptosError::CheckpointFailed(_) => {
                "Checkpoint certification failed. This may indicate: \
                 1) The epoch change is in progress, \
                 2) Validator set has changed, or \
                 3) The ledger version is not yet committed. \
                 Wait for the next block and retry."
                    .to_string()
            }
            AptosError::TransactionFailed(_) => "Transaction execution failed. Check: \
                 1) You have sufficient gas (APT tokens), \
                 2) The transaction sequence number is correct, \
                 3) The Move contract doesn't abort. \
                 Simulate the transaction first to identify issues."
                .to_string(),
            AptosError::SerializationError(_) => {
                "BCS serialization/deserialization failed. Ensure the data \
                 structure matches the expected Move types and all required \
                 fields are present."
                    .to_string()
            }
            AptosError::ConfirmationTimeout {
                tx_hash,
                timeout_ms,
            } => {
                format!(
                    "Transaction {} did not confirm within {}ms. \
                     The transaction may still succeed. Check the transaction \
                     status on the Aptos explorer before retrying.",
                    tx_hash, timeout_ms
                )
            }
            AptosError::ReorgDetected { version } => {
                format!(
                    "Chain reorganization detected at version {}. \
                     Your anchor may be invalid. Wait for the reorg to complete \
                     and republish at the new chain tip.",
                    version
                )
            }
            AptosError::NetworkMismatch { expected, actual } => {
                format!(
                    "Network mismatch: expected chain_id {}, got {}. \
                     Ensure your configuration matches the target network. \
                     Mainnet is chain_id 1, testnet is chain_id 2.",
                    expected, actual
                )
            }
            AptosError::FeatureNotEnabled(feature) => {
                format!(
                    "Feature '{}' is not enabled. \
                     Rebuild with the required feature: cargo build --features {}",
                    feature, feature
                )
            }
            AptosError::CoreError(e) => format!("Core error: {}", e),
        }
    }

    fn docs_url(&self) -> String {
        error_codes::docs_url(self.error_code())
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            AptosError::RpcError(_) => Some(FixAction::Retry {
                backoff_secs: 5,
                parameter_changes: vec!["rpc_endpoint".to_string()],
            }),
            AptosError::ConfirmationTimeout { .. } => Some(FixAction::Retry {
                backoff_secs: 30,
                parameter_changes: vec!["wait_seconds".to_string()],
            }),
            AptosError::TransactionFailed(_) => Some(FixAction::Retry {
                backoff_secs: 10,
                parameter_changes: vec!["check_gas".to_string(), "dry_run_first".to_string()],
            }),
            AptosError::ReorgDetected { .. } => Some(FixAction::CheckState {
                check: "chain state".to_string(),
                url: "https://explorer.aptoslabs.com".to_string(),
                what: "Check current Aptos ledger version".to_string(),
            }),
            AptosError::StateProofFailed(_) | AptosError::EventProofFailed(_) => {
                Some(FixAction::Retry {
                    backoff_secs: 5,
                    parameter_changes: vec!["rpc_endpoint".to_string()],
                })
            }
            AptosError::FeatureNotEnabled(_) => Some(FixAction::CheckState {
                check: "feature flags".to_string(),
                url: "https://github.com/Diewan/csv-adapter".to_string(),
                what: "Enable required feature in Cargo.toml".to_string(),
            }),
            AptosError::CoreError(_) => None,
            _ => None,
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AptosError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        AptosError::RpcError(err.to_string())
    }
}

impl From<AptosError> for csv_protocol::ProtocolError {
    fn from(err: AptosError) -> Self {
        match err {
            AptosError::CoreError(e) => e,
            AptosError::RpcError(msg) | AptosError::TransactionFailed(msg) => {
                csv_protocol::ProtocolError::NetworkError(msg)
            }
            AptosError::ResourceUsed(msg) => csv_protocol::ProtocolError::InvalidSeal(msg),
            AptosError::StateProofFailed(msg) | AptosError::EventProofFailed(msg) => {
                csv_protocol::ProtocolError::InclusionProofFailed(msg)
            }
            AptosError::CheckpointFailed(msg) => csv_protocol::ProtocolError::NetworkError(msg),
            AptosError::SerializationError(msg) => csv_protocol::ProtocolError::InvalidSeal(msg),
            AptosError::ConfirmationTimeout {
                tx_hash,
                timeout_ms,
            } => csv_protocol::ProtocolError::NetworkError(format!(
                "Timeout waiting for tx {} after {}ms",
                tx_hash, timeout_ms
            )),
            AptosError::ReorgDetected { version } => {
                csv_protocol::ProtocolError::ReorgInvalid(format!("Reorg at version {}", version))
            }
            aptos_err => csv_protocol::ProtocolError::NetworkError(format!("{}", aptos_err)),
        }
    }
}

pub type AptosResult<T> = Result<T, AptosError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_errors() {
        assert!(AptosError::RpcError("connection refused".to_string()).is_transient());
        assert!(
            AptosError::ConfirmationTimeout {
                tx_hash: "abc".to_string(),
                timeout_ms: 30000
            }
            .is_transient()
        );
        assert!(AptosError::TransactionFailed("out of gas".to_string()).is_transient());
    }

    #[test]
    fn test_non_transient_errors() {
        assert!(!AptosError::ResourceUsed("seal consumed".to_string()).is_transient());
        assert!(!AptosError::StateProofFailed("invalid merkle".to_string()).is_transient());
        assert!(!AptosError::ReorgDetected { version: 100 }.is_transient());
    }

    #[test]
    fn test_error_conversion() {
        let aptos_err = AptosError::StateProofFailed("bad proof".to_string());
        let core_err: csv_protocol::ProtocolError = aptos_err.into();
        assert!(matches!(
            core_err,
            csv_protocol::ProtocolError::InclusionProofFailed(_)
        ));
    }
}
