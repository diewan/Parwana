//! Error types for CSV adapters

use crate::mcp::{FixAction, HasErrorSuggestion, error_codes};
use csv_codec::error::CodecError;
use thiserror::Error;

/// Result type alias for adapter operations
pub type Result<T> = core::result::Result<T, ProtocolError>;

/// Error types for CSV adapter operations
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Seal has already been used (replay attack)
    #[error("Seal replay detected: seal {0:?}")]
    SealReplay(String),

    /// Seal is invalid or malformed
    #[error("Invalid seal: {0}")]
    InvalidSeal(String),

    /// Seal was never created on-chain (caught fake seal IDs)
    #[error("Seal {0} has no on-chain anchor — was it created via a real chain adapter?")]
    SealNotAnchored(String),

    /// Commitment hash mismatch
    #[error("Commitment hash mismatch: expected {expected}, got {actual}")]
    CommitmentMismatch {
        /// Expected commitment hash
        expected: String,
        /// Actual commitment hash
        actual: String,
    },

    /// Inclusion proof verification failed
    #[error("Inclusion proof failed: {0}")]
    InclusionProofFailed(String),

    /// Finality not reached
    #[error("Finality not reached: {0}")]
    FinalityNotReached(String),

    /// Chain reorg invalidated anchor
    #[error("Anchor invalidated by reorg: {0:?}")]
    ReorgInvalid(String),

    /// Network or RPC error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Transaction publishing failed
    #[error("Publish failed: {0}")]
    PublishFailed(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Version mismatch
    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Expected version
        expected: u8,
        /// Actual version
        actual: u8,
    },

    /// Unsupported protocol version
    #[error("Unsupported protocol version: found {found}, max supported {max_supported}")]
    UnsupportedVersion {
        /// Version found in the data
        found: u16,
        /// Maximum version supported by this implementation
        max_supported: u16,
    },

    /// Malformed envelope or data
    #[error("Malformed envelope or data")]
    MalformedEnvelope,

    /// Domain separator mismatch
    #[error("Domain separator mismatch")]
    DomainSeparatorMismatch,

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Storage error (database persistence)
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Generic error with message
    #[error("Adapter error: {0}")]
    Generic(String),

    /// Invalid state transition
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    /// RPC quorum failed
    #[error("RPC quorum failed: {0}")]
    RpcQuorumFailed(String),

    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Verification error
    #[error("Verification error: {0}")]
    VerificationError(String),

    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(String),
}

impl ProtocolError {
    /// Check if this error is a reorg-related error
    pub fn is_reorg(&self) -> bool {
        matches!(self, ProtocolError::ReorgInvalid(_))
    }

    /// Check if this error is a replay attack detection
    pub fn is_replay(&self) -> bool {
        matches!(self, ProtocolError::SealReplay(_))
    }

    /// Check if this error indicates a seal without on-chain anchor
    pub fn is_seal_not_anchored(&self) -> bool {
        matches!(self, ProtocolError::SealNotAnchored(_))
    }

    /// Check if this error is a signature verification failure
    pub fn is_signature_error(&self) -> bool {
        matches!(self, ProtocolError::SignatureVerificationFailed(_))
    }

    /// Check if this error is transient (can be retried)
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ProtocolError::NetworkError(_)
                | ProtocolError::PublishFailed(_)
                | ProtocolError::FinalityNotReached(_)
                | ProtocolError::ReorgInvalid(_)
                | ProtocolError::StorageError(_)
        )
    }
}

impl HasErrorSuggestion for ProtocolError {
    fn error_code(&self) -> &'static str {
        match self {
            ProtocolError::SealReplay(_) => error_codes::CORE_SEAL_REPLAY,
            ProtocolError::InvalidSeal(_) => error_codes::CORE_INVALID_SEAL,
            ProtocolError::SealNotAnchored(_) => error_codes::CORE_SEAL_NOT_ANCHORED,
            ProtocolError::CommitmentMismatch { .. } => error_codes::CORE_COMMITMENT_MISMATCH,
            ProtocolError::InclusionProofFailed(_) => error_codes::CORE_INCLUSION_PROOF_FAILED,
            ProtocolError::FinalityNotReached(_) => error_codes::CORE_FINALITY_NOT_REACHED,
            ProtocolError::ReorgInvalid(_) => error_codes::CORE_REORG_INVALID,
            ProtocolError::NetworkError(_) => error_codes::CORE_NETWORK_ERROR,
            ProtocolError::PublishFailed(_) => error_codes::CORE_PUBLISH_FAILED,
            ProtocolError::SerializationError(_) => error_codes::CORE_SERIALIZATION_ERROR,
            ProtocolError::InvalidConfig(_) => error_codes::CORE_INVALID_CONFIG,
            ProtocolError::VersionMismatch { .. } => error_codes::CORE_VERSION_MISMATCH,
            ProtocolError::UnsupportedVersion { .. } => error_codes::CORE_VERSION_MISMATCH,
            ProtocolError::MalformedEnvelope => error_codes::CORE_INVALID_CONFIG,
            ProtocolError::DomainSeparatorMismatch => error_codes::CORE_DOMAIN_SEPARATOR_MISMATCH,
            ProtocolError::SignatureVerificationFailed(_) => {
                error_codes::CORE_SIGNATURE_VERIFICATION_FAILED
            }
            ProtocolError::InvalidInput(_) => error_codes::CORE_INVALID_CONFIG,
            ProtocolError::StorageError(_) => error_codes::CORE_STORAGE_ERROR,
            ProtocolError::Generic(_) => error_codes::CORE_GENERIC,
            ProtocolError::InvalidStateTransition(_) => error_codes::CORE_INVALID_CONFIG,
            ProtocolError::RpcQuorumFailed(_) => error_codes::CORE_NETWORK_ERROR,
            ProtocolError::InvalidData(_) => error_codes::CORE_INVALID_CONFIG,
            ProtocolError::VerificationError(_) => error_codes::CORE_INCLUSION_PROOF_FAILED,
            ProtocolError::RpcError(_) => error_codes::CORE_NETWORK_ERROR,
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            ProtocolError::SealReplay(_) => {
                "This seal has already been consumed. You cannot reuse a single-use seal. \
                 Check the seal state or use a different seal."
                    .to_string()
            }
            ProtocolError::InvalidSeal(_) => {
                "The seal format is invalid. Verify the seal is properly constructed \
                 and matches the expected format for this chain."
                    .to_string()
            }
            ProtocolError::SealNotAnchored(seal_id) => {
                format!(
                    "Seal {} was never created on-chain via a real chain adapter. \
                     This typically means a fake/timestamp-based seal ID was used. \
                     Create the seal using the chain adapter's create_seal() method \
                     to get a real chain-native seal reference.",
                    seal_id
                )
            }
            ProtocolError::CommitmentMismatch { expected, actual } => {
                format!(
                    "Commitment hash mismatch: expected {}, got {}. \
                     Regenerate the commitment with the correct parameters.",
                    expected, actual
                )
            }
            ProtocolError::InclusionProofFailed(_) => {
                "The inclusion proof could not be verified. This may indicate: \
                 1) The anchor has not been confirmed on-chain, \
                 2) The proof is for a different commitment, or \
                 3) A chain reorganization occurred. \
                 Retry with a more recent anchor."
                    .to_string()
            }
            ProtocolError::FinalityNotReached(_) => {
                "The required finality has not been reached. Wait for more confirmations \
                 or lower the required finality threshold."
                    .to_string()
            }
            ProtocolError::ReorgInvalid(_) => {
                "The anchor was invalidated by a chain reorganization. \
                 Republish the commitment at the new chain tip."
                    .to_string()
            }
            ProtocolError::NetworkError(_) => {
                "Network communication failed. Check your internet connection, \
                 verify the RPC endpoint is accessible, or try a different node."
                    .to_string()
            }
            ProtocolError::PublishFailed(_) => "Failed to publish the transaction. Check: \
                 1) You have sufficient funds for gas fees, \
                 2) The transaction is properly signed, \
                 3) The chain is accepting transactions."
                .to_string(),
            ProtocolError::SerializationError(_) => {
                "Data serialization/deserialization failed. Check the data format \
                 matches the expected schema for this operation."
                    .to_string()
            }
            ProtocolError::InvalidConfig(_) => {
                "The configuration is invalid. Review your config file and ensure \
                 all required fields are present and correctly formatted."
                    .to_string()
            }
            ProtocolError::VersionMismatch { expected, actual } => {
                format!(
                    "Version mismatch: expected {}, got {}. \
                     Upgrade or downgrade to the correct protocol version.",
                    expected, actual
                )
            }
            ProtocolError::UnsupportedVersion {
                found,
                max_supported,
            } => {
                format!(
                    "Protocol version {} is not supported. Maximum supported version is {}. \
                     Upgrade your client to a version that supports protocol v{}.",
                    found, max_supported, max_supported
                )
            }
            ProtocolError::MalformedEnvelope => {
                "The envelope data is malformed or corrupted. Verify the data format \
                 matches the expected canonical serialization."
                    .to_string()
            }
            ProtocolError::DomainSeparatorMismatch => {
                "The domain separator does not match. Ensure you are using \
                 the correct network (mainnet vs testnet)."
                    .to_string()
            }
            ProtocolError::SignatureVerificationFailed(_) => {
                "Signature verification failed. Check: \
                 1) The message was not tampered with, \
                 2) The correct public key is being used, \
                 3) The signature algorithm matches."
                    .to_string()
            }
            ProtocolError::InvalidInput(msg) => format!("Invalid input parameters: {}", msg),
            ProtocolError::StorageError(msg) => {
                format!(
                    "Storage operation failed: {}. Ensure the database is accessible and has sufficient space.",
                    msg
                )
            }
            ProtocolError::Generic(_) => {
                "An unexpected error occurred. Check the logs for details \
                 or contact support with the error context."
                    .to_string()
            }
            ProtocolError::InvalidStateTransition(msg) => {
                format!(
                    "Invalid state transition: {}. Check the state machine and ensure transitions are valid.",
                    msg
                )
            }
            ProtocolError::RpcQuorumFailed(msg) => {
                format!(
                    "RPC quorum failed: {}. Check RPC endpoints and network connectivity.",
                    msg
                )
            }
            ProtocolError::InvalidData(msg) => {
                format!(
                    "Invalid data: {}. Check the data format and ensure it matches expected schema.",
                    msg
                )
            }
            ProtocolError::VerificationError(msg) => {
                format!(
                    "Verification error: {}. Check the proof data and verification logic.",
                    msg
                )
            }
            ProtocolError::RpcError(msg) => {
                format!(
                    "RPC error: {}. Check RPC endpoints and network connectivity.",
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
            ProtocolError::NetworkError(_) => Some(FixAction::Retry {
                parameter_changes: crate::collections::HashMap::new(),
            }),
            ProtocolError::FinalityNotReached(_) => Some(FixAction::WaitForConfirmations {
                confirmations: 6,
                estimated_seconds: 600,
            }),
            ProtocolError::ReorgInvalid(_) => Some(FixAction::CheckState {
                url: "https://docs.csv.dev/reorg-handling".to_string(),
                what: "Check current chain tip and republish anchor".to_string(),
            }),
            ProtocolError::PublishFailed(_) => Some(FixAction::Retry {
                parameter_changes: crate::collections::HashMap::from([(
                    "check_gas".to_string(),
                    "true".to_string(),
                )]),
            }),
            _ => None,
        }
    }
}

impl From<CodecError> for ProtocolError {
    fn from(err: CodecError) -> Self {
        ProtocolError::SerializationError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ProtocolError::SealReplay("abc123".to_string());
        assert!(err.to_string().contains("replay"));
    }

    #[test]
    fn test_error_is_reorg() {
        let err = ProtocolError::ReorgInvalid("anchor".to_string());
        assert!(err.is_reorg());
    }

    #[test]
    fn test_error_is_replay() {
        let err = ProtocolError::SealReplay("seal".to_string());
        assert!(err.is_replay());
    }

    #[test]
    fn test_error_is_signature_error() {
        let err = ProtocolError::SignatureVerificationFailed("invalid sig".to_string());
        assert!(err.is_signature_error());
    }

    #[test]
    fn test_error_signature_verification_failed() {
        let err = ProtocolError::SignatureVerificationFailed("bad signature".to_string());
        assert!(err.to_string().contains("Signature verification failed"));
    }
}
