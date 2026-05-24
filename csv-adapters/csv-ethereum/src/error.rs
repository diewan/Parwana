//! Ethereum adapter error types

use thiserror::Error;

// Local implementations (mcp module removed during migration)
#[derive(Debug, Clone)]
pub enum FixAction {
    Retry {
        backoff_secs: u64,
        parameter_changes: Vec<String>,
    },
    CheckState {
        check: String,
        url: String,
        what: String,
    },
    SwitchEndpoint {
        endpoint: String,
    },
    WaitForConfirmations {
        confirmations: u64,
    },
}

pub trait HasErrorSuggestion {
    fn error_code(&self) -> u32;
    fn fix_action(&self) -> Option<FixAction>;
    fn description(&self) -> String;
    fn suggested_fix(&self) -> String;
    fn docs_url(&self) -> String;
}

mod error_codes {
    pub const ETH_RPC_ERROR: u32 = 5001;
    pub const ETH_SLOT_USED: u32 = 5002;
    pub const ETH_INVALID_RECEIPT_PROOF: u32 = 5003;
    pub const ETH_REORG_DETECTED: u32 = 5004;
    pub const ETH_INSUFFICIENT_CONFIRMATIONS: u32 = 5005;
    pub const ETH_WALLET_ERROR: u32 = 5006;
    pub const ETH_CONFIG_ERROR: u32 = 5007;
    pub const ETH_DEPLOYMENT_ERROR: u32 = 5008;

    pub fn docs_url(code: u32) -> String {
        format!("https://docs.csv-protocol.io/errors/{}", code)
    }
}

/// Ethereum adapter specific errors
#[derive(Error, Debug)]
pub enum EthereumError {
    /// Ethereum RPC error
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Storage slot already used
    #[error("Storage slot already used: {0}")]
    SlotUsed(String),

    /// Invalid receipt proof
    #[error("Invalid receipt proof: {0}")]
    InvalidReceiptProof(String),

    /// Reorg detected
    #[error("Reorg detected at block {block}, depth {depth}")]
    ReorgDetected { block: u64, depth: u64 },

    /// Insufficient confirmations
    #[error("Insufficient confirmations: got {got}, need {need}")]
    InsufficientConfirmations { got: u64, need: u64 },

    /// Wallet error
    #[error("Wallet error: {0}")]
    WalletError(String),

    /// Configuration error
    #[error("Config error: {0}")]
    ConfigError(String),

    /// Deployment error
    #[error("Deployment error: {0}")]
    DeploymentError(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// Wrapper for core adapter errors
    #[error(transparent)]
    CoreError(#[from] csv_protocol::ProtocolError),
}

impl EthereumError {
    /// Whether this error is transient and may be retried
    pub fn is_transient(&self) -> bool {
        match self {
            EthereumError::RpcError(_) => true,
            EthereumError::InsufficientConfirmations { .. } => true,
            EthereumError::ReorgDetected { .. } => true,
            EthereumError::WalletError(_) => false,
            EthereumError::ConfigError(_) => false,
            EthereumError::DeploymentError(_) => false,
            EthereumError::SlotUsed(_) => false,
            EthereumError::InvalidReceiptProof(_) => false,
            EthereumError::InvalidInput(_) => false,
            EthereumError::TransactionError(_) => false,
            EthereumError::CoreError(_) => false,
        }
    }
}

impl HasErrorSuggestion for EthereumError {
    fn error_code(&self) -> u32 {
        match self {
            EthereumError::RpcError(_) => error_codes::ETH_RPC_ERROR,
            EthereumError::SlotUsed(_) => error_codes::ETH_SLOT_USED,
            EthereumError::InvalidReceiptProof(_) => error_codes::ETH_INVALID_RECEIPT_PROOF,
            EthereumError::ReorgDetected { .. } => error_codes::ETH_REORG_DETECTED,
            EthereumError::InsufficientConfirmations { .. } => {
                error_codes::ETH_INSUFFICIENT_CONFIRMATIONS
            }
            EthereumError::WalletError(_) => error_codes::ETH_WALLET_ERROR,
            EthereumError::ConfigError(_) => error_codes::ETH_CONFIG_ERROR,
            EthereumError::DeploymentError(_) => error_codes::ETH_DEPLOYMENT_ERROR,
            EthereumError::CoreError(_) => 1,
            EthereumError::InvalidInput(_) => 2,
            EthereumError::TransactionError(_) => 3,
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            EthereumError::RpcError(_) => "Ethereum RPC call failed. Check: \
                 1) Your internet connection, \
                 2) The RPC endpoint is accessible (try https://ethereum-rpc.publicnode.com), \
                 3) Rate limits haven't been exceeded. \
                 Ensure you're using the correct network (mainnet/sepolia)."
                .to_string(),
            EthereumError::SlotUsed(slot) => {
                format!(
                    "The storage slot {} is already used. Each seal requires a unique slot. \
                     Use a different slot index or verify the existing seal state.",
                    slot
                )
            }
            EthereumError::InvalidReceiptProof(_) => {
                "The transaction receipt proof is invalid. This may indicate: \
                 1) The transaction is not in the claimed block, \
                 2) The receipt root hash is incorrect, or \
                 3) The proof structure is malformed. \
                 Regenerate the proof from a confirmed transaction."
                    .to_string()
            }
            EthereumError::ReorgDetected { block, depth } => {
                format!(
                    "Chain reorganization detected at block {} with depth {}. \
                     Your anchor may be invalid. Wait for the reorg to complete \
                     and republish at the new chain tip.",
                    block, depth
                )
            }
            EthereumError::InsufficientConfirmations { got, need } => {
                format!(
                    "Insufficient confirmations: got {}, need {}. \
                     Wait for {} more block confirmations (approximately {} seconds).",
                    got,
                    need,
                    need - got,
                    (need - got) * 12
                )
            }
            EthereumError::CoreError(_) => "See protocol error documentation".to_string(),
            _ => "See documentation for this error type.".to_string(),
        }
    }

    fn docs_url(&self) -> String {
        error_codes::docs_url(self.error_code())
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            EthereumError::RpcError(_) => Some(FixAction::Retry {
                backoff_secs: 5,
                parameter_changes: vec![
                    "rpc_endpoint=https://ethereum-rpc.publicnode.com".to_string(),
                    "network=mainnet".to_string(),
                ],
            }),
            EthereumError::InsufficientConfirmations { need, .. } => {
                Some(FixAction::WaitForConfirmations {
                    confirmations: *need,
                })
            }
            EthereumError::ReorgDetected { .. } => Some(FixAction::CheckState {
                check: "reorg_detected".to_string(),
                url: "https://etherscan.io".to_string(),
                what: "Check current Ethereum chain tip".to_string(),
            }),
            EthereumError::SlotUsed(_) => Some(FixAction::Retry {
                backoff_secs: 5,
                parameter_changes: vec!["increment_slot=true".to_string()],
            }),
            EthereumError::CoreError(_) => None,
            _ => None,
        }
    }
}

impl From<EthereumError> for csv_protocol::ProtocolError {
    fn from(err: EthereumError) -> Self {
        match err {
            EthereumError::CoreError(e) => e,
            EthereumError::RpcError(msg) => csv_protocol::ProtocolError::NetworkError(msg),
            EthereumError::SlotUsed(msg) => csv_protocol::ProtocolError::InvalidSeal(msg),
            EthereumError::InvalidReceiptProof(msg) => {
                csv_protocol::ProtocolError::InclusionProofFailed(msg)
            }
            EthereumError::ReorgDetected { block, depth } => {
                csv_protocol::ProtocolError::ReorgInvalid(format!(
                    "Reorg at block {}, depth {}",
                    block, depth
                ))
            }
            EthereumError::InsufficientConfirmations { got, need } => {
                csv_protocol::ProtocolError::FinalityNotReached(format!(
                    "Got {} confirmations, need {}",
                    got, need
                ))
            }
            EthereumError::WalletError(msg) => {
                csv_protocol::ProtocolError::Generic(format!("Wallet error: {}", msg))
            }
            EthereumError::ConfigError(msg) => csv_protocol::ProtocolError::InvalidInput(msg),
            EthereumError::DeploymentError(msg) => csv_protocol::ProtocolError::PublishFailed(msg),
            EthereumError::InvalidInput(msg) => csv_protocol::ProtocolError::InvalidInput(msg),
            EthereumError::TransactionError(msg) => csv_protocol::ProtocolError::NetworkError(msg),
        }
    }
}

/// Result type for Ethereum adapter operations
pub type EthereumResult<T> = Result<T, EthereumError>;
