//! Error types for Solana adapter

use csv_core::mcp::{FixAction, HasErrorSuggestion, error_codes};
use thiserror::Error;

/// Solana-specific errors
#[derive(Debug, Error)]
pub enum SolanaError {
    /// RPC client error
    #[error("RPC error: {0}")]
    Rpc(String),

    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(String),

    /// Transaction failed
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    /// Timeout error
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Account not found
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    /// Invalid program ID
    #[error("Invalid program ID: {0}")]
    InvalidProgramId(String),

    /// Invalid instruction
    #[error("Invalid instruction: {0}")]
    InvalidInstruction(String),

    /// Insufficient funds
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Keypair error
    #[error("Keypair error: {0}")]
    Keypair(String),

    /// Wallet error
    #[error("Wallet error: {0}")]
    Wallet(String),

    /// Commitment error
    #[error("Commitment error: {0}")]
    Commitment(String),

    /// Seal creation error
    #[error("Seal creation error: {0}")]
    SealCreation(String),

    /// Anchor creation error
    #[error("Anchor creation error: {0}")]
    AnchorCreation(String),

    /// Proof generation error
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Operation not supported/available
    #[error("Operation not supported: {0}")]
    UnsupportedOperation(String),
}

/// Result type for Solana operations
pub type SolanaResult<T> = std::result::Result<T, SolanaError>;

impl From<solana_sdk::transport::TransportError> for SolanaError {
    fn from(err: solana_sdk::transport::TransportError) -> Self {
        Self::Rpc(format!("Transport error: {}", err))
    }
}

impl From<solana_sdk::program_error::ProgramError> for SolanaError {
    fn from(err: solana_sdk::program_error::ProgramError) -> Self {
        Self::Transaction(format!("Program error: {}", err))
    }
}

impl From<bs58::decode::Error> for SolanaError {
    fn from(err: bs58::decode::Error) -> Self {
        Self::Keypair(format!("Base58 decode error: {}", err))
    }
}

impl From<serde_json::Error> for SolanaError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(format!("JSON error: {}", err))
    }
}

impl From<ed25519_dalek::ed25519::Error> for SolanaError {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        Self::Keypair(format!("Ed25519 error: {}", err))
    }
}

impl From<SolanaError> for csv_core::error::ProtocolError {
    fn from(err: SolanaError) -> Self {
        csv_core::error::ProtocolError::NetworkError(format!("Solana: {}", err))
    }
}

impl SolanaError {
    /// Whether this error is transient and may be retried
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            SolanaError::Rpc(_) | SolanaError::Network(_) | SolanaError::Commitment(_)
        )
    }
}

impl HasErrorSuggestion for SolanaError {
    fn error_code(&self) -> &'static str {
        match self {
            SolanaError::Rpc(_) => error_codes::SOL_RPC_ERROR,
            SolanaError::Transaction(_) => error_codes::SOL_TRANSACTION_ERROR,
            SolanaError::AccountNotFound(_) => error_codes::SOL_ACCOUNT_NOT_FOUND,
            SolanaError::InvalidProgramId(_) => error_codes::SOL_INVALID_PROGRAM_ID,
            SolanaError::InvalidInstruction(_) => error_codes::SOL_INVALID_INSTRUCTION,
            SolanaError::InsufficientFunds { .. } => error_codes::SOL_INSUFFICIENT_FUNDS,
            SolanaError::Network(_) => error_codes::SOL_NETWORK_ERROR,
            SolanaError::Serialization(_) => error_codes::SOL_SERIALIZATION_ERROR,
            SolanaError::Deserialization(_) => error_codes::SOL_DESERIALIZATION_ERROR,
            SolanaError::Keypair(_) => error_codes::SOL_KEYPAIR_ERROR,
            SolanaError::Wallet(_) => error_codes::SOL_WALLET_ERROR,
            SolanaError::Commitment(_) => error_codes::SOL_COMMITMENT_ERROR,
            SolanaError::SealCreation(_) => error_codes::SOL_SEAL_CREATION_ERROR,
            SolanaError::AnchorCreation(_) => error_codes::SOL_ANCHOR_CREATION_ERROR,
            SolanaError::ProofGeneration(_) => error_codes::SOL_PROOF_GENERATION_ERROR,
            SolanaError::InvalidInput(_) => error_codes::SOL_INVALID_INPUT,
            SolanaError::UnsupportedOperation(_) => error_codes::SOL_UNSUPPORTED_OPERATION,
            SolanaError::TransactionFailed(_) => error_codes::SOL_TRANSACTION_ERROR,
            SolanaError::Timeout(_) => error_codes::SOL_NETWORK_ERROR,
        }
    }

    fn description(&self) -> String {
        self.to_string()
    }

    fn suggested_fix(&self) -> String {
        match self {
            SolanaError::Rpc(_) => "Solana RPC call failed. Check: \
                 1) Your internet connection, \
                 2) The RPC endpoint is accessible (try https://api.mainnet-beta.solana.com), \
                 3) Rate limits haven't been exceeded. \
                 For devnet, use https://api.devnet.solana.com"
                .to_string(),
            SolanaError::Transaction(msg) => {
                format!(
                    "Solana transaction failed: {}. Check: \
                     1) You have sufficient SOL for fees, \
                     2) The instruction data is valid, \
                     3) The program exists and is executable. \
                     Simulate the transaction before sending.",
                    msg
                )
            }
            SolanaError::AccountNotFound(addr) => {
                format!(
                    "Account {} was not found. The account may not exist yet \
                     (needs funding) or may have been closed. Fund the account \
                     with at least 0.001 SOL (rent-exempt minimum).",
                    addr
                )
            }
            SolanaError::InvalidProgramId(id) => {
                format!(
                    "Invalid program ID: {}. Verify the program is deployed \
                     and the address is correct. Check on Solana Explorer.",
                    id
                )
            }
            SolanaError::InvalidInstruction(msg) => {
                format!(
                    "Invalid instruction: {}. Check the instruction data \
                     matches the program's expected format and all accounts \
                     are provided in the correct order.",
                    msg
                )
            }
            SolanaError::InsufficientFunds {
                required,
                available,
            } => {
                format!(
                    "Insufficient funds: need {} lamports, have {}. \
                     Fund your wallet with at least {} more lamports ({} SOL).",
                    required,
                    available,
                    required.saturating_sub(*available),
                    (required.saturating_sub(*available)) as f64 / 1e9
                )
            }
            SolanaError::Network(_) => {
                "Network communication failed. Check your internet connection \
                 and verify the Solana network is accessible."
                    .to_string()
            }
            SolanaError::Serialization(_) => {
                "Data serialization failed. Ensure the data structure matches \
                 the expected format for Solana programs."
                    .to_string()
            }
            SolanaError::Deserialization(_) => {
                "Data deserialization failed. The data format may have changed \
                 or be incompatible with the expected structure."
                    .to_string()
            }
            SolanaError::Keypair(_) => "Keypair operation failed. Verify the private key format \
                 and ensure it's a valid ed25519 key."
                .to_string(),
            SolanaError::Wallet(_) => "Wallet operation failed. Check wallet configuration \
                 and ensure the wallet has the required permissions."
                .to_string(),
            SolanaError::Commitment(_) => "Commitment level error. Use 'confirmed' or 'finalized' \
                 for reliable results. 'processed' may be too optimistic."
                .to_string(),
            SolanaError::SealCreation(_) => "Failed to create seal. Check the seal parameters \
                 and ensure the account has sufficient space."
                .to_string(),
            SolanaError::AnchorCreation(_) => {
                "Failed to create anchor. Verify the blockhash is recent \
                 and the transaction is properly signed."
                    .to_string()
            }
            SolanaError::ProofGeneration(_) => {
                "Proof generation failed. Check the anchor is confirmed \
                 and has the required number of signatures."
                    .to_string()
            }
            SolanaError::InvalidInput(_) => {
                "The provided input is invalid. Check all parameters are correct \
                 and within acceptable ranges."
                    .to_string()
            }
            SolanaError::UnsupportedOperation(_) => "This operation is not supported. \
                 Consider using an alternative approach or waiting for a future release."
                .to_string(),
            SolanaError::TransactionFailed(msg) => format!(
                "Transaction failed on-chain: {}. Check: \
                 1) Program logs for specific errors, \
                 2) Account permissions are correct, \
                 3) Instruction data is valid.",
                msg
            ),
            SolanaError::Timeout(msg) => format!(
                "Operation timed out: {}. Check: \
                 1) Network connection is stable, \
                 2) RPC endpoint is responsive, \
                 3) Consider using a higher commitment level.",
                msg
            ),
        }
    }

    fn docs_url(&self) -> String {
        error_codes::docs_url(self.error_code())
    }

    fn fix_action(&self) -> Option<FixAction> {
        match self {
            SolanaError::Rpc(_) | SolanaError::Network(_) => Some(FixAction::Retry {
                parameter_changes: std::collections::HashMap::from([(
                    "rpc_endpoint".to_string(),
                    "https://api.mainnet-beta.solana.com".to_string(),
                )]),
            }),
            SolanaError::InsufficientFunds {
                required,
                available,
            } => {
                let need = required.saturating_sub(*available);
                Some(FixAction::FundFromFaucet {
                    url: "https://faucet.solana.com".to_string(),
                    amount: format!("{} lamports ({} SOL)", need, need as f64 / 1e9),
                })
            }
            SolanaError::AccountNotFound(_) => Some(FixAction::FundFromFaucet {
                url: "https://faucet.solana.com".to_string(),
                amount: "0.001 SOL (rent-exempt minimum)".to_string(),
            }),
            SolanaError::Transaction(_) | SolanaError::InvalidInstruction(_) => {
                Some(FixAction::Retry {
                    parameter_changes: std::collections::HashMap::from([
                        ("simulate_first".to_string(), "true".to_string()),
                        ("check_program".to_string(), "true".to_string()),
                    ]),
                })
            }
            _ => None,
        }
    }
}
