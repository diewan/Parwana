//! Agent-friendly types for CSV Adapter
//!
//! This module provides structured error types and status reporting
//! optimized for AI agent consumption.
//!
//! ## Key Features
//!
//! - **Self-describing errors**: Every error includes machine-actionable metadata
//! - **Structured status**: All operations return machine-readable progress
//! - **Fix suggestions**: Errors include actionable `FixAction` for autonomous resolution

use crate::collections::HashMap;
use csv_protocol::version::ProtocolVersion;
use serde::Serialize;

/// Trait for types that can provide machine-actionable error suggestions.
///
/// Implement this trait on error types to enable AI agents to auto-resolve issues.
pub trait HasErrorSuggestion {
    /// Get the error code for this error.
    fn error_code(&self) -> &'static str;

    /// Get a human-readable description of the error.
    fn description(&self) -> String;

    /// Get the suggested fix for this error.
    fn suggested_fix(&self) -> String;

    /// Get the documentation URL for this error.
    fn docs_url(&self) -> String;

    /// Get the optional machine-actionable fix action.
    fn fix_action(&self) -> Option<FixAction>;

    /// Convert this error into a complete ErrorSuggestion.
    fn to_suggestion(&self) -> ErrorSuggestion {
        ErrorSuggestion {
            error_code: self.error_code().to_string(),
            message: self.description(),
            docs_url: self.docs_url(),
            fix: self.fix_action(),
        }
    }
}

/// Centralized error codes for all CSV components.
///
/// These codes follow the pattern: COMPONENT_NUMBER (e.g., CORE_001, BTC_001)
pub mod error_codes {
    // Core adapter errors (CORE_001 - CORE_099)
    /// Seal replay attack detected.
    pub const CORE_SEAL_REPLAY: &str = "CORE_001";
    /// Invalid seal provided.
    pub const CORE_INVALID_SEAL: &str = "CORE_002";
    /// Commitment mismatch error.
    pub const CORE_COMMITMENT_MISMATCH: &str = "CORE_003";
    /// Inclusion proof verification failed.
    pub const CORE_INCLUSION_PROOF_FAILED: &str = "CORE_004";
    /// Finality not reached on chain.
    pub const CORE_FINALITY_NOT_REACHED: &str = "CORE_005";
    /// Invalid reorganization detected.
    pub const CORE_REORG_INVALID: &str = "CORE_006";
    /// Network communication error.
    pub const CORE_NETWORK_ERROR: &str = "CORE_007";
    /// Failed to publish transaction.
    pub const CORE_PUBLISH_FAILED: &str = "CORE_008";
    /// Serialization or deserialization error.
    pub const CORE_SERIALIZATION_ERROR: &str = "CORE_009";
    /// Invalid configuration.
    pub const CORE_INVALID_CONFIG: &str = "CORE_010";
    /// Version mismatch detected.
    pub const CORE_VERSION_MISMATCH: &str = "CORE_011";
    /// Domain separator mismatch.
    pub const CORE_DOMAIN_SEPARATOR_MISMATCH: &str = "CORE_012";
    /// Signature verification failed.
    pub const CORE_SIGNATURE_VERIFICATION_FAILED: &str = "CORE_013";
    /// Feature not available/enabled (replaces NOT_IMPLEMENTED).
    pub const CORE_FEATURE_NOT_ENABLED: &str = "CORE_014";
    /// Seal has no on-chain anchor (fake seal detected).
    pub const CORE_SEAL_NOT_ANCHORED: &str = "CORE_015";
    /// Storage/database error.
    pub const CORE_STORAGE_ERROR: &str = "CORE_016";
    /// Generic core error.
    pub const CORE_GENERIC: &str = "CORE_099";

    // Bitcoin adapter errors (BTC_001 - BTC_099)
    /// Bitcoin RPC error.
    pub const BTC_RPC_ERROR: &str = "BTC_001";
    /// Bitcoin transaction not found.
    pub const BTC_TRANSACTION_NOT_FOUND: &str = "BTC_002";
    /// Bitcoin UTXO already spent.
    pub const BTC_UTXO_SPENT: &str = "BTC_003";
    /// Invalid Bitcoin Merkle proof.
    pub const BTC_INVALID_MERKLE_PROOF: &str = "BTC_004";
    /// Bitcoin registry full.
    pub const BTC_REGISTRY_FULL: &str = "BTC_005";
    /// Bitcoin reorganization detected.
    pub const BTC_REORG_DETECTED: &str = "BTC_006";
    /// Insufficient Bitcoin confirmations.
    pub const BTC_INSUFFICIENT_CONFIRMATIONS: &str = "BTC_007";
    /// Insufficient Bitcoin funds.
    pub const BTC_INSUFFICIENT_FUNDS: &str = "BTC_008";

    // Ethereum adapter errors (ETH_001 - ETH_099)
    /// Ethereum RPC error.
    pub const ETH_RPC_ERROR: &str = "ETH_001";
    /// Ethereum storage slot already used.
    pub const ETH_SLOT_USED: &str = "ETH_002";
    /// Invalid Ethereum receipt proof.
    pub const ETH_INVALID_RECEIPT_PROOF: &str = "ETH_003";
    /// Ethereum reorganization detected.
    pub const ETH_REORG_DETECTED: &str = "ETH_004";
    /// Insufficient Ethereum confirmations.
    pub const ETH_INSUFFICIENT_CONFIRMATIONS: &str = "ETH_005";
    /// Ethereum wallet error.
    pub const ETH_WALLET_ERROR: &str = "ETH_006";
    /// Ethereum configuration error.
    pub const ETH_CONFIG_ERROR: &str = "ETH_007";
    /// Ethereum deployment error.
    pub const ETH_DEPLOYMENT_ERROR: &str = "ETH_008";

    // Sui adapter errors (SUI_001 - SUI_099)
    /// Sui RPC error.
    pub const SUI_RPC_ERROR: &str = "SUI_001";
    /// Sui object already used.
    pub const SUI_OBJECT_USED: &str = "SUI_002";
    /// Sui state proof failed.
    pub const SUI_STATE_PROOF_FAILED: &str = "SUI_003";
    /// Sui event proof failed.
    pub const SUI_EVENT_PROOF_FAILED: &str = "SUI_004";
    /// Sui checkpoint failed.
    pub const SUI_CHECKPOINT_FAILED: &str = "SUI_005";
    /// Sui transaction failed.
    pub const SUI_TRANSACTION_FAILED: &str = "SUI_006";
    /// Sui serialization error.
    pub const SUI_SERIALIZATION_ERROR: &str = "SUI_007";
    /// Sui confirmation timeout.
    pub const SUI_CONFIRMATION_TIMEOUT: &str = "SUI_008";
    /// Sui reorganization detected.
    pub const SUI_REORG_DETECTED: &str = "SUI_009";
    /// Sui network mismatch.
    pub const SUI_NETWORK_MISMATCH: &str = "SUI_010";

    // Aptos adapter errors (APT_001 - APT_099)
    /// Aptos RPC error.
    pub const APT_RPC_ERROR: &str = "APT_001";
    /// Aptos resource already used.
    pub const APT_RESOURCE_USED: &str = "APT_002";
    /// Aptos state proof failed.
    pub const APT_STATE_PROOF_FAILED: &str = "APT_003";
    /// Aptos event proof failed.
    pub const APT_EVENT_PROOF_FAILED: &str = "APT_004";
    /// Aptos checkpoint failed.
    pub const APT_CHECKPOINT_FAILED: &str = "APT_005";
    /// Aptos transaction failed.
    pub const APT_TRANSACTION_FAILED: &str = "APT_006";
    /// Aptos serialization error.
    pub const APT_SERIALIZATION_ERROR: &str = "APT_007";
    /// Aptos confirmation timeout.
    pub const APT_CONFIRMATION_TIMEOUT: &str = "APT_008";
    /// Aptos reorganization detected.
    pub const APT_REORG_DETECTED: &str = "APT_009";
    /// Aptos network mismatch.
    pub const APT_NETWORK_MISMATCH: &str = "APT_010";

    // Solana adapter errors (SOL_001 - SOL_099)
    /// Solana RPC error.
    pub const SOL_RPC_ERROR: &str = "SOL_001";
    /// Solana transaction error.
    pub const SOL_TRANSACTION_ERROR: &str = "SOL_002";
    /// Solana account not found.
    pub const SOL_ACCOUNT_NOT_FOUND: &str = "SOL_003";
    /// Solana invalid program ID.
    pub const SOL_INVALID_PROGRAM_ID: &str = "SOL_004";
    /// Solana invalid instruction.
    pub const SOL_INVALID_INSTRUCTION: &str = "SOL_005";
    /// Solana insufficient funds.
    pub const SOL_INSUFFICIENT_FUNDS: &str = "SOL_006";
    /// Solana network error.
    pub const SOL_NETWORK_ERROR: &str = "SOL_007";
    /// Solana serialization error.
    pub const SOL_SERIALIZATION_ERROR: &str = "SOL_008";
    /// Solana deserialization error.
    pub const SOL_DESERIALIZATION_ERROR: &str = "SOL_009";
    /// Solana keypair error.
    pub const SOL_KEYPAIR_ERROR: &str = "SOL_010";
    /// Solana wallet error.
    pub const SOL_WALLET_ERROR: &str = "SOL_011";
    /// Solana commitment error.
    pub const SOL_COMMITMENT_ERROR: &str = "SOL_012";
    /// Solana seal creation error.
    pub const SOL_SEAL_CREATION_ERROR: &str = "SOL_013";
    /// Solana anchor creation error.
    pub const SOL_ANCHOR_CREATION_ERROR: &str = "SOL_014";
    /// Solana proof generation error.
    pub const SOL_PROOF_GENERATION_ERROR: &str = "SOL_015";
    /// Solana invalid input.
    pub const SOL_INVALID_INPUT: &str = "SOL_016";
    /// Solana not implemented.
    pub const SOL_NOT_IMPLEMENTED: &str = "SOL_017";
    /// Solana unsupported operation.
    pub const SOL_UNSUPPORTED_OPERATION: &str = "SOL_018";

    // Wallet errors (WALLET_001 - WALLET_099)
    /// Wallet encryption failed.
    pub const WALLET_ENCRYPTION_FAILED: &str = "WALLET_001";
    /// Wallet decryption failed.
    pub const WALLET_DECRYPTION_FAILED: &str = "WALLET_002";
    /// Wallet invalid password.
    pub const WALLET_INVALID_PASSWORD: &str = "WALLET_003";
    /// Wallet key invalid format.
    pub const WALLET_KEY_INVALID_FORMAT: &str = "WALLET_004";
    /// Wallet key derivation failed.
    pub const WALLET_KEY_DERIVATION_FAILED: &str = "WALLET_005";
    /// Wallet signing failed.
    pub const WALLET_SIGNING_FAILED: &str = "WALLET_006";
    /// Wallet storage not found.
    pub const WALLET_STORAGE_NOT_FOUND: &str = "WALLET_007";
    /// Wallet storage serialization error.
    pub const WALLET_STORAGE_SERIALIZATION: &str = "WALLET_008";
    /// Wallet seal not found.
    pub const WALLET_SEAL_NOT_FOUND: &str = "WALLET_009";
    /// Wallet asset not found.
    pub const WALLET_ASSET_NOT_FOUND: &str = "WALLET_010";
    /// Wallet asset invalid data.
    pub const WALLET_ASSET_INVALID_DATA: &str = "WALLET_011";
    /// Wallet chain API HTTP error.
    pub const WALLET_CHAIN_API_HTTP: &str = "WALLET_012";
    /// Wallet chain API JSON error.
    pub const WALLET_CHAIN_API_JSON: &str = "WALLET_013";
    /// Wallet chain API invalid address.
    pub const WALLET_CHAIN_API_INVALID_ADDRESS: &str = "WALLET_014";
    /// Wallet chain API error.
    pub const WALLET_CHAIN_API_ERROR: &str = "WALLET_015";
    /// Wallet browser storage error.
    pub const WALLET_BROWSER_STORAGE: &str = "WALLET_016";
    /// Wallet native signer error.
    pub const WALLET_NATIVE_SIGNER_ERROR: &str = "WALLET_017";
    /// Wallet seal service error.
    pub const WALLET_SEAL_SERVICE_ERROR: &str = "WALLET_018";

    // Explorer errors (EXP_001 - EXP_099)
    /// Explorer I/O error.
    pub const EXP_IO_ERROR: &str = "EXP_001";
    /// Explorer TOML error.
    pub const EXP_TOML_ERROR: &str = "EXP_002";
    /// Explorer JSON error.
    pub const EXP_JSON_ERROR: &str = "EXP_003";
    /// Explorer database error.
    pub const EXP_DATABASE_ERROR: &str = "EXP_004";
    /// Explorer migration error.
    pub const EXP_MIGRATION_ERROR: &str = "EXP_005";
    /// Explorer entity not found.
    pub const EXP_ENTITY_NOT_FOUND: &str = "EXP_006";
    /// Explorer HTTP error.
    pub const EXP_HTTP_ERROR: &str = "EXP_007";
    /// Explorer RPC error.
    pub const EXP_RPC_ERROR: &str = "EXP_008";
    /// Explorer RPC parse error.
    pub const EXP_RPC_PARSE_ERROR: &str = "EXP_009";
    /// Explorer indexer stopped.
    pub const EXP_INDEXER_STOPPED: &str = "EXP_010";
    /// Explorer block error.
    pub const EXP_BLOCK_ERROR: &str = "EXP_011";
    /// Explorer chain reorganization.
    pub const EXP_CHAIN_REORG: &str = "EXP_012";
    /// Explorer GraphQL error.
    pub const EXP_GRAPHQL_ERROR: &str = "EXP_013";
    /// Explorer HTTP server error.
    pub const EXP_HTTP_SERVER_ERROR: &str = "EXP_014";
    /// Explorer hex decode error.
    pub const EXP_HEX_DECODE_ERROR: &str = "EXP_015";
    /// Explorer parse error.
    pub const EXP_PARSE_ERROR: &str = "EXP_016";
    /// Explorer internal error.
    pub const EXP_INTERNAL_ERROR: &str = "EXP_017";

    // Meta-crate errors (CSV_001 - CSV_099)
    /// CSV chain not supported.
    pub const CSV_CHAIN_NOT_SUPPORTED: &str = "CSV_001";
    /// CSV chain operation not enabled.
    pub const CSV_CHAIN_NOT_ENABLED: &str = "CSV_018";
    /// CSV insufficient funds.
    pub const CSV_INSUFFICIENT_FUNDS: &str = "CSV_002";
    /// CSV invalid sanad ID.
    pub const CSV_INVALID_SANAD_ID: &str = "CSV_003";
    /// CSV sanad not found.
    pub const CSV_SANAD_NOT_FOUND: &str = "CSV_004";
    /// CSV transfer not found.
    pub const CSV_TRANSFER_NOT_FOUND: &str = "CSV_005";
    /// CSV transfer failed.
    pub const CSV_TRANSFER_FAILED: &str = "CSV_006";
    /// CSV sanad already consumed.
    pub const CSV_SANAD_ALREADY_CONSUMED: &str = "CSV_007";
    /// CSV invalid commitment.
    pub const CSV_INVALID_COMMITMENT: &str = "CSV_008";
    /// CSV proof verification failed.
    pub const CSV_PROOF_VERIFICATION_FAILED: &str = "CSV_009";
    /// CSV wallet error.
    pub const CSV_WALLET_ERROR: &str = "CSV_019";
    /// CSV network error.
    pub const CSV_NETWORK_ERROR: &str = "CSV_010";
    /// CSV serialization error.
    pub const CSV_SERIALIZATION_ERROR: &str = "CSV_011";
    /// CSV config error.
    pub const CSV_CONFIG_ERROR: &str = "CSV_012";
    /// CSV store error.
    pub const CSV_STORE_ERROR: &str = "CSV_013";
    /// CSV builder error.
    pub const CSV_BUILDER_ERROR: &str = "CSV_014";
    /// CSV deployment error.
    pub const CSV_DEPLOYMENT_ERROR: &str = "CSV_015";
    /// CSV event stream error.
    pub const CSV_EVENT_STREAM_ERROR: &str = "CSV_016";
    /// CSV adapter error.
    pub const CSV_ADAPTER_ERROR: &str = "CSV_017";
    /// CSV generic error.
    pub const CSV_GENERIC: &str = "CSV_099";

    /// Generate a documentation URL for an error code.
    pub fn docs_url(code: &str) -> String {
        format!("https://docs.csv.dev/errors/{}", code)
    }
}

/// Agent-friendly transfer status with structured progress
///
/// Every operation returns machine-readable progress that agents can parse and act upon.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TransferStatus {
    /// Transfer initiated
    Initiated {
        /// Unique transfer identifier
        transfer_id: String,
        /// ISO 8601 timestamp
        timestamp: String,
    },
    /// Locking Sanad on source chain
    Locking {
        /// Source chain
        chain: ChainId,
        /// Estimated blocks to wait
        estimated_blocks: u32,
        /// Current confirmation count
        current_confirmations: u32,
        /// Required confirmation count
        required_confirmations: u32,
    },
    /// Generating cryptographic proof
    GeneratingProof {
        /// Type of proof being generated
        proof_type: String,
        /// Estimated proof size in bytes
        estimated_size_bytes: usize,
        /// Progress percentage (0-100)
        progress_percent: u8,
    },
    /// Submitting proof to destination chain
    SubmittingProof {
        /// Destination chain
        destination_chain: ChainId,
        /// Estimated gas cost
        gas_estimate: String,
        /// Transaction hash (if submitted)
        tx_hash: Option<String>,
    },
    /// Verifying proof on destination chain
    Verifying {
        /// Destination chain
        chain: ChainId,
        /// Verification time in milliseconds
        verification_time_ms: Option<u64>,
    },
    /// Minting Sanad on destination chain
    Minting {
        /// Destination chain
        chain: ChainId,
        /// Transaction hash
        tx_hash: String,
    },
    /// Transfer completed successfully
    Completed {
        /// Sanad ID on destination chain
        sanad_id: String,
        /// Destination chain
        destination_chain: ChainId,
        /// Destination transaction hash
        transaction_hash: String,
        /// Total transfer time in milliseconds
        total_time_ms: u64,
    },
    /// Transfer failed
    Failed {
        /// Machine-readable error code
        error_code: String,
        /// Human-readable error message
        error_message: String,
        /// Whether retrying might succeed
        retryable: bool,
        /// Suggested action for agent
        suggested_action: String,
    },
}

impl TransferStatus {
    /// Get progress percentage (0-100)
    pub fn progress_percent(&self) -> u8 {
        match self {
            Self::Initiated { .. } => 0,
            Self::Locking {
                current_confirmations,
                required_confirmations,
                ..
            } => ((current_confirmations * 25) / required_confirmations).min(25) as u8,
            Self::GeneratingProof {
                progress_percent, ..
            } => *progress_percent,
            Self::SubmittingProof { .. } => 50,
            Self::Verifying { .. } => 75,
            Self::Minting { .. } => 90,
            Self::Completed { .. } => 100,
            Self::Failed { .. } => 0,
        }
    }

    /// Check if transfer is complete
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Check if transfer has failed
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Get current step name
    pub fn current_step(&self) -> &'static str {
        match self {
            Self::Initiated { .. } => "initiated",
            Self::Locking { .. } => "locking",
            Self::GeneratingProof { .. } => "generating_proof",
            Self::SubmittingProof { .. } => "submitting_proof",
            Self::Verifying { .. } => "verifying",
            Self::Minting { .. } => "minting",
            Self::Completed { .. } => "completed",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Machine-actionable fix suggestion for errors
///
/// Agents can use this to automatically resolve issues without human intervention.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FixAction {
    /// Fund wallet from faucet
    FundFromFaucet {
        /// Faucet URL
        url: String,
        /// Amount to request
        amount: String,
    },
    /// Retry with different parameters
    Retry {
        /// Parameter changes to apply
        parameter_changes: HashMap<String, String>,
    },
    /// Check external state
    CheckState {
        /// URL to check
        url: String,
        /// What to check for
        what: String,
    },
    /// Wait for confirmations
    WaitForConfirmations {
        /// Required confirmations
        confirmations: u32,
        /// Estimated time in seconds
        estimated_seconds: u64,
    },
}

/// Self-describing error with machine-actionable metadata
///
/// Every error includes:
/// - Human-readable message
/// - Machine-readable error code
/// - Suggested fix (if available)
/// - Documentation URL
#[derive(Debug, Clone, Serialize)]
pub struct ErrorSuggestion {
    /// Human-readable suggestion
    pub message: String,
    /// Machine-actionable fix (if available)
    pub fix: Option<FixAction>,
    /// Related documentation URL
    pub docs_url: String,
    /// Error code for agent lookup
    pub error_code: String,
}

impl ErrorSuggestion {
    /// Create a new error suggestion
    pub fn new(
        error_code: impl Into<String>,
        message: impl Into<String>,
        docs_url: impl Into<String>,
    ) -> Self {
        Self {
            error_code: error_code.into(),
            message: message.into(),
            docs_url: docs_url.into(),
            fix: None,
        }
    }

    /// Add a fix action
    pub fn with_fix(mut self, fix: FixAction) -> Self {
        self.fix = Some(fix);
        self
    }
}

/// Chain identifier for agent compatibility
///
/// Re-export of canonical ChainId for agent-facing APIs.
pub use csv_hash::chain_id::ChainId;

// ─── Verification level ────────────────────────────────────────────────────

/// Verification level has been moved to csv-protocol.
/// Re-exporting for backward compatibility during migration.
pub use csv_protocol::verification::VerificationLevel;

// ─── Agent-facing result types ─────────────────────────────────────────────

/// Agent-friendly proof verification result.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentVerifyProofResult {
    pub is_valid: bool,
    pub verification_level: VerificationLevel,
    pub sanad_id: Option<String>,
    pub chain: Option<String>,
    pub seal_consumed: bool,
    pub replay_detected: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Agent-friendly transfer status enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum AgentTransferStatus {
    AwaitingLock,
    Locked,
    AwaitingFinality,
    ProofBuilding,
    ProofValidated,
    Minting,
    Complete,
    RolledBack,
    Compromised,
}

/// Agent-friendly transfer result.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentTransferResult {
    pub transfer_id: String,
    pub replay_id: String,
    pub lock_tx_hash: String,
    pub mint_tx_hash: String,
    pub source_chain: String,
    pub destination_chain: String,
    pub status: AgentTransferStatus,
    pub proof_bundle_available: bool,
}

/// Agent-friendly seal creation result.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentCreateSealResult {
    pub seal_id: String,
    pub chain: String,
    pub tx_hash: String,
    pub block_height: u64,
    pub status: AgentSealStatus,
}

/// Agent-friendly seal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum AgentSealStatus {
    Pending,
    Confirmed,
    Consumed,
    Invalid,
}

/// Agent-friendly sanad summary.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentSanadSummary {
    pub sanad_id: String,
    pub chain: String,
    pub status: String,
    pub created_at: String,
    /// Opaque; not interpreted by the agent layer.
    pub value: Option<String>,
    /// Hash of semantic schema if present.
    pub schema_id: Option<String>,
}

/// Agent-friendly get sanads result.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentGetSanadsResult {
    pub items: Vec<AgentSanadSummary>,
    pub total: u64,
    pub has_more: bool,
}

/// Agent-friendly RPC status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum AgentRpcStatus {
    Connected,
    Degraded,
    Unavailable,
}

/// Agent-friendly chain adapter info.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentChainAdapterInfo {
    pub chain_id: String,
    pub adapter_version: ProtocolVersion,
    pub capabilities: Vec<String>,
    pub network: String,
    pub rpc_status: AgentRpcStatus,
}

/// Agent-friendly protocol info result.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentProtocolInfoResult {
    pub protocol_version: ProtocolVersion,
    pub minimum_runtime_version: ProtocolVersion,
    pub chain_adapters: Vec<AgentChainAdapterInfo>,
}

/// Agent-friendly proof export result.
#[derive(Debug, Clone, Serialize)]
#[allow(missing_docs)]
pub struct AgentExportProofResult {
    pub transfer_id: String,
    pub format: String,
    pub bundle: String,
    /// `csv_tagged_hash("csv.proof.bundle.export.v1", bundle_bytes)` as hex
    pub bundle_hash: String,
    pub provenance_included: bool,
    pub verification_level: VerificationLevel,
}

#[cfg(any())]
mod tests {
    use super::*;
    use crate::protocol_version::builtin;

    #[test]
    fn test_chain_display() {
        assert_eq!(builtin::BITCOIN.to_string(), "bitcoin");
        assert_eq!(builtin::ETHEREUM.to_string(), "ethereum");
        assert_eq!(builtin::SUI.to_string(), "sui");
        assert_eq!(builtin::APTOS.to_string(), "aptos");
        assert_eq!(builtin::SOLANA.to_string(), "solana");
    }

    #[test]
    fn test_chain_from_str() {
        assert_eq!("bitcoin".parse::<ChainId>().unwrap(), *builtin::BITCOIN);
        assert_eq!("BITCOIN".parse::<ChainId>().unwrap(), *builtin::BITCOIN);
        assert_eq!("ethereum".parse::<ChainId>().unwrap(), *builtin::ETHEREUM);
        assert_eq!("ETHEREUM".parse::<ChainId>().unwrap(), *builtin::ETHEREUM);
        assert_eq!("solana".parse::<ChainId>().unwrap(), *builtin::SOLANA);
        assert_eq!("SOLANA".parse::<ChainId>().unwrap(), *builtin::SOLANA);
    }

    #[test]
    fn test_transfer_status_progress() {
        let status = TransferStatus::Initiated {
            transfer_id: "0x123".to_string(),
            timestamp: "2026-04-11T10:00:00Z".to_string(),
        };
        assert_eq!(status.progress_percent(), 0);
        assert_eq!(status.current_step(), "initiated");
        assert!(!status.is_complete());
        assert!(!status.is_failed());
    }

    #[test]
    fn test_error_suggestion_with_fix() {
        let suggestion = ErrorSuggestion::new(
            "CSV_001",
            "Insufficient funds",
            "https://docs.csv.dev/errors/CSV_001",
        )
        .with_fix(FixAction::FundFromFaucet {
            url: "https://faucet.csv.dev".to_string(),
            amount: "0.01 BTC".to_string(),
        });

        assert!(suggestion.fix.is_some());
        assert_eq!(suggestion.error_code, "CSV_001");
    }
}
