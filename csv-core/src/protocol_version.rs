//! CSV Protocol Version and Canonical Contract
//!
//! This module defines the **single source of truth** for all protocol-facing
//! consumers: Rust adapters, CLI, TypeScript SDK, MCP server, Explorer, and Wallet.
//!
//! ## What lives here
//!
//! - Protocol version constants
//! - Chain IDs (canonical registry)
//! - Transfer status enums
//! - Error code registry
//! - Capability flags
//!
//! ## Stability guarantees
//!
//! Items in this module are categorized into three tiers:
//!
//! ### 🔒 Stable API
//! Items marked as stable will not change without a semver-major bump.
//! Safe for production use and external SDK consumption.
//!
//! ### 🟡 Beta API
//! Items may receive additive changes (new variants, fields) but breaking
//! changes require a minor version bump with deprecation warnings.
//!
//! ### 🧪 Experimental API
//! Items may change or be removed without notice. Feature-gated behind
//! `experimental` feature flag.
//!
//! ## Cross-language alignment
//!
//! These types MUST be mirrored in:
//! - `typescript-sdk/src/types.ts`
//! - `csv-cli/src/output.rs`
//! - `csv-mcp-server/src/types/`
//! - `csv-explorer/shared/src/types.rs`
//! - `csv-wallet/src/services/`

use serde::{Deserialize, Serialize};

// Include auto-generated version constants from build.rs
include!(concat!(env!("OUT_DIR"), "/version.rs"));

// ===========================================================================
// Protocol Version
// ===========================================================================

/// Current CSV protocol version.
///
/// This version is used to ensure all components (adapters, CLI, SDK, explorer,
/// wallet) are speaking the same protocol dialect.
///
/// Note: This is auto-generated from the workspace Cargo.toml version.
pub const PROTOCOL_VERSION: &str = PROTOCOL_VERSION_STR;

/// Protocol version components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version (breaking changes)
    pub major: u32,
    /// Minor version (additive changes)
    pub minor: u32,
    /// Patch version (bug fixes)
    pub patch: u32,
}

impl ProtocolVersion {
    /// Current stable protocol version.
    pub const fn current() -> Self {
        Self {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            patch: VERSION_PATCH,
        }
    }

    /// Check if this version is compatible with the current protocol.
    pub fn is_compatible(&self) -> bool {
        self.major == Self::current().major
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ===========================================================================
pub use csv_hash::chain_id::ChainId;

// Chain IDs (Open Registry) [🔒 STABLE]
// ===========================================================================

/// Open chain identifier — any string is valid.
///
/// For the 100-chain goal, chain IDs are plain strings. This type is a thin
/// newtype over `String` that provides ergonomic comparison, display, and
/// serialization.
///
/// ### Adding a new chain
///
/// 1. Create a new `csv-{chain}` crate implementing `ChainBackend`
/// 2. The chain ID is specified in the chain's configuration file.
///
/// Built-in chain IDs for the five supported chains.
///
/// These are convenience constants — the protocol accepts any string ID.
pub mod builtin {
    use csv_hash::chain_id::ChainId;
    use lazy_static::lazy_static;

    lazy_static! {
        /// Bitcoin mainnet/testnet (UTXO-based)
        pub static ref BITCOIN: ChainId = ChainId::new("bitcoin");
        /// Ethereum mainnet/testnet (EVM-based)
        pub static ref ETHEREUM: ChainId = ChainId::new("ethereum");
        /// Sui mainnet/testnet (Move-based, object-oriented)
        pub static ref SUI: ChainId = ChainId::new("sui");
        /// Aptos mainnet/testnet (Move-based, resource-oriented)
        pub static ref APTOS: ChainId = ChainId::new("aptos");
        /// Solana mainnet/devnet (Sealevel-based, account-oriented)
        pub static ref SOLANA: ChainId = ChainId::new("solana");
    }
}

// ===========================================================================
// Transfer Status Enums [🔒 STABLE]
// ===========================================================================

/// Transfer lifecycle status.
///
/// This enum tracks the complete lifecycle of a cross-chain transfer.
/// Every protocol consumer (CLI, SDK, Explorer, Wallet) MUST use this
/// exact status sequence.
///
/// ### Variants
///
/// The status progresses through these states:
/// `Initiated` → `Locking` → `GeneratingProof` → `SubmittingProof` → `Verifying` → `Minting` → `Completed`
///
/// Any state can transition to `Failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    /// Transfer initiated, waiting for source chain lock
    Initiated,
    /// Sanad locked on source chain, waiting for confirmations
    Locking {
        /// Current confirmation count
        current_confirmations: u32,
        /// Required confirmation count
        required_confirmations: u32,
    },
    /// Proof generation in progress
    GeneratingProof {
        /// Progress percentage (0-100)
        progress_percent: u8,
    },
    /// Inclusion proof ready, waiting for P2P delivery
    ProofReady {
        /// Block height where the lock transaction was confirmed
        proof_block: u64,
    },
    /// Proof submitted to destination chain
    SubmittingProof,
    /// Proof verification in progress on destination chain
    Verifying,
    /// Sanad minting in progress on destination chain
    Minting,
    /// Transfer completed successfully
    Completed,
    /// Transfer failed (with error details)
    Failed {
        /// Machine-readable error code
        error_code: String,
        /// Whether retrying might succeed
        retryable: bool,
    },
}

impl TransferStatus {
    /// Check if transfer is pending (initiated or locking).
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Initiated | Self::Locking { .. })
    }

    /// Check if transfer is in progress (proof generation, submission, verification, minting).
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            Self::GeneratingProof { .. } | Self::SubmittingProof | Self::Verifying | Self::Minting
        )
    }

    /// Get progress percentage (0-100).
    pub fn progress_percent(&self) -> u8 {
        match self {
            Self::Initiated => 0,
            Self::Locking {
                current_confirmations,
                required_confirmations,
                ..
            } => {
                if *required_confirmations == 0 {
                    25
                } else {
                    ((current_confirmations * 25) / required_confirmations).min(25) as u8
                }
            }
            Self::GeneratingProof { progress_percent } => *progress_percent,
            Self::ProofReady { .. } => 40,
            Self::SubmittingProof => 50,
            Self::Verifying => 75,
            Self::Minting => 90,
            Self::Completed => 100,
            Self::Failed { .. } => 0,
        }
    }

    /// Check if transfer is terminal (completed or failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed { .. })
    }

    /// Check if transfer succeeded.
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Check if transfer failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

impl std::fmt::Display for TransferStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initiated => write!(f, "initiated"),
            Self::Locking { .. } => write!(f, "locking"),
            Self::GeneratingProof { .. } => write!(f, "generating_proof"),
            Self::ProofReady { .. } => write!(f, "proof_ready"),
            Self::SubmittingProof => write!(f, "submitting_proof"),
            Self::Verifying => write!(f, "verifying"),
            Self::Minting => write!(f, "minting"),
            Self::Completed => write!(f, "completed"),
            Self::Failed { .. } => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for TransferStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "initiated" => Ok(Self::Initiated),
            "locking" => Ok(Self::Locking {
                current_confirmations: 0,
                required_confirmations: 1,
            }),
            "generating_proof" => Ok(Self::GeneratingProof {
                progress_percent: 0,
            }),
            "proof_ready" => Ok(Self::ProofReady { proof_block: 0 }),
            "submitting_proof" => Ok(Self::SubmittingProof),
            "verifying" => Ok(Self::Verifying),
            "minting" => Ok(Self::Minting),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed {
                error_code: "unknown".to_string(),
                retryable: false,
            }),
            _ => Err(format!("Unknown transfer status: '{}'", s)),
        }
    }
}

/// Conversion from a simplified transfer status (used by stores/UI) to the full protocol status
///
/// Maps simplified states to their closest protocol equivalent:
/// - `Initiated` → `Initiated`
/// - `Locked` → `ProofReady` (lock confirmed, proof ready)
/// - `Verifying` → `Verifying`
/// - `Minting` → `Minting`
/// - `Completed` → `Completed`
/// - `Failed` → `Failed { retryable: true }`
pub fn simplified_to_full(status: SimplifiedTransferStatus) -> TransferStatus {
    match status {
        SimplifiedTransferStatus::Initiated => TransferStatus::Initiated,
        SimplifiedTransferStatus::Locked => TransferStatus::ProofReady { proof_block: 0 },
        SimplifiedTransferStatus::Verifying => TransferStatus::Verifying,
        SimplifiedTransferStatus::Minting => TransferStatus::Minting,
        SimplifiedTransferStatus::Completed => TransferStatus::Completed,
        SimplifiedTransferStatus::Failed => TransferStatus::Failed {
            error_code: "unknown".to_string(),
            retryable: true,
        },
    }
}

/// Simplified transfer status for stores and UI
///
/// This is a reduced set of states used by storage layers and UI components.
/// Convert to/from the full protocol status using [`simplified_to_full`] and [`Self::to_full`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SimplifiedTransferStatus {
    /// Transfer initiated (lock transaction created).
    Initiated,
    /// Assets locked on source chain.
    Locked,
    /// Proof being verified.
    Verifying,
    /// Assets being minted on destination chain.
    Minting,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed.
    Failed,
}

impl SimplifiedTransferStatus {
    /// Convert to the full protocol status
    pub fn to_full(self) -> TransferStatus {
        simplified_to_full(self)
    }
}

impl std::fmt::Display for SimplifiedTransferStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initiated => write!(f, "initiated"),
            Self::Locked => write!(f, "locked"),
            Self::Verifying => write!(f, "verifying"),
            Self::Minting => write!(f, "minting"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// ===========================================================================
// Error Code Registry [🟡 BETA]
// ===========================================================================

/// CSV protocol error codes.
///
/// All error codes follow the pattern: `CSV_<CATEGORY>_<NUMBER>`
///
/// Categories:
/// - `0xx`: Protocol errors
/// - `1xx`: Adapter errors
/// - `2xx`: Network/RPC errors
/// - `3xx`: Validation errors
/// - `4xx`: State/Storage errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    // Protocol errors (0xx)
    /// Protocol version mismatch
    ProtocolVersionMismatch,
    /// Invalid sanad ID
    InvalidSanadId,
    /// Sanad already spent
    SanadAlreadySpent,
    /// Invalid seal reference
    InvalidSealPoint,
    /// Invalid commitment
    InvalidCommitment,

    // Adapter errors (1xx)
    /// Chain not supported
    ChainNotSupported,
    /// Adapter not initialized
    AdapterNotInitialized,
    /// Unsupported operation
    UnsupportedOperation,

    // Network/RPC errors (2xx)
    /// RPC request failed
    RpcRequestFailed,
    /// Network timeout
    NetworkTimeout,
    /// Rate limit exceeded
    RateLimitExceeded,

    // Validation errors (3xx)
    /// Invalid signature
    InvalidSignature,
    /// Invalid proof
    InvalidProof,
    /// Insufficient confirmations
    InsufficientConfirmations,

    // State/Storage errors (4xx)
    /// Storage error
    StorageError,
    /// State corruption detected
    StateCorruption,
    /// Concurrent modification conflict
    ConcurrentModification,
}

impl ErrorCode {
    /// Machine-readable error code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProtocolVersionMismatch => "CSV_001",
            Self::InvalidSanadId => "CSV_002",
            Self::SanadAlreadySpent => "CSV_003",
            Self::InvalidSealPoint => "CSV_004",
            Self::InvalidCommitment => "CSV_005",
            Self::ChainNotSupported => "CSV_101",
            Self::AdapterNotInitialized => "CSV_102",
            Self::UnsupportedOperation => "CSV_103",
            Self::RpcRequestFailed => "CSV_201",
            Self::NetworkTimeout => "CSV_202",
            Self::RateLimitExceeded => "CSV_203",
            Self::InvalidSignature => "CSV_301",
            Self::InvalidProof => "CSV_302",
            Self::InsufficientConfirmations => "CSV_303",
            Self::StorageError => "CSV_401",
            Self::StateCorruption => "CSV_402",
            Self::ConcurrentModification => "CSV_403",
        }
    }

    /// Human-readable error category.
    pub fn category(&self) -> &'static str {
        match self {
            Self::ProtocolVersionMismatch
            | Self::InvalidSanadId
            | Self::SanadAlreadySpent
            | Self::InvalidSealPoint
            | Self::InvalidCommitment => "protocol",
            Self::ChainNotSupported | Self::AdapterNotInitialized | Self::UnsupportedOperation => {
                "adapter"
            }
            Self::RpcRequestFailed | Self::NetworkTimeout | Self::RateLimitExceeded => "network",
            Self::InvalidSignature | Self::InvalidProof | Self::InsufficientConfirmations => {
                "validation"
            }
            Self::StorageError | Self::StateCorruption | Self::ConcurrentModification => "storage",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

// ===========================================================================
// Capability Flags [🟡 BETA]
// ===========================================================================

/// Protocol capability flags.
///
/// Used to negotiate features between protocol versions and components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Capabilities {
    /// Supports advanced commitment schemes beyond basic hash commitments
    pub advanced_commitments: bool,
    /// Supports MPC (Multi-Party Computation) tree proofs
    pub mpc_proofs: bool,
    /// Supports deterministic VM transitions
    pub vm_transitions: bool,
    /// Supports RGB protocol compatibility layer
    pub rgb_compat: bool,
    /// Supports tapret verification
    pub tapret_verify: bool,
    /// Supports cross-chain atomic transfers
    pub cross_chain_transfers: bool,
}

impl Capabilities {
    /// Default capabilities (stable protocol baseline).
    pub const fn default() -> Self {
        Self {
            advanced_commitments: false,
            mpc_proofs: false,
            vm_transitions: false,
            rgb_compat: false,
            tapret_verify: false,
            cross_chain_transfers: true,
        }
    }

    /// Full capabilities (experimental features enabled).
    #[cfg(feature = "experimental")]
    pub fn experimental() -> Self {
        Self {
            advanced_commitments: true,
            mpc_proofs: true,
            vm_transitions: true,
            rgb_compat: true,
            tapret_verify: true,
            cross_chain_transfers: true,
        }
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::default()
    }
}

// ===========================================================================
// Default Finality Depths [🟡 BETA]
// ===========================================================================

/// Default finality depths per chain (number of confirmations required).
///
/// These are the protocol-recommended minimum confirmation counts for each
/// supported chain. Runtime policies SHOULD use these as defaults but may
/// override them for specific deployment requirements.
///
/// | Chain      | Confirmations | Rationale                          |
/// |------------|---------------|-------------------------------------|
/// | Bitcoin    | 6             | 6 confirmations for double-spend safety |
/// | Ethereum   | 15            | ~3 minutes at 12s block time       |
/// | Solana     | 32            | ~16 seconds at 400ms slot time     |
/// | Aptos      | 5             | Quick finality with BFT consensus  |
/// | Sui        | 15            | Similar to Ethereum                |
/// | Celestia   | 100           | DA chain, high finality threshold  |
///
/// **DEPRECATED**: This type has been moved to csv-protocol.
/// Please use `csv_protocol::finality::capabilities::FinalityDepths` instead.
pub use csv_protocol::finality::capabilities::FinalityDepths;

#[cfg(test)]
mod finality_tests {
    use super::*;

    #[test]
    fn test_default_finality_depths() {
        let depths = FinalityDepths::defaults();
        assert_eq!(depths.bitcoin, 6);
        assert_eq!(depths.ethereum, 15);
        assert_eq!(depths.solana, 32);
        assert_eq!(depths.aptos, 5);
        assert_eq!(depths.sui, 15);
        assert_eq!(depths.celestia, 100);
    }

    #[test]
    fn test_finality_depths_for_chain() {
        let depths = FinalityDepths::defaults();
        assert_eq!(depths.for_chain("bitcoin"), Some(6));
        assert_eq!(depths.for_chain("ethereum"), Some(15));
        assert_eq!(depths.for_chain("solana"), Some(32));
        assert_eq!(depths.for_chain("unknown"), None);
    }

    #[test]
    fn test_finality_depths_for_chain_or_default() {
        let depths = FinalityDepths::defaults();
        assert_eq!(depths.for_chain_or_default("bitcoin", 1), 6);
        assert_eq!(depths.for_chain_or_default("unknown", 1), 1);
        assert_eq!(depths.for_chain_or_default("unknown", 10), 10);
    }

    #[test]
    fn test_finality_depths_has_depth() {
        let depths = FinalityDepths::defaults();
        assert!(depths.has_depth("bitcoin"));
        assert!(depths.has_depth("ethereum"));
        assert!(!depths.has_depth("unknown"));
    }
}

// ===========================================================================
// Standardized Protocol Nouns [🔒 STABLE]
// ===========================================================================

/// Standardized nouns that MUST be used across wallet/explorer/core:
///
/// | Concept       | Canonical Name  | Description                                    |
/// |---------------|-----------------|------------------------------------------------|
/// | Ownership     | `sanad`         | A verifiable, single-use digital sanad         |
/// | Binding       | `seal`          | Chain-specific binding mechanism               |
/// | Publication   | `anchor`        | Published commitment on-chain                  |
/// | Movement      | `transfer`      | Cross-chain sanad movement                     |
/// | Verification  | `proof`         | Cryptographic proof of lock/mint               |
/// | Progress      | `sync_status`   | Indexer/sync freshness indicator               |
///
/// Sync status for indexers and data systems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// Not yet started
    NotStarted,
    /// Currently syncing
    Syncing {
        /// Current block/checkpoint/version
        current: u64,
        /// Target block/checkpoint/version
        target: u64,
    },
    /// Fully synced
    Synced {
        /// Latest block/checkpoint/version
        latest: u64,
    },
    /// Sync encountered an error
    Error {
        /// Error code
        error_code: String,
    },
}

impl SyncStatus {
    /// Check if fully synced.
    pub fn is_synced(&self) -> bool {
        matches!(self, Self::Synced { .. })
    }

    /// Get progress percentage (0-100).
    pub fn progress_percent(&self) -> u8 {
        match self {
            Self::NotStarted => 0,
            Self::Syncing { current, target } => {
                if *target == 0 {
                    0
                } else {
                    ((*current as f64 / *target as f64) * 100.0).min(100.0) as u8
                }
            }
            Self::Synced { .. } => 100,
            Self::Error { .. } => 0,
        }
    }
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => write!(f, "not_started"),
            Self::Syncing { current, target } => {
                write!(f, "syncing ({}/{})", current, target)
            }
            Self::Synced { latest } => write!(f, "synced ({})", latest),
            Self::Error { error_code } => write!(f, "error ({})", error_code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        let v = ProtocolVersion::current();
        assert_eq!(v.major, VERSION_MAJOR);
        assert_eq!(v.minor, VERSION_MINOR);
        assert_eq!(v.patch, VERSION_PATCH);
        assert!(v.is_compatible());
        assert_eq!(v.to_string(), PROTOCOL_VERSION_STR);
    }

    #[test]
    fn test_chain_canonical_ids() {
        assert_eq!(builtin::BITCOIN.as_str(), "bitcoin");
        assert_eq!(builtin::ETHEREUM.as_str(), "ethereum");
        assert_eq!(builtin::SUI.as_str(), "sui");
        assert_eq!(builtin::APTOS.as_str(), "aptos");
        assert_eq!(builtin::SOLANA.as_str(), "solana");
    }

    #[test]
    fn test_chain_roundtrip() {
        let chains = [
            builtin::BITCOIN.clone(),
            builtin::ETHEREUM.clone(),
            builtin::SUI.clone(),
            builtin::APTOS.clone(),
            builtin::SOLANA.clone(),
        ];
        for chain in &chains {
            let s = chain.to_string();
            let parsed: ChainId = s
                .parse()
                .unwrap_or_else(|_| panic!("Failed to parse: {}", s));
            assert_eq!(chain, &parsed, "Chain roundtrip failed for {}", s);
        }
    }

    #[test]
    fn test_chain_open_registry() {
        // Any string is a valid chain ID
        let arbitrary = ChainId::new("cosmos");
        assert_eq!(arbitrary.as_str(), "cosmos");
        let upper = ChainId::new("POLYGON");
        assert_eq!(upper.as_str(), "polygon");
    }

    #[test]
    fn test_transfer_status_progress() {
        assert_eq!(TransferStatus::Initiated.progress_percent(), 0);
        assert_eq!(TransferStatus::Completed.progress_percent(), 100);
        assert!(TransferStatus::Completed.is_terminal());
        assert!(TransferStatus::Completed.is_completed());
    }

    #[test]
    fn test_transfer_status_locking() {
        let status = TransferStatus::Locking {
            current_confirmations: 3,
            required_confirmations: 6,
        };
        assert_eq!(status.progress_percent(), 12); // (3*25)/6 = 12
        assert!(!status.is_terminal());
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ErrorCode::ProtocolVersionMismatch.code(), "CSV_001");
        assert_eq!(ErrorCode::ChainNotSupported.code(), "CSV_101");
        assert_eq!(ErrorCode::RpcRequestFailed.code(), "CSV_201");
        assert_eq!(ErrorCode::InvalidSignature.code(), "CSV_301");
        assert_eq!(ErrorCode::StorageError.code(), "CSV_401");
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(ErrorCode::ProtocolVersionMismatch.category(), "protocol");
        assert_eq!(ErrorCode::ChainNotSupported.category(), "adapter");
        assert_eq!(ErrorCode::RpcRequestFailed.category(), "network");
        assert_eq!(ErrorCode::InvalidSignature.category(), "validation");
        assert_eq!(ErrorCode::StorageError.category(), "storage");
    }

    #[test]
    fn test_capabilities_default() {
        let caps = Capabilities::default();
        assert!(caps.cross_chain_transfers);
        assert!(!caps.advanced_commitments);
        assert!(!caps.mpc_proofs);
    }

    #[test]
    fn test_sync_status() {
        let syncing = SyncStatus::Syncing {
            current: 500,
            target: 1000,
        };
        assert_eq!(syncing.progress_percent(), 50);
        assert!(!syncing.is_synced());

        let synced = SyncStatus::Synced { latest: 1000 };
        assert_eq!(synced.progress_percent(), 100);
        assert!(synced.is_synced());
    }
}
