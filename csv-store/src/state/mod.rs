//! Application state types for CSV Wallet and CLI.
//!
//! This module provides the core state types used by both
//! csv-wallet (browser) and csv-cli (desktop) applications.
//!
//! # Module Structure
//!
//! ```text
//! state/
//! ├── mod.rs       # Re-exports
//! ├── core.rs      # ChainId, Network, ChainConfig
//! ├── wallet.rs    # WalletAccount, WalletConfig
//! ├── domain.rs    # Sanads, transfers, contracts, seals, proofs
//! ├── storage.rs   # StateStorage (main storage struct)
//! └── backend.rs   # StorageBackend trait + FileStorage
//! ```
//!
//! # Architecture
//!
//! This module stores **metadata and state only** - never private keys.
//! Key storage is handled by `csv-adapter-keystore` via references:
//!
//! ```text
//! // In StateStorage (this crate)
//! wallet.accounts[0].keystore_ref = Some("550e8400-e29b-41d4-a716-446655440000");
//!
//! // In csv-adapter-keystore (~/.csv/keystore/550e8400-e29b-41d4-a716-446655440000.json)
//! // { encrypted_private_key: "...", cipher: "aes-256-gcm", ... }
//! ```

// Core types
pub mod core;
// Domain-specific types (sanads, transfers, contracts)
pub mod domain;
// Storage backend trait and implementations
pub mod backend;
// Main storage container
pub mod storage;
// Wallet-specific types
pub mod wallet;

// Re-exports for backward compatibility
#[cfg(all(not(target_arch = "wasm32"), feature = "file-storage"))]
pub use backend::FileStorage;
pub use backend::{StorageBackend, StorageError};
pub use core::{ChainConfig, Network};
pub use csv_core::ChainId;
pub use domain::{
    ContractRecord, ProofRecord, SanadRecord, SanadStatus, SealRecord, SealStatus, TestResult,
    TestStatus, TransactionRecord, TransactionStatus, TransactionType, TransferRecord,
    TransferStatus,
};
pub use storage::StateStorage;
/// Backward compatibility alias
pub type UnifiedStorage = StateStorage;
pub use wallet::{FaucetConfig, GasAccount, WalletAccount, WalletConfig};

/// Version of the state format.
pub const STATE_VERSION: u32 = 1;

/// Backward compatibility: Chain is now ChainId.
#[deprecated(since = "0.5.0", note = "Use ChainId instead")]
pub type Chain = ChainId;
