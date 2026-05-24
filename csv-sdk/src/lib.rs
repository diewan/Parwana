//! CSV SDK — Unified Meta-Crate
//!
//! This crate provides a single entry point for all CSV (Client-Side Validation)
//! operations, unifying the individual chain backend crates behind a coherent,
//! ergonomic API.
//!
//! # Architecture
//!
//! ```text
//! csv-sdk (this crate)
//! ├── csv-core       (always included)
//! ├── csv-bitcoin    (optional, feature: "bitcoin")
//! ├── csv-ethereum   (optional, feature: "ethereum")
//! ├── csv-sui        (optional, feature: "sui")
//! ├── csv-aptos      (optional, feature: "aptos")
//! └── csv-store      (optional, feature: "sqlite")
//! ```
//!
//! # Quick Start
//!
//! ```no_run
//! use csv_sdk::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Build a client with Bitcoin support
//!     let client = CsvClient::builder()
//!         .with_chain(ChainId::new("bitcoin"))
//!         .with_store_backend(StoreBackend::InMemory)
//!         .build()?;
//!
//!     // Access managers
//!     let sanads = client.sanads();
//!     let transfers = client.transfers();
//!     let proofs = client.proofs();
//!
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `bitcoin` | Enable Bitcoin backend |
//! | `ethereum` | Enable Ethereum backend |
//! | `sui` | Enable Sui backend |
//! | `aptos` | Enable Aptos backend |
//! | `all-chains` | Enable all chain backends |
//! | `tokio` | Enable tokio async runtime (default) |
//! | `async-std` | Enable async-std runtime |
//! | `sqlite` | Enable SQLite persistence |
//! | `in-memory` | Enable in-memory store backend |
//! | `wallet` | Enable unified wallet management |
//!
//! # Key Concepts
//!
//! - **Sanad**: A verifiable, single-use digital sanad (deed) that can be transferred
//!   cross-chain. Exists in client state, not on any chain.
//! - **Seal**: The on-chain mechanism that enforces a Sanad's single-use.
//!   Chain-specific and exists on one chain only.
//! - **Client-Side Validation (CSV)**: The client does the verification, not
//!   the blockchain. The chain only records commitments and enforces single-use.

#![warn(missing_docs)]

// Internal modules
pub mod builder;
pub mod client;
pub mod config;
pub mod cross_chain;
pub mod error;
pub mod events;
pub mod prelude;
pub mod proofs;
pub mod runtime;
pub mod sanads;
pub mod transfers;
pub mod wallet;

// Re-export core types from new modular crates (🔒 STABLE API only by default)
pub use csv_protocol::{
    CommitAnchor, Commitment, Consignment, CrossChainLockEvent, DAGNode,
    DAGSegment, FinalityProof, Genesis, InclusionProof, OwnedState, OwnershipProof,
    ProtocolError, Result as CoreResult, Sanad, SealProtocol, StateRef, StoreError, Transition,
};
pub use csv_hash::Hash;
pub use csv_hash::sanad::SanadId;
pub use csv_hash::seal::SealPoint;
pub use csv_proof::proof::ProofBundle;

// Re-export canonical protocol types (🔒 STABLE + 🟡 BETA)
pub use csv_protocol::protocol_version::{
    Capabilities, ErrorCode, PROTOCOL_VERSION, ProtocolVersion, SyncStatus, TransferStatus,
};
pub use csv_hash::chain_id::ChainId;

// ===========================================================================
// Experimental re-exports (feature-gated)
// ===========================================================================

/// Re-exports of experimental modules — requires `experimental` feature.
///
/// These APIs may change or be removed without notice.
#[cfg(feature = "experimental")]
pub mod experimental {
    pub use csv_hash::commit_mux::{CommitMux, MuxLeaf, MuxProof};
}

/// Re-export error types
pub use error::CsvError;

/// Re-export client
pub use client::CsvClient;

/// Re-export builder types
pub use builder::{ClientBuilder, StoreBackend};

/// Re-export runtime types
pub use runtime::{AdapterBuilder, ChainRuntime, RuntimeConfig, RuntimeManager};

/// Unified result type alias.
///
/// Equivalent to `Result<T, CsvError>`.
pub type Result<T> = core::result::Result<T, CsvError>;

// Re-export chain adapter crates for use by csv-wallet and csv-cli
// This allows apps to access chain-specific types through csv-sdk,
// respecting the Engineering Plan rule that apps must not import
// csv-bitcoin/csv-ethereum/etc. directly.
#[cfg(feature = "bitcoin")]
pub use csv_bitcoin;
#[cfg(feature = "ethereum")]
pub use csv_ethereum;
#[cfg(feature = "sui")]
pub use csv_sui;
#[cfg(feature = "aptos")]
pub use csv_aptos;
#[cfg(feature = "solana")]
pub use csv_solana;

// Note: TransferStatus is already re-exported from protocol_version module above
