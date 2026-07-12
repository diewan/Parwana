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
//! ├── csv-protocol   (always included)
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
//!         .build()
//!         .await?;
//!
//!     // Access managers
//!     let sanads = client.sanads();
//!     let transfers = client.transfers();
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
pub mod local_store;
pub mod mcp;
pub mod prelude;
pub mod runtime;
pub mod sanads;
pub mod transfers;
pub mod wallet;

// Re-export core types from new modular crates (🔒 STABLE API only by default)
pub use csv_hash::Hash;
pub use csv_hash::commitment::Commitment;
pub use csv_hash::dag::{DAGNode, DAGSegment};
pub use csv_hash::sanad::SanadId;
pub use csv_hash::seal::{CommitAnchor, SealPoint};
pub use csv_protocol::error::ProtocolError;
pub use csv_protocol::genesis::Genesis;
pub use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof, ProofBundle};
pub use csv_protocol::chain_adapter_traits::SealOwnershipTarget;
pub use csv_protocol::seal_protocol::SealProtocol;
pub use csv_protocol::state::{OwnedState, StateRef};
pub use csv_protocol::transition::Transition;

// Re-export canonical protocol types (🔒 STABLE + 🟡 BETA)
pub use csv_hash::chain_id::ChainId;
pub use csv_protocol::version::{
    Capabilities, ErrorCode, PROTOCOL_VERSION, ProtocolVersion, SyncStatus, TransferStatus,
};

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

// Note: TransferStatus is already re-exported from protocol_version module above
