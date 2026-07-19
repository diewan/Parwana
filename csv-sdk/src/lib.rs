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
//! | `client` | Enable Parwana's primary protocol, transfer, wallet, and runtime SDK surface (default) |
//! | `accountability` | Enable the optional Accountability protocol facade |
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
#[cfg(feature = "accountability")]
pub mod accountability;
#[cfg(feature = "accountability")]
pub mod accountability_verification;
#[cfg(feature = "client")]
pub mod builder;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod config;
#[cfg(feature = "client")]
pub mod contract;
#[cfg(feature = "client")]
pub mod cross_chain;
#[cfg(feature = "client")]
pub mod error;
#[cfg(feature = "client")]
pub mod events;
#[cfg(feature = "client")]
pub mod local_store;
#[cfg(feature = "client")]
pub mod mcp;
pub mod prelude;
#[cfg(feature = "client")]
pub mod rpc_identity;
#[cfg(feature = "client")]
pub mod rpc_policy;
#[cfg(feature = "client")]
pub mod runtime;
#[cfg(feature = "client")]
pub mod sanads;
#[cfg(feature = "client")]
pub mod transfers;
#[cfg(feature = "client")]
pub mod wallet;

/// Canonical encoding and wire contracts supported for application consumers.
#[cfg(feature = "client")]
pub mod canonical {
    pub use csv_codec::{from_canonical_cbor, to_canonical_cbor};
    pub use csv_wire::*;
}

/// Pure, side-effect-free proof verification supported by the SDK facade.
#[cfg(feature = "client")]
pub mod verification {
    pub use csv_verifier::verify_proof;
}

/// Stable protocol type namespace for consumers that need more than the
/// convenience re-exports at the crate root.
#[cfg(feature = "client")]
pub mod protocol {
    pub use csv_hash as hash;
    pub use csv_protocol::*;
}

/// Portable key-management capability for external wallet applications.
#[cfg(feature = "consumer-wallet")]
pub mod key_management {
    pub use csv_keys::*;
}

/// Versioned encrypted wallet-envelope capability.
#[cfg(feature = "consumer-wallet")]
pub mod wallet_format {
    pub use csv_wallet::*;
}

/// Portable consumer storage capability. This is application persistence, not
/// protocol transfer authority or server-side storage.
#[cfg(feature = "consumer-wallet")]
pub mod consumer_storage {
    pub use csv_store::*;
}

/// SDK-owned application types returned by delegated runtime operations.
#[cfg(feature = "client")]
pub mod application {
    pub use csv_runtime::FinalityObservation;
}

// Re-export core types from new modular crates (🔒 STABLE API only by default)
#[cfg(feature = "client")]
pub use csv_hash::Hash;
#[cfg(feature = "client")]
pub use csv_hash::commitment::Commitment;
#[cfg(feature = "client")]
pub use csv_hash::dag::{DAGNode, DAGSegment};
#[cfg(feature = "client")]
pub use csv_hash::sanad::SanadId;
#[cfg(feature = "client")]
pub use csv_hash::seal::{CommitAnchor, SealPoint};
#[cfg(feature = "client")]
pub use csv_protocol::chain_adapter_traits::SealOwnershipTarget;
#[cfg(feature = "client")]
pub use csv_protocol::error::ProtocolError;
#[cfg(feature = "client")]
pub use csv_protocol::genesis::Genesis;
#[cfg(feature = "client")]
pub use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof, ProofBundle};
#[cfg(feature = "client")]
pub use csv_protocol::seal_protocol::SealProtocol;
#[cfg(feature = "client")]
pub use csv_protocol::state::{OwnedState, StateRef};
#[cfg(feature = "client")]
pub use csv_protocol::transition::Transition;

// Re-export canonical protocol types (🔒 STABLE + 🟡 BETA)
#[cfg(feature = "client")]
pub use csv_hash::chain_id::ChainId;
#[cfg(feature = "client")]
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
/// Remote chain-dispatch (WASM-REMOTE-001): forward adapter port calls to a
/// user-owned native host. Re-exported so hosts (e.g. `csv runtime serve`) can
/// reach [`csv_remote::host`] without importing the adapter crate directly.
#[cfg(feature = "client")]
pub use csv_remote;

#[cfg(feature = "client")]
pub use error::CsvError;

/// Re-export client
#[cfg(feature = "client")]
pub use client::CsvClient;

/// Re-export builder types
#[cfg(feature = "client")]
pub use builder::{ClientBuilder, StoreBackend};

/// Re-export runtime types
#[cfg(feature = "client")]
pub use runtime::{AdapterBuilder, ChainRuntime, RuntimeConfig, RuntimeManager};

/// Unified result type alias.
///
/// Equivalent to `Result<T, CsvError>`.
#[cfg(feature = "client")]
pub type Result<T> = core::result::Result<T, CsvError>;

// Note: TransferStatus is already re-exported from protocol_version module above
