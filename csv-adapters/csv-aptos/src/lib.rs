#![allow(clippy::collapsible_if)]
#![allow(unused_variables)]
//! Aptos Adapter for CSV (Client-Side Validation)
//!
//! This adapter implements the SealProtocol trait for Aptos,
//! using resources with key + delete as seals.
//!
//! ## Architecture
//!
//! - **Seals**: Move resources that can be deleted once (via `move_from`)
//! - **Anchors**: Events emitted when seal resources are deleted
//! - **Finality**: HotStuff consensus provides deterministic finality via 2f+1 certification
//!
//! ## Usage
//!
//! ```no_run
//! use csv_aptos::{AptosSealProtocol, AptosConfig, AptosNetwork};
//!
//! // Create adapter with configuration and RPC client
//! let config = AptosConfig::new(AptosNetwork::Devnet);
//! // let rpc = ...;
//! // let adapter = AptosSealProtocol::from_config(config, rpc).unwrap();
//! ```
//!
//! ## Production
//!
//! Enable the `rpc` feature to use real Aptos RPC calls:
//! ```toml
//! [dependencies]
//! csv-adapter-aptos = { version = "0.1", features = ["rpc"] }
//! ```

#![warn(missing_docs)]
#![allow(missing_docs)]
#![allow(dead_code)]

pub mod address_utils;
pub mod anchor;
pub mod chain_verification;
pub mod checkpoint;
pub mod config;
pub mod entry_function;
pub mod error;
pub mod merkle;
pub mod mint;
pub mod ops;
pub mod proofs;
pub mod rpc;
pub mod seal;
pub mod seal_protocol;
pub mod signatures;
pub mod types;
// pub mod verifier;  // REMOVED: verification centralized in csv-verifier per implementation.md

#[cfg(feature = "rpc")]
pub mod node;

pub use seal_protocol::AptosSealProtocol;

pub use checkpoint::CheckpointVerifier;
pub use config::{AptosConfig, AptosNetwork, CheckpointConfig};
pub use error::AptosError;
#[cfg(feature = "rpc")]
pub use node::AptosNode;
pub use proofs::{
    CommitmentEventBuilder, EventProof, EventProofVerifier, StateProof, StateProofVerifier,
    TransactionProof,
};
#[cfg(test)]
pub use rpc::MockAptosRpc;
pub use rpc::{
    AptosAccountReader, AptosBlockInfo, AptosCheckpointVerifier, AptosEvent, AptosEventReader,
    AptosLedgerInfo, AptosLedgerReader, AptosModulePublisher, AptosResource, AptosRpc,
    AptosSignerIdentity, AptosTransaction, AptosTransactionReader, AptosTransactionSubmitter,
};
pub use seal::{SealRecord, SealRegistry, SealStore};
pub use types::{AptosCommitAnchor, AptosFinalityProof, AptosInclusionProof, AptosSealPoint};

// Ops exports
pub use ops::AptosBackend;
