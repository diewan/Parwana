//! Sui Adapter for CSV (Client-Side Validation)
#![allow(clippy::needless_return)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::redundant_field_names)]
//!
//! This adapter implements the SealProtocol trait for Sui,
//! using owned objects with one_time attributes as seals.
//!
//! ## Architecture
//!
//! - **Seals**: Sui objects that can be transferred and consumed once
//! - **Anchors**: Dynamic fields created when seal objects are consumed
//! - **Finality**: Narwhal consensus provides deterministic finality via checkpoint certification
//!
//! ## Usage
//!
//! ```no_run
//! use csv_sui::{SuiSealProtocol, SuiConfig, SuiNetwork};
//!
//! // Create adapter with configuration
//! let config = SuiConfig::new(SuiNetwork::Testnet);
//! // let rpc = ...;
//! // let adapter = SuiSealProtocol::from_config(config, rpc).unwrap();
//! ```
//!
//! ## Production
//!
//! Enable the `rpc` feature to use real Sui RPC calls:
//! ```toml
//! [dependencies]
//! csv-adapter-sui = { version = "0.1", features = ["rpc"] }
//! ```

#![warn(missing_docs)]
#![allow(missing_docs)]
#![allow(dead_code)]

pub mod chain_verification;
pub mod checkpoint;
pub mod config;
pub mod deploy;
pub mod error;
pub mod gas_utils;
pub mod mint;
pub mod ops;
pub mod proofs;
pub mod runtime_adapter;
pub mod seal;
pub mod seal_protocol;
pub mod signatures;
pub mod types;
pub mod wallet_operations;
// pub mod verifier;  // REMOVED: verification centralized in csv-verifier per implementation.md

#[cfg(feature = "rpc")]
pub mod node;

pub use seal_protocol::SuiSealProtocol;

pub use checkpoint::CheckpointVerifier;
pub use config::{CheckpointConfig, SealContractConfig, SuiConfig, SuiNetwork, TransactionConfig};
pub use error::SuiError;
#[cfg(feature = "rpc")]
pub use mint::submit_mint;
pub use mint::{SuiMintArgs, build_sui_mint_args, parse_destination_owner};
#[cfg(feature = "rpc")]
pub use node::SuiNode;
pub use proofs::{
    CommitmentEventBuilder, EventProof, EventProofVerifier, StateProof, StateProofVerifier,
    TransactionProof,
};
pub use seal::{SealRecord, SealRegistry, SealStore};
pub use types::{SuiCommitAnchor, SuiFinalityProof, SuiInclusionProof, SuiSealPoint};

// Ops exports
pub use ops::SuiBackend;
pub use runtime_adapter::SuiRuntimeAdapter;
