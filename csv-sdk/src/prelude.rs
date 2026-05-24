//! Prelude module for ergonomic imports.
//!
//! Import everything you need with a single statement:
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//! ```

// Core types
pub use crate::builder::{ClientBuilder, StoreBackend};
pub use crate::client::{CsvClient, NetworkType};
pub use crate::config::{Config, Network, RpcConfig};
pub use crate::cross_chain::{CrossChainError, is_mint_supported, mint_sanad_on_chain};
pub use crate::error::CsvError;
pub use crate::events::Event;
#[cfg(feature = "tokio")]
pub use crate::events::EventStream;
pub use crate::proofs::ProofManager;
pub use crate::sanads::{SanadFilters, SanadsManager};
pub use crate::transfers::{TransferBuilder, TransferManager};
pub use crate::wallet::Wallet;

// Re-exports from csv-adapter-core
pub use csv_protocol::{Commitment, OwnershipProof, Sanad};
pub use csv_hash::Hash;
pub use csv_hash::sanad::SanadId;
pub use csv_hash::seal::SealPoint;
pub use csv_proof::proof::ProofBundle;

// Agent-friendly types
pub use csv_protocol::mcp::{ChainId, ErrorSuggestion, FixAction};

// Unified result type
pub use crate::Result;

// Event types
pub use crate::events::EventRecvError;
