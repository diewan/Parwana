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
pub use crate::cross_chain::CrossChainError;
pub use crate::error::CsvError;
pub use crate::events::Event;
#[cfg(feature = "tokio")]
pub use crate::events::EventStream;
pub use crate::rpc_policy::{
    ChainRpcPolicy, RpcCapability, RpcCredentialRef, RpcEndpoint, RpcEndpointSource,
    RpcPolicyError, RpcSelectionMode, RpcTransport, RpcTrustRequirement,
};
pub use crate::sanads::{SanadFilters, SanadsManager};
pub use crate::transfers::{TransferBuilder, TransferManager};
pub use crate::wallet::Wallet;

// Re-exports from csv-chain-ports
pub use csv_hash::Hash;
pub use csv_hash::chain_id::ChainId;
pub use csv_hash::commitment::Commitment;
pub use csv_hash::sanad::SanadId;
pub use csv_hash::seal::SealPoint;
pub use csv_protocol::proof_taxonomy::ProofBundle;

// Agent-friendly types
pub use crate::mcp::{ErrorSuggestion, FixAction};

// Unified result type
pub use crate::Result;

// Event types
pub use crate::events::EventRecvError;
