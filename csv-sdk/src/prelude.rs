//! Prelude module for ergonomic imports.
//!
//! Import everything you need with a single statement:
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//! ```

// Core types
#[cfg(feature = "accountability")]
pub use crate::accountability::{
    ActionIntent, ActionIntentWire, CanonicalAccountabilityObjectWire, GitHubDeploymentIntentV1,
    GitHubDeploymentIntentV1Wire, RequiredContexts, RequiredContextsWire,
};
#[cfg(feature = "client")]
pub use crate::builder::{ClientBuilder, StoreBackend};
#[cfg(feature = "client")]
pub use crate::client::{CsvClient, NetworkType};
#[cfg(feature = "client")]
pub use crate::config::{Config, Network, RpcConfig};
#[cfg(feature = "client")]
pub use crate::cross_chain::CrossChainError;
#[cfg(feature = "client")]
pub use crate::error::CsvError;
#[cfg(feature = "client")]
pub use crate::events::Event;
#[cfg(all(feature = "client", feature = "tokio"))]
pub use crate::events::EventStream;
#[cfg(feature = "client")]
pub use crate::rpc_policy::{
    ChainRpcPolicy, RpcCapability, RpcCredentialRef, RpcEndpoint, RpcEndpointSource,
    RpcPolicyError, RpcSelectionMode, RpcTransport, RpcTrustRequirement,
};
#[cfg(feature = "client")]
pub use crate::sanads::{SanadFilters, SanadsManager};
#[cfg(feature = "client")]
pub use crate::transfers::{TransferBuilder, TransferManager};
#[cfg(feature = "client")]
pub use crate::wallet::Wallet;

// Re-exports from csv-chain-ports
#[cfg(feature = "client")]
pub use csv_hash::Hash;
#[cfg(feature = "client")]
pub use csv_hash::chain_id::ChainId;
#[cfg(feature = "client")]
pub use csv_hash::commitment::Commitment;
#[cfg(feature = "client")]
pub use csv_hash::sanad::SanadId;
#[cfg(feature = "client")]
pub use csv_hash::seal::SealPoint;
#[cfg(feature = "client")]
pub use csv_protocol::proof_taxonomy::ProofBundle;

// Agent-friendly types
#[cfg(feature = "client")]
pub use crate::mcp::{ErrorSuggestion, FixAction};

// Unified result type
#[cfg(feature = "client")]
pub use crate::Result;

// Event types
#[cfg(feature = "client")]
pub use crate::events::EventRecvError;
