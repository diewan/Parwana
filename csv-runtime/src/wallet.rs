//! Wallet operations for chain-specific functionality
//!
//! This module re-exports wallet operations from csv-coordinator.
//! csv-coordinator can depend on chain adapters, but csv-runtime cannot.

// Re-export wallet factory operations from csv-coordinator
pub use csv_coordinator::wallet_factory::{
    init_wallet_factory, get_wallet_factory, get_wallet_operations,
    is_chain_registered, registered_chains,
};
