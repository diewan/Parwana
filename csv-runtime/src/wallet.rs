//! Wallet operations for chain-specific functionality
//!
//! This module re-exports wallet operations from csv-coordinator.
//! csv-coordinator can depend on chain adapters, but csv-runtime cannot.

// Re-export wallet operations from csv-coordinator
pub use csv_coordinator::wallet;
