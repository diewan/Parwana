//! Lease management for coordinated cross-chain transfers
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::lease` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all lease types from csv-protocol
pub use csv_protocol::lease::{LeaseId, Lease, LeaseManager, LeaseError, now_secs};
