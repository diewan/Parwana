//! Chain-specific finality and commitment grades.
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::finality::chain_specific` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all chain-specific types from csv-protocol
pub use csv_protocol::finality::chain_specific::{SolanaCommitmentGrade, EthereumFinalityStage};