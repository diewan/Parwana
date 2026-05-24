//! Chain configuration system for dynamic chain loading.
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::finality::capabilities` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all chain configuration types from csv-protocol
pub use csv_protocol::finality::capabilities::{
    StateModel, FinalityModel, ProofModel, ReplayProtectionModel,
    ReorgRisk, ChainRole, ChainCapabilities,
};
