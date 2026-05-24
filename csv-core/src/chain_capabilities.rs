//! Chain capability model with traits per Phase 6
//!
//! This module defines the capability traits that chains must implement
//! to participate in the CSV protocol. This enables runtime to query
//! chain capabilities and adapt behavior accordingly.
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::finality::capabilities::{
    ChainCapability, CapabilitySet, Capability, ChainCapabilityRegistry,
    FinalityType,
};
