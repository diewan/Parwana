//! Typed finality guarantee — chain-agnostic, runtime-enforceable.
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::finality::{
    FinalityGuarantee, FinalityPolicy, FinalityPolicyRegistry,
};
