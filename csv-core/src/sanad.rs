//! Sanad and envelope types (stable API compatibility layer).
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::sanad::{
    SanadId, OwnershipProof, Sanad, SanadEnvelope, SCHEMA_VERSION, Schema,
};
