//! Seal types — re-exported from csv-protocol for backward compatibility.
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::seal::{
    SealPoint, CommitAnchor,
    MAX_SEAL_ID_SIZE, MAX_ANCHOR_ID_SIZE, MAX_ANCHOR_METADATA_SIZE,
};