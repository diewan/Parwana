//! Restart-safe finality anchoring — canonical chain snapshot persistence.
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::finality::{
    FinalityAnchor, AncestorContinuityProof, ContinuityError,
    RestartVerification, FinalityAnchorStore, AnchorStoreError,
};