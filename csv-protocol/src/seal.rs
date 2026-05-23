//! Seal types — re-exported from csv-hash for backward compatibility.
//!
//! The canonical seal point and commit anchor types live in `csv-hash::seal`.
//! This module re-exports them so that chain adapters and other crates can use
//! `csv_protocol::seal::*` without depending directly on csv-hash.

pub use csv_hash::seal::{
    SealPoint, CommitAnchor,
    MAX_SEAL_ID_SIZE, MAX_ANCHOR_ID_SIZE, MAX_ANCHOR_METADATA_SIZE,
};
