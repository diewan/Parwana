//! Commitment types — re-exported from csv-hash for backward compatibility.
//!
//! The canonical commitment types live in `csv-hash::commitment`.
//! This module re-exports them so that chain adapters and other crates can use
//! `csv_protocol::commitment::*` without depending directly on csv-hash.

pub use csv_hash::commitment::Commitment;
