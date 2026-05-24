//! Canonical Sanad Envelope — re-exported from csv-protocol.
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::envelope` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all envelope types from csv-protocol
pub use csv_protocol::envelope::{
    CanonicalSanadEnvelope, TypeId, SignatureScheme, EncodingType, decode_envelope,
};
