//! Typed state enums for CSV contracts
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::state` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all state types from csv-protocol
pub use csv_protocol::state::{GlobalState, OwnedState, Metadata, StateAssignment, StateRef, StateTypeId};
