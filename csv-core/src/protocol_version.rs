//! CSV Protocol Version and Canonical Contract
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Please use `csv_protocol::version` instead.
//!
//! This module is kept as a compatibility shim during the migration period.
//! All types are re-exported from csv-protocol.

// Re-export all protocol version types from csv-protocol
pub use csv_protocol::version::{
    ProtocolVersion, TransferStatus, SimplifiedTransferStatus, ErrorCode,
    Capabilities, SyncStatus, builtin,
};
