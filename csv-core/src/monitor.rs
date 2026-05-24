//! Reorg monitoring and censorship detection
//!
//! Cross-cutting components that track chain state across all adapters:
//! - Reorg detection and anchor invalidation
//! - Publication timeout tracking (censorship detection)
//!
//! **DEPRECATED**: This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::monitor::{
    ReorgEvent, ReorgMonitor, PublicationTracker, PendingPublication,
};
