//! CSV Storage - Persistence abstractions and implementations
#![allow(clippy::collapsible_if)]
//!
//! This crate provides storage traits and concrete implementations for:
//! - Replay database (deduplication, nullifier tracking)
//! - Transfer store (cross-chain transfer persistence)
//! - Generic key-value storage backends
//!
//! Backends:
//! - redb (single-node, CAS semantics, pure Rust)
//! - PostgreSQL (distributed, advisory locks)
//! - InMemory (testing)

#![warn(missing_docs)]
#![allow(unexpected_cfgs)]

pub mod accepted_state;
pub mod backends;
pub mod errors;
pub mod traits;

// Re-exports
#[cfg(feature = "redb")]
pub use accepted_state::RedbAcceptedStateStore;
pub use accepted_state::{
    AcceptedAssuranceReading, AcceptedAssuranceReport, AcceptedStateError, AcceptedStateRecord,
    AcceptedStateStore, InMemoryAcceptedStateStore,
};
pub use backends::in_memory::InMemoryReplayDb;
#[cfg(feature = "postgres")]
pub use backends::postgres::PostgresReplayDb;
#[cfg(feature = "redb")]
pub use backends::redb::RedbReplayDb;
pub use errors::{ReplayDbError, StorageError};
pub use traits::{ReplayDatabase, ReplayEntryState, StorageBackend, TransferStore};
