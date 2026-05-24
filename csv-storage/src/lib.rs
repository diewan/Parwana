//! CSV Storage - Persistence abstractions and implementations
#![allow(clippy::collapsible_if)]
//!
//! This crate provides storage traits and concrete implementations for:
//! - Replay database (deduplication, nullifier tracking)
//! - Transfer store (cross-chain transfer persistence)
//! - Generic key-value storage backends
//!
//! Backends:
//! - RocksDB (single-node, CAS semantics)
//! - PostgreSQL (distributed, advisory locks)
//! - InMemory (testing)

#![warn(missing_docs)]
#![allow(unexpected_cfgs)]

pub mod backends;
pub mod errors;
pub mod traits;

// Re-exports
pub use backends::in_memory::InMemoryReplayDb;
#[cfg(feature = "postgres")]
pub use backends::postgres::PostgresReplayDb;
#[cfg(feature = "rocksdb")]
pub use backends::rocksdb::RocksDbReplayDb;
pub use errors::{ReplayDbError, StorageError};
pub use traits::{ReplayDatabase, ReplayEntryState, StorageBackend, TransferStore};
