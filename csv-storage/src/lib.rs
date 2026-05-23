//! CSV Storage - Persistence abstractions and implementations
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

pub mod traits;
pub mod errors;
pub mod backends;

// Re-exports
pub use traits::{ReplayEntryState, ReplayDatabase, StorageBackend, TransferStore};
pub use errors::{StorageError, ReplayDbError};
pub use backends::in_memory::InMemoryReplayDb;
#[cfg(feature = "rocksdb")]
pub use backends::rocksdb::RocksDbReplayDb;
#[cfg(feature = "postgres")]
pub use backends::postgres::PostgresReplayDb;