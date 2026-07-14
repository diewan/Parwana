//! Replay persistence — delegated to csv-storage (RULE 4).
//!
//! csv-runtime does not own replay backends; it re-exports the canonical
//! storage trait and implementations from `csv-storage`.

#![allow(missing_docs)]

#[cfg(feature = "postgres")]
pub use csv_storage::PostgresReplayDb;
#[cfg(feature = "persistent")]
pub use csv_storage::RedbReplayDb;
pub use csv_storage::{InMemoryReplayDb, ReplayDatabase, ReplayDbError, ReplayEntryState};
