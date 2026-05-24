//! Storage backend implementations
//!
//! Concrete implementations of storage traits:
//! - `in_memory`: Testing-only in-memory storage
//! - `rocksdb`: Single-node durable storage with CAS semantics
//! - `postgres`: Distributed storage with advisory locks

pub mod in_memory;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "rocksdb")]
pub mod rocksdb;
