//! No-std compatible collections.
//!
//! Provides `HashMap` and `HashSet` aliases that use `std::collections` when
//! the `std` feature is enabled and `alloc::collections::BTreeMap` / `BTreeSet`
//! otherwise.

#[cfg(feature = "std")]
pub use std::collections::{btree_map, btree_set, hash_map, hash_set, *};

#[cfg(not(feature = "std"))]
pub use alloc::collections::{
    BTreeMap, BTreeSet, BTreeSet as HashSet, TryReserveError, btree_map, btree_set,
};
