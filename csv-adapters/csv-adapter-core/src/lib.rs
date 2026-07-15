//! Deprecated compatibility facade for chain-neutral adapter ports.
//!
//! New runtime and adapter code must depend on [`csv_chain_ports`] directly.
//! This package remains only to avoid a semver-breaking removal for downstream
//! users during the compatibility window.

#![warn(missing_docs)]

pub use csv_chain_ports::*;
