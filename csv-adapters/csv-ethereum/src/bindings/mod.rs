//! Ethereum Contract Bindings
//!
//! This module contains type-safe bindings for Ethereum smart contracts
//! generated using Alloy for ABI encoding/decoding.

#[cfg(feature = "rpc")]
pub mod csv_seal;

#[cfg(feature = "rpc")]
pub mod csv_lock;
