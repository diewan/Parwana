//! Ethereum Contract Bindings
//!
//! This module contains type-safe bindings for Ethereum smart contracts
//! generated using Alloy for ABI encoding/decoding.
//!
//! NOTE: These bindings are work-in-progress. The main Ethereum adapter
//! currently uses manual ABI encoding in sanad_contract.rs and seal_contract.rs.
//! Migration to generated bindings is tracked in PRODUCTION_READINESS_PLAN.md Phase 5.

#[cfg(feature = "rpc")]
pub mod csv_lock;
#[cfg(feature = "rpc")]
pub mod csv_mint;
