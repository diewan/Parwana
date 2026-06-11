//! CSV Protocol Coordinator
//!
//! This crate provides per-chain execution cells with isolated failure domains.
//! Each chain has its own bounded queue, circuit breaker, and memory ceiling.

pub mod cell;
pub mod circuit;
pub mod handler;
pub mod memory;
pub mod negotiation;
pub mod router;
pub mod wallet;

pub use cell::TransferTask;
pub use cell::{CellConfig, CellError, CellTask, ChainCell};
pub use circuit::{CellCircuitBreaker, CircuitState};
pub use memory::MemoryCeiling;
pub use negotiation::{
    CapabilityNegotiator, NegotiatedPlan, NegotiationError, SecurityRequirements,
};
pub use router::{RouterError, TransferRouter};
