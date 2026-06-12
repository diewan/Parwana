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
pub mod wallet_factory;

pub use cell::TransferTask;
pub use cell::{CellConfig, CellError, CellTask, ChainCell};
pub use circuit::{CellCircuitBreaker, CircuitState};
pub use memory::MemoryCeiling;
pub use negotiation::{
    CapabilityNegotiator, NegotiatedPlan, NegotiationError, SecurityRequirements,
};
pub use router::{RouterError, TransferRouter};
pub use wallet_factory::{
    init_wallet_factory, get_wallet_factory, get_wallet_operations,
    is_chain_registered, registered_chains,
};
