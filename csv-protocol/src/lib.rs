//! CSV Protocol - State machines, protocol constants, types, invariants, replay semantics, transition legality, versioning
//!
//! This crate contains the core protocol logic without dependencies on serialization, hashing, or proof systems.
//! It defines the state machines, invariants, and transition rules that all other protocol components must follow.

#![warn(missing_docs)]

pub mod error;
pub mod events;
pub mod verified;
pub mod chain_config;

// State machine modules
pub mod state_machine;

// Transfer state machine
pub mod transfer_state;

// Finality semantics
pub mod finality;

// Reorg handling
pub mod reorg;

// Protocol constants
pub mod constants;

// Protocol invariants
pub mod invariants;

// Replay semantics
pub mod replay;

// Transition legality
pub mod transition;

// Versioning
pub mod version;

// Re-export error types
pub use error::{ProtocolError, Result as ProtocolResult};

// Re-export replay registry for convenience
pub use replay::{ReplayKey, ReplayEntry, ReplayRegistry, ReplayRegistryBackend};

// Re-export finality types
pub use finality::{FinalityType, FinalityRequirement, FinalityProof, ChainCapabilities, Capability};
