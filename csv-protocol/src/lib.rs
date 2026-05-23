//! CSV Protocol - State machines, protocol constants, types, invariants, replay semantics, transition legality, versioning
//!
//! This crate contains the core protocol logic without dependencies on serialization, hashing, or proof systems.
//! It defines the state machines, invariants, and transition rules that all other protocol components must follow.

#![warn(missing_docs)]
#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(clippy::useless_format)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::type_complexity)]
#![allow(clippy::let_unit_value)]

pub mod error;
pub mod events;
pub mod verified;
pub mod chain_config;
pub mod signature;
pub mod backend;
pub mod verification;
pub mod cross_chain;
pub mod sanad;
pub mod seal;
pub mod commitment;
pub mod proof;
pub mod proof_verification;

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

// Re-export signature types
pub use signature::{Signature, SignatureScheme, verify_signatures, parse_signatures_from_bundle, parse_signatures_from_bytes};

// Re-export backend types
pub use backend::{
    ChainOpError, ChainOpResult, ChainQuery, ChainSigner, ChainBroadcaster, ChainDeployer,
    ChainProofProvider, ChainSanadOps, ChainBackend, ChainCapability,
    TransactionStatus, DeploymentStatus, FinalityStatus,
    BalanceInfo, TransactionInfo, ContractStatus,
    SanadOperation, SanadOperationResult,
};

// Re-export verification types
pub use verification::VerificationLevel;

// Re-export cross-chain types
pub use cross_chain::HashEntry;

// Re-export sanad types
pub use sanad::{SanadId, OwnershipProof, Sanad, SanadEnvelope, SCHEMA_VERSION, Schema};

// Re-export seal types
pub use seal::{SealPoint, CommitAnchor};

// Re-export commitment types
pub use commitment::Commitment;

// Re-export proof types (excluding FinalityProof to avoid conflict with finality module)
pub use proof::{InclusionProof, ProofBundle};

// Re-export transfer state types
pub use transfer_state::TransferStage;
