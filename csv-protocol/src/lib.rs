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

pub mod backend;
pub mod canonical_proof;
pub mod chain_config;
pub mod chain_registry;
pub mod commitment;
pub mod cross_chain;
pub mod deployment_manifest;
pub mod deterministic_recovery;
pub mod envelope;
pub mod error;
pub mod events;
pub mod failure_domains;
pub mod lease;
pub mod proof;
pub mod proof_types;
pub mod proof_verification;
pub mod sanad;
pub mod secret;
pub mod seal;
pub mod seal_protocol;
pub mod signature;
pub mod verification;
pub mod verified;

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

// Reorg monitoring and censorship detection
pub mod monitor;

// Replay semantics
pub mod replay;

// Transition legality
pub mod transition;

// Versioning
pub mod genesis;
pub mod state;
pub mod version;

// Re-export version types
pub use version::{
    Capabilities, ErrorCode, ProtocolVersion, SimplifiedTransferStatus, SyncStatus, TransferStatus,
    Version, builtin,
};

// Re-export state types
pub use state::{GlobalState, Metadata, OwnedState, StateAssignment, StateRef, StateTypeId};

// Re-export genesis types
pub use genesis::Genesis;

// Re-export error types
pub use error::{ProtocolError, Result as ProtocolResult};

// Re-export replay registry for convenience
pub use replay::{ReplayEntry, ReplayKey, ReplayRegistry, ReplayRegistryBackend};

// Re-export finality types
pub use finality::{ChainCapabilities, FinalityProof, FinalityRequirement, FinalityType};

// Re-export signature types
pub use signature::{
    Signature, SignatureScheme, parse_signatures_from_bundle, parse_signatures_from_bytes,
    verify_signatures,
};

// Re-export backend types
pub use backend::{
    BalanceInfo, ChainBackend, ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError,
    ChainOpResult, ChainProofProvider, ChainQuery, ChainSanadOps, ChainSigner, ContractStatus,
    DeploymentStatus, FinalityStatus, SanadOperation, SanadOperationResult, TransactionInfo,
    TransactionStatus,
};

// Re-export verification types
pub use verification::VerificationLevel;

// Re-export cross-chain types
pub use cross_chain::HashEntry;

// Re-export sanad types
pub use sanad::{OwnershipProof, SCHEMA_VERSION, Sanad, SanadEnvelope, SanadId, SanadPayloadDescriptor, Schema};

// Re-export seal types
pub use seal::{CommitAnchor, SealPoint};

// Re-export commitment types
pub use commitment::Commitment;

// Re-export envelope types
pub use envelope::{CanonicalSanadEnvelope, TypeId, decode_envelope};

// Re-export proof types (excluding FinalityProof to avoid conflict with finality module)
pub use proof::{InclusionProof, ProofBundle};
pub use proof_types::{HashFunction, ProofLeafV1};

// Re-export transfer state types
pub use transfer_state::TransferStage;

// Re-export lease types
pub use lease::{Lease, LeaseError, LeaseId, LeaseManager, now_secs};

// Re-export verification types
pub use verified::{
    FinalityStrength, InclusionStrength, VerificationAssurance, VerificationFailure,
    VerificationResult, VerifiedComponents,
};

// Re-export canonical proof types
pub use canonical_proof::{CanonicalProof, ProofValidationError};

// Re-export secret handling types
pub use secret::{SecretHandle, SharedSecretHandle};
