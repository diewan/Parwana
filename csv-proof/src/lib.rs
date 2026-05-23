//! CSV Proof - Formal proof taxonomy, proof DAGs, and proof composition
//!
//! This crate provides the canonical proof types and DAG structures for the CSV protocol.
//! All proof-related operations must use this crate to ensure consistency.
//!
//! # Proof Taxonomy
//!
//! The crate defines a formal `Proof` enum with 8 variants:
//! - `Inclusion` - Merkle inclusion proofs
//! - `Finality` - Chain finality proofs
//! - `Ownership` - Asset/seal ownership proofs
//! - `Transition` - State transition proofs
//! - `Replay` - Replay prevention proofs
//! - `Execution` - Computation execution proofs
//! - `ZK` - Zero-knowledge proofs
//! - `Composite` - Composed proofs
//!
//! # Proof DAGs
//!
//! Proofs can be composed into directed acyclic graphs (DAGs) for
//! complex verification chains.

#![warn(missing_docs)]

pub mod error;
pub mod proof_types;
pub mod proof_dags;
pub mod proof_composition;
pub mod proof_validation;

// Migrated from csv-core
pub mod proof;
// pub mod proof_pipeline;  // REMOVED: verification centralized in csv-verifier per implementation.md
pub mod proof_material;

// Stub modules for protocol types to break cyclic dependency
pub mod chain_config;
pub mod cross_chain;
pub mod provenance;
pub mod certification;
pub mod signature;
pub mod dag;
pub mod replay_registry;
pub mod events;

// Re-exports
pub use error::{ProofError, Result};
pub use proof_types::{
    Proof, ProofCategory,
    InclusionProof, FinalityProof, OwnershipProof, TransitionProof,
    ReplayProof, ExecutionProof, ZKProof, CompositeProof,
    CompositionRule,
    ProofPhase,
};
pub use proof_dags::{ProofNode, ProofDag, ProofId};
pub use proof::{MAX_PROOF_BYTES, MAX_FINALITY_DATA, MAX_SIGNATURES_TOTAL_SIZE};
pub use chain_config::{EthereumFinalityStage, SolanaCommitmentGrade, ChainCapabilities};
pub use dag::DAGSegment;
pub use signature::SignatureScheme;
pub use cross_chain::CrossChainTransferProof;
pub use replay_registry::{ReplayKey, ReplayRegistryBackend};
pub use events::{CsvEvent, EventIndexerRegistry};
