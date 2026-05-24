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
#![allow(missing_docs)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(clippy::new_without_default)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::redundant_slicing)]

pub mod error;
pub mod proof_composition;
pub mod proof_dags;
pub mod proof_types;
pub mod proof_validation;

// Migrated from csv-core
pub mod proof;
// pub mod proof_pipeline;  // REMOVED: verification centralized in csv-verifier per implementation.md
pub mod commitment_chain;
pub mod commitments_ext;
pub mod proof_material;

// Stub modules for protocol types to break cyclic dependency
pub mod certification;
pub mod chain_config;
pub mod cross_chain;
pub mod dag;
pub mod events;
pub mod provenance;
pub mod replay_registry;
pub mod signature;

// Re-exports
pub use chain_config::{ChainCapabilities, EthereumFinalityStage, SolanaCommitmentGrade};
pub use cross_chain::CrossChainTransferProof;
pub use dag::DAGSegment;
pub use error::{ProofError, Result};
pub use events::{CsvEvent, EventIndexerRegistry};
pub use proof::{MAX_FINALITY_DATA, MAX_PROOF_BYTES, MAX_SIGNATURES_TOTAL_SIZE};
pub use proof_dags::{ProofDag, ProofId, ProofNode};
pub use proof_types::{
    CompositeProof, CompositionRule, ExecutionProof, FinalityProof, InclusionProof, OwnershipProof,
    Proof, ProofCategory, ProofPhase, ReplayProof, TransitionProof, ZKProof,
};
pub use replay_registry::{ReplayKey, ReplayRegistryBackend};
pub use signature::SignatureScheme;
