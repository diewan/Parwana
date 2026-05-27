//! CSV Proof - Thin re-export crate for backward compatibility
//!
//! The canonical proof types now live in `csv-protocol`. This crate re-exports them
//! for backward compatibility. New code should use `csv_protocol::proof::*` directly.
//!
//! # Migration Path
//!
//! - Old: `use csv_proof::Proof;`
//! - New: `use csv_protocol::proof::Proof;`

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
pub mod proof_validation;
pub mod zk_proof;

// Migrated from csv-core - these types are still here for now
pub mod commitment_chain;
pub mod commitments_ext;
pub mod proof_material;

// proof_types and proof modules removed - types now live in csv-protocol

// Stub modules for protocol types to break cyclic dependency
pub mod certification;
pub mod chain_config;
pub mod cross_chain;
pub mod dag;
pub mod events;
pub mod provenance;
pub mod replay_registry;
pub mod signature;

// Re-exports from csv-protocol (canonical location)
pub use csv_protocol::proof_types::{
    CompositeProof, CompositionRule, ExecutionProof, FinalityProof, InclusionProof,
    MAX_FINALITY_DATA, MAX_PROOF_BYTES, MAX_SIGNATURES_TOTAL_SIZE, OwnershipProof, Proof,
    ProofBundle, ProofCategory, ProofPhase, ReplayId, ReplayProof, TransitionProof, ZKProof,
};

// Re-exports from csv-proof (types not yet migrated)
pub use chain_config::{ChainCapabilities, EthereumFinalityStage, SolanaCommitmentGrade};
pub use cross_chain::CrossChainTransferProof;
pub use dag::DAGSegment;
pub use error::{ProofError, Result};
pub use events::{CsvEvent, EventIndexerRegistry};
pub use proof_dags::{ProofDag, ProofId, ProofNode};
pub use replay_registry::{ReplayKey, ReplayRegistryBackend};
pub use signature::SignatureScheme;
