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
pub mod provenance;

// proof_types and proof modules removed - types now live in csv-protocol

// Re-exports from csv-protocol (canonical location)
pub use csv_protocol::proof_types::{
    CompositeProof, CompositionRule, ExecutionProof, FinalityProof, InclusionProof,
    MAX_FINALITY_DATA, MAX_PROOF_BYTES, MAX_SIGNATURES_TOTAL_SIZE, OwnershipProof, Proof,
    ProofBundle, ProofCategory, ProofPhase, ReplayId, ReplayProof, TransitionProof, ZKProof,
};

// Compatibility re-exports from their canonical crates.
/// Backwards-compatible DAG import path backed by `csv-hash`.
pub mod dag {
    pub use csv_hash::dag::{DAGNode, DAGSegment};
}
pub use csv_hash::dag::DAGSegment;
pub use csv_protocol::cross_chain::CrossChainTransferProof;
pub use csv_protocol::events::{CsvEvent, EventIndexerRegistry};
pub use csv_protocol::finality::{ChainCapabilities, EthereumFinalityStage, SolanaCommitmentGrade};
pub use csv_protocol::replay::{ReplayKey, ReplayRegistryBackend};
pub use csv_protocol::signature::SignatureScheme;
pub use error::{ProofError, Result};
pub use proof_dags::{ProofDag, ProofId, ProofNode};
