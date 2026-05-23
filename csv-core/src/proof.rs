//! Proof types — re-exported from csv-proof for backward compatibility.
//!
//! The canonical proof types live in `csv-proof`. This module re-exports them
//! so that chain adapters and other crates can use `csv_core::proof::*` without
//! depending directly on csv-proof.

// Re-export canonical types from csv-proof
pub use csv_proof::proof::{
    InclusionProof, FinalityProof, ProofBundle,
    MAX_PROOF_BYTES, MAX_FINALITY_DATA, MAX_SIGNATURES_TOTAL_SIZE,
};

// Re-export proof taxonomy
pub use csv_proof::proof_types::{
    Proof, ProofCategory,
    InclusionProof as InclusionProofType,
    FinalityProof as FinalityProofType,
    OwnershipProof, TransitionProof,
    ReplayProof, ExecutionProof,
    ZKProof as ZKProofType,
    CompositeProof,
    CompositionRule,
    ProofPhase,
};

// Re-export proof DAGs
pub use csv_proof::proof_dags::{ProofNode, ProofDag, ProofId};