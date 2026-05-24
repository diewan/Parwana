//! Proof types — re-exported from csv-proof for backward compatibility.
//!
//! The canonical proof types live in `csv-proof`. This module re-exports them
//! so that chain adapters and other crates can use `csv_protocol::proof::*` without
//! depending directly on csv-proof.

// Re-export canonical types from csv-proof
pub use csv_proof::proof::{
    FinalityProof, InclusionProof, MAX_FINALITY_DATA, MAX_PROOF_BYTES, MAX_SIGNATURES_TOTAL_SIZE,
    ProofBundle,
};

// Re-export proof taxonomy
pub use csv_proof::proof_types::{
    CompositeProof, CompositionRule, ExecutionProof, FinalityProof as FinalityProofType,
    InclusionProof as InclusionProofType, OwnershipProof, Proof, ProofCategory, ProofPhase,
    ReplayProof, TransitionProof, ZKProof as ZKProofType,
};

// Re-export proof DAGs
pub use csv_proof::proof_dags::{ProofDag, ProofId, ProofNode};
