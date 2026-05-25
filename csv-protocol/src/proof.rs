//! Proof types — canonical proof taxonomy for the CSV protocol.
//!
//! This module contains the canonical proof types. For backward compatibility,
//! csv-proof now re-exports these types.

// Re-export canonical types from local proof_types module
pub use crate::proof_types::{
    CompositeProof, CompositionRule, ExecutionProof, FinalityProof, InclusionProof,
    MAX_FINALITY_DATA, MAX_PROOF_BYTES, MAX_SIGNATURES_TOTAL_SIZE, OwnershipProof, Proof,
    ProofBundle, ProofCategory, ProofPhase, ReplayId, ReplayProof, TransitionProof, ZKProof,
};
