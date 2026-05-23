//! Proof types — re-exported from csv-protocol for backward compatibility.
//!
//! This module has been moved to csv-protocol.
//! Re-exporting for backward compatibility during migration.

pub use csv_protocol::proof::{
    InclusionProof, FinalityProof, ProofBundle,
    Proof, ProofCategory,
    InclusionProofType, FinalityProofType,
    OwnershipProof, TransitionProof,
    ReplayProof, ExecutionProof,
    ZKProofType, CompositeProof,
    CompositionRule, ProofPhase,
    ProofNode, ProofDag, ProofId,
    MAX_PROOF_BYTES, MAX_FINALITY_DATA, MAX_SIGNATURES_TOTAL_SIZE,
};