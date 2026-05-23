//! Proof composition
//!
//! This module provides utilities for composing proofs.

use crate::proof::{ProofBundle, InclusionProof, FinalityProof};

/// Proof composer for combining proofs
pub struct ProofComposer {
    /// Composed proofs
    proofs: Vec<ProofBundle>,
}

impl ProofComposer {
    /// Create a new proof composer
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
    }

    /// Add a proof to the composition
    pub fn add_proof(&mut self, proof: ProofBundle) {
        self.proofs.push(proof);
    }

    /// Compose all proofs into a single proof bundle
    pub fn compose(&self) -> Option<ComposedProof> {
        if self.proofs.is_empty() {
            return None;
        }

        let inclusion_proofs: Vec<_> = self.proofs.iter().map(|p| p.inclusion_proof.clone()).collect();
        let finality_proofs: Vec<_> = self.proofs.iter().map(|p| p.finality_proof.clone()).collect();

        Some(ComposedProof {
            inclusion_proofs,
            finality_proofs,
        })
    }
}

/// Composed proof from multiple proofs
#[derive(Debug, Clone)]
pub struct ComposedProof {
    /// Inclusion proofs
    pub inclusion_proofs: Vec<InclusionProof>,
    /// Finality proofs
    pub finality_proofs: Vec<FinalityProof>,
}
