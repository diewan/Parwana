//! Proof Building State
//!
//! Building zero-knowledge proof for the transfer.

use super::{ProofValidated, TransferData};
use crate::error::Result;
use csv_hash::Hash;

/// Transfer is in proof building phase
#[derive(Clone, Debug)]
pub struct ProofBuilding {
    /// Shared transfer data
    pub data: TransferData,
    /// Proof generation started at
    pub started_at: u64,
    /// Proof progress (0-100)
    pub progress: u8,
}

impl ProofBuilding {
    /// Create a new proof building state
    pub fn new(data: TransferData) -> Self {
        Self {
            data,
            started_at: 0, // Will be set when proof building starts
            progress: 0,
        }
    }

    /// Update proof progress
    pub fn update_progress(&mut self, progress: u8) {
        self.progress = progress.min(100);
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Transition to ProofValidated state after proof is complete
    ///
    /// This is the only valid transition from ProofBuilding state.
    /// The proof must be successfully generated and validated.
    ///
    /// # Arguments
    ///
    /// * `proof_hash` - Hash of the generated proof
    ///
    /// # Returns
    ///
    /// ProofValidated state if proof is complete
    pub fn complete_proof(self, proof_hash: Hash) -> Result<ProofValidated> {
        if self.progress < 100 {
            return Err(crate::error::ProtocolError::InvalidStateTransition(
                "Cannot complete proof before progress reaches 100%".to_string(),
            ));
        }

        Ok(ProofValidated::new(
            self.data,
            proof_hash.as_bytes().to_vec(),
        ))
    }
}
