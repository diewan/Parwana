//! Awaiting Finality State
//!
//! Proof submitted, awaiting finality confirmation on source chain.

use super::{ProofBuilding, TransferData};
use crate::error::Result;

/// Transfer is awaiting finality confirmation
#[derive(Clone, Debug)]
pub struct AwaitingFinality {
    /// Shared transfer data
    pub data: TransferData,
    /// Block height when proof was submitted
    pub proof_height: u64,
    /// Required confirmations
    pub required_confirmations: u32,
    /// Current confirmations
    pub current_confirmations: u32,
}

impl AwaitingFinality {
    /// Create a new awaiting finality state
    pub fn new(data: TransferData, proof_height: u64, required_confirmations: u32) -> Self {
        Self {
            data,
            proof_height,
            required_confirmations,
            current_confirmations: 0,
        }
    }

    /// Update confirmation count
    pub fn update_confirmations(&mut self, confirmations: u32) {
        self.current_confirmations = confirmations;
    }

    /// Check if finality is achieved
    pub fn is_finalized(&self) -> bool {
        self.current_confirmations >= self.required_confirmations
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Transition to ProofBuilding state after finality is achieved
    ///
    /// This is the only valid transition from AwaitingFinality state.
    /// The transfer must have achieved finality before building the proof.
    ///
    /// # Returns
    ///
    /// ProofBuilding state if finality is achieved, error otherwise
    pub fn build_proof(self) -> Result<ProofBuilding> {
        if !self.is_finalized() {
            return Err(crate::error::ProtocolError::InvalidStateTransition(
                "Cannot build proof before finality is achieved".to_string(),
            ));
        }

        Ok(ProofBuilding::new(self.data))
    }
}
