//! Proof Validated State
//!
//! Proof has been validated, ready for minting on destination chain.

use super::{Minting, TransferData};
use crate::error::Result;

/// Transfer proof has been validated
#[derive(Clone, Debug)]
pub struct ProofValidated {
    /// Shared transfer data
    pub data: TransferData,
    /// Validated proof bytes
    pub proof: Vec<u8>,
    /// Proof validation timestamp
    pub validated_at: u64,
}

impl ProofValidated {
    /// Create a new proof validated state
    pub fn new(data: TransferData, proof: Vec<u8>) -> Self {
        Self {
            data,
            proof,
            validated_at: 0, // Will be set when validation completes
        }
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Get the proof
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Transition to Minting state to begin minting on destination chain
    ///
    /// This is the only valid transition from ProofValidated state.
    /// The proof must be validated before minting can begin.
    ///
    /// # Returns
    ///
    /// Minting state if transition is valid
    pub fn begin_minting(self) -> Result<Minting> {
        if self.proof.is_empty() {
            return Err(crate::error::ProtocolError::InvalidStateTransition(
                "Cannot begin minting with empty proof".to_string(),
            ));
        }

        Ok(Minting::new(self.data))
    }
}
