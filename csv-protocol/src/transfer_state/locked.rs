//! Locked State
//!
//! Transfer is locked on source chain, awaiting proof submission.

use super::{AwaitingFinality, TransferData};
use crate::error::Result;

/// Transfer is locked on source chain
#[derive(Clone, Debug)]
pub struct Locked {
    /// Shared transfer data
    pub data: TransferData,
    /// Block height when lock occurred
    pub lock_height: u64,
    /// Lock transaction hash
    pub lock_tx_hash: Vec<u8>,
}

impl Locked {
    /// Create a new locked state
    pub fn new(data: TransferData, lock_height: u64, lock_tx_hash: Vec<u8>) -> Self {
        Self {
            data,
            lock_height,
            lock_tx_hash,
        }
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Transition to AwaitingFinality state after proof submission
    ///
    /// This is the only valid transition from Locked state.
    /// The transfer must wait for finality confirmation before proceeding.
    ///
    /// # Arguments
    ///
    /// * `proof_height` - Block height where proof was submitted
    /// * `required_confirmations` - Number of confirmations required for finality
    ///
    /// # Returns
    ///
    /// AwaitingFinality state if transition is valid
    pub fn await_finality(
        self,
        proof_height: u64,
        required_confirmations: u32,
    ) -> Result<AwaitingFinality> {
        // Validate that proof_height is after lock_height
        if proof_height <= self.lock_height {
            return Err(crate::error::ProtocolError::InvalidStateTransition(
                "Proof height must be after lock height".to_string(),
            ));
        }

        Ok(AwaitingFinality::new(
            self.data,
            proof_height,
            required_confirmations,
        ))
    }
}
