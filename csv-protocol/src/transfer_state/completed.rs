//! Completed State
//!
//! Transfer successfully completed.

use super::TransferData;

/// Transfer has successfully completed
#[derive(Clone, Debug)]
pub struct Completed {
    /// Shared transfer data
    pub data: TransferData,
    /// Completion timestamp
    pub completed_at: u64,
    /// Final mint transaction hash
    pub mint_tx_hash: Vec<u8>,
}

impl Completed {
    /// Create a new completed state
    pub fn new(data: TransferData, mint_tx_hash: Vec<u8>) -> Self {
        Self {
            data,
            completed_at: 0, // Will be set when completion is recorded
            mint_tx_hash,
        }
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Get the mint transaction hash
    pub fn mint_tx_hash(&self) -> &[u8] {
        &self.mint_tx_hash
    }
}
