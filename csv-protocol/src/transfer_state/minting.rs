//! Minting State
//!
//! Minting on destination chain.

use super::{Completed, TransferData};
use crate::error::Result;

/// Transfer is being minted on destination chain
#[derive(Clone, Debug)]
pub struct Minting {
    /// Shared transfer data
    pub data: TransferData,
    /// Mint transaction hash
    pub mint_tx_hash: Option<Vec<u8>>,
    /// Mint started at
    pub started_at: u64,
}

impl Minting {
    /// Create a new minting state
    pub fn new(data: TransferData) -> Self {
        Self {
            data,
            mint_tx_hash: None,
            started_at: 0, // Will be set when minting starts
        }
    }

    /// Set mint transaction hash
    pub fn set_mint_tx_hash(&mut self, tx_hash: Vec<u8>) {
        self.mint_tx_hash = Some(tx_hash);
    }

    /// Get the transfer data
    pub fn data(&self) -> &TransferData {
        &self.data
    }

    /// Transition to Completed state after minting is confirmed
    ///
    /// This is the only valid transition from Minting state.
    /// The mint transaction must be confirmed before completion.
    ///
    /// # Arguments
    ///
    /// * `mint_tx_hash` - Transaction hash of the mint transaction
    ///
    /// # Returns
    ///
    /// Completed state if minting is confirmed
    pub fn complete_minting(self, mint_tx_hash: Vec<u8>) -> Result<Completed> {
        if mint_tx_hash.is_empty() {
            return Err(crate::error::ProtocolError::InvalidStateTransition(
                "Cannot complete minting with empty transaction hash".to_string(),
            ));
        }

        Ok(Completed::new(self.data, mint_tx_hash))
    }
}
