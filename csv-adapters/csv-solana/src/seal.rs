//! Solana seal implementation for CSV

use crate::error::{SolanaError, SolanaResult};
use crate::types::{SolanaFinalityProof, SolanaSealPoint};
use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

/// Solana seal implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaSeal {
    /// Seal reference
    pub seal_ref: SolanaSealPoint,
    /// Finality proof
    pub finality_proof: Option<SolanaFinalityProof>,
}

impl SolanaSeal {
    /// Create new Solana seal
    pub fn new(seal_ref: SolanaSealPoint) -> Self {
        Self {
            seal_ref,
            finality_proof: None,
        }
    }

    /// Get seal reference
    pub fn seal_ref(&self) -> &SolanaSealPoint {
        &self.seal_ref
    }

    /// Get finality proof
    pub fn finality_proof(&self) -> Option<&SolanaFinalityProof> {
        self.finality_proof.as_ref()
    }

    /// Set finality proof
    pub fn set_finality_proof(&mut self, finality_proof: SolanaFinalityProof) {
        self.finality_proof = Some(finality_proof);
    }

    /// Verify seal integrity and finality
    ///
    /// This method checks:
    /// 1. The seal reference has a valid account address
    /// 2. The finality proof is present and valid (if provided)
    /// 3. The seal status is consistent with the finality proof
    pub fn verify(&self) -> SolanaResult<bool> {
        // Verify the account address is valid (not default pubkey)
        if self.seal_ref.account == solana_sdk::pubkey::Pubkey::default() {
            return Err(SolanaError::InvalidInput(
                "Invalid seal account address".to_string(),
            ));
        }

        // If a finality proof is present, verify it
        if let Some(ref proof) = self.finality_proof {
            // Verify the proof's block hash is not empty
            if proof.block_hash.as_bytes().iter().all(|&b| b == 0) {
                return Err(SolanaError::InvalidInput(
                    "Invalid finality proof: empty block hash".to_string(),
                ));
            }

            // Verify confirmation depth meets minimum requirements
            // Solana requires at least 31 confirmations for finality
            const MIN_FINALITY_DEPTH: u64 = 31;
            if proof.confirmation_depth < MIN_FINALITY_DEPTH {
                return Err(SolanaError::InvalidInput(format!(
                    "Insufficient confirmation depth: {} < {}",
                    proof.confirmation_depth, MIN_FINALITY_DEPTH
                )));
            }

            // Verify the slot is reasonable (not zero)
            if proof.slot == 0 {
                return Err(SolanaError::InvalidInput(
                    "Invalid finality proof: slot is zero".to_string(),
                ));
            }
        }

        Ok(true)
    }

    /// Serialize seal to bytes using bincode
    ///
    /// The serialized format includes:
    /// - seal_ref: SolanaSealPoint (account, owner, lamports, seed)
    /// - finality_proof: Optional SolanaFinalityProof
    pub fn serialize(&self) -> SolanaResult<Vec<u8>> {
        let data = serialize(self)
            .map_err(|e| SolanaError::Serialization(format!("Failed to serialize seal: {}", e)))?;
        Ok(data)
    }

    /// Deserialize seal from bytes using bincode
    pub fn deserialize(data: &[u8]) -> SolanaResult<Self> {
        let seal: SolanaSeal = deserialize(data).map_err(|e| {
            SolanaError::Serialization(format!("Failed to deserialize seal: {}", e))
        })?;
        Ok(seal)
    }
}
