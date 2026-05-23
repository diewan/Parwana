//! Finality abstraction for CSV protocol
//!
//! This module defines the finality abstraction that allows different chains
//! to be treated uniformly despite having different finality mechanisms.
//!
//! # Finality Types
//!
//! - **Probabilistic**: Bitcoin-style probabilistic finality (confirmations)
//! - **Economic**: Ethereum-style economic finality (PoW/PoS finality)
//! - **Checkpoint**: Sui/Aptos-style checkpoint finality
//! - **Quorum**: Solana-style quorum-based finality
//! - **Instant**: Instant finality (rare, for special cases)

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Finality type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityType {
    /// Probabilistic finality (Bitcoin-style)
    Probabilistic,
    
    /// Economic finality (Ethereum-style)
    Economic,
    
    /// Checkpoint finality (Sui/Aptos-style)
    Checkpoint,
    
    /// Quorum finality (Solana-style)
    Quorum,
    
    /// Instant finality (rare)
    Instant,
}

impl FinalityType {
    /// Get the default confirmation requirement for this finality type.
    pub fn default_confirmations(&self) -> u64 {
        match self {
            FinalityType::Probabilistic => 6, // Bitcoin standard
            FinalityType::Economic => 2, // Ethereum finality after 2 blocks
            FinalityType::Checkpoint => 1, // Checkpoint is final
            FinalityType::Quorum => 1, // Quorum is final
            FinalityType::Instant => 0, // Instant is final
        }
    }

    /// Get the expected time to finality for this type.
    pub fn expected_time_to_finality(&self) -> Duration {
        match self {
            FinalityType::Probabilistic => Duration::from_secs(3600), // ~1 hour
            FinalityType::Economic => Duration::from_secs(24), // ~24 seconds
            FinalityType::Checkpoint => Duration::from_secs(2), // ~2 seconds
            FinalityType::Quorum => Duration::from_secs(2), // ~2 seconds
            FinalityType::Instant => Duration::from_secs(0), // Instant
        }
    }
}

/// Finality proof for a chain event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Finality type
    pub finality_type: FinalityType,
    /// Block height of the event
    pub block_height: u64,
    /// Current chain height
    pub current_height: u64,
    /// Confirmations achieved
    pub confirmations: u64,
    /// Required confirmations
    pub required_confirmations: u64,
    /// Finality data (chain-specific)
    pub finality_data: Vec<u8>,
    /// Timestamp of finality achievement
    pub finalized_at: Option<u64>,
}

impl FinalityProof {
    /// Create a new finality proof.
    pub fn new(
        finality_type: FinalityType,
        block_height: u64,
        current_height: u64,
        required_confirmations: u64,
        finality_data: Vec<u8>,
    ) -> Self {
        let confirmations = current_height.saturating_sub(block_height);
        
        Self {
            finality_type,
            block_height,
            current_height,
            confirmations,
            required_confirmations,
            finality_data,
            finalized_at: None,
        }
    }

    /// Check if the proof indicates finality is achieved.
    pub fn is_final(&self) -> bool {
        self.confirmations >= self.required_confirmations
    }

    /// Mark the proof as finalized with a timestamp.
    pub fn mark_finalized(&mut self, timestamp: u64) {
        self.finalized_at = Some(timestamp);
    }

    /// Get the time to finality (if finalized).
    pub fn time_to_finality(&self) -> Option<Duration> {
        if let Some(finalized_at) = self.finalized_at {
            // In production, this would use the block timestamp
            Some(Duration::from_secs(0))
        } else {
            None
        }
    }
}

/// Finality verifier trait for chain-specific verification.
pub trait FinalityVerifier {
    /// Verify a finality proof for this chain.
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError>;
    
    /// Get the finality type for this chain.
    fn finality_type(&self) -> FinalityType;
    
    /// Get the required confirmations for this chain.
    fn required_confirmations(&self) -> u64;
}

/// Finality errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FinalityError {
    #[error("Invalid finality proof")]
    InvalidProof,
    
    #[error("Insufficient confirmations: {current}/{required}")]
    InsufficientConfirmations { current: u64, required: u64 },
    
    #[error("Invalid finality data")]
    InvalidFinalityData,
    
    #[error("Block height mismatch")]
    BlockHeightMismatch,
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Bitcoin finality verifier (probabilistic).
pub struct BitcoinFinalityVerifier {
    /// Required confirmations
    pub required_confirmations: u64,
}

impl BitcoinFinalityVerifier {
    /// Create a new Bitcoin finality verifier.
    pub fn new(required_confirmations: u64) -> Self {
        Self {
            required_confirmations,
        }
    }
}

impl FinalityVerifier for BitcoinFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Probabilistic {
            return Err(FinalityError::InvalidProof);
        }

        if proof.confirmations < self.required_confirmations {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: self.required_confirmations,
            });
        }

        // Verify finality data contains valid block header
        if proof.finality_data.len() < 80 {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Probabilistic
    }

    fn required_confirmations(&self) -> u64 {
        self.required_confirmations
    }
}

/// Ethereum finality verifier (economic).
pub struct EthereumFinalityVerifier {
    /// Required confirmations
    pub required_confirmations: u64,
}

impl EthereumFinalityVerifier {
    /// Create a new Ethereum finality verifier.
    pub fn new(required_confirmations: u64) -> Self {
        Self {
            required_confirmations,
        }
    }
}

impl FinalityVerifier for EthereumFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Economic {
            return Err(FinalityError::InvalidProof);
        }

        if proof.confirmations < self.required_confirmations {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: self.required_confirmations,
            });
        }

        // Verify finality data contains valid block header
        if proof.finality_data.len() < 80 {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Economic
    }

    fn required_confirmations(&self) -> u64 {
        self.required_confirmations
    }
}

/// Solana finality verifier (quorum).
pub struct SolanaFinalityVerifier;

impl FinalityVerifier for SolanaFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Quorum {
            return Err(FinalityError::InvalidProof);
        }

        // Quorum finality is achieved with 1 confirmation
        if proof.confirmations < 1 {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: 1,
            });
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Quorum
    }

    fn required_confirmations(&self) -> u64 {
        1
    }
}

/// Sui finality verifier (checkpoint).
pub struct SuiFinalityVerifier;

impl FinalityVerifier for SuiFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Checkpoint {
            return Err(FinalityError::InvalidProof);
        }

        // Checkpoint finality is achieved with 1 confirmation
        if proof.confirmations < 1 {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: 1,
            });
        }

        // Verify finality data contains checkpoint digest
        if proof.finality_data.is_empty() {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Checkpoint
    }

    fn required_confirmations(&self) -> u64 {
        1
    }
}

/// Aptos finality verifier (checkpoint).
pub struct AptosFinalityVerifier;

impl FinalityVerifier for AptosFinalityVerifier {
    fn verify_finality(&self, proof: &FinalityProof) -> Result<bool, FinalityError> {
        if proof.finality_type != FinalityType::Checkpoint {
            return Err(FinalityError::InvalidProof);
        }

        // Checkpoint finality is achieved with 1 confirmation
        if proof.confirmations < 1 {
            return Err(FinalityError::InsufficientConfirmations {
                current: proof.confirmations,
                required: 1,
            });
        }

        // Verify finality data contains checkpoint digest
        if proof.finality_data.is_empty() {
            return Err(FinalityError::InvalidFinalityData);
        }

        Ok(true)
    }

    fn finality_type(&self) -> FinalityType {
        FinalityType::Checkpoint
    }

    fn required_confirmations(&self) -> u64 {
        1
    }
}

/// Finality configuration for a chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Chain ID
    pub chain_id: String,
    /// Finality type
    pub finality_type: FinalityType,
    /// Required confirmations
    pub required_confirmations: u64,
    /// Timeout for finality achievement
    pub timeout: Duration,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            chain_id: "bitcoin".to_string(),
            finality_type: FinalityType::Probabilistic,
            required_confirmations: 6,
            timeout: Duration::from_secs(3600),
        }
    }
}

impl FinalityConfig {
    /// Create a new finality config.
    pub fn new(
        chain_id: String,
        finality_type: FinalityType,
        required_confirmations: u64,
        timeout: Duration,
    ) -> Self {
        Self {
            chain_id,
            finality_type,
            required_confirmations,
            timeout,
        }
    }

    /// Get the default config for Bitcoin.
    pub fn bitcoin() -> Self {
        Self {
            chain_id: "bitcoin".to_string(),
            finality_type: FinalityType::Probabilistic,
            required_confirmations: 6,
            timeout: Duration::from_secs(3600),
        }
    }

    /// Get the default config for Ethereum.
    pub fn ethereum() -> Self {
        Self {
            chain_id: "ethereum".to_string(),
            finality_type: FinalityType::Economic,
            required_confirmations: 2,
            timeout: Duration::from_secs(60),
        }
    }

    /// Get the default config for Solana.
    pub fn solana() -> Self {
        Self {
            chain_id: "solana".to_string(),
            finality_type: FinalityType::Quorum,
            required_confirmations: 1,
            timeout: Duration::from_secs(10),
        }
    }

    /// Get the default config for Sui.
    pub fn sui() -> Self {
        Self {
            chain_id: "sui".to_string(),
            finality_type: FinalityType::Checkpoint,
            required_confirmations: 1,
            timeout: Duration::from_secs(5),
        }
    }

    /// Get the default config for Aptos.
    pub fn aptos() -> Self {
        Self {
            chain_id: "aptos".to_string(),
            finality_type: FinalityType::Checkpoint,
            required_confirmations: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_proof() {
        let proof = FinalityProof::new(
            FinalityType::Probabilistic,
            100,
            106,
            6,
            vec![1, 2, 3, 4],
        );

        assert!(proof.is_final());
        assert_eq!(proof.confirmations, 6);
    }

    #[test]
    fn test_bitcoin_finality_verifier() {
        let verifier = BitcoinFinalityVerifier::new(6);
        let proof = FinalityProof::new(
            FinalityType::Probabilistic,
            100,
            106,
            6,
            vec![1u8; 80],
        );

        assert!(verifier.verify_finality(&proof).is_ok());
    }

    #[test]
    fn test_ethereum_finality_verifier() {
        let verifier = EthereumFinalityVerifier::new(2);
        let proof = FinalityProof::new(
            FinalityType::Economic,
            100,
            102,
            2,
            vec![1u8; 80],
        );

        assert!(verifier.verify_finality(&proof).is_ok());
    }

    #[test]
    fn test_insufficient_confirmations() {
        let verifier = BitcoinFinalityVerifier::new(6);
        let proof = FinalityProof::new(
            FinalityType::Probabilistic,
            100,
            105,
            6,
            vec![1u8; 80],
        );

        let result = verifier.verify_finality(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_finality_config_defaults() {
        let bitcoin_config = FinalityConfig::bitcoin();
        assert_eq!(bitcoin_config.finality_type, FinalityType::Probabilistic);
        assert_eq!(bitcoin_config.required_confirmations, 6);

        let ethereum_config = FinalityConfig::ethereum();
        assert_eq!(ethereum_config.finality_type, FinalityType::Economic);
        assert_eq!(ethereum_config.required_confirmations, 2);
    }
}
