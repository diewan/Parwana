//! Chain Finality Policy
//!
//! Defines the finality requirements for each chain.

/// Chain finality policy trait
pub trait ChainFinalityPolicy {
    /// Get the required confirmations for finality
    fn required_confirmations(&self) -> u32;

    /// Get the finality threshold (percentage of validators)
    fn finality_threshold(&self) -> f64;

    /// Check if a block at given height is considered finalized
    fn is_block_finalized(&self, block_height: u64, current_height: u64) -> bool;
}

/// Finality threshold configuration
#[derive(Clone, Debug)]
pub struct FinalityThreshold {
    /// Minimum confirmations required
    pub min_confirmations: u32,
    /// Percentage of validators required (0.0 - 1.0)
    pub validator_percentage: f64,
}

impl FinalityThreshold {
    /// Create a new finality threshold
    pub fn new(min_confirmations: u32, validator_percentage: f64) -> Self {
        Self {
            min_confirmations,
            validator_percentage,
        }
    }
}

/// Bitcoin finality policy
#[derive(Clone, Debug)]
pub struct BitcoinFinalityPolicy {
    threshold: FinalityThreshold,
}

impl Default for BitcoinFinalityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl BitcoinFinalityPolicy {
    /// Create a new Bitcoin finality policy (6 confirmations)
    pub fn new() -> Self {
        Self {
            threshold: FinalityThreshold::new(6, 0.0), // Bitcoin uses probabilistic finality
        }
    }
}

impl ChainFinalityPolicy for BitcoinFinalityPolicy {
    fn required_confirmations(&self) -> u32 {
        self.threshold.min_confirmations
    }

    fn finality_threshold(&self) -> f64 {
        self.threshold.validator_percentage
    }

    fn is_block_finalized(&self, block_height: u64, current_height: u64) -> bool {
        current_height >= block_height + self.threshold.min_confirmations as u64
    }
}

/// Ethereum finality policy
#[derive(Clone, Debug)]
pub struct EthereumFinalityPolicy {
    threshold: FinalityThreshold,
}

impl Default for EthereumFinalityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl EthereumFinalityPolicy {
    /// Create a new Ethereum finality policy (using checkpoint finality)
    pub fn new() -> Self {
        Self {
            threshold: FinalityThreshold::new(64, 0.66), // ~2/3 of validators
        }
    }
}

impl ChainFinalityPolicy for EthereumFinalityPolicy {
    fn required_confirmations(&self) -> u32 {
        self.threshold.min_confirmations
    }

    fn finality_threshold(&self) -> f64 {
        self.threshold.validator_percentage
    }

    fn is_block_finalized(&self, block_height: u64, current_height: u64) -> bool {
        current_height >= block_height + self.threshold.min_confirmations as u64
    }
}

/// Aptos finality policy
#[derive(Clone, Debug)]
pub struct AptosFinalityPolicy {
    threshold: FinalityThreshold,
}

impl Default for AptosFinalityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl AptosFinalityPolicy {
    /// Create a new Aptos finality policy (instant finality)
    pub fn new() -> Self {
        Self {
            threshold: FinalityThreshold::new(0, 0.67), // Aptos has instant finality
        }
    }
}

impl ChainFinalityPolicy for AptosFinalityPolicy {
    fn required_confirmations(&self) -> u32 {
        self.threshold.min_confirmations
    }

    fn finality_threshold(&self) -> f64 {
        self.threshold.validator_percentage
    }

    fn is_block_finalized(&self, _block_height: u64, _current_height: u64) -> bool {
        // Aptos has instant finality - any block is considered finalized
        true
    }
}

/// Solana finality policy
#[derive(Clone, Debug)]
pub struct SolanaFinalityPolicy {
    threshold: FinalityThreshold,
}

impl Default for SolanaFinalityPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl SolanaFinalityPolicy {
    /// Create a new Solana finality policy (32 confirmations for probabilistic finality)
    pub fn new() -> Self {
        Self {
            threshold: FinalityThreshold::new(32, 0.67), // ~2/3 of stake
        }
    }
}

impl ChainFinalityPolicy for SolanaFinalityPolicy {
    fn required_confirmations(&self) -> u32 {
        self.threshold.min_confirmations
    }

    fn finality_threshold(&self) -> f64 {
        self.threshold.validator_percentage
    }

    fn is_block_finalized(&self, block_height: u64, current_height: u64) -> bool {
        current_height >= block_height + self.threshold.min_confirmations as u64
    }
}
