//! Chain-specific finality and commitment grades.
//!
//! These types ensure that chain-specific semantics are never collapsed into
//! scalar values or binary booleans, which would lose information critical for
//! correct verification decision-making.

use serde::{Deserialize, Serialize};

/// Solana commitment grades — never collapse these into `u64 confirmations`.
///
/// Solana's consensus model has three distinct commitment levels with different
/// safety guarantees. The protocol must respect these distinctions rather than
/// treating them as scalar confirmation counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolanaCommitmentGrade {
    /// Transaction was processed by the leader but not confirmed by any
    /// supermajority vote. Sub-second finality risk. NOT SAFE for minting.
    Processed,
    /// Transaction was voted on by a supermajority of validators (>2/3).
    /// Equivalent to usual "confirmed" in Solana terminology. Reasonably safe
    /// for most use cases, but fork resolution may revert.
    Confirmed,
    /// Transaction is rooted — at least 32 confirmed blocks built on top.
    /// Maximum safety guarantee Solana offers. Equivalent to "finalized".
    Finalized,
}

/// Ethereum finality stages — not binary.
///
/// Ethereum post-merge has three distinct finality stages with different
/// safety properties. Proof validation must respect these stages and
/// should not authorize minting below `Finalized` unless in degraded mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthereumFinalityStage {
    /// The latest block tip — no finality guarantee.
    UnsafeHead,
    /// The safe head as reported by the execution layer — typically 1-2 slots
    /// behind the tip. Protected against single-slot reorgs.
    SafeHead,
    /// A checkpoint that has been justified by the consensus layer but not yet
    /// finalized. Two-epoch safety.
    Justified,
    /// A checkpoint finalized by the Casper FFG consensus. Two epochs of
    /// attestations. This is the canonical finalized checkpoint.
    Finalized,
}

impl EthereumFinalityStage {
    /// Returns true if this stage is at or above the given minimum stage.
    pub fn meets_threshold(&self, minimum: EthereumFinalityStage) -> bool {
        self.stage_level() >= minimum.stage_level()
    }

    fn stage_level(&self) -> u8 {
        match self {
            Self::UnsafeHead => 0,
            Self::SafeHead => 1,
            Self::Justified => 2,
            Self::Finalized => 3,
        }
    }
}

impl SolanaCommitmentGrade {
    /// Returns true if this grade meets or exceeds the required minimum.
    pub fn meets_threshold(&self, minimum: SolanaCommitmentGrade) -> bool {
        self.grade_level() >= minimum.grade_level()
    }

    fn grade_level(&self) -> u8 {
        match self {
            Self::Processed => 0,
            Self::Confirmed => 1,
            Self::Finalized => 2,
        }
    }
}
