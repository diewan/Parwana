//! Transfer stage — protocol-level transfer lifecycle state machine
//!
//! This module defines the canonical transfer stages used throughout the CSV protocol.
//! It is the single source of truth for transfer state tracking and recovery.
//!
//! # Protocol Invariant
//!
//! All transfer state transitions MUST follow the defined stage sequence.
//! No component may skip stages or create ad-hoc state tracking.
//!
//! # Stage Sequence
//!
//! ```text
//! Initialized → LockSubmitted → LockConfirmed → ProofBuilding → ProofValidated
//!   → AwaitingFinality → MintSubmitted → MintConfirmed → Completed
//! ```
//!
//! Terminal states: `Completed`, `RolledBack`, `Compromised`

use serde::{Deserialize, Serialize};

/// Transfer stage for recovery and state tracking.
///
/// This enum represents the complete lifecycle of a cross-chain transfer.
/// Every component (runtime, CLI, SDK, explorer) MUST use this exact
/// stage sequence for transfer state tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TransferStage {
    /// Initial state — transfer created, not yet submitted
    Initialized,
    /// Lock transaction submitted to source chain
    LockSubmitted,
    /// Lock transaction confirmed on source chain
    LockConfirmed,
    /// Proof building in progress
    ProofBuilding,
    /// Proof validated by canonical verifier
    ProofValidated,
    /// Awaiting finality on source chain
    AwaitingFinality,
    /// Mint transaction submitted to destination chain
    MintSubmitted,
    /// Mint transaction confirmed on destination chain
    MintConfirmed,
    /// Transfer completed successfully
    Completed,
    /// Transfer rolled back (safe failure recovery)
    RolledBack,
    /// Transfer compromised (security incident detected)
    Compromised,
}

impl TransferStage {
    /// Returns true if this stage is terminal (no further progress possible).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransferStage::Completed | TransferStage::RolledBack | TransferStage::Compromised
        )
    }

    /// Returns the next expected stage in the happy path.
    pub fn next_stage(&self) -> Option<TransferStage> {
        match self {
            TransferStage::Initialized => Some(TransferStage::LockSubmitted),
            TransferStage::LockSubmitted => Some(TransferStage::LockConfirmed),
            TransferStage::LockConfirmed => Some(TransferStage::ProofBuilding),
            TransferStage::ProofBuilding => Some(TransferStage::ProofValidated),
            TransferStage::ProofValidated => Some(TransferStage::AwaitingFinality),
            TransferStage::AwaitingFinality => Some(TransferStage::MintSubmitted),
            TransferStage::MintSubmitted => Some(TransferStage::MintConfirmed),
            TransferStage::MintConfirmed => Some(TransferStage::Completed),
            _ => None,
        }
    }

    /// Returns true if the transfer is in progress (not terminal, not initialized).
    pub fn is_in_progress(&self) -> bool {
        !self.is_terminal() && !matches!(self, TransferStage::Initialized)
    }

    /// Returns true if proof has been validated (proof is ready for minting).
    pub fn proof_validated(&self) -> bool {
        matches!(
            self,
            TransferStage::ProofValidated
                | TransferStage::AwaitingFinality
                | TransferStage::MintSubmitted
                | TransferStage::MintConfirmed
                | TransferStage::Completed
        )
    }
}

impl Default for TransferStage {
    fn default() -> Self {
        Self::Initialized
    }
}

impl std::fmt::Display for TransferStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initialized => write!(f, "initialized"),
            Self::LockSubmitted => write!(f, "lock_submitted"),
            Self::LockConfirmed => write!(f, "lock_confirmed"),
            Self::ProofBuilding => write!(f, "proof_building"),
            Self::ProofValidated => write!(f, "proof_validated"),
            Self::AwaitingFinality => write!(f, "awaiting_finality"),
            Self::MintSubmitted => write!(f, "mint_submitted"),
            Self::MintConfirmed => write!(f, "mint_confirmed"),
            Self::Completed => write!(f, "completed"),
            Self::RolledBack => write!(f, "rolled_back"),
            Self::Compromised => write!(f, "compromised"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_stage_terminal() {
        assert!(TransferStage::Completed.is_terminal());
        assert!(TransferStage::RolledBack.is_terminal());
        assert!(TransferStage::Compromised.is_terminal());
        assert!(!TransferStage::Initialized.is_terminal());
        assert!(!TransferStage::LockConfirmed.is_terminal());
    }

    #[test]
    fn test_transfer_stage_next() {
        assert_eq!(
            TransferStage::Initialized.next_stage(),
            Some(TransferStage::LockSubmitted)
        );
        assert_eq!(
            TransferStage::LockConfirmed.next_stage(),
            Some(TransferStage::ProofBuilding)
        );
        assert_eq!(
            TransferStage::ProofValidated.next_stage(),
            Some(TransferStage::AwaitingFinality)
        );
        assert_eq!(TransferStage::Completed.next_stage(), None);
        assert_eq!(TransferStage::RolledBack.next_stage(), None);
    }

    #[test]
    fn test_transfer_stage_in_progress() {
        assert!(!TransferStage::Initialized.is_in_progress());
        assert!(TransferStage::LockConfirmed.is_in_progress());
        assert!(TransferStage::ProofValidated.is_in_progress());
        assert!(!TransferStage::Completed.is_in_progress());
        assert!(!TransferStage::RolledBack.is_in_progress());
    }

    #[test]
    fn test_transfer_stage_proof_validated() {
        assert!(!TransferStage::LockConfirmed.proof_validated());
        assert!(TransferStage::ProofValidated.proof_validated());
        assert!(TransferStage::AwaitingFinality.proof_validated());
        assert!(TransferStage::Completed.proof_validated());
    }

    #[test]
    fn test_transfer_stage_default() {
        assert_eq!(TransferStage::default(), TransferStage::Initialized);
    }

    #[test]
    fn test_transfer_stage_display() {
        assert_eq!(format!("{}", TransferStage::Completed), "completed");
        assert_eq!(format!("{}", TransferStage::ProofValidated), "proof_validated");
        assert_eq!(format!("{}", TransferStage::RolledBack), "rolled_back");
    }
}
