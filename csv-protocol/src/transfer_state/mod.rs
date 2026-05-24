//! Transfer State Machine (Typestate Pattern)
//!
//! This module implements a typestate pattern for transfer states to enforce
//! valid state transitions at compile time. This prevents illegal mutations
//! and ensures protocol invariants are structurally enforced.
//!
//! ## Typestate Pattern
//!
//! Each state is a distinct type, and transitions are only possible through
//! specific methods that consume the current state and return the next state.
//! This makes invalid state transitions compile-time errors.
//!
//! ## States
//!
//! - **Locked**: Transfer is locked on source chain, awaiting proof
//! - **AwaitingFinality**: Proof submitted, awaiting finality confirmation
//! - **ProofBuilding**: Building zero-knowledge proof
//! - **ProofValidated**: Proof validated, ready for minting
//! - **Minting**: Minting on destination chain
//! - **Completed**: Transfer successfully completed
//! - **RolledBack**: Transfer rolled back due to reorg
//! - **Compromised**: Transfer compromised (security incident)

pub mod awaiting_finality;
pub mod completed;
pub mod compromised;
pub mod locked;
pub mod minting;
pub mod proof_building;
pub mod proof_validated;
pub mod rolled_back;

// Re-export state types
pub use awaiting_finality::AwaitingFinality;
pub use completed::Completed;
pub use compromised::Compromised;
pub use locked::Locked;
pub use minting::Minting;
pub use proof_building::ProofBuilding;
pub use proof_validated::ProofValidated;
pub use rolled_back::RolledBack;

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;
use serde::{Deserialize, Serialize};

/// Base transfer data shared across all states
#[derive(Clone, Debug)]
pub struct TransferData {
    /// Unique transfer identifier
    pub transfer_id: Hash,
    /// Sanad being transferred
    pub sanad_id: SanadId,
    /// Source chain
    pub source_chain: ChainId,
    /// Destination chain
    pub destination_chain: ChainId,
    /// Seal point on source chain
    pub seal_point: Vec<u8>,
    /// Commitment hash
    pub commitment_hash: Hash,
    /// Timestamp when transfer was initiated
    pub initiated_at: u64,
}

impl TransferData {
    /// Create new transfer data
    pub fn new(
        transfer_id: Hash,
        sanad_id: SanadId,
        source_chain: ChainId,
        destination_chain: ChainId,
        seal_point: Vec<u8>,
        commitment_hash: Hash,
    ) -> Self {
        Self {
            transfer_id,
            sanad_id,
            source_chain,
            destination_chain,
            seal_point,
            commitment_hash,
            initiated_at: 0, // Will be set when transfer is created
        }
    }
}

/// Transfer stage for recovery and state tracking.
///
/// This enum represents the complete lifecycle of a cross-chain transfer.
/// Every component (runtime, CLI, SDK, explorer) MUST use this exact
/// stage sequence for transfer state tracking.
///
/// # Stage Sequence
///
/// ```text
/// Initialized → LockSubmitted → LockConfirmed → ProofBuilding → ProofValidated
///   → AwaitingFinality → MintSubmitted → MintConfirmed → Completed
/// ```
///
/// Terminal states: `Completed`, `RolledBack`, `Compromised`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum TransferStage {
    /// Initial state — transfer created, not yet submitted
    #[default]
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
