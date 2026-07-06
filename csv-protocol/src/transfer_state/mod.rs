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
//! - **AwaitingFinality**: Lock confirmed, awaiting required source-chain finality
//! - **ProofBuilding**: Building zero-knowledge proof
//! - **ProofValidated**: Proof validated, ready for minting
//! - **Minting**: Minting on destination chain
//! - **Completed**: Transfer successfully completed
//! - **RolledBack**: Transfer rolled back due to reorg
//! - **Compromised**: Transfer compromised (security incident)
//!
//! **Layer Classification:**
//! - L3 (Storage type): TransferStage MAY use serde for persistence layer serialization.

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
/// Initialized → LockSubmitted → LockConfirmed → AwaitingFinality → ProofBuilding
///   → ProofValidated → MintSubmitted → MintConfirmed → Completed
/// ```
///
/// Terminal states: `Completed`, `RolledBack`, `Compromised`
///
/// # Transfer modes
///
/// The intermediate stages split into two mode-specific lifecycles that share
/// the same `Initialized` entry point and the same terminal states
/// (`Completed` / `RolledBack` / `Compromised`):
///
/// - **Materialize** (on-chain thin-registry mint): `LockSubmitted` →
///   `LockConfirmed` → `AwaitingFinality` → `ProofBuilding` → `ProofValidated`
///   → `MintSubmitted` → `MintConfirmed`. Has an asynchronous destination
///   phase, so `resume`/`retry` progress it toward mint confirmation.
/// - **Send** (interactive off-chain RGB-style transfer): `SealAssigned` →
///   `SourceSealClosed` → `ConsignmentEmitted`. There is no destination
///   transaction; resume is idempotent over source-seal close and consignment
///   emission and must never re-close the single-use source seal or re-emit.
///
/// [`TransferStage::mode`] classifies a stage into its owning [`TransferMode`];
/// the shared entry/terminal states belong to neither.
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
    /// Awaiting finality on source chain
    AwaitingFinality,
    /// Proof building in progress after source finality is established
    ProofBuilding,
    /// Proof validated by canonical verifier
    ProofValidated,
    /// Mint transaction submitted to destination chain
    MintSubmitted,
    /// Mint transaction confirmed on destination chain
    MintConfirmed,
    /// Send mode: the Sanad has been assigned to the recipient-controlled
    /// destination seal named by the invoice (no chain mutation yet).
    SealAssigned,
    /// Send mode: the single-use source seal has been closed. This is the
    /// single-use commitment — once journaled `Completed`, resume MUST NOT
    /// re-close it.
    SourceSealClosed,
    /// Send mode: the consignment has been emitted for off-band delivery. The
    /// sender's obligations are discharged; the next stage is `Completed`.
    ConsignmentEmitted,
    /// Transfer completed successfully
    Completed,
    /// Transfer rolled back (safe failure recovery)
    RolledBack,
    /// Transfer compromised (security incident detected)
    Compromised,
}

/// The transfer mode a stage belongs to.
///
/// The two modes have distinct lifecycles and distinct resume semantics; see
/// [`TransferStage`]. The shared entry (`Initialized`) and terminal states
/// belong to neither mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TransferMode {
    /// On-chain transfer via the thin-registry mint (asynchronous destination
    /// finality; `resume`/`retry` apply).
    Materialize,
    /// Interactive off-chain transfer (assign → close source seal → emit
    /// consignment; resume is idempotent, no destination phase).
    Send,
}

impl std::fmt::Display for TransferMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Materialize => write!(f, "materialize"),
            Self::Send => write!(f, "send"),
        }
    }
}

impl TransferStage {
    /// Returns true if this stage is terminal (no further progress possible).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransferStage::Completed | TransferStage::RolledBack | TransferStage::Compromised
        )
    }

    /// Returns the next expected stage in the **materialize** happy path.
    ///
    /// Send-mode stages have no successor here; use [`TransferStage::next_send_stage`]
    /// for the interactive off-chain lifecycle.
    pub fn next_stage(&self) -> Option<TransferStage> {
        match self {
            TransferStage::Initialized => Some(TransferStage::LockSubmitted),
            TransferStage::LockSubmitted => Some(TransferStage::LockConfirmed),
            TransferStage::LockConfirmed => Some(TransferStage::AwaitingFinality),
            TransferStage::AwaitingFinality => Some(TransferStage::ProofBuilding),
            TransferStage::ProofBuilding => Some(TransferStage::ProofValidated),
            TransferStage::ProofValidated => Some(TransferStage::MintSubmitted),
            TransferStage::MintSubmitted => Some(TransferStage::MintConfirmed),
            TransferStage::MintConfirmed => Some(TransferStage::Completed),
            _ => None,
        }
    }

    /// Returns the next expected stage in the **send** (interactive off-chain)
    /// happy path.
    ///
    /// The send lifecycle branches from the shared `Initialized` entry:
    /// `Initialized` → `SealAssigned` → `SourceSealClosed` →
    /// `ConsignmentEmitted` → `Completed`. Materialize stages have no successor
    /// here.
    pub fn next_send_stage(&self) -> Option<TransferStage> {
        match self {
            TransferStage::Initialized => Some(TransferStage::SealAssigned),
            TransferStage::SealAssigned => Some(TransferStage::SourceSealClosed),
            TransferStage::SourceSealClosed => Some(TransferStage::ConsignmentEmitted),
            TransferStage::ConsignmentEmitted => Some(TransferStage::Completed),
            _ => None,
        }
    }

    /// Returns the mode this stage belongs to, or `None` for the shared entry
    /// (`Initialized`) and terminal (`Completed`/`RolledBack`/`Compromised`)
    /// states which are common to both modes.
    pub fn mode(&self) -> Option<TransferMode> {
        match self {
            TransferStage::LockSubmitted
            | TransferStage::LockConfirmed
            | TransferStage::AwaitingFinality
            | TransferStage::ProofBuilding
            | TransferStage::ProofValidated
            | TransferStage::MintSubmitted
            | TransferStage::MintConfirmed => Some(TransferMode::Materialize),
            TransferStage::SealAssigned
            | TransferStage::SourceSealClosed
            | TransferStage::ConsignmentEmitted => Some(TransferMode::Send),
            TransferStage::Initialized
            | TransferStage::Completed
            | TransferStage::RolledBack
            | TransferStage::Compromised => None,
        }
    }

    /// Returns true if this is a send-mode stage.
    pub fn is_send_stage(&self) -> bool {
        matches!(self.mode(), Some(TransferMode::Send))
    }

    /// Returns true if this is a materialize-mode stage.
    pub fn is_materialize_stage(&self) -> bool {
        matches!(self.mode(), Some(TransferMode::Materialize))
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
            Self::SealAssigned => write!(f, "seal_assigned"),
            Self::SourceSealClosed => write!(f, "source_seal_closed"),
            Self::ConsignmentEmitted => write!(f, "consignment_emitted"),
            Self::Completed => write!(f, "completed"),
            Self::RolledBack => write!(f, "rolled_back"),
            Self::Compromised => write!(f, "compromised"),
        }
    }
}

#[cfg(test)]
mod mode_tests {
    use super::*;

    #[test]
    fn materialize_stages_classify_as_materialize() {
        for stage in [
            TransferStage::LockSubmitted,
            TransferStage::LockConfirmed,
            TransferStage::AwaitingFinality,
            TransferStage::ProofBuilding,
            TransferStage::ProofValidated,
            TransferStage::MintSubmitted,
            TransferStage::MintConfirmed,
        ] {
            assert_eq!(stage.mode(), Some(TransferMode::Materialize), "{stage:?}");
            assert!(stage.is_materialize_stage());
            assert!(!stage.is_send_stage());
        }
    }

    #[test]
    fn send_stages_classify_as_send() {
        for stage in [
            TransferStage::SealAssigned,
            TransferStage::SourceSealClosed,
            TransferStage::ConsignmentEmitted,
        ] {
            assert_eq!(stage.mode(), Some(TransferMode::Send), "{stage:?}");
            assert!(stage.is_send_stage());
            assert!(!stage.is_materialize_stage());
        }
    }

    #[test]
    fn shared_stages_belong_to_no_mode() {
        for stage in [
            TransferStage::Initialized,
            TransferStage::Completed,
            TransferStage::RolledBack,
            TransferStage::Compromised,
        ] {
            assert_eq!(stage.mode(), None, "{stage:?}");
            assert!(!stage.is_send_stage());
            assert!(!stage.is_materialize_stage());
        }
    }

    #[test]
    fn send_happy_path_walks_from_initialized_to_completed() {
        let mut stage = TransferStage::Initialized;
        let expected = [
            TransferStage::SealAssigned,
            TransferStage::SourceSealClosed,
            TransferStage::ConsignmentEmitted,
            TransferStage::Completed,
        ];
        for want in expected {
            stage = stage.next_send_stage().expect("send path has a successor");
            assert_eq!(stage, want);
        }
        assert_eq!(stage.next_send_stage(), None);
    }

    #[test]
    fn materialize_and_send_paths_do_not_cross() {
        // A materialize stage has no send successor, and vice versa.
        assert_eq!(TransferStage::LockConfirmed.next_send_stage(), None);
        assert_eq!(TransferStage::SealAssigned.next_stage(), None);
        assert_eq!(TransferStage::SourceSealClosed.next_stage(), None);
        assert_eq!(TransferStage::ConsignmentEmitted.next_stage(), None);
    }

    #[test]
    fn send_stages_are_not_terminal_before_completed() {
        assert!(!TransferStage::SealAssigned.is_terminal());
        assert!(!TransferStage::SourceSealClosed.is_terminal());
        assert!(!TransferStage::ConsignmentEmitted.is_terminal());
    }
}
