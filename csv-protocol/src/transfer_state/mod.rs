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
