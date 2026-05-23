//! Replay semantics
//!
//! This module defines the replay protection semantics for the CSV protocol.
//! Replay protection prevents duplicate proof acceptance across chains.

/// Replay protection semantics
pub mod semantics {
    /// A proof can only be consumed once across all chains
    pub const SINGLE_CONSUMPTION: bool = true;

    /// Replay ID is derived from proof hash, seal ID, and commitment hash
    pub const REPLAY_ID_DERIVATION: &str = "proof_hash || seal_id || commitment_hash";

    /// Replay registry must persist across restarts
    pub const PERSISTENT_REGISTRY: bool = true;

    /// Replay entries must have timestamps for age-based cleanup
    pub const TIMESTAMPED_ENTRIES: bool = true;
}

/// Replay registry implementation
pub mod registry;

pub use registry::{
    ReplayKey, ReplayEntry, ReplayRegistry, ReplayRegistryBackend,
    ReplayNullifier, NullifierRegistry, NullifierRegistryStats,
    ReplayError, ReplayConstitutionValidator,
    REPLAY_CONSTITUTION_VERSION, NULLIFIER_EXPIRY_SECONDS,
};
