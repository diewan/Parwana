//! Chain capability model
//!
//! Defines the capabilities that chains must expose.
//! This prevents semantic flattening and allows chains to declare what they can do.

use serde::{Deserialize, Serialize};

/// Chain capabilities
///
/// Each chain declares which capabilities it supports.
/// This prevents assuming all chains can do the same things.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCapabilities {
    /// Chain supports state proofs
    pub supports_state_proofs: bool,
    /// Chain supports finality proofs
    pub supports_finality_proofs: bool,
    /// Chain supports event proofs
    pub supports_event_proofs: bool,
    /// Chain supports object ownership model (e.g., Sui objects)
    pub supports_objects: bool,
    /// Chain supports account model (e.g., Ethereum accounts)
    pub supports_accounts: bool,
    /// Chain supports UTXO model (e.g., Bitcoin UTXOs)
    pub supports_utxo: bool,
    /// Chain supports resource model (e.g., Aptos resources)
    pub supports_resources: bool,
    /// Chain supports deterministic execution
    pub supports_deterministic_execution: bool,
    /// Chain supports replay protection natively
    pub supports_replay_protection: bool,
    /// Chain supports Merkle proofs
    pub supports_merkle_proofs: bool,
    /// Chain supports ZK proofs
    pub supports_zk_proofs: bool,
}

impl ChainCapabilities {
    /// Create a new capability set with all features disabled
    pub fn new() -> Self {
        Self {
            supports_state_proofs: false,
            supports_finality_proofs: false,
            supports_event_proofs: false,
            supports_objects: false,
            supports_accounts: false,
            supports_utxo: false,
            supports_resources: false,
            supports_deterministic_execution: false,
            supports_replay_protection: false,
            supports_merkle_proofs: false,
            supports_zk_proofs: false,
        }
    }

    /// Bitcoin-like capabilities
    pub fn bitcoin_like() -> Self {
        Self {
            supports_state_proofs: true,
            supports_finality_proofs: true,
            supports_event_proofs: false,
            supports_objects: false,
            supports_accounts: false,
            supports_utxo: true,
            supports_resources: false,
            supports_deterministic_execution: true,
            supports_replay_protection: true,
            supports_merkle_proofs: true,
            supports_zk_proofs: false,
        }
    }

    /// Ethereum-like capabilities
    pub fn ethereum_like() -> Self {
        Self {
            supports_state_proofs: true,
            supports_finality_proofs: true,
            supports_event_proofs: true,
            supports_objects: false,
            supports_accounts: true,
            supports_utxo: false,
            supports_resources: false,
            supports_deterministic_execution: true,
            supports_replay_protection: true,
            supports_merkle_proofs: true,
            supports_zk_proofs: false,
        }
    }

    /// Solana-like capabilities
    pub fn solana_like() -> Self {
        Self {
            supports_state_proofs: true,
            supports_finality_proofs: true,
            supports_event_proofs: true,
            supports_objects: false,
            supports_accounts: true,
            supports_utxo: false,
            supports_resources: false,
            supports_deterministic_execution: true,
            supports_replay_protection: true,
            supports_merkle_proofs: true,
            supports_zk_proofs: false,
        }
    }

    /// Sui-like capabilities
    pub fn sui_like() -> Self {
        Self {
            supports_state_proofs: true,
            supports_finality_proofs: true,
            supports_event_proofs: true,
            supports_objects: true,
            supports_accounts: false,
            supports_utxo: false,
            supports_resources: false,
            supports_deterministic_execution: true,
            supports_replay_protection: true,
            supports_merkle_proofs: true,
            supports_zk_proofs: false,
        }
    }

    /// Aptos-like capabilities
    pub fn aptos_like() -> Self {
        Self {
            supports_state_proofs: true,
            supports_finality_proofs: true,
            supports_event_proofs: true,
            supports_objects: false,
            supports_accounts: false,
            supports_utxo: false,
            supports_resources: true,
            supports_deterministic_execution: true,
            supports_replay_protection: true,
            supports_merkle_proofs: true,
            supports_zk_proofs: false,
        }
    }

    /// Check if chain supports a specific capability
    pub fn supports(&self, capability: Capability) -> bool {
        match capability {
            Capability::StateProofs => self.supports_state_proofs,
            Capability::FinalityProofs => self.supports_finality_proofs,
            Capability::EventProofs => self.supports_event_proofs,
            Capability::Objects => self.supports_objects,
            Capability::Accounts => self.supports_accounts,
            Capability::UTXO => self.supports_utxo,
            Capability::Resources => self.supports_resources,
            Capability::DeterministicExecution => self.supports_deterministic_execution,
            Capability::ReplayProtection => self.supports_replay_protection,
            Capability::MerkleProofs => self.supports_merkle_proofs,
            Capability::ZKProofs => self.supports_zk_proofs,
        }
    }
}

impl Default for ChainCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

/// Individual capability
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// State proofs
    StateProofs,
    /// Finality proofs
    FinalityProofs,
    /// Event proofs
    EventProofs,
    /// Object ownership model
    Objects,
    /// Account model
    Accounts,
    /// UTXO model
    UTXO,
    /// Resource model
    Resources,
    /// Deterministic execution
    DeterministicExecution,
    /// Replay protection
    ReplayProtection,
    /// Merkle proofs
    MerkleProofs,
    /// ZK proofs
    ZKProofs,
}
