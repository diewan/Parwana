//! Chain capability model
//!
//! Defines the capabilities that chains must expose.
//! This prevents semantic flattening and allows chains to declare what they can do.

use crate::verified::{FinalityStrength, InclusionStrength};
use serde::{Deserialize, Serialize};
use std::fmt;

/// State model used by a chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateModel {
    /// UTXO-based model (Bitcoin)
    Utxo,
    /// Account-based model (Ethereum)
    Account,
    /// Object-based model (Sui)
    Object,
    /// Resource-based model (Aptos Move resources)
    Resource,
    /// Data blob model (Celestia)
    DataBlob,
}

/// Finality model for a chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalityModel {
    /// Proof of work with N confirmations (Bitcoin)
    ProofOfWork { confirmations: u64 },
    /// Finalized checkpoint (Ethereum post-merge)
    FinalizedCheckpoint,
    /// BFT instant finality (Aptos HotStuff, Sui Narwhal)
    BftInstant,
    /// Optimistic with slot expiry (Solana)
    OptimisticWithSlotExpiry { slots: u64 },
    /// Data availability header (Celestia)
    DataAvailabilityHeader,
}

/// Proof model used by a chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofModel {
    /// SPV Merkle branch + header PoW (Bitcoin)
    SpvMerkle,
    /// Merkle Patricia trie storage/receipt proof (Ethereum)
    MerklePatricia,
    /// Sparse Merkle accumulator (Aptos)
    AccumulatorPath,
    /// Checkpoint Merkle path (Sui)
    CheckpointMerkle,
    /// Slot-based ledger proof (Solana)
    SlotConfirmation,
    /// Namespace Merkle proof (Celestia)
    DaNamespace,
}

/// Replay protection model for a chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReplayProtectionModel {
    /// UTXO is spent = consumed (Bitcoin)
    UtxoSpentCheck,
    /// Nullifier mapping in contract (Ethereum)
    SmartContractNullifier,
    /// Account closed = consumed (Solana PDA)
    PdaClosed,
    /// Move resource moved away (Aptos)
    ResourceDeleted,
    /// Object deleted = consumed (Sui)
    ObjectDeleted,
}

/// Reorg risk level for a chain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReorgRisk {
    /// Rare but deep reorgs possible (Bitcoin)
    High,
    /// Finalized checkpoints, but pre-finality risk (Ethereum)
    Medium,
    /// BFT or near-instant finality (Solana, Aptos, Sui)
    Low,
    /// DA only (Celestia)
    None,
}

/// A chain's role in the CSV protocol architecture.
/// Celestia is DA, not Settlement. This distinction must be enforced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChainRole {
    /// Can hold and transfer value: BTC, ETH, SOL, APT, SUI
    Settlement,
    /// Can post commitment data: Celestia
    DataAvailability,
    /// Can verify proofs on-chain
    Verification,
}

/// Security-relevant capabilities of a chain adapter.
/// Transfer logic MUST depend on these capabilities, NOT on chain names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCapabilities {
    // --- State model ---
    pub state_model: StateModel,

    // --- Finality model ---
    pub finality_model: FinalityModel,
    /// Blocks/slots/checkpoints required for probabilistic finality
    pub finality_depth: u64,
    /// Whether finality is deterministic (BFT) vs probabilistic (PoW/PoS)
    pub deterministic_finality: bool,

    // --- Proof model ---
    pub proof_model: ProofModel,

    // --- Replay protection ---
    pub replay_protection: ReplayProtectionModel,
    /// Whether the chain supports atomic single-use seal semantics natively
    pub native_single_use_semantics: bool,

    // --- Reorg characteristics ---
    pub reorg_risk: ReorgRisk,
    /// Maximum reorg depth the adapter is designed to handle safely
    pub max_safe_reorg_depth: u64,

    // --- Verification capabilities ---
    pub supports_light_client_proofs: bool,
    pub supports_state_proofs: bool,
    pub supports_transaction_inclusion_proofs: bool,
    pub supports_offline_verification: bool,
    pub supports_zk_proofs: bool,

    // --- DA role ---
    pub chain_role: ChainRole,
}

/// Runtime capability requirements for a protocol operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRequirements {
    /// Human-readable operation name for diagnostics.
    pub operation: String,
    /// Operation requires a settlement chain.
    pub require_settlement: bool,
    /// Operation requires light-client proof support.
    pub require_light_client_proofs: bool,
    /// Operation requires state proof support.
    pub require_state_proofs: bool,
    /// Operation requires transaction inclusion proof support.
    pub require_transaction_inclusion_proofs: bool,
    /// Operation requires offline verification support.
    pub require_offline_verification: bool,
    /// Operation requires ZK proof support.
    pub require_zk_proofs: bool,
    /// Minimum finality depth accepted by the planner.
    pub min_finality_depth: u64,
}

impl CapabilityRequirements {
    /// Requirements for a chain used as a cross-chain transfer source.
    pub fn cross_chain_source() -> Self {
        Self {
            operation: "cross_chain_source".to_string(),
            require_settlement: true,
            require_light_client_proofs: false,
            require_state_proofs: false,
            require_transaction_inclusion_proofs: true,
            require_offline_verification: false,
            require_zk_proofs: false,
            min_finality_depth: 1,
        }
    }

    /// Requirements for a chain used as a cross-chain transfer destination.
    pub fn cross_chain_destination() -> Self {
        Self {
            operation: "cross_chain_destination".to_string(),
            require_settlement: true,
            require_light_client_proofs: false,
            require_state_proofs: false,
            require_transaction_inclusion_proofs: false,
            require_offline_verification: false,
            require_zk_proofs: false,
            min_finality_depth: 1,
        }
    }
}

/// Result of checking advertised chain capabilities against operation requirements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityPlan {
    /// Operation being planned.
    pub operation: String,
    /// Whether all requirements were satisfied.
    pub satisfied: bool,
    /// Missing requirement names.
    pub missing: Vec<String>,
}

impl CapabilityPlan {
    /// Return `Ok(())` if requirements are satisfied, otherwise return a compact diagnostic.
    pub fn ensure_satisfied(&self) -> Result<(), String> {
        if self.satisfied {
            return Ok(());
        }
        Err(format!(
            "Capability requirements for {} not satisfied: {}",
            self.operation,
            self.missing.join(", ")
        ))
    }
}

impl ChainCapabilities {
    /// Plan whether this chain can satisfy a runtime operation.
    pub fn plan_for(&self, requirements: &CapabilityRequirements) -> CapabilityPlan {
        let mut missing = Vec::new();

        if requirements.require_settlement && !matches!(self.chain_role, ChainRole::Settlement) {
            missing.push("settlement_role".to_string());
        }
        if requirements.require_light_client_proofs && !self.supports_light_client_proofs {
            missing.push("light_client_proofs".to_string());
        }
        if requirements.require_state_proofs && !self.supports_state_proofs {
            missing.push("state_proofs".to_string());
        }
        if requirements.require_transaction_inclusion_proofs
            && !self.supports_transaction_inclusion_proofs
        {
            missing.push("transaction_inclusion_proofs".to_string());
        }
        if requirements.require_offline_verification && !self.supports_offline_verification {
            missing.push("offline_verification".to_string());
        }
        if requirements.require_zk_proofs && !self.supports_zk_proofs {
            missing.push("zk_proofs".to_string());
        }
        if self.finality_depth < requirements.min_finality_depth {
            missing.push(format!(
                "finality_depth({}<{})",
                self.finality_depth, requirements.min_finality_depth
            ));
        }

        CapabilityPlan {
            operation: requirements.operation.clone(),
            satisfied: missing.is_empty(),
            missing,
        }
    }

    /// Returns true if the observed inclusion strength meets this chain's minimum.
    pub fn inclusion_threshold_met(&self, observed: &InclusionStrength) -> bool {
        match self.proof_model {
            ProofModel::SpvMerkle => matches!(
                observed,
                InclusionStrength::MerklePath | InclusionStrength::AnchoredMerklePath
            ),
            ProofModel::MerklePatricia => matches!(
                observed,
                InclusionStrength::MerklePath | InclusionStrength::AnchoredMerklePath
            ),
            ProofModel::AccumulatorPath | ProofModel::CheckpointMerkle => matches!(
                observed,
                InclusionStrength::MerklePath | InclusionStrength::AnchoredMerklePath
            ),
            ProofModel::SlotConfirmation => matches!(
                observed,
                InclusionStrength::Checksum | InclusionStrength::MerklePath
            ),
            ProofModel::DaNamespace => matches!(
                observed,
                InclusionStrength::MerklePath | InclusionStrength::AnchoredMerklePath
            ),
        }
    }

    /// Returns true if the observed finality strength meets this chain's minimum.
    pub fn finality_threshold_met(&self, observed: &FinalityStrength) -> bool {
        // Deterministic finality is always sufficient regardless of chain model
        if matches!(observed, FinalityStrength::Deterministic) {
            return true;
        }
        match (&self.finality_model, observed) {
            (
                FinalityModel::ProofOfWork { confirmations },
                FinalityStrength::Probabilistic { confirmations: obs },
            ) => obs >= confirmations,
            (
                FinalityModel::OptimisticWithSlotExpiry { slots },
                FinalityStrength::Probabilistic { confirmations: obs },
            ) => obs >= slots,
            (
                FinalityModel::FinalizedCheckpoint
                | FinalityModel::BftInstant
                | FinalityModel::DataAvailabilityHeader,
                FinalityStrength::Deterministic,
            ) => true,
            _ => false,
        }
    }

    /// Returns true if this chain can authorize minting (i.e., is a settlement chain).
    /// Data availability chains (e.g., Celestia) cannot mint.
    pub fn can_authorize_mint(&self) -> bool {
        matches!(self.chain_role, ChainRole::Settlement)
    }

    /// Create Bitcoin chain capabilities (convenience method for backward compatibility)
    pub fn bitcoin() -> Self {
        Self {
            state_model: StateModel::Utxo,
            finality_model: FinalityModel::ProofOfWork { confirmations: 6 },
            finality_depth: 6,
            deterministic_finality: false,
            proof_model: ProofModel::SpvMerkle,
            replay_protection: ReplayProtectionModel::UtxoSpentCheck,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::High,
            max_safe_reorg_depth: 6,
            supports_light_client_proofs: true,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: true,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        }
    }

    /// Create Ethereum chain capabilities (convenience method for backward compatibility)
    pub fn ethereum() -> Self {
        Self {
            state_model: StateModel::Account,
            finality_model: FinalityModel::FinalizedCheckpoint,
            finality_depth: 15,
            deterministic_finality: true,
            proof_model: ProofModel::MerklePatricia,
            replay_protection: ReplayProtectionModel::SmartContractNullifier,
            native_single_use_semantics: false,
            reorg_risk: ReorgRisk::Medium,
            max_safe_reorg_depth: 2,
            supports_light_client_proofs: true,
            supports_state_proofs: true,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: false,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        }
    }

    /// Create Celestia chain capabilities (convenience method for backward compatibility)
    pub fn celestia() -> Self {
        Self {
            state_model: StateModel::DataBlob,
            finality_model: FinalityModel::DataAvailabilityHeader,
            finality_depth: 100,
            deterministic_finality: true,
            proof_model: ProofModel::DaNamespace,
            replay_protection: ReplayProtectionModel::UtxoSpentCheck,
            native_single_use_semantics: false,
            reorg_risk: ReorgRisk::None,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: true,
            supports_zk_proofs: false,
            chain_role: ChainRole::DataAvailability,
        }
    }
}

/// Protocol-recommended minimum confirmation counts for each supported chain.
///
/// These are the protocol-recommended minimum confirmation counts for each
/// supported chain. Runtime policies SHOULD use these as defaults but may
/// override them for specific deployment requirements.
///
/// | Chain      | Confirmations | Rationale                          |
/// |------------|---------------|-------------------------------------|
/// | Bitcoin    | 6             | 6 confirmations for double-spend safety |
/// | Ethereum   | 15            | ~3 minutes at 12s block time       |
/// | Solana     | 32            | ~16 seconds at 400ms slot time     |
/// | Aptos      | 5             | Quick finality with BFT consensus  |
/// | Sui        | 15            | Similar to Ethereum                |
/// | Celestia   | 100           | DA chain, high finality threshold  |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityDepths {
    /// Bitcoin mainnet/testnet confirmations required
    pub bitcoin: u64,
    /// Ethereum mainnet/testnet confirmations required
    pub ethereum: u64,
    /// Solana mainnet/devnet confirmations required
    pub solana: u64,
    /// Aptos mainnet/testnet confirmations required
    pub aptos: u64,
    /// Sui mainnet/testnet confirmations required
    pub sui: u64,
    /// Celestia mainnet/testnet confirmations required
    pub celestia: u64,
}

impl FinalityDepths {
    /// Default finality depths for all supported chains.
    pub const fn defaults() -> Self {
        Self {
            bitcoin: 6,
            ethereum: 15,
            solana: 32,
            aptos: 5,
            sui: 15,
            celestia: 100,
        }
    }

    /// Get the finality depth for a chain by ID.
    pub fn for_chain(&self, chain_id: &str) -> Option<u64> {
        match chain_id {
            "bitcoin" => Some(self.bitcoin),
            "ethereum" => Some(self.ethereum),
            "solana" => Some(self.solana),
            "aptos" => Some(self.aptos),
            "sui" => Some(self.sui),
            "celestia" => Some(self.celestia),
            _ => None,
        }
    }

    /// Get the finality depth for a chain, falling back to a default.
    pub fn for_chain_or_default(&self, chain_id: &str, fallback: u64) -> u64 {
        self.for_chain(chain_id).unwrap_or(fallback)
    }

    /// Check if a chain has a configured finality depth.
    pub fn has_depth(&self, chain_id: &str) -> bool {
        self.for_chain(chain_id).is_some()
    }
}

impl Default for FinalityDepths {
    fn default() -> Self {
        Self::defaults()
    }
}

impl std::fmt::Display for FinalityDepths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FinalityDepths {{ bitcoin: {}, ethereum: {}, solana: {}, aptos: {}, sui: {}, celestia: {} }}",
            self.bitcoin, self.ethereum, self.solana, self.aptos, self.sui, self.celestia
        )
    }
}

// ============================================================================
// Legacy ChainCapability trait (for backward compatibility)
// ============================================================================

/// Chain capability trait - all chains must implement this.
///
/// **DEPRECATED**: Use ChainCapabilities struct instead.
/// This trait is kept for backward compatibility during migration.
pub trait ChainCapability: std::fmt::Debug {
    /// Get the chain ID.
    fn chain_id(&self) -> &str;

    /// Get the chain name.
    fn chain_name(&self) -> &str;

    /// Get the finality type for this chain.
    fn finality_type(&self) -> FinalityType;

    /// Get the required confirmations for this chain.
    fn required_confirmations(&self) -> u64;

    /// Check if the chain supports SPV proofs.
    fn supports_spv(&self) -> bool;

    /// Check if the chain supports contract calls.
    fn supports_contracts(&self) -> bool;

    /// Check if the chain supports tapret commitments.
    fn supports_tapret(&self) -> bool;

    /// Get the maximum proof size for this chain.
    fn max_proof_size(&self) -> usize;

    /// Get the maximum transaction size for this chain.
    fn max_tx_size(&self) -> usize;

    /// Get the block time for this chain.
    fn block_time(&self) -> u64;

    /// Check if the chain supports reorg detection.
    fn supports_reorg_detection(&self) -> bool;

    /// Get the capability set for this chain.
    fn capabilities(&self) -> CapabilitySet;
}

/// Finality type (legacy, for ChainCapability trait)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityType {
    /// Probabilistic finality (Bitcoin PoW)
    Probabilistic,
    /// Economic finality (Ethereum PoS)
    Economic,
    /// Quorum-based finality (Solana)
    Quorum,
    /// Checkpoint finality (Aptos, Sui)
    Checkpoint,
}

/// Capability set for a chain (legacy)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    /// Chain ID
    pub chain_id: String,
    /// Supported capabilities
    pub capabilities: Vec<Capability>,
}

impl CapabilitySet {
    /// Create a new capability set.
    pub fn new(chain_id: String, capabilities: Vec<Capability>) -> Self {
        Self {
            chain_id,
            capabilities,
        }
    }

    /// Check if a capability is supported.
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Add a capability.
    pub fn add_capability(&mut self, capability: Capability) {
        if !self.has_capability(capability) {
            self.capabilities.push(capability);
        }
    }

    /// Remove a capability.
    pub fn remove_capability(&mut self, capability: Capability) {
        self.capabilities.retain(|c| c != &capability);
    }
}

/// Individual capability flags (legacy)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// SPV proof support
    SpvProofs,

    /// Contract call support
    ContractCalls,

    /// Tapret commitment support
    TapretCommitments,

    /// Reorg detection
    ReorgDetection,

    /// State proofs
    StateProofs,

    /// Receipt proofs
    ReceiptProofs,

    /// Event indexing
    EventIndexing,

    /// Account abstraction
    AccountAbstraction,

    /// ZK proof verification
    ZkProofVerification,

    /// Cross-chain messaging
    CrossChainMessaging,
}

/// Chain capability registry for querying chain capabilities (legacy)
#[derive(Debug, Default)]
pub struct ChainCapabilityRegistry {
    /// Registered chain capabilities
    pub chains: std::collections::HashMap<String, Box<dyn ChainCapability>>,
}

impl ChainCapabilityRegistry {
    /// Create a new chain capability registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a chain capability.
    pub fn register(&mut self, capability: Box<dyn ChainCapability>) {
        self.chains
            .insert(capability.chain_id().to_string(), capability);
    }

    /// Get a chain capability by ID.
    pub fn get(&self, chain_id: &str) -> Option<&dyn ChainCapability> {
        self.chains
            .get(chain_id)
            .map(|capability| capability.as_ref())
    }

    /// Check if a chain supports a specific capability.
    pub fn supports_capability(&self, chain_id: &str, capability: Capability) -> bool {
        self.get(chain_id)
            .map(|c| c.capabilities().has_capability(capability))
            .unwrap_or(false)
    }

    /// Get all chains that support a specific capability.
    pub fn get_chains_with_capability(&self, capability: Capability) -> Vec<String> {
        self.chains
            .iter()
            .filter(|(_, c)| c.capabilities().has_capability(capability))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_source_plan_accepts_bitcoin() {
        let plan =
            ChainCapabilities::bitcoin().plan_for(&CapabilityRequirements::cross_chain_source());
        assert!(plan.ensure_satisfied().is_ok());
    }

    #[test]
    fn settlement_source_plan_rejects_da_only_chain() {
        let plan =
            ChainCapabilities::celestia().plan_for(&CapabilityRequirements::cross_chain_source());
        assert!(!plan.satisfied);
        assert!(plan.missing.contains(&"settlement_role".to_string()));
    }

    #[test]
    fn plan_reports_missing_zk_support() {
        let mut requirements = CapabilityRequirements::cross_chain_source();
        requirements.require_zk_proofs = true;

        let plan = ChainCapabilities::bitcoin().plan_for(&requirements);
        assert!(!plan.satisfied);
        assert!(plan.missing.contains(&"zk_proofs".to_string()));
    }
}
