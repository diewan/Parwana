//! Chain capability model
//!
//! Defines the capabilities that chains must expose.
//! This prevents semantic flattening and allows chains to declare what they can do.

use crate::verified::{FinalityStrength, InclusionStrength};
use serde::{Deserialize, Serialize};

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

impl ChainCapabilities {
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
                FinalityModel::FinalizedCheckpoint | FinalityModel::BftInstant | FinalityModel::DataAvailabilityHeader,
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
