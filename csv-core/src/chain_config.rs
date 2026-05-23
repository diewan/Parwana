//! Chain configuration system for dynamic chain loading.
//!
//! Security-relevant chain capabilities that drive transfer authorization logic.

#![allow(missing_docs)]

use crate::collections::HashMap;
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

/// Solana commitment grade - explicit distinction for finality stages.
/// Never collapse these into u64 confirmations - that is semantically wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolanaCommitmentGrade {
    /// Transaction processed but not confirmed
    Processed,
    /// Transaction confirmed by at least one leader
    Confirmed,
    /// Transaction finalized by cluster consensus
    Finalized,
}

/// Ethereum finality stage - explicit distinction for checkpoint progression.
/// Safe head, justified, and finalized are operationally different.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthereumFinalityStage {
    /// Unsafe head - latest block, may be reorged
    UnsafeHead,
    /// Safe head - block that is unlikely to be reorged
    SafeHead,
    /// Justified checkpoint - attested by 2/3 of validators
    Justified,
    /// Finalized checkpoint - cannot be reorged
    Finalized,
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
            _ => false,
        }
    }

    /// Bitcoin chain capabilities.
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

    /// Ethereum chain capabilities.
    pub fn ethereum() -> Self {
        Self {
            state_model: StateModel::Account,
            finality_model: FinalityModel::FinalizedCheckpoint,
            finality_depth: 2,
            deterministic_finality: true,
            proof_model: ProofModel::MerklePatricia,
            replay_protection: ReplayProtectionModel::SmartContractNullifier,
            native_single_use_semantics: false,
            reorg_risk: ReorgRisk::Medium,
            max_safe_reorg_depth: 12,
            supports_light_client_proofs: true,
            supports_state_proofs: true,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: true,
            supports_zk_proofs: true,
            chain_role: ChainRole::Settlement,
        }
    }

    /// Solana chain capabilities.
    pub fn solana() -> Self {
        Self {
            state_model: StateModel::Account,
            finality_model: FinalityModel::OptimisticWithSlotExpiry { slots: 32 },
            finality_depth: 32,
            deterministic_finality: false,
            proof_model: ProofModel::SlotConfirmation,
            replay_protection: ReplayProtectionModel::PdaClosed,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::Low,
            max_safe_reorg_depth: 32,
            supports_light_client_proofs: false,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: false,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        }
    }

    /// Aptos chain capabilities.
    pub fn aptos() -> Self {
        Self {
            state_model: StateModel::Resource,
            finality_model: FinalityModel::BftInstant,
            finality_depth: 1,
            deterministic_finality: true,
            proof_model: ProofModel::AccumulatorPath,
            replay_protection: ReplayProtectionModel::ResourceDeleted,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::Low,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: true,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: true,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        }
    }

    /// Sui chain capabilities.
    pub fn sui() -> Self {
        Self {
            state_model: StateModel::Object,
            finality_model: FinalityModel::BftInstant,
            finality_depth: 1,
            deterministic_finality: true,
            proof_model: ProofModel::CheckpointMerkle,
            replay_protection: ReplayProtectionModel::ObjectDeleted,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::Low,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: true,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: true,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        }
    }

    /// Celestia chain capabilities (DA only, not Settlement).
    pub fn celestia() -> Self {
        Self {
            state_model: StateModel::DataBlob,
            finality_model: FinalityModel::DataAvailabilityHeader,
            finality_depth: 1,
            deterministic_finality: true,
            proof_model: ProofModel::DaNamespace,
            replay_protection: ReplayProtectionModel::SmartContractNullifier,
            native_single_use_semantics: false,
            reorg_risk: ReorgRisk::None,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: false,
            supports_offline_verification: false,
            supports_zk_proofs: false,
            chain_role: ChainRole::DataAvailability,
        }
    }

    /// Returns true if this chain may authorize a mint operation.
    /// DA-only chains (Celestia) may never mint.
    pub fn can_authorize_mint(&self) -> bool {
        self.chain_role == ChainRole::Settlement
    }

    /// Returns true if a proof from this chain supports full offline verification.
    pub fn supports_offline(&self) -> bool {
        self.supports_offline_verification && self.supports_transaction_inclusion_proofs
    }
}

/// Chain-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Unique identifier for this chain
    pub chain_id: String,
    /// Human-readable name for this chain
    pub chain_name: String,
    /// Default network to use
    pub default_network: String,
    /// List of RPC endpoints
    pub rpc_endpoints: Vec<String>,
    /// CSV program ID for this chain
    pub program_id: Option<String>,
    /// Block explorer URLs
    pub block_explorer_urls: Vec<String>,
    /// Starting block for indexing (0 = genesis)
    #[serde(default = "default_start_block")]
    pub start_block: u64,
    /// Chain capabilities
    pub capabilities: ChainCapabilities,
    /// Chain-specific settings (legacy fields stored here for backward compatibility)
    #[serde(default)]
    pub custom_settings: HashMap<String, String>,
}

fn default_start_block() -> u64 {
    0
}

/// Trait for file system and environment operations.
///
/// This abstraction allows chain config loading to work in both `std` and
/// `no_std` environments. Implementations can be provided for real file
/// system access, in-memory mocks, or WASI.
pub trait FileSystem {
    /// Read all files in a directory, returning file paths and contents.
    fn read_dir_toml_files(&self, dir: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error + Send + Sync>>;
    
    /// Read a single file by path.
    fn read_file(&self, path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
    
    /// Check if a path exists.
    fn path_exists(&self, path: &str) -> bool;
}

/// Environment variable access trait.
pub trait EnvVars {
    /// Get an environment variable by name.
    fn get_var(&self, name: &str) -> Option<String>;
}

/// Default std-based file system implementation.
#[cfg(feature = "std")]
pub struct StdFileSystem;

#[cfg(feature = "std")]
impl FileSystem for StdFileSystem {
    fn read_dir_toml_files(&self, dir: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error + Send + Sync>> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension() == Some(std::ffi::OsStr::new("toml")))
            .collect();
        paths.sort();
        
        let mut result = Vec::new();
        for path in paths {
            let content = std::fs::read_to_string(&path)?;
            let name = path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            result.push((name, content));
        }
        Ok(result)
    }
    
    fn read_file(&self, path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(std::fs::read_to_string(path)?)
    }
    
    fn path_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
}

/// Default no-op environment variable implementation (returns None for all vars).
pub struct NoEnvVars;
impl EnvVars for NoEnvVars {
    fn get_var(&self, _name: &str) -> Option<String> {
        None
    }
}

/// Std-based environment variable implementation.
#[cfg(feature = "std")]
pub struct StdEnvVars;

#[cfg(feature = "std")]
impl EnvVars for StdEnvVars {
    fn get_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Configuration loader for dynamic chain discovery.
///
/// Uses trait-based abstractions for file system and environment access
/// to support both `std` and `no_std` environments.
pub struct ChainConfigLoader<F: FileSystem, E: EnvVars> {
    configs: HashMap<String, ChainConfig>,
    fs: F,
    env: E,
}

impl Default for ChainConfigLoader<StdFileSystem, StdEnvVars> {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainConfigLoader<StdFileSystem, StdEnvVars> {
    /// Create new loader with default std implementations.
    pub fn new() -> Self {
        Self::with_fs_env(StdFileSystem, StdEnvVars)
    }
}

impl<F: FileSystem, E: EnvVars> ChainConfigLoader<F, E> {
    /// Create new loader with custom file system and environment implementations.
    pub fn with_fs_env(fs: F, env: E) -> Self {
        Self {
            configs: HashMap::new(),
            fs,
            env,
        }
    }

    /// Load all chain configurations from directory.
    /// Invalid configs are skipped with a warning rather than failing the entire operation.
    pub fn load_from_directory(
        &mut self,
        config_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let files = self.fs.read_dir_toml_files(config_dir)?;
        
        for (name, content) in files {
            self.load_content(&name, &content)?;
        }

        Ok(())
    }

    /// Load a single chain configuration from TOML content.
    fn load_content(
        &mut self,
        name: &str,
        content: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match toml::from_str::<ChainConfig>(content) {
            Ok(config) => {
                let chain_id = config.chain_id.clone();
                self.configs.insert(chain_id.clone(), config);
                println!("Loaded chain config: {} (from {})", chain_id, name);
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse {}: {}", name, e);
            }
        }

        Ok(())
    }

    /// Load chain configurations from the default search locations.
    ///
    /// Search order:
    /// 1. `CSV_CHAIN_CONFIG_DIR` environment variable
    /// 2. `chains` directory
    pub fn load_from_default_locations(
        &mut self,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut candidates = Vec::new();

        if let Some(path) = self.env.get_var("CSV_CHAIN_CONFIG_DIR") {
            candidates.push(path);
        }
        candidates.push("chains".to_string());

        for candidate in candidates {
            if self.fs.path_exists(&candidate) {
                self.load_from_directory(&candidate)?;
                return Ok(Some(candidate));
            }
        }

        Ok(None)
    }

    /// Insert or replace a configuration programmatically.
    pub fn insert_config(&mut self, config: ChainConfig) {
        self.configs.insert(config.chain_id.clone(), config);
    }

    /// Get configuration for specific chain
    pub fn get_config(&self, chain_id: &str) -> Option<&ChainConfig> {
        self.configs.get(chain_id)
    }

    /// Get all loaded configurations
    pub fn all_configs(&self) -> &HashMap<String, ChainConfig> {
        &self.configs
    }

    /// Get all supported chain IDs
    pub fn supported_chain_ids(&self) -> Vec<String> {
        self.configs.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_config_loader() {
        let mut loader = ChainConfigLoader::new();

        let config = ChainConfig {
            chain_id: "test-chain".to_string(),
            chain_name: "Test Chain".to_string(),
            default_network: "testnet".to_string(),
            rpc_endpoints: vec!["https://test-rpc.example.com".to_string()],
            program_id: Some("TestProgram11111111111111111111111111111".to_string()),
            block_explorer_urls: vec!["https://test-explorer.example.com".to_string()],
            start_block: 0,
            capabilities: ChainCapabilities::bitcoin(),
            custom_settings: HashMap::new(),
        };

        loader.configs.insert("test-chain".to_string(), config);

        let retrieved = loader.get_config("test-chain");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().chain_id, "test-chain");
    }

    #[test]
    fn test_bitcoin_capabilities() {
        let caps = ChainCapabilities::bitcoin();
        assert_eq!(caps.state_model, StateModel::Utxo);
        assert_eq!(caps.finality_depth, 6);
        assert!(!caps.deterministic_finality);
        assert!(caps.native_single_use_semantics);
        assert!(caps.can_authorize_mint());
        assert!(caps.supports_offline());
    }

    #[test]
    fn test_ethereum_capabilities() {
        let caps = ChainCapabilities::ethereum();
        assert_eq!(caps.state_model, StateModel::Account);
        assert!(caps.deterministic_finality);
        assert!(!caps.native_single_use_semantics);
        assert!(caps.supports_zk_proofs);
        assert!(caps.can_authorize_mint());
    }

    #[test]
    fn test_celestia_da_only() {
        let caps = ChainCapabilities::celestia();
        assert_eq!(caps.chain_role, ChainRole::DataAvailability);
        assert!(!caps.can_authorize_mint());
        assert_eq!(caps.state_model, StateModel::DataBlob);
    }

    #[test]
    fn test_solana_capabilities() {
        let caps = ChainCapabilities::solana();
        assert_eq!(
            caps.finality_model,
            FinalityModel::OptimisticWithSlotExpiry { slots: 32 }
        );
        assert_eq!(caps.finality_depth, 32);
        assert!(!caps.deterministic_finality);
        assert!(!caps.supports_light_client_proofs);
    }

    #[test]
    fn test_aptos_capabilities() {
        let caps = ChainCapabilities::aptos();
        assert_eq!(caps.state_model, StateModel::Resource);
        assert_eq!(caps.finality_model, FinalityModel::BftInstant);
        assert!(caps.deterministic_finality);
        assert!(caps.native_single_use_semantics);
    }

    #[test]
    fn test_sui_capabilities() {
        let caps = ChainCapabilities::sui();
        assert_eq!(caps.state_model, StateModel::Object);
        assert_eq!(caps.finality_model, FinalityModel::BftInstant);
        assert!(caps.deterministic_finality);
        assert_eq!(caps.proof_model, ProofModel::CheckpointMerkle);
    }

    #[test]
    fn test_inclusion_thresholds() {
        let btc = ChainCapabilities::bitcoin();
        assert!(btc.inclusion_threshold_met(&InclusionStrength::MerklePath));
        assert!(btc
            .inclusion_threshold_met(&InclusionStrength::AnchoredMerklePath));
        assert!(!btc.inclusion_threshold_met(&InclusionStrength::None));
        assert!(!btc.inclusion_threshold_met(&InclusionStrength::Checksum));

        let sol = ChainCapabilities::solana();
        // Solana: SlotConfirmation accepts Checksum and MerklePath
        assert!(sol.inclusion_threshold_met(&InclusionStrength::Checksum));
        assert!(sol.inclusion_threshold_met(&InclusionStrength::MerklePath));
        assert!(!sol.inclusion_threshold_met(&InclusionStrength::None));
    }

    #[test]
    fn test_finality_thresholds() {
        let btc = ChainCapabilities::bitcoin();
        // Bitcoin needs 6 confirmations
        assert!(btc.finality_threshold_met(&FinalityStrength::Probabilistic {
            confirmations: 6
        }));
        assert!(btc.finality_threshold_met(&FinalityStrength::Probabilistic {
            confirmations: 10
        }));
        assert!(!btc.finality_threshold_met(&FinalityStrength::Probabilistic {
            confirmations: 5
        }));
        assert!(btc.finality_threshold_met(&FinalityStrength::Deterministic));
        assert!(!btc.finality_threshold_met(&FinalityStrength::None));

        let eth = ChainCapabilities::ethereum();
        // Ethereum: FinalizedCheckpoint accepts Deterministic
        assert!(eth.finality_threshold_met(&FinalityStrength::Deterministic));
        assert!(!eth.finality_threshold_met(&FinalityStrength::None));

        let apt = ChainCapabilities::aptos();
        // Aptos: BftInstant accepts Deterministic
        assert!(apt.finality_threshold_met(&FinalityStrength::Deterministic));
    }
}
