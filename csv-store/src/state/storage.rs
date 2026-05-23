//! Main state storage container.
//!
//! This module defines `StateStorage` (formerly `UnifiedStorage`),
//! the central data structure for CSV application state.

use super::core::ChainId;
use super::core::{ChainConfig, Network};
use super::domain::{
    ContractRecord, ProofRecord, SanadRecord, SealRecord, TransactionRecord, TransferRecord,
};
use super::wallet::{FaucetConfig, GasAccount};
use super::wallet::{WalletAccount, WalletConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Version of the state format.
pub const STATE_VERSION: u32 = 1;

/// Default data directory path.
fn default_data_dir() -> String {
    "~/.csv/data".to_string()
}

/// Main application state storage.
///
/// This struct holds all non-sensitive application state. Private keys
/// are **never** stored here - they are referenced via `keystore_ref` fields
/// and stored in `csv-adapter-keystore`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateStorage {
    /// Version for migration compatibility.
    pub version: u32,

    /// Chain configurations (RPC endpoints, etc.).
    #[serde(default)]
    pub chains: HashMap<ChainId, ChainConfig>,

    /// Wallet configuration with accounts.
    #[serde(default)]
    pub wallet: WalletConfig,

    /// Faucet configurations (mainly for CLI testnet usage).
    #[serde(default)]
    pub faucets: HashMap<ChainId, FaucetConfig>,

    /// Tracked sanads (both CLI and Wallet).
    #[serde(default)]
    pub sanads: Vec<SanadRecord>,

    /// Tracked transfers (both CLI and Wallet).
    #[serde(default)]
    pub transfers: Vec<TransferRecord>,

    /// Deployed contracts (both CLI and Wallet).
    #[serde(default)]
    pub contracts: Vec<ContractRecord>,

    /// Seal records (both CLI and Wallet).
    #[serde(default)]
    pub seals: Vec<SealRecord>,

    /// Proof records (both CLI and Wallet).
    #[serde(default)]
    pub proofs: Vec<ProofRecord>,

    /// Transaction history (mainly Wallet).
    #[serde(default)]
    pub transactions: Vec<TransactionRecord>,

    /// Gas accounts per chain (CLI).
    #[serde(default)]
    pub gas_accounts: Vec<GasAccount>,

    /// Selected chain (UI state - mainly Wallet).
    #[serde(default)]
    pub selected_chain: Option<ChainId>,

    /// Selected network (UI state - mainly Wallet).
    #[serde(default)]
    pub selected_network: Option<Network>,

    /// Whether wallet has been initialized.
    #[serde(default)]
    pub initialized: bool,

    /// Data directory path (CLI only, for file-based storage).
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

impl StateStorage {
    /// Create new empty storage with current version.
    pub fn new() -> Self {
        Self {
            version: STATE_VERSION,
            ..Default::default()
        }
    }

    /// Initialize with defaults (chains, faucets, selected network).
    pub fn with_defaults(mut self) -> Self {
        self.chains = Self::default_chains();
        self.faucets = Self::default_faucets();
        self.selected_chain = Some(csv_core::builtin::BITCOIN.clone());
        self.selected_network = Some(Network::Test);
        self
    }

    /// Get default chain configurations.
    fn default_chains() -> HashMap<ChainId, ChainConfig> {
        let mut chains = HashMap::new();

        for chain in [
            csv_core::builtin::BITCOIN.clone(),
            csv_core::builtin::ETHEREUM.clone(),
            csv_core::builtin::SUI.clone(),
            csv_core::builtin::APTOS.clone(),
            csv_core::builtin::SOLANA.clone(),
        ] {
            chains.insert(
                chain.clone(),
                ChainConfig::default_for(&chain, &Network::Test),
            );
        }

        chains
    }

    /// Get default faucet configurations.
    fn default_faucets() -> HashMap<ChainId, FaucetConfig> {
        let mut faucets = HashMap::new();

        for chain in [
            csv_core::builtin::BITCOIN.clone(),
            csv_core::builtin::ETHEREUM.clone(),
            csv_core::builtin::SUI.clone(),
            csv_core::builtin::APTOS.clone(),
            csv_core::builtin::SOLANA.clone(),
        ] {
            if let Some(config) = FaucetConfig::default_for(&chain, &Network::Test) {
                faucets.insert(chain, config);
            }
        }

        faucets
    }

    // ===== Sanad operations =====

    /// Find a sanad by ID.
    pub fn get_sanad(&self, id: &str) -> Option<&SanadRecord> {
        self.sanads.iter().find(|r| r.id == id)
    }

    /// Find a sanad by ID (mutable).
    pub fn get_sanad_mut(&mut self, id: &str) -> Option<&mut SanadRecord> {
        self.sanads.iter_mut().find(|r| r.id == id)
    }

    /// Add a sanad.
    pub fn add_sanad(&mut self, sanad: SanadRecord) {
        self.sanads.push(sanad);
    }

    // ===== Transfer operations =====

    /// Find a transfer by ID.
    pub fn get_transfer(&self, id: &str) -> Option<&TransferRecord> {
        self.transfers.iter().find(|t| t.id == id)
    }

    /// Add a transfer.
    pub fn add_transfer(&mut self, transfer: TransferRecord) {
        self.transfers.push(transfer);
    }

    // ===== Contract operations =====

    /// Get contracts for a chain.
    pub fn get_contracts(&self, chain: &ChainId) -> Vec<&ContractRecord> {
        self.contracts
            .iter()
            .filter(|c| &c.chain == chain)
            .collect()
    }

    /// Add a contract.
    pub fn add_contract(&mut self, contract: ContractRecord) {
        self.contracts.push(contract);
    }

    // ===== Wallet/Account operations =====

    /// Get account for a chain.
    pub fn get_account(&self, chain: &ChainId) -> Option<&WalletAccount> {
        self.wallet.get_account(chain)
    }

    /// Add or update account.
    pub fn set_account(&mut self, account: WalletAccount) {
        self.wallet.add_account(account);
    }

    /// Get address for a chain.
    pub fn get_address(&self, chain: &ChainId) -> Option<&str> {
        self.get_account(chain).map(|a| a.address.as_str())
    }

    /// Store address for a chain.
    pub fn store_address(&mut self, chain: ChainId, address: String) {
        let account = WalletAccount::new(
            format!("{}_{}", chain, address),
            chain.clone(),
            format!("{:?} Account", chain),
            address,
        );
        self.set_account(account);
    }

    /// Store address with derivation path.
    pub fn store_address_with_derivation(
        &mut self,
        chain: ChainId,
        address: String,
        derivation_path: Option<String>,
    ) {
        let mut account = WalletAccount::new(
            format!("{}_{}", chain, address),
            chain.clone(),
            format!("{:?} Account", chain),
            address,
        );
        if let Some(path) = derivation_path {
            account = account.with_derivation_path(path);
        }
        self.set_account(account);
    }

    // ===== Gas account operations =====

    /// Get gas account for a chain.
    pub fn get_gas_account(&self, chain: &ChainId) -> Option<&str> {
        self.gas_accounts
            .iter()
            .find(|g| &g.chain == chain)
            .map(|g| g.address.as_str())
            .or_else(|| self.get_address(chain))
    }
}
