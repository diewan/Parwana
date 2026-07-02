//! Configuration management for the CSV Adapter.
//!
//! Provides a serializable [`Config`] struct that can be loaded from a TOML
//! file (`~/.csv/config.toml`) with environment variable overrides.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use csv_hash::chain_id::ChainId;

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use dirs;

/// Network identifier for chain endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Production network (real value).
    Mainnet,
    /// Public test network (test value).
    Testnet,
    /// Developer sandbox network (dev value).
    Devnet,
    /// Local isolated network (local value).
    Regtest,
}

impl Network {
    /// Returns `true` if this is a production network.
    pub fn is_mainnet(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// Returns `true` if this is a test or development network.
    pub fn is_testnet(&self) -> bool {
        !self.is_mainnet()
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Devnet => write!(f, "devnet"),
            Self::Regtest => write!(f, "regtest"),
        }
    }
}

/// RPC configuration for a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// RPC endpoint URL.
    pub url: String,
    /// REST/esplora indexer base URL for Bitcoin address scanning. `None` falls
    /// back to `url` when that is itself a REST endpoint.
    #[serde(default)]
    pub indexer_url: Option<String>,
    /// Explicit indexer transport for Bitcoin scanning: `"esplora"` or
    /// `"blockbook"` (Alchemy UTXO API). Selected explicitly, never sniffed.
    #[serde(default)]
    pub indexer_backend: Option<String>,
    /// API key (if required by the provider).
    pub api_key: Option<String>,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of retries for transient failures.
    pub max_retries: u32,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            indexer_url: None,
            indexer_backend: None,
            api_key: None,
            timeout_ms: 30_000,
            max_retries: 3,
        }
    }
}

/// Per-chain configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// RPC endpoint configuration.
    pub rpc: RpcConfig,
    /// Required confirmation depth for finality.
    pub finality_depth: u32,
    /// Whether this chain is enabled.
    pub enabled: bool,
    /// Extended public key for HD wallet derivation (Bitcoin xpub).
    /// Used to derive addresses and watch for transactions without spending.
    pub xpub: Option<String>,
    /// BIP-39 seed for HD wallet derivation (64 bytes, 128 hex chars).
    /// Used for Bitcoin wallet creation when xpub is not available.
    /// Takes precedence over xpub for wallet creation if provided.
    pub seed: Option<String>,
    /// Deployed seal or mint contract/package address required for mutation.
    pub contract_address: Option<String>,
    /// Deployed program identifier for program-based chains.
    pub program_id: Option<String>,
    /// Account index for HD wallet derivation (Bitcoin only, default: 0)
    pub account: u32,
    /// Address index for HD wallet derivation (Bitcoin only, default: 0)
    pub index: u32,
    /// Pre-loaded UTXOs for Bitcoin wallet (for persistence across commands)
    pub utxos: Vec<UtxoConfig>,
    /// Pre-loaded sanad_id -> seal mappings for Bitcoin cross-chain lock lookups
    pub sanad_seals: Vec<SanadSealConfig>,
}

/// UTXO configuration for Bitcoin wallet (for SDK config)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoConfig {
    /// Transaction ID (hex)
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: u64,
    /// Account index
    pub account: u32,
    /// Address index
    pub index: u32,
    /// ScriptPubKey (hex) from blockchain for correct sighash calculation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_pubkey: Option<String>,
}

/// Sanad seal configuration for Bitcoin cross-chain lock lookups (for SDK config)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanadSealConfig {
    /// Sanad ID (hex)
    pub sanad_id: String,
    /// Anchor transaction ID (hex)
    pub anchor_txid: String,
    /// Output index of the commitment in the anchor transaction
    pub vout: u32,
    /// Tapret commitment (hex) embedded in the seal output's Taproot leaf.
    /// Needed to reconstruct the key-path tweak when the seal is spent (lock).
    #[serde(default)]
    pub commitment: Option<String>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            rpc: RpcConfig::default(),
            finality_depth: 6,
            enabled: false,
            xpub: None,
            seed: None,
            contract_address: None,
            program_id: None,
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        }
    }
}

/// Store backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
#[derive(Default)]
pub enum StoreConfig {
    /// In-memory store (non-persistent, for testing).
    #[default]
    InMemory,
    /// SQLite file-backed store.
    Sqlite {
        /// Path to the SQLite database file.
        path: String,
    },
}

/// Top-level CSV Adapter configuration.
///
/// Can be loaded from a TOML file or constructed programmatically.
/// Environment variables prefixed with `CSV_` override file values.
///
/// # Example TOML (`~/.csv/config.toml`)
///
/// ```toml
/// network = "testnet"
///
/// [chains.bitcoin]
/// enabled = true
/// finality_depth = 6
/// [chains.bitcoin.rpc]
/// url = "https://mempool.space/api"
/// timeout_ms = 30000
///
/// [chains.ethereum]
/// enabled = true
/// finality_depth = 12
/// [chains.ethereum.rpc]
/// url = "https://eth.llamarpc.com"
///
/// [store]
/// backend = "sqlite"
/// path = "~/.csv/data.db"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Global network setting.
    pub network: Network,
    /// Per-chain configurations.
    pub chains: HashMap<String, ChainConfig>,
    /// Store backend configuration.
    pub store: StoreConfig,
    /// Log level (e.g., "info", "debug", "warn").
    pub log_level: Option<String>,
    /// Data directory override.
    pub data_dir: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let mut chains = HashMap::new();
        chains.insert("bitcoin".to_string(), ChainConfig::default());
        chains.insert("ethereum".to_string(), ChainConfig::default());
        chains.insert("sui".to_string(), ChainConfig::default());
        chains.insert("aptos".to_string(), ChainConfig::default());

        Self {
            network: Network::Testnet,
            chains,
            store: StoreConfig::default(),
            log_level: Some("info".to_string()),
            data_dir: None,
        }
    }
}

impl Config {
    /// Default configuration file path: `~/.csv/config.toml`.
    ///
    /// Returns `~/.csv/config.toml` on native targets.
    /// On wasm32, returns `/.csv/config.toml` (browser storage path).
    pub fn default_path() -> PathBuf {
        #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
        {
            let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push(".csv");
            path.push("config.toml");
            path
        }
        #[cfg(all(not(target_arch = "wasm32"), not(feature = "native")))]
        {
            PathBuf::from("./.csv/config.toml")
        }
        #[cfg(target_arch = "wasm32")]
        {
            PathBuf::from("/.csv/config.toml")
        }
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: &PathBuf) -> Result<Self, crate::CsvError> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Load from the default path, falling back to defaults if the file
    /// does not exist.
    pub fn load() -> Self {
        let path = Self::default_path();
        Self::from_file(&path).unwrap_or_else(|_| {
            let mut config = Self::default();
            config.apply_env_overrides();
            config
        })
    }

    /// Apply environment variable overrides.
    ///
    /// Environment variables follow the pattern `CSV_<SECTION>_<KEY>`:
    /// - `CSV_NETWORK` — override the global network
    /// - `CSV_BITCOIN_RPC_URL` — override Bitcoin RPC URL
    /// - `CSV_ETHEREUM_RPC_URL` — override Ethereum RPC URL
    /// - `CSV_SUI_RPC_URL` — override Sui RPC URL
    /// - `CSV_APTOS_RPC_URL` — override Aptos RPC URL
    /// - `CSV_STORE_BACKEND` — override store backend ("sqlite" or "in-memory")
    /// - `CSV_STORE_PATH` — override SQLite path
    fn apply_env_overrides(&mut self) {
        // Network override
        if let Ok(val) = std::env::var("CSV_NETWORK") {
            self.network = match val.to_lowercase().as_str() {
                "mainnet" => Network::Mainnet,
                "testnet" => Network::Testnet,
                "devnet" => Network::Devnet,
                "regtest" => Network::Regtest,
                _ => self.network,
            };
        }

        // Per-chain RPC overrides
        for (name, chain_cfg) in self.chains.iter_mut() {
            let env_key = format!("CSV_{}_RPC_URL", name.to_uppercase());
            if let Ok(url) = std::env::var(&env_key) {
                chain_cfg.rpc.url = url;
                chain_cfg.enabled = true;
            }
        }

        // Store backend override
        if let Ok(backend) = std::env::var("CSV_STORE_BACKEND") {
            match backend.to_lowercase().as_str() {
                "sqlite" => {
                    let path = std::env::var("CSV_STORE_PATH")
                        .unwrap_or_else(|_| "~/.csv/data.db".to_string());
                    self.store = StoreConfig::Sqlite { path };
                }
                _ => {
                    self.store = StoreConfig::InMemory;
                }
            }
        }
    }

    /// Get the RPC configuration for a specific chain.
    pub fn rpc_for(&self, chain: ChainId) -> Option<&RpcConfig> {
        let name = chain.to_string();
        self.chains.get(&name).map(|c| &c.rpc)
    }

    /// Check if a chain is enabled in the configuration.
    pub fn is_chain_enabled(&self, chain: ChainId) -> bool {
        let name = chain.to_string();
        self.chains.get(&name).map(|c| c.enabled).unwrap_or(false)
    }

    /// Set the RPC URL for a specific chain.
    pub fn with_rpc_url(mut self, chain: ChainId, url: impl Into<String>) -> Self {
        let name = chain.to_string();
        let entry = self.chains.entry(name).or_default();
        entry.rpc.url = url.into();
        entry.enabled = true;
        self
    }
}
