//! CLI configuration management

#![allow(dead_code)]
#![allow(deprecated)]

// Configuration management — chains, wallets, RPC endpoints
// Uses unified storage types from csv-store for compatibility with csv-wallet.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

// Re-export unified types from csv-store
pub use csv_store::state::{Chain, ChainConfig, ChainId, Network, WalletAccount};

// Import deployment manifest reader
use csv_protocol::deployment_manifest::{
    get_aptos_contract_address, get_ethereum_contract_address, get_solana_program_id,
    get_sui_package_id,
};

/// CSV Wallet exported JSON format (legacy, for migration from csv-wallet < 0.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsvWalletData {
    accounts: Vec<CsvAccount>,
    selected_account_id: Option<String>,
}

/// CSV Wallet account entry (legacy format)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsvAccount {
    id: String,
    chain: String,
    name: String,
    private_key: String,
    address: String,
}

impl CsvWalletData {
    /// Load from csv-wallet JSON file (legacy format)
    fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let data: CsvWalletData = serde_json::from_str(&content)?;
        Ok(data)
    }

    /// Find account by chain name (case-insensitive)
    fn find_account(&self, chain: &str) -> Option<&CsvAccount> {
        self.accounts
            .iter()
            .find(|a| a.chain.eq_ignore_ascii_case(chain))
    }
}

/// Global cache for csv-wallet configs loaded at runtime
static CSV_WALLET_CACHE: OnceLock<Mutex<HashMap<Chain, LegacyWalletConfig>>> = OnceLock::new();

fn get_csv_wallet_cache() -> &'static Mutex<HashMap<Chain, LegacyWalletConfig>> {
    CSV_WALLET_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Legacy wallet config for backwards compatibility (maps to unified WalletAccount)
#[derive(Debug, Clone)]
pub(crate) struct LegacyWalletConfig {
    /// Private key (raw string for TOML deserialization only - converted to SecretHandle immediately)
    pub private_key: Option<String>,
    pub xpub: Option<String>,
    pub mnemonic: Option<String>,
    pub mnemonic_passphrase: Option<String>,
    pub derivation_path: Option<String>,
}

impl LegacyWalletConfig {
    /// Convert private_key String to typed SecretHandle (zeroize-on-drop)
    /// This should be called immediately after deserialization to ensure secrets are never exposed as raw strings
    pub fn to_secret_handle(&self, chain: &str) -> Option<csv_wallet::SecretHandle> {
        self.private_key.as_ref().map(|pk| {
            let bytes = hex::decode(pk).unwrap_or_else(|_| pk.as_bytes().to_vec());
            let key_array: [u8; 32] = if bytes.len() >= 32 {
                bytes[..32].try_into().unwrap_or([0u8; 32])
            } else {
                let mut arr = [0u8; 32];
                let len = bytes.len().min(32);
                arr[..len].copy_from_slice(&bytes[..len]);
                arr
            };
            let secret_key = csv_keys::memory::SecretKey::new(key_array);
            csv_wallet::SecretHandle::from_key(secret_key)
        })
    }
}

/// Parse chain from string (for clap)
pub fn parse_chain(s: &str) -> anyhow::Result<Chain> {
    match s.to_lowercase().as_str() {
        "bitcoin" => Ok(ChainId::new("bitcoin")),
        "ethereum" => Ok(ChainId::new("ethereum")),
        "sui" => Ok(ChainId::new("sui")),
        "aptos" => Ok(ChainId::new("aptos")),
        "solana" => Ok(ChainId::new("solana")),
        _ => Err(anyhow::anyhow!("Unknown chain: {}", s)),
    }
}

/// Parse network from string (for clap)
pub fn parse_network(s: &str) -> anyhow::Result<Network> {
    match s.to_lowercase().as_str() {
        "dev" => Ok(Network::Dev),
        "test" => Ok(Network::Test),
        "main" => Ok(Network::Main),
        _ => Err(anyhow::anyhow!("Unknown network: {}", s)),
    }
}

/// Full CLI configuration using unified storage types
///
/// Note: New code should use UnifiedStorage from csv_store::state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Chain configurations
    #[serde(default)]
    pub chains: HashMap<Chain, ChainConfig>,
    /// Legacy wallet configurations (per chain) - migrated to unified.accounts
    #[serde(default)]
    pub wallets: HashMap<Chain, LegacyWalletConfigToml>,
    /// Data directory for state persistence
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
}

/// Legacy wallet config for TOML parsing (will be migrated to unified WalletAccount)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyWalletConfigToml {
    pub private_key: Option<String>,
    pub xpub: Option<String>,
    pub mnemonic: Option<String>,
    pub mnemonic_passphrase: Option<String>,
    pub derivation_path: Option<String>,
}

impl From<LegacyWalletConfigToml> for LegacyWalletConfig {
    fn from(cfg: LegacyWalletConfigToml) -> Self {
        Self {
            private_key: cfg.private_key,
            xpub: cfg.xpub,
            mnemonic: cfg.mnemonic,
            mnemonic_passphrase: cfg.mnemonic_passphrase,
            derivation_path: cfg.derivation_path,
        }
    }
}

fn default_data_dir() -> String {
    "~/.csv/data".to_string()
}

impl Default for Config {
    fn default() -> Self {
        let mut chains = HashMap::new();

        // Bitcoin Signet (default dev network) - use environment variable if available
        // Checks environment variables in priority order:
        // 1. BITCOIN_RPC_URL (generic)
        // 2. BITCOIN_ALCHEMY_SIGNET_HTTP_RPC (Alchemy)
        // 3. BITCOIN_ANKR_SIGNET_HTTP_RPC (Ankr)
        // 4. BITCOIN_TATUM_SIGNET_JSON_RPC (Tatum JSON-RPC)
        // 5. BITCOIN_TATUM_SIGNET_REST_RPC (Tatum REST)
        let bitcoin_rpc = std::env::var("BITCOIN_RPC_URL")
            .or_else(|_| std::env::var("BITCOIN_ALCHEMY_SIGNET_HTTP_RPC"))
            .or_else(|_| std::env::var("BITCOIN_ANKR_SIGNET_HTTP_RPC"))
            .or_else(|_| std::env::var("BITCOIN_TATUM_SIGNET_JSON_RPC"))
            .or_else(|_| std::env::var("BITCOIN_TATUM_SIGNET_REST_RPC"))
            .unwrap_or_else(|_| "https://mempool.space/signet/api".to_string());

        chains.insert(
            ChainId::new("bitcoin"),
            ChainConfig {
                rpc_url: bitcoin_rpc,
                network: Network::Test,
                contract_address: None, // UTXO-native, no contract
                chain_id: None,
                finality_depth: 6,
                default_fee: Some(10), // 10 sat/vB
                program_id: None,
            },
        );

        // Ethereum Sepolia
        let ethereum_contract_address = get_ethereum_contract_address().ok();
        chains.insert(
            ChainId::new("ethereum"),
            ChainConfig {
                rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
                network: Network::Test,
                contract_address: ethereum_contract_address,
                chain_id: Some(11155111),
                finality_depth: 15,
                default_fee: Some(20_000_000_000), // 20 gwei
                program_id: None,
            },
        );

        // Sui Testnet
        let sui_package_id = get_sui_package_id().unwrap_or_else(|_| {
            "0x3eba46bb91c08182e426bd5d3e51b5671d3529057d7846521013ebb15353ff21".to_string()
        });
        chains.insert(
            ChainId::new("sui"),
            ChainConfig {
                rpc_url: "https://fullnode.testnet.sui.io:443".to_string(),
                network: Network::Test,
                contract_address: Some(sui_package_id),
                chain_id: None,
                finality_depth: 1, // Checkpoint certified
                default_fee: Some(1000),
                program_id: None,
            },
        );

        // Aptos Testnet
        let aptos_contract_address = get_aptos_contract_address().unwrap_or_else(|_| {
            "0x9d4c8ad9b8f58c73c73327833a4bda650c590091f130b2ec1293f086cf02ed50".to_string()
        });
        chains.insert(
            ChainId::new("aptos"),
            ChainConfig {
                rpc_url: "https://fullnode.testnet.aptoslabs.com/v1".to_string(),
                network: Network::Test,
                contract_address: Some(aptos_contract_address),
                chain_id: None,
                finality_depth: 1, // HotStuff consensus
                default_fee: Some(100),
                program_id: None,
            },
        );

        // Solana Devnet
        let solana_program_id = get_solana_program_id()
            .unwrap_or_else(|_| "HdxSFwzk2v6JMm3w55MW1EuMeNcM9gTC4ETFMKqYyy6m".to_string());
        chains.insert(
            ChainId::new("solana"),
            ChainConfig {
                rpc_url: "https://api.devnet.solana.com".to_string(),
                network: Network::Test,
                contract_address: None, // Not deployed yet
                chain_id: None,
                finality_depth: 32,      // Solana finality
                default_fee: Some(5000), // 5000 lamports
                program_id: Some(solana_program_id),
            },
        );

        let wallets = HashMap::new();

        Self {
            chains,
            wallets,
            data_dir: "~/.csv/data".to_string(),
        }
    }
}

#[allow(dead_code)]
impl Config {
    /// Get default network
    pub fn network(&self) -> Network {
        Network::Dev
    }

    /// Load configuration from file or return defaults
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        let path = match path {
            Some(p) => expand_path(p),
            None => expand_path("~/.csv/config.toml"),
        };

        if Path::new(&path).exists() {
            let content = std::fs::read_to_string(&path)?;
            let mut config: Config = toml::from_str(&content)?;

            // Merge missing chains and fields from defaults
            let defaults = Config::default();
            let mut changed = false;
            for (chain, default_chain_config) in &defaults.chains {
                if let Some(existing_chain_config) = config.chains.get_mut(chain) {
                    // Merge missing fields from defaults
                    if existing_chain_config.program_id.is_none() {
                        existing_chain_config.program_id = default_chain_config.program_id.clone();
                        changed = true;
                    }
                    if existing_chain_config.contract_address.is_none() {
                        existing_chain_config.contract_address =
                            default_chain_config.contract_address.clone();
                        changed = true;
                    }
                } else {
                    config
                        .chains
                        .insert(chain.clone(), default_chain_config.clone());
                    changed = true;
                }
            }

            for chain_name in ["sui", "aptos"] {
                let chain = ChainId::new(chain_name);
                let invalid = config
                    .chains
                    .get(&chain)
                    .and_then(|chain_config| chain_config.contract_address.as_deref())
                    .is_some_and(|address| !is_hex_address_len(address, 32));
                if invalid {
                    let replacement = defaults
                        .chains
                        .get(&chain)
                        .and_then(|chain_config| chain_config.contract_address.clone())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "No canonical {} deployment address is available",
                                chain_name
                            )
                        })?;
                    let chain_config = config.chains.get_mut(&chain).ok_or_else(|| {
                        anyhow::anyhow!("{} chain disappeared during config migration", chain_name)
                    })?;
                    eprintln!(
                        "Migrating invalid {} contract address to canonical deployment: {}",
                        chain_name, replacement
                    );
                    chain_config.contract_address = Some(replacement);
                    changed = true;
                }
            }

            if changed {
                let toml_content = toml::to_string_pretty(&config)?;
                std::fs::write(&path, toml_content)?;
            }

            Ok(config)
        } else {
            // Create default config
            let config = Config::default();
            // Ensure directory exists
            if let Some(parent) = Path::new(&path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Write default config
            let toml_content = toml::to_string_pretty(&config)?;
            std::fs::write(&path, toml_content)?;
            eprintln!("Created default config at {}", path);
            Ok(config)
        }
    }

    /// Get chain configuration
    pub fn chain(&self, chain: &Chain) -> anyhow::Result<&ChainConfig> {
        self.chains
            .get(chain)
            .ok_or_else(|| anyhow::anyhow!("Chain {} not configured", chain))
    }

    /// Get wallet configuration (legacy - use unified storage instead)
    /// First checks config.toml, then falls back to ~/.csv/wallet/csv-wallet.json
    #[deprecated(since = "0.4.0", note = "Use unified storage WalletConfig instead")]
    pub fn wallet(&self, chain: &Chain) -> Option<LegacyWalletConfig> {
        // First check config.toml wallets
        if let Some(wallet) = self.wallets.get(chain) {
            return Some(wallet.clone().into());
        }

        // Fall back to csv-wallet exported JSON (legacy format)
        let csv_wallet_path = expand_path("~/.csv/wallet/csv-wallet.json");
        if let Ok(csv_wallet) = CsvWalletData::load_from_file(&csv_wallet_path)
            && let Some(account) = csv_wallet.find_account(chain.as_ref())
        {
            // Create a LegacyWalletConfig from the CSV account
            return get_cached_wallet_config(chain, account);
        }

        None
    }

    /// Get unified wallet account for a chain (preferred method)
    pub fn wallet_account(&self, chain: &Chain) -> Option<WalletAccount> {
        // Fall back to legacy config.toml
        if let Some(legacy) = self.wallets.get(chain) {
            return Some(WalletAccount {
                id: format!("{}-legacy", chain),
                chain: chain.clone(),
                name: format!("{} Legacy", chain),
                address: String::new(), // Will be derived from private key
                xpub: legacy.xpub.clone(),
                derivation_path: legacy.derivation_path.clone(),
                keystore_ref: None,
            });
        }

        None
    }

    /// Set chain configuration
    pub fn set_chain(&mut self, chain: Chain, config: ChainConfig) {
        self.chains.insert(chain, config);
    }

    /// Set wallet configuration (legacy TOML format)
    pub fn set_wallet(&mut self, chain: Chain, config: LegacyWalletConfigToml) {
        self.wallets.insert(chain, config);
    }

    /// Set unified wallet account
    pub fn set_wallet_account(
        &mut self,
        _chain: Chain,
        _account: WalletAccount,
    ) -> anyhow::Result<()> {
        // Unified storage is managed separately via UnifiedStateManager
        Ok(())
    }

    /// Get RPC URL for a chain
    pub fn get_rpc_url(&self, chain: &Chain) -> String {
        // First check if chain config has an RPC URL
        if let Ok(chain_config) = self.chain(chain)
            && !chain_config.rpc_url.is_empty()
        {
            return chain_config.rpc_url.clone();
        }

        // Fall back to environment variables
        match chain.as_str() {
            "bitcoin" => std::env::var("BTC_RPC_URL")
                .unwrap_or_else(|_| "https://signet.bc-2.jp".to_string()),
            "ethereum" => std::env::var("ETH_RPC_URL")
                .unwrap_or_else(|_| "https://sepolia.infura.io/v3/YOUR_API_KEY".to_string()),
            "solana" => std::env::var("SOL_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            "sui" => std::env::var("SUI_RPC_URL")
                .unwrap_or_else(|_| "https://fullnode.testnet.sui.io:443".to_string()),
            "aptos" => std::env::var("APTOS_RPC_URL")
                .unwrap_or_else(|_| "https://fullnode.testnet.aptoslabs.com/v1".to_string()),
            _ => String::new(),
        }
    }
}

fn is_hex_address_len(value: &str, expected_bytes: usize) -> bool {
    let value = value.strip_prefix("0x").unwrap_or(value);
    value.len() == expected_bytes * 2 && hex::decode(value).is_ok()
}

/// Get cached wallet config from csv-wallet data (internal helper, legacy format)
fn get_cached_wallet_config(chain: &Chain, _account: &CsvAccount) -> Option<LegacyWalletConfig> {
    let cache = get_csv_wallet_cache();
    let mut cache = cache.lock().ok()?;

    // Insert if not exists
    // Note: private keys are no longer stored in WalletAccount
    cache
        .entry(chain.clone())
        .or_insert_with(|| LegacyWalletConfig {
            private_key: None,
            xpub: None,
            mnemonic: None,
            mnemonic_passphrase: None,
            derivation_path: None,
        });

    cache.get(chain).cloned()
}

/// Expand ~ to home directory
fn expand_path(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(stripped).to_string_lossy().to_string();
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(
            !config.chains.is_empty(),
            "Default config should have chains"
        );
        assert!(
            config.wallets.is_empty(),
            "Default config should have empty wallets"
        );
        assert_eq!(config.data_dir, "~/.csv/data");
    }

    #[test]
    fn test_config_with_missing_chains_field() {
        // This was the original bug - config with only wallet section
        let toml_content = r#"
[wallet]
mnemonic = "word1 word2 word3"
network = "dev"

[wallet.bitcoin]
address = "bcrt1test"
"#;
        let config: Result<Config, _> = toml::from_str(toml_content);
        assert!(
            config.is_ok(),
            "Should parse config without chains field: {:?}",
            config.err()
        );

        let config = config.unwrap();
        assert!(
            config.chains.is_empty(),
            "Chains should be empty when not specified"
        );
        assert!(
            config.wallets.is_empty(),
            "Wallets HashMap not populated from [wallet]"
        );
    }

    #[test]
    fn test_config_with_empty_file() {
        let toml_content = "";
        let config: Result<Config, _> = toml::from_str(toml_content);
        assert!(
            config.is_ok(),
            "Should parse empty config: {:?}",
            config.err()
        );

        let config = config.unwrap();
        assert!(config.chains.is_empty());
        assert!(config.wallets.is_empty());
        assert_eq!(config.data_dir, "~/.csv/data");
    }

    #[test]
    fn test_config_with_partial_chains() {
        let toml_content = r#"
[chains.bitcoin]
rpc_url = "https://bitcoin.example.com"
network = "test"
finality_depth = 6

[chains.ethereum]
rpc_url = "https://ethereum.example.com"
network = "main"
finality_depth = 12
chain_id = 1
"#;
        let config: Result<Config, _> = toml::from_str(toml_content);
        assert!(
            config.is_ok(),
            "Should parse config with partial chains: {:?}",
            config.err()
        );

        let config = config.unwrap();
        assert_eq!(config.chains.len(), 2);
        assert!(config.chains.contains_key(&ChainId::new("bitcoin")));
        assert!(config.chains.contains_key(&ChainId::new("ethereum")));
    }

    #[test]
    fn test_config_with_wallets() {
        let toml_content = r#"
[wallets.bitcoin]
mnemonic = "word1 word2"
derivation_path = "m/84'/0'/0'/0/0"

[wallets.ethereum]
private_key = "0xabc123"
"#;
        let config: Result<Config, _> = toml::from_str(toml_content);
        assert!(
            config.is_ok(),
            "Should parse config with wallets: {:?}",
            config.err()
        );

        let config = config.unwrap();
        assert_eq!(config.wallets.len(), 2);
        assert!(config.wallets.contains_key(&ChainId::new("bitcoin")));
        assert!(config.wallets.contains_key(&ChainId::new("ethereum")));
    }

    #[test]
    fn test_config_roundtrip_serialization() {
        let original = Config::default();
        let toml_str = toml::to_string_pretty(&original).unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(original.chains.len(), deserialized.chains.len());
        assert_eq!(original.data_dir, deserialized.data_dir);
    }

    #[test]
    fn test_config_load_creates_default_when_missing() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("nonexistent_config.toml");

        let config = Config::load(Some(config_path.to_str().unwrap()));
        assert!(
            config.is_ok(),
            "Should create default config when file missing: {:?}",
            config.err()
        );

        // Verify file was created
        assert!(config_path.exists(), "Config file should be created");
    }

    #[test]
    fn test_config_load_from_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");

        // Create a config file with valid structure
        // data_dir must be at top level, not inside any table
        let toml_content = r#"data_dir = "/custom/data/dir"

[chains.bitcoin]
rpc_url = "https://custom.bitcoin.com"
network = "test"
finality_depth = 3
"#;
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();
        drop(file);

        // Test direct TOML parsing first
        let parsed: Result<Config, _> = toml::from_str(toml_content);
        assert!(
            parsed.is_ok(),
            "Direct TOML parse failed: {:?}",
            parsed.err()
        );
        let direct = parsed.unwrap();
        assert_eq!(
            direct.data_dir, "/custom/data/dir",
            "Direct parse: data_dir mismatch"
        );

        // Test loading from file
        let config = Config::load(Some(config_path.to_str().unwrap()));
        assert!(
            config.is_ok(),
            "Should load existing config: {:?}",
            config.err()
        );

        let config = config.unwrap();
        // Config now merges missing chains from defaults, so we expect 5 chains total
        assert_eq!(
            config.chains.len(),
            5,
            "Expected 5 chains (1 from file + 4 merged defaults), got {}",
            config.chains.len()
        );
        assert!(
            config.chains.contains_key(&ChainId::new("bitcoin")),
            "Should have Bitcoin chain"
        );
        assert!(
            config.chains.contains_key(&ChainId::new("ethereum")),
            "Should have Ethereum chain (merged)"
        );
        assert!(
            config.chains.contains_key(&ChainId::new("sui")),
            "Should have Sui chain (merged)"
        );
        assert!(
            config.chains.contains_key(&ChainId::new("aptos")),
            "Should have Aptos chain (merged)"
        );
        assert!(
            config.chains.contains_key(&ChainId::new("solana")),
            "Should have Solana chain (merged)"
        );
        assert_eq!(
            config.data_dir, "/custom/data/dir",
            "Loaded config: data_dir should be from file"
        );
    }

    #[test]
    fn test_config_load_migrates_invalid_sui_and_aptos_addresses() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("legacy-config.toml");
        let toml_content = r#"data_dir = "/custom/data"

[chains.sui]
rpc_url = "https://fullnode.testnet.sui.io:443"
network = "test"
contract_address = "0xd71e8e8d48f98f9cb68cc59e3283121b68a4c507"
finality_depth = 1

[chains.aptos]
rpc_url = "https://fullnode.testnet.aptoslabs.com/v1"
network = "test"
contract_address = "0xd71e8e8d48f98f9cb68cc59e3283121b68a4c507"
finality_depth = 1
"#;
        std::fs::write(&config_path, toml_content).unwrap();

        let config = Config::load(Some(config_path.to_str().unwrap())).unwrap();
        for chain_name in ["sui", "aptos"] {
            let address = config
                .chain(&ChainId::new(chain_name))
                .unwrap()
                .contract_address
                .as_deref()
                .unwrap();
            assert!(is_hex_address_len(address, 32));
        }

        let persisted = std::fs::read_to_string(config_path).unwrap();
        assert!(!persisted.contains("0xd71e8e8d48f98f9cb68cc59e3283121b68a4c507"));
    }

    #[test]
    fn test_config_chain_accessor() {
        let config = Config::default();

        // Should get existing chain
        let bitcoin = config.chain(&ChainId::new("bitcoin"));
        assert!(bitcoin.is_ok());

        // Should error for non-existent chain in default config (all chains exist)
        // But if we create empty config:
        let empty_config = Config {
            chains: HashMap::new(),
            wallets: HashMap::new(),
            data_dir: "~/.csv/data".to_string(),
        };
        let missing = empty_config.chain(&ChainId::new("bitcoin"));
        assert!(missing.is_err());
    }

    #[test]
    fn test_expand_path() {
        let expanded = expand_path("~/.csv/config.toml");
        assert!(!expanded.starts_with('~'), "Path should be expanded");

        let absolute = expand_path("/absolute/path/config.toml");
        assert_eq!(absolute, "/absolute/path/config.toml");
    }

    #[test]
    fn test_invalid_toml_errors_gracefully() {
        let invalid_toml = r#"
[chains.bitcoin
rpc_url = "missing bracket"
"#;
        let config: Result<Config, _> = toml::from_str(invalid_toml);
        assert!(config.is_err(), "Should error on invalid TOML");
    }

    #[test]
    fn test_config_set_chain_and_wallet() {
        let mut config = Config::default();

        // Set a new chain config
        let new_chain = ChainConfig {
            rpc_url: "https://new.chain.com".to_string(),
            network: Network::Test,
            contract_address: None,
            chain_id: Some(12345),
            finality_depth: 10,
            default_fee: Some(1000),
            program_id: None,
        };
        config.set_chain(ChainId::new("solana"), new_chain);

        assert!(config.chains.contains_key(&ChainId::new("solana")));

        // Set a wallet
        let wallet = LegacyWalletConfigToml {
            private_key: Some("key".to_string()),
            xpub: None,
            mnemonic: None,
            mnemonic_passphrase: None,
            derivation_path: None,
        };
        config.set_wallet(ChainId::new("bitcoin"), wallet);

        assert!(config.wallets.contains_key(&ChainId::new("bitcoin")));
    }

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Dev.to_string(), "dev");
        assert_eq!(Network::Test.to_string(), "test");
        assert_eq!(Network::Main.to_string(), "main");
    }

    #[test]
    fn test_chain_display() {
        assert_eq!(ChainId::new("bitcoin").to_string(), "bitcoin");
        assert_eq!(ChainId::new("ethereum").to_string(), "ethereum");
        assert_eq!(ChainId::new("sui").to_string(), "sui");
        assert_eq!(ChainId::new("aptos").to_string(), "aptos");
        assert_eq!(ChainId::new("solana").to_string(), "solana");
    }
}
