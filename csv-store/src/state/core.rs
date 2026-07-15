//! Core types: Chains and Networks.
//!
//! Defines the supported blockchain networks and their configurations.
//!
//! Chain IDs are strings for extensibility (100+ chains without code changes).
//! Uses csv_hash::chain_id::ChainId as the canonical type.

pub use csv_hash::chain_id::ChainId;
use serde::{Deserialize, Serialize};

// Import deployment manifest reader
use csv_protocol::deployment_manifest::{
    get_aptos_contract_address, get_ethereum_contract_address, get_solana_program_id,
    get_sui_package_id,
};

/// Network environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Development network (local nodes).
    Dev,
    /// Test network (public testnets).
    #[default]
    Test,
    /// Main network (production).
    Main,
}

impl Network {
    /// Check if this is a testnet or devnet (non-production).
    pub fn is_testnet(&self) -> bool {
        matches!(self, Self::Test | Self::Dev)
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Dev => write!(f, "dev"),
            Network::Test => write!(f, "test"),
            Network::Main => write!(f, "main"),
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dev" => Ok(Network::Dev),
            "test" => Ok(Network::Test),
            "main" => Ok(Network::Main),
            _ => Err(format!("Unknown network: {}", s)),
        }
    }
}

/// Chain-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// REST/esplora indexer base URL for address→UTXO scanning (Bitcoin).
    ///
    /// Address-index scanning is a REST-only capability; a JSON-RPC `rpc_url`
    /// (e.g. Alchemy) cannot enumerate an address's UTXOs. When `rpc_url` is
    /// itself a REST endpoint this may be left unset and the scanner falls back
    /// to `rpc_url`. `#[serde(default)]` keeps older config/state files loading.
    #[serde(default)]
    pub indexer_url: Option<String>,
    /// Explicit indexer transport for scanning (Bitcoin): `"esplora"` (mempool /
    /// blockstream) or `"blockbook"` (Alchemy UTXO API / self-hosted Blockbook).
    /// Selected explicitly, never sniffed from the URL. `None` = chain default
    /// (esplora for Bitcoin).
    #[serde(default)]
    pub indexer_backend: Option<String>,
    /// Network environment.
    pub network: Network,
    /// Contract/package address (if deployed).
    pub contract_address: Option<String>,
    /// Chain ID (for EVM chains) or magic bytes (Bitcoin).
    pub chain_id: Option<u64>,
    /// Finality depth (confirmations required).
    pub finality_depth: u64,
    /// Default gas price / fee rate.
    pub default_fee: Option<u64>,
    /// Program ID for program-based chains (Solana, etc.).
    pub program_id: Option<String>,
}

impl ChainConfig {
    /// Create default configuration for a chain and network.
    pub fn default_for(chain: &ChainId, network: &Network) -> Self {
        match chain.as_str() {
            "bitcoin" => Self {
                // Reviewed built-in defaults. No environment override below the
                // application layer (RFC-0013): a host that needs a different
                // endpoint supplies a typed policy explicitly.
                rpc_url: match network {
                    Network::Dev => "http://localhost:18443".to_string(),
                    Network::Test => "https://bitcoin-signet.g.alchemy.com/v2/".to_string(),
                    Network::Main => "https://rpc.ankr.com/btc".to_string(),
                },
                // Default `rpc_url` above is JSON-RPC (Alchemy/Ankr), which has no
                // address index, so provide an explicit esplora indexer for scans.
                indexer_url: Some(match network {
                    Network::Dev => "http://localhost:3000/api".to_string(),
                    Network::Test => "https://mempool.space/signet/api".to_string(),
                    Network::Main => "https://mempool.space/api".to_string(),
                }),
                indexer_backend: None, // esplora (mempool) is the default flavour
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 6,
                default_fee: Some(10),
                program_id: None,
            },
            "ethereum" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:8545".to_string(),
                    Network::Test => "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
                    Network::Main => "https://ethereum-rpc.publicnode.com".to_string(),
                },
                indexer_url: None,
                indexer_backend: None,
                network: *network,
                contract_address: get_ethereum_contract_address().ok(),
                chain_id: match network {
                    Network::Dev => Some(1337),
                    Network::Test => Some(11155111),
                    Network::Main => Some(1),
                },
                finality_depth: 12,
                default_fee: Some(20_000_000_000),
                program_id: None,
            },
            "sui" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:9000".to_string(),
                    Network::Test => "https://fullnode.testnet.sui.io:443".to_string(),
                    Network::Main => "https://fullnode.mainnet.sui.io:443".to_string(),
                },
                indexer_url: None,
                indexer_backend: None,
                network: *network,
                contract_address: Some(get_sui_package_id().unwrap_or_else(|_| {
                    "0x3eba46bb91c08182e426bd5d3e51b5671d3529057d7846521013ebb15353ff21".to_string()
                })),
                chain_id: None,
                finality_depth: 1,
                default_fee: Some(1000),
                program_id: None,
            },
            "aptos" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:8080".to_string(),
                    Network::Test => "https://fullnode.testnet.aptoslabs.com/v1".to_string(),
                    Network::Main => "https://fullnode.mainnet.aptoslabs.com/v1".to_string(),
                },
                indexer_url: None,
                indexer_backend: None,
                network: *network,
                contract_address: Some(get_aptos_contract_address().unwrap_or_else(|_| {
                    "0x9d4c8ad9b8f58c73c73327833a4bda650c590091f130b2ec1293f086cf02ed50".to_string()
                })),
                chain_id: None,
                finality_depth: 100,
                default_fee: Some(100),
                program_id: None,
            },
            "solana" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:8899".to_string(),
                    Network::Test => "https://api.devnet.solana.com".to_string(),
                    Network::Main => "https://api.mainnet-beta.solana.com".to_string(),
                },
                indexer_url: None,
                indexer_backend: None,
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 32,
                default_fee: Some(5000),
                program_id: Some(get_solana_program_id().unwrap_or_else(|_| {
                    "HdxSFwzk2v6JMm3w55MW1EuMeNcM9gTC4ETFMKqYyy6m".to_string()
                })),
            },
            _ => Self {
                rpc_url: String::new(),
                indexer_url: None,
                indexer_backend: None,
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 1,
                default_fee: None,
                program_id: None,
            },
        }
    }
}
