//! Core types: Chains and Networks.
//!
//! Defines the supported blockchain networks and their configurations.
//!
//! Chain IDs are strings for extensibility (100+ chains without code changes).
//! Uses csv_hash::chain_id::ChainId as the canonical type.

pub use csv_hash::chain_id::ChainId;
use serde::{Deserialize, Serialize};

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
}

impl ChainConfig {
    /// Create default configuration for a chain and network.
    pub fn default_for(chain: &ChainId, network: &Network) -> Self {
        match chain.as_str() {
            "bitcoin" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:18443".to_string(),
                    Network::Test => "https://mempool.space/signet/api/".to_string(),
                    Network::Main => "https://mempool.space/api/".to_string(),
                },
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 6,
                default_fee: Some(10),
            },
            "ethereum" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:8545".to_string(),
                    Network::Test => "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
                    Network::Main => "https://ethereum-rpc.publicnode.com".to_string(),
                },
                network: *network,
                contract_address: None,
                chain_id: match network {
                    Network::Dev => Some(1337),
                    Network::Test => Some(11155111),
                    Network::Main => Some(1),
                },
                finality_depth: 12,
                default_fee: Some(20_000_000_000),
            },
            "sui" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:9000".to_string(),
                    Network::Test => "https://fullnode.testnet.sui.io:443".to_string(),
                    Network::Main => "https://fullnode.mainnet.sui.io:443".to_string(),
                },
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 1,
                default_fee: Some(1000),
            },
            "aptos" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:8080".to_string(),
                    Network::Test => "https://fullnode.testnet.aptoslabs.com/v1".to_string(),
                    Network::Main => "https://fullnode.mainnet.aptoslabs.com/v1".to_string(),
                },
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 100,
                default_fee: Some(100),
            },
            "solana" => Self {
                rpc_url: match network {
                    Network::Dev => "http://localhost:8899".to_string(),
                    Network::Test => "https://api.devnet.solana.com".to_string(),
                    Network::Main => "https://api.mainnet-beta.solana.com".to_string(),
                },
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 32,
                default_fee: Some(5000),
            },
            _ => Self {
                rpc_url: String::new(),
                network: *network,
                contract_address: None,
                chain_id: None,
                finality_depth: 1,
                default_fee: None,
            },
        }
    }
}
