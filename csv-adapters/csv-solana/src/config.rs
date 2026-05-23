//! Configuration for Solana adapter

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Solana network configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Network {
    /// Solana mainnet
    Mainnet,
    /// Solana devnet
    #[default]
    Devnet,
    /// Solana testnet
    Testnet,
    /// Local development
    Local,
}

impl Network {
    /// Get the default RPC URL for this network
    pub fn default_rpc_url(&self) -> &'static str {
        match self {
            Self::Mainnet => "https://api.mainnet-beta.solana.com",
            Self::Devnet => "https://api.devnet.solana.com",
            Self::Testnet => "https://api.testnet.solana.com",
            Self::Local => "http://localhost:8899",
        }
    }

    /// Get the cluster name for Solana SDK
    pub fn cluster(&self) -> String {
        match self {
            Self::Mainnet => "mainnet-beta".to_string(),
            Self::Devnet => "devnet".to_string(),
            Self::Testnet => "testnet".to_string(),
            Self::Local => "local".to_string(),
        }
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" | "mainnet-beta" => Ok(Self::Mainnet),
            "devnet" => Ok(Self::Devnet),
            "testnet" => Ok(Self::Testnet),
            "local" | "localhost" => Ok(Self::Local),
            _ => Err(format!(
                "Invalid network: {}. Supported: mainnet, devnet, testnet, local",
                s
            )),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Devnet => write!(f, "devnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Local => write!(f, "local"),
        }
    }
}

/// Configuration for Solana adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaConfig {
    /// Solana network
    pub network: Network,
    /// RPC endpoint URL
    pub rpc_url: String,
    /// CSV program ID
    pub csv_program_id: String,
    /// Wallet keypair (base58 encoded)
    pub keypair: Option<String>,
    /// Commitment level
    pub commitment: Option<String>,
    /// Maximum retries for RPC calls
    pub max_retries: u32,
    /// Timeout for RPC calls (seconds)
    pub timeout_seconds: u64,
}

impl Default for SolanaConfig {
    fn default() -> Self {
        Self {
            network: Network::Devnet,
            rpc_url: Network::Devnet.default_rpc_url().to_string(),
            csv_program_id: "CsvProgram11111111111111111111111111111111111".to_string(),
            keypair: None,
            commitment: Some("confirmed".to_string()),
            max_retries: 3,
            timeout_seconds: 30,
        }
    }
}

impl SolanaConfig {
    /// Create configuration for specific network
    pub fn for_network(network: Network) -> Self {
        Self {
            network,
            rpc_url: network.default_rpc_url().to_string(),
            ..Default::default()
        }
    }

    /// Create configuration with custom RPC URL
    pub fn with_rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = rpc_url.into();
        self
    }

    /// Set CSV program ID
    pub fn with_csv_program_id(mut self, program_id: impl Into<String>) -> Self {
        self.csv_program_id = program_id.into();
        self
    }

    /// Set wallet keypair
    pub fn with_keypair(mut self, keypair: impl Into<String>) -> Self {
        self.keypair = Some(keypair.into());
        self
    }

    /// Get commitment configuration for Solana SDK
    pub fn commitment_config(&self) -> String {
        match self.commitment.as_deref() {
            Some("processed") => "processed".to_string(),
            Some("confirmed") => "confirmed".to_string(),
            Some("finalized") => "finalized".to_string(),
            _ => "confirmed".to_string(), // Default to confirmed
        }
    }
}
