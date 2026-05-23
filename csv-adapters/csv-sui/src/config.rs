//! Sui adapter configuration
//!
//! This module provides comprehensive configuration for the Sui adapter,
//! including network selection, checkpoint settings, and transaction parameters.

use serde::{Deserialize, Serialize};

/// Sui network type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuiNetwork {
    /// Sui mainnet
    Mainnet,
    /// Sui testnet
    Testnet,
    /// Sui devnet
    Devnet,
    /// Local network
    Local,
    /// Custom network with user-defined chain ID
    Custom { chain_id: String },
}

impl SuiNetwork {
    /// Returns the default RPC URL for this network.
    pub fn default_rpc_url(&self) -> &str {
        match self {
            SuiNetwork::Mainnet => "https://fullnode.mainnet.sui.io:443",
            SuiNetwork::Testnet => "https://fullnode.testnet.sui.io:443",
            SuiNetwork::Devnet => "https://fullnode.devnet.sui.io:443",
            SuiNetwork::Local => "http://127.0.0.1:9000",
            SuiNetwork::Custom { .. } => "",
        }
    }

    /// Returns the chain ID for this network.
    pub fn chain_id(&self) -> &str {
        match self {
            SuiNetwork::Mainnet => "mainnet",
            SuiNetwork::Testnet => "testnet",
            SuiNetwork::Devnet => "devnet",
            SuiNetwork::Local => "local",
            SuiNetwork::Custom { chain_id } => chain_id.as_str(),
        }
    }
}

/// Configuration for checkpoint verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointConfig {
    /// Whether to require certified checkpoints.
    pub require_certified: bool,
    /// Maximum number of epochs to look back for checkpoint verification.
    pub max_epoch_lookback: u64,
    /// Timeout for checkpoint verification in milliseconds.
    pub timeout_ms: u64,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            require_certified: true,
            max_epoch_lookback: 5,
            timeout_ms: 30_000,
        }
    }
}

/// Configuration for transaction submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionConfig {
    /// Maximum gas budget for transactions (in MIST).
    pub max_gas_budget: u64,
    /// Maximum gas price (in MIST).
    pub max_gas_price: u64,
    /// Timeout for transaction confirmation in milliseconds.
    pub confirmation_timeout_ms: u64,
    /// Number of retries for failed transactions.
    pub max_retries: u32,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            max_gas_budget: 1_000_000_000, // 1 SUI
            max_gas_price: 1_000,
            confirmation_timeout_ms: 60_000,
            max_retries: 3,
        }
    }
}

/// Configuration for the CSV seal contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealContractConfig {
    /// Package ID where CSVSeal module is deployed.
    /// Must be set explicitly — there is no safe default.
    pub package_id: Option<String>,
    /// Module name (typically "csv_seal").
    pub module_name: String,
    /// Seal object type name.
    pub seal_type: String,
}

impl Default for SealContractConfig {
    fn default() -> Self {
        Self {
            package_id: None, // No safe default — must be set explicitly
            module_name: "csv_seal".to_string(),
            seal_type: "Seal".to_string(),
        }
    }
}

/// Configuration for the Sui anchor layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuiConfig {
    /// Sui network (mainnet, testnet, devnet, local).
    pub network: SuiNetwork,
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// Checkpoint verification configuration.
    pub checkpoint: CheckpointConfig,
    /// Transaction submission configuration.
    pub transaction: TransactionConfig,
    /// CSV seal contract configuration.
    pub seal_contract: SealContractConfig,
    /// Signer address for transaction signing (required for deployment).
    pub signer_address: Option<String>,
    /// Signer private key bytes (32 bytes, required for deployment).
    #[serde(with = "serde_bytes")]
    pub signer_private_key: Option<Vec<u8>>,
}

impl SuiConfig {
    /// Create a new configuration for the specified network.
    pub fn new(network: SuiNetwork) -> Self {
        let rpc_url = network.default_rpc_url().to_string();
        Self {
            network,
            rpc_url,
            checkpoint: CheckpointConfig::default(),
            transaction: TransactionConfig::default(),
            seal_contract: SealContractConfig::default(),
            signer_address: None,
            signer_private_key: None,
        }
    }

    /// Returns the chain ID for the configured network.
    pub fn chain_id(&self) -> &str {
        self.network.chain_id()
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.rpc_url.is_empty() {
            return Err("RPC URL cannot be empty".to_string());
        }
        match &self.seal_contract.package_id {
            Some(id) if id.is_empty() => {
                return Err("Seal contract package ID cannot be empty".to_string());
            }
            None => {
                return Err(
                    "Seal contract package ID must be set — deploy the contract first".to_string(),
                );
            }
            _ => {}
        }
        if self.transaction.max_gas_budget == 0 {
            return Err("Max gas budget must be greater than 0".to_string());
        }
        if self.checkpoint.timeout_ms == 0 {
            return Err("Checkpoint timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

impl Default for SuiConfig {
    fn default() -> Self {
        Self::new(SuiNetwork::Testnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SuiConfig::default();
        assert_eq!(config.network, SuiNetwork::Testnet);
        assert_eq!(config.rpc_url, "https://fullnode.testnet.sui.io:443");
    }

    #[test]
    fn test_config_custom_rpc() {
        let config = SuiConfig::new(SuiNetwork::Mainnet);
        assert_eq!(config.network, SuiNetwork::Mainnet);
        assert_eq!(config.rpc_url, "https://fullnode.mainnet.sui.io:443");
    }

    #[test]
    fn test_config_validation() {
        let config = SuiConfig {
            seal_contract: SealContractConfig {
                package_id: Some("0x1234".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        let config = SuiConfig {
            rpc_url: "".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_network_chain_ids() {
        assert_eq!(SuiNetwork::Mainnet.chain_id(), "mainnet");
        assert_eq!(SuiNetwork::Testnet.chain_id(), "testnet");
        assert_eq!(SuiNetwork::Devnet.chain_id(), "devnet");
    }

    #[test]
    fn test_invalid_config() {
        let config = SuiConfig {
            seal_contract: SealContractConfig {
                package_id: Some("".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
