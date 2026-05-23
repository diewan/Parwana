//! Aptos adapter configuration
//!
//! This module provides configuration for the Aptos adapter including
//! network selection, RPC endpoints, and production settings.

use serde::{Deserialize, Serialize};

/// Aptos network types with known chain IDs and RPC endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AptosNetwork {
    /// Aptos Mainnet
    Mainnet,
    /// Aptos Testnet
    Testnet,
    /// Aptos Devnet
    Devnet,
    /// Custom network with user-defined chain ID
    Custom {
        /// Chain ID for the custom network
        chain_id: u8,
        /// Human-readable name for the network
        name: String,
    },
}

impl AptosNetwork {
    /// Returns the chain ID for this network.
    pub fn chain_id(&self) -> u8 {
        match self {
            AptosNetwork::Mainnet => 1,
            AptosNetwork::Testnet => 2,
            AptosNetwork::Devnet => 4,
            AptosNetwork::Custom { chain_id, .. } => *chain_id,
        }
    }

    /// Returns the default fullnode RPC URL for this network.
    pub fn default_rpc_url(&self) -> &'static str {
        match self {
            AptosNetwork::Mainnet => "https://fullnode.mainnet.aptoslabs.com/v1",
            AptosNetwork::Testnet => "https://fullnode.testnet.aptoslabs.com/v1",
            AptosNetwork::Devnet => "https://fullnode.devnet.aptoslabs.com/v1",
            AptosNetwork::Custom { .. } => "",
        }
    }

    /// Returns the default indexer URL for this network.
    pub fn default_indexer_url(&self) -> &'static str {
        match self {
            AptosNetwork::Mainnet => "https://indexer.mainnet.aptoslabs.com/v1/graphql",
            AptosNetwork::Testnet => "https://indexer.testnet.aptoslabs.com/v1/graphql",
            AptosNetwork::Devnet => "",
            AptosNetwork::Custom { .. } => "",
        }
    }

    /// Returns the explorer URL for viewing transactions.
    pub fn explorer_url(&self) -> &'static str {
        match self {
            AptosNetwork::Mainnet => "https://explorer.aptoslabs.com",
            AptosNetwork::Testnet => "https://explorer.aptoslabs.com",
            AptosNetwork::Devnet => "",
            AptosNetwork::Custom { .. } => "",
        }
    }

    /// Known validator count for 2f+1 verification calculations.
    pub fn known_validator_count(&self) -> u64 {
        match self {
            AptosNetwork::Mainnet => 100, // ~100 validators on mainnet
            AptosNetwork::Testnet => 10,  // ~10 validators on testnet
            AptosNetwork::Devnet => 4,    // 4 validators on devnet
            AptosNetwork::Custom { .. } => 4,
        }
    }
}

/// Checkpoint verification configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointConfig {
    /// Require checkpoint to be certified by 2f+1 validators.
    pub require_certified: bool,
    /// Maximum number of epochs to look back for certification.
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

/// Transaction submission configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionConfig {
    /// Maximum gas units for a transaction.
    pub max_gas: u64,
    /// Timeout waiting for transaction confirmation in milliseconds.
    pub confirmation_timeout_ms: u64,
    /// Number of retries on transient failures.
    pub max_retries: u32,
    /// Base retry delay in milliseconds (exponential backoff).
    pub retry_delay_ms: u64,
}

impl Default for TransactionConfig {
    fn default() -> Self {
        Self {
            max_gas: 100_000,
            confirmation_timeout_ms: 30_000,
            max_retries: 3,
            retry_delay_ms: 1_000,
        }
    }
}

/// CSVSeal Move contract configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealContractConfig {
    /// Account address where the CSVSeal module is deployed.
    pub module_address: String,
    /// Module name (without account prefix).
    pub module_name: String,
    /// Resource name for seals.
    pub seal_resource: String,
}

impl Default for SealContractConfig {
    fn default() -> Self {
        Self {
            module_address: "0x1".to_string(),
            module_name: "csv_seal".to_string(),
            seal_resource: "Seal".to_string(),
        }
    }
}

/// Complete configuration for the Aptos adapter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AptosConfig {
    /// Network to connect to.
    pub network: AptosNetwork,
    /// RPC URL for the Aptos fullnode.
    pub rpc_url: String,
    /// Optional indexer URL for GraphQL queries.
    pub indexer_url: Option<String>,
    /// Checkpoint verification settings.
    pub checkpoint: CheckpointConfig,
    /// Transaction submission settings.
    pub transaction: TransactionConfig,
    /// CSVSeal contract deployment details.
    pub seal_contract: SealContractConfig,
}

impl Default for AptosConfig {
    fn default() -> Self {
        let network = AptosNetwork::Devnet;
        Self {
            network: network.clone(),
            rpc_url: network.default_rpc_url().to_string(),
            indexer_url: None,
            checkpoint: CheckpointConfig::default(),
            transaction: TransactionConfig::default(),
            seal_contract: SealContractConfig::default(),
        }
    }
}

impl AptosConfig {
    /// Create a new config for the given network with default RPC URL.
    pub fn new(network: AptosNetwork) -> Self {
        Self {
            rpc_url: network.default_rpc_url().to_string(),
            network,
            ..Self::default()
        }
    }

    /// Create a config with a custom RPC URL.
    pub fn with_rpc(network: AptosNetwork, rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            network,
            ..Self::default()
        }
    }

    /// Validate the configuration is correct for the target network.
    pub fn validate(&self) -> Result<(), String> {
        if self.rpc_url.is_empty() {
            return Err("RPC URL cannot be empty".to_string());
        }
        if self.transaction.max_gas == 0 {
            return Err("Max gas must be greater than 0".to_string());
        }
        if self.transaction.confirmation_timeout_ms == 0 {
            return Err("Confirmation timeout must be greater than 0".to_string());
        }
        if self.checkpoint.max_epoch_lookback == 0 {
            return Err("Epoch lookback must be greater than 0".to_string());
        }
        if self.seal_contract.module_address.is_empty() {
            return Err("Seal contract address cannot be empty".to_string());
        }
        Ok(())
    }

    /// Returns the chain ID for quick network identification.
    pub fn chain_id(&self) -> u8 {
        self.network.chain_id()
    }

    /// Returns the expected 2f+1 threshold for validator signatures.
    /// In production, this should match the actual validator set.
    pub fn f_plus_one(&self) -> u64 {
        let n = self.network.known_validator_count();
        // 2f + 1 where 3f + 1 = n => f = (n - 1) / 3
        // 2f + 1 = 2 * (n - 1) / 3 + 1
        (2 * n) / 3 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_chain_ids() {
        assert_eq!(AptosNetwork::Mainnet.chain_id(), 1);
        assert_eq!(AptosNetwork::Testnet.chain_id(), 2);
        assert_eq!(AptosNetwork::Devnet.chain_id(), 4);
        assert_eq!(
            AptosNetwork::Custom {
                chain_id: 99,
                name: "local".to_string()
            }
            .chain_id(),
            99
        );
    }

    #[test]
    fn test_default_rpc_urls() {
        assert!(AptosNetwork::Mainnet.default_rpc_url().contains("mainnet"));
        assert!(AptosNetwork::Testnet.default_rpc_url().contains("testnet"));
    }

    #[test]
    fn test_config_validation() {
        let config = AptosConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_custom_rpc() {
        let config = AptosConfig::with_rpc(AptosNetwork::Mainnet, "https://custom.example.com");
        assert_eq!(config.rpc_url, "https://custom.example.com");
        assert_eq!(config.network.chain_id(), 1);
    }

    #[test]
    fn test_f_plus_one() {
        let config = AptosConfig::new(AptosNetwork::Devnet);
        // For 4 validators: 2f+1 where f=(4-1)/3=1, so 2*1+1=3
        assert!(config.f_plus_one() >= 3);
    }

    #[test]
    fn test_invalid_config() {
        let config = AptosConfig {
            rpc_url: "".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = AptosConfig {
            transaction: TransactionConfig {
                max_gas: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
