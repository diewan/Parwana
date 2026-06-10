//! Ethereum adapter configuration

use csv_keys::memory::SecretKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error;

/// Configuration for the Ethereum anchor layer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthereumConfig {
    /// Ethereum network (mainnet, goerli, sepolia, etc.)
    pub network: Network,
    /// Required confirmation depth for probabilistic finality
    pub finality_depth: u64,
    /// Whether to use post-merge finalized checkpoints
    pub use_checkpoint_finality: bool,
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Optional private key hex (for signing/deployment; may be None for read-only)
    #[serde(
        serialize_with = "serialize_secret_key",
        deserialize_with = "deserialize_secret_key"
    )]
    pub private_key: Option<SecretKey>,
    /// Seal contract address for cross-chain transfers (merged lock + mint)
    pub contract_address: Option<[u8; 20]>,
}

/// Helper for serializing/deserializing Option<SecretKey> as hex string
fn serialize_secret_key<S>(key: &Option<SecretKey>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(k) => serializer.serialize_some(&hex::encode(k.expose_secret())),
        None => serializer.serialize_none(),
    }
}

fn deserialize_secret_key<'de, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_str: Option<String> = Option::deserialize(deserializer)?;
    match opt_str {
        Some(s) => {
            let bytes = hex::decode(&s).map_err(|e| D::Error::custom(format!("invalid hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(D::Error::custom(format!("private key must be 32 bytes, got {}", bytes.len())));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            Ok(Some(SecretKey::new(key_bytes)))
        }
        None => Ok(None),
    }
}

/// Ethereum network type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Ethereum mainnet
    Mainnet,
    /// Goerli testnet
    Goerli,
    /// Sepolia testnet
    Sepolia,
    /// Local development
    Dev,
}

impl Network {
    /// Get chain ID for the network
    pub fn chain_id(&self) -> u64 {
        match self {
            Network::Mainnet => 1,
            Network::Goerli => 5,
            Network::Sepolia => 11155111,
            Network::Dev => 1337,
        }
    }
}

impl EthereumConfig {
    /// Validate configuration values
    pub fn validate(&self) -> Result<String, String> {
        if self.rpc_url.is_empty() {
            return Err("rpc_url cannot be empty".to_string());
        }
        if self.finality_depth == 0 {
            return Err("finality_depth must be greater than 0".to_string());
        }
        if self.finality_depth > 10000 {
            return Err("finality_depth must be <= 10000".to_string());
        }
        if self.network == Network::Mainnet && self.rpc_url.contains("127.0.0.1") {
            return Err("mainnet config should not use localhost rpc_url".to_string());
        }
        Ok("Configuration is valid".to_string())
    }
}

impl Default for EthereumConfig {
    fn default() -> Self {
        Self {
            network: Network::Sepolia,
            finality_depth: 15,
            use_checkpoint_finality: true,
            rpc_url: "http://127.0.0.1:8545".to_string(),
            private_key: None,
            contract_address: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EthereumConfig::default();
        assert_eq!(config.network, Network::Sepolia);
        assert_eq!(config.finality_depth, 15);
        assert!(config.use_checkpoint_finality);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_rpc_url() {
        let config = EthereumConfig {
            rpc_url: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_finality_depth() {
        let config = EthereumConfig {
            finality_depth: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_mainnet_localhost() {
        let config = EthereumConfig {
            network: Network::Mainnet,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_network_chain_id() {
        assert_eq!(Network::Mainnet.chain_id(), 1);
        assert_eq!(Network::Sepolia.chain_id(), 11155111);
    }
}
