//! Bitcoin adapter configuration

/// Configuration for the Bitcoin anchor layer
#[derive(Clone, Debug)]
pub struct BitcoinConfig {
    /// Bitcoin network (mainnet, testnet, signet, regtest)
    pub network: Network,
    /// Required confirmation depth for finality
    pub finality_depth: u32,
    /// Publication timeout (for censorship detection)
    pub publication_timeout_seconds: u64,
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Optional xpub for HD wallet derivation (BIP-86)
    /// If None, adapter operates in query-only mode or requires external signing
    pub xpub: Option<String>,
}

/// Bitcoin network type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet3
    Testnet,
    /// Bitcoin signet
    Signet,
    /// Bitcoin regtest
    Regtest,
}

impl Network {
    /// Get magic bytes for the network
    pub fn magic_bytes(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet => [0x0b, 0x11, 0x09, 0x07],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }

    /// Convert to bitcoin crate Network type
    pub fn to_bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

impl BitcoinConfig {
    /// Validate configuration values
    pub fn validate(&self) -> Result<String, String> {
        if self.rpc_url.is_empty() {
            return Err("rpc_url cannot be empty".to_string());
        }
        if self.finality_depth == 0 {
            return Err("finality_depth must be greater than 0".to_string());
        }
        if self.finality_depth > 1000 {
            return Err("finality_depth must be <= 1000".to_string());
        }
        if self.publication_timeout_seconds == 0 {
            return Err("publication_timeout_seconds must be greater than 0".to_string());
        }
        let expected_mainnet =
            self.network == Network::Mainnet && self.rpc_url.contains("127.0.0.1");
        if expected_mainnet {
            return Err("mainnet config should not use localhost rpc_url".to_string());
        }
        Ok("Configuration is valid".to_string())
    }
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            network: Network::Signet,
            finality_depth: 6,
            publication_timeout_seconds: 3600, // 1 hour
            rpc_url: "http://127.0.0.1:8332".to_string(),
            xpub: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BitcoinConfig::default();
        assert_eq!(config.network, Network::Signet);
        assert_eq!(config.finality_depth, 6);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_rpc_url() {
        let config = BitcoinConfig {
            rpc_url: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_finality_depth() {
        let config = BitcoinConfig {
            finality_depth: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_excessive_finality_depth() {
        let config = BitcoinConfig {
            finality_depth: 1001,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_network_magic_bytes() {
        assert_eq!(Network::Mainnet.magic_bytes(), [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(Network::Signet.magic_bytes(), [0x0a, 0x03, 0xcf, 0x40]);
    }
}
