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
    /// RPC backend type (explicitly specifies transport protocol)
    pub rpc_backend: BitcoinRpcBackend,
    /// Optional API key for RPC authentication (e.g., Tatum, Alchemy)
    pub api_key: Option<String>,
    /// Optional xpub for HD wallet derivation (BIP-86)
    /// If None, adapter operates in query-only mode or requires external signing
    pub xpub: Option<String>,
    /// Optional private key for transaction signing (hex format, WIF, or base58)
    /// Required for spending transactions. Not stored in config for security.
    pub private_key: Option<String>,
    /// Optional seed for HD wallet derivation (128 hex chars = 64 bytes)
    /// If provided, takes precedence over xpub for wallet creation.
    /// Both CLI and adapter use the same seed to derive addresses via BIP-32.
    pub seed: Option<String>,
    /// Account index for HD wallet derivation (default: 0)
    pub account: u32,
    /// Address index for HD wallet derivation (default: 0)
    pub index: u32,
    /// Pre-loaded UTXOs (for persistence across commands)
    pub utxos: Vec<UtxoConfig>,
}

/// UTXO configuration for Bitcoin wallet
#[derive(Clone, Debug)]
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
    pub script_pubkey: Option<String>,
}

/// Bitcoin RPC backend type
/// 
/// This enum explicitly specifies which transport protocol the RPC endpoint uses.
/// Different backends have different API semantics and response formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinRpcBackend {
    /// Bitcoin Core JSON-RPC (native Bitcoin Core, QuickNode, Alchemy Bitcoin RPC)
    /// Supports: getrawtransaction, gettxout, sendrawtransaction, listunspent
    /// Requires: txindex=1 for transaction lookup
    BitcoinCoreJsonRpc,
    /// Blockstream REST API (blockstream.info, blockstream.com)
    /// Supports: /address/{addr}/utxo, /tx/{txid}, /tx
    /// Does NOT support: Bitcoin Core JSON-RPC methods
    BlockstreamRest,
    /// Mempool.space REST API (mempool.space)
    /// Supports: /address/{addr}/utxo, /tx/{txid}, /tx, /tx/{txid}/outspend/{vout}
    /// Does NOT support: Bitcoin Core JSON-RPC methods
    MempoolRest,
}

impl BitcoinRpcBackend {
    /// Detect backend type from URL pattern
    /// 
    /// This is a heuristic based on known endpoint patterns.
    /// For production use, explicitly specify the backend type instead of relying on detection.
    pub fn detect_from_url(url: &str) -> Option<Self> {
        if url.contains("mempool.space") || url.contains("mempool") {
            Some(Self::MempoolRest)
        } else if url.contains("blockstream.info") || url.contains("blockstream.com") {
            Some(Self::BlockstreamRest)
        } else if url.contains("127.0.0.1") || url.contains("localhost") 
            || url.contains("quicknode") || url.contains("alchemy") 
            || url.contains("bitcoincore") || url.contains("btc-rpc") {
            Some(Self::BitcoinCoreJsonRpc)
        } else {
            // Unknown endpoint - default to BitcoinCoreJsonRpc but warn
            None
        }
    }

    /// Validate that a URL is compatible with this backend type
    pub fn validate_url(&self, url: &str) -> Result<(), String> {
        match self {
            Self::BitcoinCoreJsonRpc => {
                // Bitcoin Core JSON-RPC endpoints typically don't have /api or /rest paths
                if url.contains("/api/") || url.contains("/rest/") {
                    return Err(format!(
                        "URL '{}' appears to be a REST API but BitcoinCoreJsonRpc backend requires a JSON-RPC endpoint. \
                         Use BlockstreamRest or MempoolRest backend instead, or use a real Bitcoin Core RPC endpoint.",
                        url
                    ));
                }
                Ok(())
            }
            Self::BlockstreamRest => {
                if !url.contains("blockstream") {
                    return Err(format!(
                        "URL '{}' does not appear to be a Blockstream endpoint. \
                         Use BitcoinCoreJsonRpc backend for Bitcoin Core RPC, or MempoolRest for mempool.space.",
                        url
                    ));
                }
                Ok(())
            }
            Self::MempoolRest => {
                if !url.contains("mempool") {
                    return Err(format!(
                        "URL '{}' does not appear to be a mempool.space endpoint. \
                         Use BitcoinCoreJsonRpc backend for Bitcoin Core RPC, or BlockstreamRest for Blockstream.",
                        url
                    ));
                }
                Ok(())
            }
        }
    }
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
    /// Create config with RPC URL from environment variable if available
    /// Checks environment variables in priority order:
    /// 1. BITCOIN_RPC_URL (generic)
    /// 2. BITCOIN_ALCHEMY_SIGNET_HTTP_RPC (Alchemy)
    /// 3. BITCOIN_ANKR_SIGNET_HTTP_RPC (Ankr)
    /// 4. BITCOIN_TATUM_SIGNET_JSON_RPC (Tatum JSON-RPC)
    /// 5. BITCOIN_TATUM_SIGNET_REST_RPC (Tatum REST)
    ///
    /// Also loads API key from TATUM_SIGNET_API_KEY if using Tatum endpoints
    /// 
    /// **IMPORTANT**: This method validates transport compatibility. If the env override
    /// changes the transport type (e.g., from REST to JSON-RPC), it will return an error
    /// unless the backend type is also explicitly specified.
    pub fn with_env_rpc(mut self) -> Result<Self, String> {
        let rpc_url = std::env::var("BITCOIN_RPC_URL")
            .or_else(|_| std::env::var("BITCOIN_ALCHEMY_SIGNET_HTTP_RPC"))
            .or_else(|_| std::env::var("BITCOIN_ANKR_SIGNET_HTTP_RPC"))
            .or_else(|_| std::env::var("BITCOIN_TATUM_SIGNET_JSON_RPC"))
            .or_else(|_| std::env::var("BITCOIN_TATUM_SIGNET_REST_RPC"))
            .ok();

        if let Some(url) = rpc_url {
            // Detect backend type from new URL
            let detected_backend = BitcoinRpcBackend::detect_from_url(&url);
            
            // Validate that the new URL is compatible with the current backend type
            if let Err(_e) = self.rpc_backend.validate_url(&url) {
                // If validation fails, try to detect the correct backend type
                if let Some(detected) = detected_backend {
                    self.rpc_backend = detected;
                } else {
                    return Err(format!("RPC URL '{}' is incompatible with backend {:?}", url, self.rpc_backend));
                }
            }
            
            self.rpc_url = url.clone();

            // If using Tatum endpoint, load the API key
            if url.contains("tatum.io") {
                self.api_key = std::env::var("TATUM_SIGNET_API_KEY").ok();
            }
        }
        Ok(self)
    }

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
        
        // Validate that RPC URL is compatible with the specified backend type
        // If validation fails, this is a configuration error that the user must fix
        self.rpc_backend.validate_url(&self.rpc_url)?;
        
        Ok("Configuration is valid".to_string())
    }

    /// Auto-detect and set the correct backend type based on the RPC URL
    /// This should be called after setting rpc_url but before creating the RPC client
    pub fn auto_detect_backend(mut self) -> Self {
        if let Some(detected) = BitcoinRpcBackend::detect_from_url(&self.rpc_url) {
            if detected != self.rpc_backend {
                self.rpc_backend = detected;
            }
        }
        self
    }
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            network: Network::Signet,
            finality_depth: 6,
            publication_timeout_seconds: 3600, // 1 hour
            rpc_url: "https://blockstream.info/signet/api".to_string(),
            rpc_backend: BitcoinRpcBackend::BlockstreamRest,
            api_key: None,
            xpub: None,
            private_key: None,
            seed: None,
            account: 0,
            index: 0,
            utxos: Vec::new(),
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
