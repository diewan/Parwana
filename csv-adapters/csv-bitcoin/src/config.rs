//! Bitcoin adapter configuration

use csv_keys::memory::SecretKey;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Configuration for the Bitcoin anchor layer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// Bitcoin network (mainnet, testnet, signet, regtest)
    pub network: Network,
    /// Required confirmation depth for finality
    pub finality_depth: u32,
    /// Publication timeout (for censorship detection)
    pub publication_timeout_seconds: u64,
    /// RPC endpoint URL (used for broadcast / gettxout / proof queries)
    pub rpc_url: String,
    /// RPC backend type (explicitly specifies transport protocol).
    ///
    /// This is NOT sniffed from the URL — the caller declares it. Different
    /// backends expose genuinely different capabilities (see [`BitcoinRpcBackend`]).
    pub rpc_backend: BitcoinRpcBackend,
    /// REST/esplora indexer base URL used for address→UTXO scanning and tx
    /// lookups. Address-index scanning is a REST-only capability: a JSON-RPC
    /// endpoint (Alchemy, QuickNode, bare Bitcoin Core without a wallet) cannot
    /// enumerate the UTXOs of an arbitrary address. When `rpc_backend` is itself
    /// a REST backend this may be `None` and callers fall back to `rpc_url`;
    /// when `rpc_backend` is JSON-RPC this must be set to scan.
    pub indexer_url: Option<String>,
    /// Optional API key for RPC authentication (e.g., Tatum, Alchemy)
    pub api_key: Option<String>,
    /// Optional xpub for HD wallet derivation (BIP-86)
    /// If None, adapter operates in query-only mode or requires external signing
    pub xpub: Option<String>,
    /// Optional private key for transaction signing (hex format, WIF, or base58)
    /// Required for spending transactions. Not stored in config for security.
    #[serde(
        serialize_with = "serialize_secret_key",
        deserialize_with = "deserialize_secret_key"
    )]
    pub private_key: Option<SecretKey>,
    /// Optional seed for HD wallet derivation (128 hex chars = 64 bytes)
    /// If provided, takes precedence over xpub for wallet creation.
    /// Both CLI and adapter use the same seed to derive addresses via BIP-32.
    /// Note: Seed remains as String because it's 64 bytes (BIP-39 seed), not 32 bytes like SecretKey.
    pub seed: Option<String>,
    /// Account index for HD wallet derivation (default: 0)
    pub account: u32,
    /// Address index for HD wallet derivation (default: 0)
    pub index: u32,
    /// Pre-loaded UTXOs (for persistence across commands)
    pub utxos: Vec<UtxoConfig>,
    /// Pre-loaded sanad_id -> seal mappings (for cross-chain lock lookups)
    pub sanad_seals: Vec<SanadSealConfig>,
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
            let bytes =
                hex::decode(&s).map_err(|e| D::Error::custom(format!("invalid hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(D::Error::custom(format!(
                    "key must be 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            Ok(Some(SecretKey::new(key_bytes)))
        }
        None => Ok(None),
    }
}

/// UTXO configuration for Bitcoin wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Sanad seal configuration for cross-chain lock lookups
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Bitcoin RPC backend type
///
/// This enum explicitly specifies which transport protocol the RPC endpoint uses.
/// Different backends have different API semantics and response formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Trezor Blockbook REST API (Alchemy Bitcoin "UTXO API", self-hosted Blockbook)
    /// Supports: /api/v2/utxo/{descriptor}, /api/v2/tx/{txid}, /api/v2/sendtx/{hex}
    /// Unlike Bitcoin Core JSON-RPC, this CAN enumerate an address's UTXOs, so it
    /// is a valid scanning indexer. Response shape differs from esplora (satoshi
    /// values are decimal strings; paths are /api/v2/...).
    BlockbookRest,
}

impl BitcoinRpcBackend {
    /// True if this backend speaks the esplora REST convention (append
    /// `/address/{addr}/utxo`, `/tx/{txid}`, …) rather than JSON-RPC.
    ///
    /// Only REST backends can enumerate an address's UTXOs; JSON-RPC endpoints
    /// have no address index (see [`BitcoinConfig::indexer_url`]).
    pub fn is_rest(&self) -> bool {
        matches!(
            self,
            Self::BlockstreamRest | Self::MempoolRest | Self::BlockbookRest
        )
    }

    /// Construct the concrete [`BitcoinRpc`](crate::rpc::BitcoinRpc) client for
    /// this backend. This is the single place transport selection happens; it is
    /// driven entirely by the explicitly-declared backend, never by inspecting
    /// the URL string.
    ///
    /// Blockstream and mempool.space share the esplora REST shape, so both are
    /// served by [`MempoolSignetRpc`](crate::mempool_rpc::MempoolSignetRpc)
    /// pointed at the given base URL.
    #[cfg(feature = "signet-rest")]
    pub fn build_rpc(
        &self,
        url: String,
        api_key: Option<String>,
    ) -> Box<dyn crate::rpc::BitcoinRpc + Send + Sync> {
        match self {
            Self::BitcoinCoreJsonRpc => Box::new(crate::json_rpc::BitcoinJsonRpc::new(url)),
            Self::BlockstreamRest | Self::MempoolRest => Box::new(
                crate::mempool_rpc::MempoolSignetRpc::with_url_and_key(url, api_key),
            ),
            Self::BlockbookRest => Box::new(crate::blockbook_rpc::BlockbookRpc::with_url_and_key(
                url, api_key,
            )),
        }
    }
}

/// Bitcoin network type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// This only overrides the URL and API key; it does NOT change `rpc_backend`.
    /// The transport is an explicit choice of the caller — pointing an env var at
    /// an endpoint of a different transport than the configured backend is a
    /// configuration error the caller must resolve by setting `rpc_backend` too.
    pub fn with_env_rpc(mut self) -> Result<Self, String> {
        let rpc_url = std::env::var("BITCOIN_RPC_URL")
            .or_else(|_| std::env::var("BITCOIN_ALCHEMY_SIGNET_HTTP_RPC"))
            .or_else(|_| std::env::var("BITCOIN_ANKR_SIGNET_HTTP_RPC"))
            .or_else(|_| std::env::var("BITCOIN_TATUM_SIGNET_JSON_RPC"))
            .or_else(|_| std::env::var("BITCOIN_TATUM_SIGNET_REST_RPC"))
            .ok();

        if let Some(url) = rpc_url {
            // If using Tatum endpoint, load the API key
            if url.contains("tatum.io") {
                self.api_key = std::env::var("TATUM_SIGNET_API_KEY").ok();
            }
            self.rpc_url = url;
        }
        Ok(self)
    }

    /// Resolve the REST/esplora indexer base URL to use for address scanning.
    ///
    /// Returns the explicitly-configured `indexer_url` if set; otherwise falls
    /// back to `rpc_url` when the primary backend is itself REST. Returns `None`
    /// when the primary is JSON-RPC and no indexer was configured — the caller
    /// must surface that as "address scanning requires a REST indexer" rather
    /// than silently guessing a public one.
    pub fn resolve_indexer_url(&self) -> Option<String> {
        self.indexer_url
            .clone()
            .or_else(|| self.rpc_backend.is_rest().then(|| self.rpc_url.clone()))
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

        Ok("Configuration is valid".to_string())
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
            indexer_url: None,
            api_key: None,
            xpub: None,
            private_key: None,
            seed: None,
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
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
