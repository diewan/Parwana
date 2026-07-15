//! Configuration management for the CSV Adapter.
//!
//! Provides a serializable [`Config`] struct that can be loaded from a TOML
//! file (`~/.csv/config.toml`). The SDK never reads RPC environment variables
//! or `.env` files implicitly; host applications must supply overrides through
//! the typed RPC policy API.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::rpc_identity::EndpointValidator;
use crate::rpc_policy::{
    ChainRpcPolicy, RpcCapability, RpcEndpoint, RpcEndpointSource, RpcPolicyError,
    RpcSelectionMode, RpcTransport,
};
use csv_hash::chain_id::ChainId;

#[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
use dirs;

/// Network identifier for chain endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Production network (real value).
    Mainnet,
    /// Public test network (test value).
    Testnet,
    /// Developer sandbox network (dev value).
    Devnet,
    /// Local isolated network (local value).
    Regtest,
}

impl Network {
    /// Returns `true` if this is a production network.
    pub fn is_mainnet(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// Returns `true` if this is a test or development network.
    pub fn is_testnet(&self) -> bool {
        !self.is_mainnet()
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Devnet => write!(f, "devnet"),
            Self::Regtest => write!(f, "regtest"),
        }
    }
}

/// RPC configuration for a specific chain.
///
/// Endpoints are described exclusively by the typed [`ChainRpcPolicy`]. The
/// legacy scalar URL/indexer/api-key fields were deleted (RFC-0013): an endpoint
/// is never a bare URL, its transport is never guessed, and credentials are
/// resolved from a host-owned keyring via [`RpcCredentialRef`], never stored
/// here. Hosts convert their platform configuration into a policy explicitly
/// (see [`Config::builtin_rpc`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of retries for transient failures.
    pub max_retries: u32,
    /// Typed endpoint selection and trust policy. This is the sole authority for
    /// endpoint URLs, transport, capabilities, provider identity, and trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ChainRpcPolicy>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_retries: 3,
            policy: None,
        }
    }
}

/// Per-chain configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// RPC endpoint configuration.
    pub rpc: RpcConfig,
    /// Required confirmation depth for finality.
    pub finality_depth: u32,
    /// Whether this chain is enabled.
    pub enabled: bool,
    /// Extended public key for HD wallet derivation (Bitcoin xpub).
    /// Used to derive addresses and watch for transactions without spending.
    pub xpub: Option<String>,
    /// BIP-39 seed for HD wallet derivation (64 bytes, 128 hex chars).
    /// Used for Bitcoin wallet creation when xpub is not available.
    /// Takes precedence over xpub for wallet creation if provided.
    pub seed: Option<String>,
    /// Deployed seal or mint contract/package address required for mutation.
    pub contract_address: Option<String>,
    /// Deployed program identifier for program-based chains.
    pub program_id: Option<String>,
    /// Account index for HD wallet derivation (Bitcoin only, default: 0)
    pub account: u32,
    /// Address index for HD wallet derivation (Bitcoin only, default: 0)
    pub index: u32,
    /// Pre-loaded UTXOs for Bitcoin wallet (for persistence across commands)
    pub utxos: Vec<UtxoConfig>,
    /// Pre-loaded sanad_id -> seal mappings for Bitcoin cross-chain lock lookups
    pub sanad_seals: Vec<SanadSealConfig>,
}

/// UTXO configuration for Bitcoin wallet (for SDK config)
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_pubkey: Option<String>,
}

/// Sanad seal configuration for Bitcoin cross-chain lock lookups (for SDK config)
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            rpc: RpcConfig::default(),
            finality_depth: 6,
            enabled: false,
            xpub: None,
            seed: None,
            contract_address: None,
            program_id: None,
            account: 0,
            index: 0,
            utxos: Vec::new(),
            sanad_seals: Vec::new(),
        }
    }
}

fn reviewed_endpoint(
    id: &str,
    url: &str,
    transport: RpcTransport,
    capabilities: Vec<RpcCapability>,
    provider: &str,
) -> RpcEndpoint {
    RpcEndpoint {
        id: id.to_string(),
        url: url.to_string(),
        transport,
        capabilities,
        source: RpcEndpointSource::BuiltIn,
        provider: provider.to_string(),
        priority: 0,
        credential: None,
    }
}

fn reviewed_chain_config(chain: &str, network: Network) -> ChainConfig {
    // The third tuple element records the historical REST indexer dialect
    // (esplora/blockbook). It is retained for documentation of intent only: the
    // address-index endpoint's REST transport now carries that meaning, and no
    // consumer selects a non-esplora dialect. See RFC-0013 "chain transport
    // matrix" for the typed successor.
    let (exact_network, endpoint, _indexer_dialect) = match (chain, network) {
        ("bitcoin", Network::Mainnet) => (
            "mainnet",
            reviewed_endpoint(
                "bitcoin-mainnet-mempool-space",
                "https://mempool.space/api",
                RpcTransport::Rest,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::AddressIndex,
                    RpcCapability::Verify,
                ],
                "mempool-space",
            ),
            Some("esplora".to_string()),
        ),
        ("bitcoin", Network::Devnet | Network::Regtest) => (
            "regtest",
            reviewed_endpoint(
                "bitcoin-local-json-rpc",
                "http://127.0.0.1:18443",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "local",
            ),
            None,
        ),
        ("bitcoin", Network::Testnet) => (
            "signet",
            reviewed_endpoint(
                "bitcoin-signet-mempool-space",
                "https://mempool.space/signet/api",
                RpcTransport::Rest,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::AddressIndex,
                    RpcCapability::Verify,
                ],
                "mempool-space",
            ),
            Some("esplora".to_string()),
        ),
        ("ethereum", Network::Mainnet) => (
            "mainnet",
            reviewed_endpoint(
                "ethereum-mainnet-publicnode",
                "https://ethereum-rpc.publicnode.com",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "publicnode",
            ),
            None,
        ),
        ("ethereum", Network::Devnet | Network::Regtest) => (
            "local",
            reviewed_endpoint(
                "ethereum-local-json-rpc",
                "http://127.0.0.1:8545",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "local",
            ),
            None,
        ),
        ("ethereum", Network::Testnet) => (
            "sepolia",
            reviewed_endpoint(
                "ethereum-sepolia-publicnode",
                "https://ethereum-sepolia-rpc.publicnode.com",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "publicnode",
            ),
            None,
        ),
        ("sui", Network::Mainnet) => (
            "mainnet",
            reviewed_endpoint(
                "sui-mainnet-fullnode",
                "https://fullnode.mainnet.sui.io:443",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "mysten-labs",
            ),
            None,
        ),
        ("sui", Network::Devnet | Network::Regtest) => (
            "local",
            reviewed_endpoint(
                "sui-local-json-rpc",
                "http://127.0.0.1:9000",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "local",
            ),
            None,
        ),
        ("sui", Network::Testnet) => (
            "testnet",
            reviewed_endpoint(
                "sui-testnet-fullnode",
                "https://fullnode.testnet.sui.io:443",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "mysten-labs",
            ),
            None,
        ),
        ("aptos", Network::Mainnet) => (
            "mainnet",
            reviewed_endpoint(
                "aptos-mainnet-fullnode",
                "https://fullnode.mainnet.aptoslabs.com/v1",
                RpcTransport::Rest,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "aptos-labs",
            ),
            None,
        ),
        ("aptos", Network::Devnet | Network::Regtest) => (
            "local",
            reviewed_endpoint(
                "aptos-local-fullnode",
                "http://127.0.0.1:8080",
                RpcTransport::Rest,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "local",
            ),
            None,
        ),
        ("aptos", Network::Testnet) => (
            "testnet",
            reviewed_endpoint(
                "aptos-testnet-fullnode",
                "https://fullnode.testnet.aptoslabs.com/v1",
                RpcTransport::Rest,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "aptos-labs",
            ),
            None,
        ),
        ("solana", Network::Mainnet) => (
            "mainnet-beta",
            reviewed_endpoint(
                "solana-mainnet-foundation",
                "https://api.mainnet-beta.solana.com",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "solana-foundation",
            ),
            None,
        ),
        ("solana", Network::Devnet | Network::Regtest) => (
            "local",
            reviewed_endpoint(
                "solana-local-json-rpc",
                "http://127.0.0.1:8899",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "local",
            ),
            None,
        ),
        ("solana", Network::Testnet) => (
            "devnet",
            reviewed_endpoint(
                "solana-devnet-foundation",
                "https://api.devnet.solana.com",
                RpcTransport::JsonRpcHttp,
                vec![
                    RpcCapability::Read,
                    RpcCapability::Broadcast,
                    RpcCapability::Verify,
                ],
                "solana-foundation",
            ),
            None,
        ),
        _ => return ChainConfig::default(),
    };
    ChainConfig {
        rpc: RpcConfig {
            policy: Some(ChainRpcPolicy {
                chain: chain.to_string(),
                network: exact_network.to_string(),
                selection: RpcSelectionMode::BuiltInOnly,
                endpoints: vec![endpoint],
            }),
            ..RpcConfig::default()
        },
        ..ChainConfig::default()
    }
}

/// Store backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
#[derive(Default)]
pub enum StoreConfig {
    /// In-memory store (non-persistent, for testing).
    #[default]
    InMemory,
    /// SQLite file-backed store.
    Sqlite {
        /// Path to the SQLite database file.
        path: String,
    },
}

/// Top-level CSV Adapter configuration.
///
/// Can be loaded from a TOML file or constructed programmatically. Loading is
/// deterministic: process environment and `.env` files are never consulted.
///
/// # Example TOML (`~/.csv/config.toml`)
///
/// Endpoints are described by a typed policy (RFC-0013), never a bare URL: each
/// endpoint declares its transport, capabilities, and provider so the transport
/// is never guessed and credentials stay in a host keyring.
///
/// ```toml
/// network = "testnet"
///
/// [chains.ethereum]
/// enabled = true
/// finality_depth = 12
/// [chains.ethereum.rpc]
/// timeout_ms = 30000
/// max_retries = 3
/// [chains.ethereum.rpc.policy]
/// chain = "ethereum"
/// network = "sepolia"
/// selection = "user_only"
/// [[chains.ethereum.rpc.policy.endpoints]]
/// id = "my-eth-http"
/// url = "https://rpc.example.net/eth"
/// transport = "json_rpc_http"
/// capabilities = ["read", "broadcast", "verify"]
/// source = "user"
/// provider = "self-hosted"
///
/// [store]
/// backend = "sqlite"
/// path = "~/.csv/data.db"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Global network setting.
    pub network: Network,
    /// Per-chain configurations.
    pub chains: HashMap<String, ChainConfig>,
    /// Store backend configuration.
    pub store: StoreConfig,
    /// Log level (e.g., "info", "debug", "warn").
    pub log_level: Option<String>,
    /// Data directory override.
    pub data_dir: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self::for_network(Network::Testnet)
    }
}

impl Config {
    /// Construct reviewed endpoint defaults for an exact network family.
    pub fn for_network(network: Network) -> Self {
        let chains = ["bitcoin", "ethereum", "sui", "aptos", "solana"]
            .into_iter()
            .map(|chain| (chain.to_string(), reviewed_chain_config(chain, network)))
            .collect();
        Self {
            network,
            chains,
            store: StoreConfig::default(),
            log_level: Some("info".to_string()),
            data_dir: None,
        }
    }

    /// Build a reviewed built-in [`RpcConfig`] for a chain/network, applying
    /// optional host overrides for the request and REST address-index endpoint
    /// URLs.
    ///
    /// This is the single seam a host (CLI, service, container entrypoint) uses
    /// to convert its own platform configuration — including values it may read
    /// from a config file or process environment at the executable layer — into
    /// the typed policy. Per-chain transport, capabilities, and provider identity
    /// come from the reviewed registry, so the transport of an overridden URL is
    /// taken from the endpoint it replaces and is never guessed from the string.
    ///
    /// Returns `None` for a chain that has no reviewed built-in policy.
    pub fn builtin_rpc(
        chain: &str,
        network: Network,
        request_url_override: Option<&str>,
        indexer_url_override: Option<&str>,
    ) -> Option<RpcConfig> {
        let mut rpc = reviewed_chain_config(chain, network).rpc;
        let policy = rpc.policy.as_mut()?;
        if let Some(url) = request_url_override.map(str::trim).filter(|u| !u.is_empty()) {
            if let Some(endpoint) = policy.endpoints.iter_mut().find(|endpoint| {
                endpoint.capabilities.contains(&RpcCapability::Read)
                    && endpoint.transport != RpcTransport::WebSocket
            }) {
                endpoint.url = url.to_string();
            }
        }
        if let Some(url) = indexer_url_override.map(str::trim).filter(|u| !u.is_empty()) {
            if let Some(endpoint) = policy
                .endpoints
                .iter_mut()
                .find(|endpoint| endpoint.capabilities.contains(&RpcCapability::AddressIndex))
            {
                endpoint.url = url.to_string();
            }
        }
        Some(rpc)
    }

    /// Default configuration file path: `~/.csv/config.toml`.
    ///
    /// Returns `~/.csv/config.toml` on native targets.
    /// On wasm32, returns `/.csv/config.toml` (browser storage path).
    pub fn default_path() -> PathBuf {
        #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
        {
            let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push(".csv");
            path.push("config.toml");
            path
        }
        #[cfg(all(not(target_arch = "wasm32"), not(feature = "native")))]
        {
            PathBuf::from("./.csv/config.toml")
        }
        #[cfg(target_arch = "wasm32")]
        {
            PathBuf::from("/.csv/config.toml")
        }
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: &PathBuf) -> Result<Self, crate::CsvError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config
            .validate_rpc_policies()
            .map_err(|error| crate::CsvError::ConfigError(error.to_string()))?;
        Ok(config)
    }

    /// Load from the default path. A missing file yields reviewed defaults;
    /// malformed or unsafe configuration is returned as an error.
    pub fn load() -> Result<Self, crate::CsvError> {
        let path = Self::default_path();
        if path.exists() {
            Self::from_file(&path)
        } else {
            Ok(Self::default())
        }
    }

    /// Validate every typed RPC policy in the configuration.
    pub fn validate_rpc_policies(&self) -> Result<(), RpcPolicyError> {
        for chain in self.chains.values() {
            if let Some(policy) = &chain.rpc.policy {
                policy.validate()?;
            }
        }
        Ok(())
    }

    /// Get the RPC configuration for a specific chain.
    pub fn rpc_for(&self, chain: ChainId) -> Option<&RpcConfig> {
        let name = chain.to_string();
        self.chains.get(&name).map(|c| &c.rpc)
    }

    /// Resolve the single request endpoint URL consumed by concrete adapters.
    ///
    /// The typed policy is the sole authority. A chain without a policy, or with
    /// no request-capable (non-WebSocket, `Read`) endpoint under its selection
    /// mode, is a fail-closed error — never an environment or hard-coded
    /// fallback.
    pub fn required_request_url(&self, chain: &str) -> Result<String, crate::CsvError> {
        let policy = self
            .chains
            .get(chain)
            .and_then(|config| config.rpc.policy.as_ref())
            .ok_or_else(|| crate::CsvError::ConfigError(format!("missing {chain} RPC policy")))?;
        let endpoint = policy
            .candidates(RpcCapability::Read)
            .map_err(|error| crate::CsvError::ConfigError(error.to_string()))?
            .into_iter()
            .find(|endpoint| endpoint.transport != RpcTransport::WebSocket)
            .ok_or_else(|| {
                crate::CsvError::ConfigError(format!("{chain} has no request-capable RPC endpoint"))
            })?;
        Ok(endpoint.url.clone())
    }

    /// Resolve the REST address-index (esplora-dialect) endpoint URL for a chain
    /// from the typed policy, if one is configured. Address indexing is a
    /// distinct REST capability (RFC-0013); a JSON-RPC request endpoint does not
    /// satisfy it, so this returns `None` rather than falling back to the request
    /// URL.
    pub fn indexer_url(&self, chain: &str) -> Option<String> {
        let policy = self.chains.get(chain)?.rpc.policy.as_ref()?;
        policy
            .candidates(RpcCapability::AddressIndex)
            .ok()?
            .into_iter()
            .find(|endpoint| endpoint.transport == RpcTransport::Rest)
            .map(|endpoint| endpoint.url.clone())
    }

    /// Resolve a request URL exactly like [`Self::required_request_url`], but
    /// restricted to endpoints that have passed live identity validation in
    /// `validator` (RFC-0013 / RPC-003).
    ///
    /// An endpoint that was never probed, is degraded, or was identity-rejected
    /// is excluded. When no validated request-capable endpoint remains this
    /// fails closed rather than serving an unvalidated one — there is no bypass,
    /// and built-in endpoints are gated exactly like user endpoints.
    pub fn validated_request_url(
        &self,
        chain: &str,
        validator: &EndpointValidator,
    ) -> Result<String, crate::CsvError> {
        let policy = self
            .chains
            .get(chain)
            .and_then(|config| config.rpc.policy.as_ref())
            .ok_or_else(|| crate::CsvError::ConfigError(format!("missing {chain} RPC policy")))?;
        let candidates = policy
            .candidates(RpcCapability::Read)
            .map_err(|error| crate::CsvError::ConfigError(error.to_string()))?;
        validator
            .usable(&candidates, RpcCapability::Read)
            .into_iter()
            .find(|endpoint| endpoint.transport != RpcTransport::WebSocket)
            .map(|endpoint| endpoint.url.clone())
            .ok_or_else(|| {
                crate::CsvError::ConfigError(format!(
                    "{chain} has no identity-validated request endpoint"
                ))
            })
    }

    /// Deterministic endpoint candidates for a capability, restricted to
    /// identity-validated endpoints (RFC-0013 / RPC-003) and preserving the
    /// policy's candidate order. Fails closed with [`RpcPolicyError::NoCandidate`]
    /// when none are validated.
    pub fn validated_candidates<'a>(
        &'a self,
        chain: &str,
        capability: RpcCapability,
        validator: &EndpointValidator,
    ) -> Result<Vec<&'a RpcEndpoint>, RpcPolicyError> {
        let policy = self
            .chains
            .get(chain)
            .and_then(|config| config.rpc.policy.as_ref())
            .ok_or(RpcPolicyError::NoCandidate {
                capability,
                selection: RpcSelectionMode::BuiltInOnly,
            })?;
        let candidates = policy.candidates(capability)?;
        let validated = validator.usable(&candidates, capability);
        if validated.is_empty() {
            return Err(RpcPolicyError::NoCandidate {
                capability,
                selection: policy.selection,
            });
        }
        Ok(validated)
    }

    /// Return deterministic endpoint candidates for a chain capability.
    pub fn rpc_candidates(
        &self,
        chain: ChainId,
        capability: RpcCapability,
    ) -> Result<Vec<&RpcEndpoint>, RpcPolicyError> {
        let name = chain.to_string();
        let policy = self
            .chains
            .get(&name)
            .and_then(|config| config.rpc.policy.as_ref())
            .ok_or(RpcPolicyError::NoCandidate {
                capability,
                selection: RpcSelectionMode::BuiltInOnly,
            })?;
        policy.candidates(capability)
    }

    /// Check if a chain is enabled in the configuration.
    pub fn is_chain_enabled(&self, chain: ChainId) -> bool {
        let name = chain.to_string();
        self.chains.get(&name).map(|c| c.enabled).unwrap_or(false)
    }

    /// Inject a typed user endpoint for a chain.
    ///
    /// Injection always switches that chain to strict user-only selection. The
    /// caller must explicitly call [`Self::with_rpc_selection`] to permit a
    /// fallback to reviewed built-in endpoints.
    pub fn with_rpc_endpoint(
        mut self,
        chain: ChainId,
        network: impl Into<String>,
        endpoint: RpcEndpoint,
    ) -> Result<Self, RpcPolicyError> {
        if endpoint.source != RpcEndpointSource::User {
            return Err(RpcPolicyError::InvalidEndpoint(
                "wallet/operator injection requires source = user".to_string(),
            ));
        }
        let name = chain.to_string();
        let network = network.into();
        let entry = self.chains.entry(name.clone()).or_default();
        if let Some(policy) = &entry.rpc.policy
            && policy.network != network
        {
            return Err(RpcPolicyError::InvalidEndpoint(format!(
                "cannot inject {network} endpoint into {} policy",
                policy.network
            )));
        }
        let policy = entry.rpc.policy.get_or_insert_with(|| ChainRpcPolicy {
            chain: name,
            network,
            selection: RpcSelectionMode::UserOnly,
            endpoints: Vec::new(),
        });
        policy.use_user_endpoint(endpoint)?;
        entry.enabled = true;
        Ok(self)
    }

    /// Set endpoint source/fallback behavior explicitly for one chain.
    pub fn with_rpc_selection(
        mut self,
        chain: ChainId,
        selection: RpcSelectionMode,
    ) -> Result<Self, RpcPolicyError> {
        let name = chain.to_string();
        let policy = self
            .chains
            .get_mut(&name)
            .and_then(|config| config.rpc.policy.as_mut())
            .ok_or(RpcPolicyError::NoCandidate {
                capability: RpcCapability::Read,
                selection,
            })?;
        policy.selection = selection;
        policy.validate()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_endpoint_updates_policy_and_resolves_request_url() {
        let endpoint = RpcEndpoint {
            id: "my-solana".to_string(),
            url: "https://rpc.example.test".to_string(),
            transport: RpcTransport::JsonRpcHttp,
            capabilities: vec![RpcCapability::Read, RpcCapability::Broadcast],
            source: RpcEndpointSource::User,
            provider: "self-hosted".to_string(),
            priority: 0,
            credential: None,
        };
        let config = Config::default()
            .with_rpc_endpoint(ChainId::new("solana"), "devnet", endpoint)
            .expect("valid endpoint");
        let chain = config.chains.get("solana").expect("chain created");
        assert!(chain.enabled);
        assert_eq!(
            chain.rpc.policy.as_ref().expect("policy").selection,
            RpcSelectionMode::UserOnly
        );
        // The typed policy is the sole authority: the request URL resolves from
        // the injected user endpoint, not a scalar field.
        assert_eq!(
            config.required_request_url("solana").expect("request url"),
            "https://rpc.example.test"
        );
    }

    #[test]
    fn websocket_injection_yields_no_request_endpoint() {
        let endpoint = RpcEndpoint {
            id: "my-solana-ws".to_string(),
            url: "wss://rpc.example.test".to_string(),
            transport: RpcTransport::WebSocket,
            capabilities: vec![RpcCapability::Subscribe],
            source: RpcEndpointSource::User,
            provider: "self-hosted".to_string(),
            priority: 0,
            credential: None,
        };
        let config = Config::default()
            .with_rpc_endpoint(ChainId::new("solana"), "devnet", endpoint)
            .expect("valid endpoint");
        // A subscribe-only WebSocket endpoint under strict user-only selection
        // leaves no request-capable endpoint, and there is no scalar URL to fall
        // back to: request resolution fails closed.
        assert!(config.required_request_url("solana").is_err());
    }

    /// A prober that reports a fixed chain id for every endpoint, so a matching
    /// or mismatching network identity can be simulated deterministically.
    struct FixedChainIdProbe {
        reported_chain_id: &'static str,
    }

    impl crate::rpc_identity::IdentityProbe for FixedChainIdProbe {
        async fn observe(
            &self,
            _endpoint: &RpcEndpoint,
        ) -> Result<crate::rpc_identity::ObservedIdentity, crate::rpc_identity::ProbeError> {
            Ok(crate::rpc_identity::ObservedIdentity {
                chain_id: Some(self.reported_chain_id.to_string()),
                ..Default::default()
            })
        }
    }

    fn sepolia_expected() -> crate::rpc_identity::ExpectedIdentity {
        crate::rpc_identity::ExpectedIdentity {
            chain: "ethereum".into(),
            network: "sepolia".into(),
            chain_id: Some("11155111".into()),
            genesis_hash: None,
            requires_deployment: false,
        }
    }

    #[tokio::test]
    async fn resolution_is_gated_by_identity_validation() {
        let config = Config::default();
        let candidates = config
            .rpc_candidates(ChainId::new("ethereum"), RpcCapability::Read)
            .expect("built-in ethereum candidates");
        let endpoints: Vec<RpcEndpoint> = candidates.into_iter().cloned().collect();
        let expected = sepolia_expected();

        // Never-probed: the endpoint is not usable, so resolution fails closed
        // even though the policy has a request-capable candidate.
        let mut validator = EndpointValidator::new(3600, 0);
        assert!(config.validated_request_url("ethereum", &validator).is_err());
        assert!(
            config
                .validated_candidates("ethereum", RpcCapability::Read, &validator)
                .is_err()
        );

        // A probe reporting the wrong chain id rejects the endpoint (fail closed).
        validator
            .validate_all(
                &endpoints,
                &expected,
                &FixedChainIdProbe {
                    reported_chain_id: "1",
                },
                1,
            )
            .await;
        assert!(config.validated_request_url("ethereum", &validator).is_err());

        // A probe reporting the expected chain id validates the endpoint, and it
        // now resolves through the gate to its reviewed URL.
        let mut validator = EndpointValidator::new(3600, 0);
        validator
            .validate_all(
                &endpoints,
                &expected,
                &FixedChainIdProbe {
                    reported_chain_id: "11155111",
                },
                1,
            )
            .await;
        assert_eq!(
            config
                .validated_request_url("ethereum", &validator)
                .expect("validated request url"),
            "https://ethereum-sepolia-rpc.publicnode.com"
        );
        assert!(
            !config
                .validated_candidates("ethereum", RpcCapability::Read, &validator)
                .expect("validated candidates")
                .is_empty()
        );
    }
}
