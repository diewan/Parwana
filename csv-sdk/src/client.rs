//! Unified CSV client with builder pattern.
//!
//! The [`CsvClient`] is the main entry point for all CSV operations.
//! It provides access to managers for sanads, transfers, wallet,
//! and event streaming.
//!
//! # Example
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let client = CsvClient::builder()
//!         .with_chain("bitcoin")
//!         .with_store_backend(StoreBackend::InMemory)
//!         .build()?;
//!
//!     // Access managers
//!     let sanads = client.sanads();
//!     let transfers = client.transfers();
//!
//!     // Stream events
//!     let events = client.watch();
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use csv_hash::chain_id::ChainId;
#[cfg(feature = "tokio")]
use tokio::sync::broadcast;

use crate::builder::ClientBuilder;
use crate::config::Config;
use crate::error::CsvError;
#[cfg(feature = "tokio")]
use crate::events::EventStream;
use crate::local_store::{InMemorySealStore, SanadRecord};
use crate::runtime::ChainRuntime;
use crate::sanads::SanadsManager;
use crate::transfers::TransferManager;
use crate::wallet::Wallet;
use crate::wallet::WalletManager;

/// Handle to the underlying storage backend.
pub enum StoreHandle {
    /// In-memory seal and anchor store.
    InMemory(InMemorySealStore),
}

impl StoreHandle {
    /// Save a Sanad to the store.
    pub fn save_sanad(&mut self, record: &SanadRecord) -> Result<(), CsvError> {
        match self {
            StoreHandle::InMemory(store) => store
                .save_sanad(record)
                .map_err(|e| CsvError::StoreError(e.to_string())),
        }
    }

    /// Get a Sanad by its ID.
    pub fn get_sanad(
        &self,
        sanad_id: &csv_hash::sanad::SanadId,
    ) -> Result<Option<SanadRecord>, CsvError> {
        match self {
            StoreHandle::InMemory(store) => store
                .get_sanad(sanad_id)
                .map_err(|e| CsvError::StoreError(e.to_string())),
        }
    }

    /// List all Sanads for a specific chain.
    pub fn list_sanads_by_chain(&self, chain: &str) -> Result<Vec<SanadRecord>, CsvError> {
        match self {
            StoreHandle::InMemory(store) => store
                .list_sanads_by_chain(chain)
                .map_err(|e| CsvError::StoreError(e.to_string())),
        }
    }

    /// Mark a Sanad as consumed.
    pub fn consume_sanad(
        &mut self,
        sanad_id: &csv_hash::sanad::SanadId,
        consumed_at: u64,
    ) -> Result<(), CsvError> {
        match self {
            StoreHandle::InMemory(store) => store
                .consume_sanad(sanad_id, consumed_at)
                .map_err(|e| CsvError::StoreError(e.to_string())),
        }
    }

    /// List all active (unconsumed) Sanads.
    pub fn list_active_sanads(&self) -> Result<Vec<SanadRecord>, CsvError> {
        match self {
            StoreHandle::InMemory(store) => store
                .list_active_sanads()
                .map_err(|e| CsvError::StoreError(e.to_string())),
        }
    }

    /// Check if a Sanad exists.
    pub fn has_sanad(&self, sanad_id: &csv_hash::sanad::SanadId) -> Result<bool, CsvError> {
        match self {
            StoreHandle::InMemory(store) => store
                .has_sanad(sanad_id)
                .map_err(|e| CsvError::StoreError(e.to_string())),
        }
    }
}

/// Network type for adapter initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    /// Mainnet (production network)
    Mainnet,
    /// Testnet (testing network)
    Testnet,
}

impl NetworkType {
    /// Check if this is a testnet.
    pub fn is_testnet(&self) -> bool {
        matches!(self, Self::Testnet)
    }
}

/// The unified CSV client.
///
/// This is the main entry point for all CSV operations. Construct it
/// using [`CsvClient::builder()`] or [`CsvClient::scalable_builder()`] and access the various managers for
/// sanads, transfers, proofs, and wallet operations.
///
/// # Thread Safety
///
/// `CsvClient` is `Send + Sync` and can be shared across threads via
/// `Arc<CsvClient>`.
pub struct CsvClient {
    /// Set of enabled chain adapters.
    pub(crate) enabled_chains: HashSet<ChainId>,
    /// Optional wallet for signing and address derivation.
    pub(crate) wallet: Option<Wallet>,
    /// Storage backend for seals and anchors.
    pub(crate) store: Arc<std::sync::Mutex<StoreHandle>>,
    /// Configuration.
    pub(crate) config: Config,
    /// Event broadcast channel sender.
    #[cfg(feature = "tokio")]
    pub(crate) event_tx: broadcast::Sender<crate::events::Event>,
    #[cfg(not(feature = "tokio"))]
    pub(crate) event_tx: (),
    /// Chain runtime for unified chain operations.
    pub(crate) chain_runtime: ChainRuntime,
}

impl CsvClient {
    /// Create a new [`ClientBuilder`] for constructing a `CsvClient`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    ///
    /// let client = CsvClient::builder()
    ///     .with_chain("bitcoin")
    ///     .with_store_backend(StoreBackend::InMemory)
    ///     .build()?;
    /// # Ok::<_, csv_sdk::CsvError>(())
    /// ```
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Create a new [`ScalableClientBuilder`] for constructing a `CsvClient` with dynamic chain support.
    ///
    /// This builder supports dynamic chain loading from configuration files and chain registries,
    /// enabling support for unlimited chains without code changes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    ///
    /// let client = CsvClient::builder()
    ///     .with_chain("bitcoin")
    ///     .with_chain("ethereum")
    ///     .build()?;
    /// # Ok::<_, csv_adapter::CsvError>(())
    /// ```
    #[deprecated(since = "0.4.0", note = "Use CsvClient::builder() instead")]
    pub fn scalable_builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Get a [`SanadsManager`] for creating, querying, and managing Sanads.
    pub fn sanads(&self) -> SanadsManager {
        SanadsManager::new(Arc::new(self.clone_ref()))
    }

    /// Get a [`TransferManager`] for cross-chain transfer operations.
    pub fn transfers(&self) -> TransferManager {
        TransferManager::new(
            Arc::new(self.clone_ref()),
            Arc::new(self.chain_runtime.clone()),
        )
    }

    /// Get a [`WalletManager`] for wallet operations.
    ///
    /// # Errors
    ///
    /// Returns an error if no wallet was attached to the client.
    pub fn wallet(&self) -> Result<WalletManager, CsvError> {
        self.wallet
            .as_ref()
            .map(|w| WalletManager::new(w.clone()))
            .ok_or_else(|| {
                CsvError::BuilderError(
                    "No wallet attached. Use .with_wallet() when building the client.".to_string(),
                )
            })
    }

    /// Returns an error indicating that contract deployment is not supported.
    ///
    /// Contract deployment must be done manually using Foundry/forge.
    /// Once deployed, provide the contract address directly to the SDK.
    pub fn deploy(&self) -> crate::Result<()> {
        Err(CsvError::CapabilityUnavailable {
            chain: csv_hash::chain_id::ChainId::new("unknown"),
            capability: "contract_deployment".to_string(),
        })
    }

    /// Get an [`EventStream`] for watching CSV events.
    ///
    /// Returns a stream that receives events emitted by this client
    /// and its managers.
    #[cfg(feature = "tokio")]
    pub fn watch(&self) -> EventStream {
        EventStream::new(self.event_tx.subscribe())
    }

    /// Check if a specific chain is enabled.
    pub fn is_chain_enabled(&self, chain: ChainId) -> bool {
        self.enabled_chains.contains(&chain)
    }

    /// Get the set of enabled chains.
    pub fn enabled_chains(&self) -> &HashSet<ChainId> {
        &self.enabled_chains
    }

    /// Get a reference to the attached wallet, if any.
    pub fn wallet_ref(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a reference to the chain runtime for unified chain operations.
    ///
    /// The chain runtime provides all chain operations (balance queries,
    /// transaction signing, broadcasting, proof generation, etc.) through
    /// a unified interface that delegates to the appropriate chain adapters.
    pub fn chain_runtime(&self) -> &ChainRuntime {
        &self.chain_runtime
    }

    /// Initialize and register chain adapters for all enabled chains.
    ///
    /// This method must be called after building the client to instantiate
    /// and register the actual chain adapter implementations. Without this,
    /// the runtime will have no adapters and chain operations will fail with
    /// "Chain not supported" errors.
    ///
    /// # Arguments
    ///
    /// * `network` - Network type (Mainnet or Testnet) to configure RPC endpoints
    /// * `private_keys` - Optional map of chain to private key in hex format (with or without 0x prefix)
    ///                   Only needed if performing transactions that require signing.
    ///                   The private keys are NOT stored in config.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    /// use std::collections::HashMap;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<()> {
    ///     let client = CsvClient::builder()
    ///         .with_chain("bitcoin")
    ///         .with_chain("ethereum")
    ///         .with_store_backend(StoreBackend::InMemory)
    ///         .build()?;
    ///
    ///     // Initialize adapters for all enabled chains on testnet
    ///     // Pass private keys interactively (not stored in config)
    ///     let mut keys = HashMap::new();
    ///     keys.insert("ethereum", Some("0x..."));
    ///     keys.insert("bitcoin", Some("..."));
    ///     client.init_adapters(NetworkType::Testnet, keys).await?;
    ///
    ///     // Now you can use the runtime
    ///     let balance = client.chain_runtime()
    ///         .get_balance("bitcoin", "bc1...")
    ///         .await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn init_adapters(&self, network: NetworkType, private_keys: std::collections::HashMap<String, Option<String>>) -> Result<(), CsvError> {
        let mut failed_chains: Vec<String> = Vec::new();

        for chain in &self.enabled_chains {
            let private_key = private_keys.get(chain.as_str()).and_then(|k| k.as_deref());
            let adapter_result =
                Self::build_adapter_for_chain(chain.clone(), &self.config, network, private_key).await;

            match adapter_result {
                Ok(Some(adapter)) => {
                    self.chain_runtime
                        .register_adapter(chain.clone(), adapter)
                        .await;
                    log::info!(
                        "Initialized adapter for chain: {:?} on {:?}",
                        chain,
                        network
                    );
                }
                Ok(None) => {
                    log::debug!(
                        "Skipping adapter initialization for unsupported chain: {:?}",
                        chain
                    );
                }
                Err(e) => {
                    log::warn!("Failed to initialize adapter for chain {:?}: {}", chain, e);
                    failed_chains.push(chain.to_string());
                }
            }
        }

        let registered = self.chain_runtime.registered_chains().await;
        if registered.is_empty() && !failed_chains.is_empty() {
            return Err(CsvError::ConfigError(format!(
                "No chain adapters could be initialized. Failed chains: [{}]. \
                     Check your configuration (e.g., Bitcoin requires an xpub for seal protocol).",
                failed_chains.join(", ")
            )));
        }

        Ok(())
    }

    /// Initialize and register chain adapters for all enabled chains (without signer).
    ///
    /// This is a convenience method for chains that don't require signing.
    pub async fn init_adapters_simple(&self, network: NetworkType) -> Result<(), CsvError> {
        self.init_adapters(network, std::collections::HashMap::new()).await
    }

    /// Build an adapter for a specific chain.
    #[allow(unused_variables)]
    async fn build_adapter_for_chain(
        chain: ChainId,
        _config: &crate::config::Config,
        network: NetworkType,
        private_key: Option<&str>,
    ) -> Result<Option<std::sync::Arc<dyn csv_protocol::backend::ChainBackend>>, CsvError> {
        let _builder = crate::runtime::AdapterBuilder::new();
        let _is_testnet = matches!(network, NetworkType::Testnet);

        match chain.as_str() {
            #[cfg(all(feature = "bitcoin", feature = "rpc"))]
            "bitcoin" => {
                log::info!("Building Bitcoin adapter for {:?} network", network);
                let config_rpc_url = _config
                    .chains
                    .get("bitcoin")
                    .map(|c| c.rpc.url.clone())
                    .filter(|url| !url.is_empty())
                    .unwrap_or_else(|| {
                        if _is_testnet {
                            "https://mempool.space/signet/api".to_string()
                        } else {
                            "https://mempool.space/api".to_string()
                        }
                    });
                eprintln!("SDK LAYER: RPC URL from SDK config: {}", config_rpc_url);
                let rpc_url = config_rpc_url;
                let btc_network = if _is_testnet {
                    csv_bitcoin::Network::Signet
                } else {
                    csv_bitcoin::Network::Mainnet
                };
                log::info!("Building Bitcoin adapter with RPC URL: {}", rpc_url);
                let chain_config = _config.chains.get("bitcoin");
                let mut utxos = Vec::new();
                if let Some(cc) = chain_config {
                    // Convert UTXO records from SDK config to Bitcoin adapter config
                    for utxo in &cc.utxos {
                        eprintln!("DEBUG SDK: Received UTXO from CLI: txid={}, vout={}", utxo.txid, utxo.vout);
                        utxos.push(csv_bitcoin::config::UtxoConfig {
                            txid: utxo.txid.clone(),
                            vout: utxo.vout,
                            value: utxo.value,
                            account: utxo.account,
                            index: utxo.index,
                            script_pubkey: utxo.script_pubkey.clone(),
                        });
                    }
                }

                let btc_config = csv_bitcoin::config::BitcoinConfig {
                    network: btc_network,
                    finality_depth: 6,
                    publication_timeout_seconds: 3600,
                    rpc_url: rpc_url.clone(),
                    rpc_backend: csv_bitcoin::BitcoinRpcBackend::BitcoinCoreJsonRpc, // Default to JSON-RPC, will be auto-detected by with_env_rpc
                    api_key: None, // Will be loaded by with_env_rpc if using Tatum
                    xpub: chain_config.and_then(|c| c.xpub.clone()),
                    private_key: None, // Not used when seed is provided
                    seed: private_key.map(|k| k.to_string()), // Pass seed for Bitcoin
                    account: chain_config.map(|c| c.account).unwrap_or(0),
                    index: chain_config.map(|c| c.index).unwrap_or(0),
                    utxos,
                };
                eprintln!("SDK LAYER: BitcoinConfig before with_env_rpc - RPC URL: {}, Account: {}, Index: {}", btc_config.rpc_url, btc_config.account, btc_config.index);
                let btc_config = btc_config.with_env_rpc().map_err(|e| CsvError::ProtocolError {
                    chain: chain.clone(),
                    message: format!("Failed to apply env RPC override: {}", e),
                })?; // Override RPC URL from environment variable if set
                
                // Auto-detect backend type from URL if not already set correctly
                let btc_config = btc_config.auto_detect_backend();
                eprintln!("SDK LAYER: BitcoinConfig after with_env_rpc - RPC URL: {}, backend: {:?}", btc_config.rpc_url, btc_config.rpc_backend);
                // Mark private_key as intentionally unused for Bitcoin (we use seed instead)
                let _ = private_key;
                // Create RPC client - this uses reqwest::blocking which needs its own runtime
                // We must create it outside any async context to avoid runtime conflicts
                let api_key = btc_config.api_key.clone();
                let final_rpc_url = btc_config.rpc_url.clone();
                let rpc_backend = btc_config.rpc_backend;
                eprintln!("SDK LAYER: Creating RPC client with URL: {}, backend: {:?}", final_rpc_url, rpc_backend);
                
                // Create RPC client based on explicit backend type (not URL heuristics)
                let rpc = std::thread::spawn(move || {
                    match rpc_backend {
                        csv_bitcoin::BitcoinRpcBackend::MempoolRest => {
                            eprintln!("SDK LAYER: Using MempoolSignetRpc (REST API)");
                            Box::new(csv_bitcoin::mempool_rpc::MempoolSignetRpc::with_url_and_key(
                                final_rpc_url,
                                api_key,
                            )) as Box<dyn csv_bitcoin::rpc::BitcoinRpc + Send + Sync>
                        }
                        csv_bitcoin::BitcoinRpcBackend::BlockstreamRest => {
                            eprintln!("SDK LAYER: Using MempoolSignetRpc (Blockstream REST API)");
                            Box::new(csv_bitcoin::mempool_rpc::MempoolSignetRpc::with_url_and_key(
                                final_rpc_url,
                                api_key,
                            )) as Box<dyn csv_bitcoin::rpc::BitcoinRpc + Send + Sync>
                        }
                        csv_bitcoin::BitcoinRpcBackend::BitcoinCoreJsonRpc => {
                            eprintln!("SDK LAYER: Using BitcoinJsonRpc (JSON-RPC API)");
                            Box::new(csv_bitcoin::BitcoinJsonRpc::new(final_rpc_url)) as Box<dyn csv_bitcoin::rpc::BitcoinRpc + Send + Sync>
                        }
                    }
                })
                .join()
                .map_err(|e| CsvError::ProtocolError {
                    chain,
                    message: format!("Thread panic: {:?}", e),
                })?;
                _builder
                    .bitcoin_from_config(btc_config, rpc)
                    .await
                    .map(Some)
            }
            #[cfg(all(feature = "bitcoin", not(feature = "rpc")))]
            "bitcoin" => {
                log::warn!("Bitcoin adapter requires 'rpc' feature for RPC client; skipping");
                Ok(None)
            }
            #[cfg(feature = "ethereum")]
            "ethereum" => {
                let rpc_url = _config
                    .chains
                    .get("ethereum")
                    .map(|c| c.rpc.url.clone())
                    .filter(|url| !url.is_empty())
                    .unwrap_or_else(|| {
                        if _is_testnet {
                            "https://ethereum-sepolia-rpc.publicnode.com".to_string()
                        } else {
                            "https://ethereum-rpc.publicnode.com".to_string()
                        }
                    });
                let eth_network = if _is_testnet {
                    csv_ethereum::config::Network::Sepolia
                } else {
                    csv_ethereum::config::Network::Mainnet
                };
                let eth_config = csv_ethereum::config::EthereumConfig {
                    network: eth_network,
                    finality_depth: if _is_testnet { 15 } else { 12 },
                    use_checkpoint_finality: !_is_testnet,
                    rpc_url: rpc_url.clone(),
                    private_key: None,
                    contract_address: None,
                };
                let address = _config
                    .chains
                    .get("ethereum")
                    .and_then(|chain| chain.contract_address.as_deref())
                    .ok_or_else(|| {
                        CsvError::ConfigError(
                            "Ethereum seal contract address must be configured".to_string(),
                        )
                    })?;
                let address_bytes = hex::decode(address.trim_start_matches("0x")).map_err(|e| {
                    CsvError::ConfigError(format!("Invalid Ethereum seal contract address: {e}"))
                })?;
                let csv_seal_address: [u8; 20] = address_bytes.try_into().map_err(|_| {
                    CsvError::ConfigError(
                        "Ethereum seal contract address must contain 20 bytes".to_string(),
                    )
                })?;
                let mut rpc = csv_ethereum::node::EthereumNode::new(&rpc_url, csv_seal_address)
                    .await
                    .map_err(|e| CsvError::ProtocolError {
                        chain: ChainId::new("ethereum"),
                        message: format!("Failed to create Ethereum RPC client: {}", e),
                    })?;

                // Configure signer if private key is provided
                if let Some(private_key) = private_key {
                    rpc = rpc.with_signer(private_key).map_err(|e| CsvError::ProtocolError {
                        chain: ChainId::new("ethereum"),
                        message: format!("Failed to configure Ethereum signer: {}", e),
                    })?;
                }
                _builder
                    .ethereum_from_config(
                        eth_config,
                        Box::new(rpc) as Box<dyn csv_ethereum::rpc::EthereumRpc>,
                        csv_seal_address,
                    )
                    .await
                    .map(Some)
            }
            #[cfg(feature = "sui")]
            "sui" => {
                let rpc_url = _config
                    .chains
                    .get("sui")
                    .map(|c| c.rpc.url.clone())
                    .filter(|url| !url.is_empty())
                    .unwrap_or_else(|| {
                        if _is_testnet {
                            "https://fullnode.testnet.sui.io:443".to_string()
                        } else {
                            "https://fullnode.mainnet.sui.io:443".to_string()
                        }
                    });
                let sui_network = if _is_testnet {
                    csv_sui::config::SuiNetwork::Testnet
                } else {
                    csv_sui::config::SuiNetwork::Mainnet
                };
                let mut sui_config = csv_sui::config::SuiConfig::new(sui_network);
                sui_config.rpc_url = rpc_url.clone();
                sui_config.seal_contract.package_id = Some(
                    _config
                        .chains
                        .get("sui")
                        .and_then(|chain| chain.contract_address.clone())
                        .ok_or_else(|| {
                            CsvError::ConfigError(
                                "Sui seal package ID must be configured".to_string(),
                            )
                        })?,
                );
                // Convert hex string to Vec<u8> for Sui and derive signer address
                let signer_address = if let Some(pk) = private_key {
                    let cleaned = pk.trim_start_matches("0x");
                    if let Ok(key_bytes) = hex::decode(cleaned) {
                        sui_config.signer_private_key = Some(key_bytes.clone());
                        if key_bytes.len() == 32 {
                            use ed25519_dalek::SigningKey;
                            let key_array: [u8; 32] = key_bytes
                                .try_into()
                                .map_err(|_| CsvError::ConfigError(
                                    "Invalid Sui private key length".to_string()
                                ))?;
                            let signing_key = SigningKey::from_bytes(&key_array);
                            let public_key = signing_key.verifying_key();
                            let signer_addr = format!("0x{}", hex::encode(public_key.as_bytes()));
                            sui_config.signer_address = Some(signer_addr.clone());
                            
                            // Parse signer address bytes for RPC client
                            let signer_addr_bytes = hex::decode(signer_addr.trim_start_matches("0x"))
                                .map_err(|e| CsvError::ConfigError(format!("Invalid signer address: {}", e)))?;
                            let signer_addr_array: [u8; 32] = signer_addr_bytes.try_into()
                                .map_err(|_| CsvError::ConfigError("Signer address must be 32 bytes".to_string()))?;
                            Some(signer_addr_array)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    sui_config.signer_private_key = None;
                    None
                };
                
                // Create SuiNode
                let node = csv_sui::node::SuiNode::new(&rpc_url)
                    .map_err(|e| CsvError::ConfigError(format!("Failed to create Sui node: {}", e)))?;
                
                _builder
                    .sui_from_config(sui_config, std::sync::Arc::new(node))
                    .await
                    .map(Some)
            }
            #[cfg(feature = "aptos")]
            "aptos" => {
                let rpc_url = _config
                    .chains
                    .get("aptos")
                    .map(|c| c.rpc.url.clone())
                    .filter(|url| !url.is_empty())
                    .unwrap_or_else(|| {
                        if _is_testnet {
                            "https://api.testnet.aptoslabs.com/v1".to_string()
                        } else {
                            "https://api.mainnet.aptoslabs.com/v1".to_string()
                        }
                    });
                
                // Derive signer address from private key if available
                // In Aptos, address = last 32 bytes of sha3-256(public_key + 0x00)
                let signer_address = if let Some(pk) = private_key {
                    let cleaned = pk.trim().trim_start_matches("0x");
                    if let Ok(key_bytes) = hex::decode(cleaned) {
                        if key_bytes.len() == 32 {
                            use ed25519_dalek::SigningKey;
                            use sha3::{Digest, Sha3_256};
                            log::info!("SDK LAYER: Private key (first 8 bytes): 0x{}", hex::encode(&key_bytes[..8]));
                            let key_array: [u8; 32] = key_bytes
                                .try_into()
                                .map_err(|_| CsvError::ConfigError(
                                    "Invalid Aptos private key length".to_string()
                                ))?;
                            let signing_key = SigningKey::from_bytes(&key_array);
                            let public_key = signing_key.verifying_key();
                            let public_key_bytes = public_key.as_bytes();

                            log::info!("SDK LAYER: Public key (first 8 bytes): 0x{}", hex::encode(&public_key_bytes[..8]));

                            // Aptos address derivation: sha3-256(public_key || 0x00), take last 32 bytes
                            let mut hasher = Sha3_256::new();
                            hasher.update(public_key_bytes);
                            hasher.update(&[0x00u8]); // Scheme byte for Ed25519
                            let hash = hasher.finalize();
                            let mut addr_array = [0u8; 32];
                            addr_array.copy_from_slice(&hash[..32]);

                            log::info!("SDK LAYER: Derived Aptos signer address: 0x{}", hex::encode(addr_array));
                            Some(addr_array)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                let mut aptos_config = csv_aptos::AptosConfig {
                    network: if _is_testnet {
                        csv_aptos::config::AptosNetwork::Testnet
                    } else {
                        csv_aptos::config::AptosNetwork::Mainnet
                    },
                    rpc_url: rpc_url.clone(),
                    private_key: private_key.map(|k| k.to_string()),
                    ..Default::default()
                };
                // Set module_address from config if available
                if let Some(contract_address) = _config
                    .chains
                    .get("aptos")
                    .and_then(|chain| chain.contract_address.clone())
                {
                    aptos_config.seal_contract.module_address = contract_address;
                }
                
                // Create AptosNode with signer address if available
                let rpc = if let Some(signer_addr) = signer_address {
                    csv_aptos::node::AptosNode::with_signer_address(&rpc_url, signer_addr)
                } else {
                    csv_aptos::node::AptosNode::new(&rpc_url)
                };
                
                _builder
                    .aptos_from_config(
                        aptos_config,
                        Box::new(rpc) as Box<dyn csv_aptos::rpc::AptosRpc>,
                    )
                    .await
                    .map(Some)
            }
            #[cfg(feature = "solana")]
            "solana" => {
                let rpc_url = _config
                    .chains
                    .get("solana")
                    .map(|c| c.rpc.url.clone())
                    .filter(|url| !url.is_empty())
                    .unwrap_or_else(|| {
                        if _is_testnet {
                            "https://api.devnet.solana.com".to_string()
                        } else {
                            "https://api.mainnet-beta.solana.com".to_string()
                        }
                    });
                let sol_network = if _is_testnet {
                    csv_solana::config::Network::Devnet
                } else {
                    csv_solana::config::Network::Mainnet
                };
                
                // Convert hex private key to base58 keypair for Solana
                let keypair_base58 = if let Some(pk) = private_key {
                    let cleaned = pk.trim().trim_start_matches("0x");
                    if let Ok(key_bytes) = hex::decode(cleaned) {
                        if key_bytes.len() == 32 {
                            use ed25519_dalek::SigningKey;
                            let key_array: [u8; 32] = key_bytes
                                .try_into()
                                .map_err(|_| CsvError::ConfigError(
                                    "Invalid Solana private key length".to_string()
                                ))?;
                            let signing_key = SigningKey::from_bytes(&key_array);
                            let public_key = signing_key.verifying_key();
                            
                            // Solana keypair is 64 bytes: [secret_key(32) || public_key(32)]
                            let mut keypair_bytes = [0u8; 64];
                            keypair_bytes[..32].copy_from_slice(&key_array);
                            keypair_bytes[32..].copy_from_slice(public_key.as_bytes());
                            
                            // Encode in base58
                            Some(bs58::encode(keypair_bytes).into_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                let program_id_from_config = _config
                    .chains
                    .get("solana")
                    .and_then(|chain| chain.program_id.clone())
                    .ok_or_else(|| {
                        CsvError::ConfigError(
                            "Solana CSV program ID must be configured".to_string(),
                        )
                    })?;
                log::info!("SDK: Solana program_id from config: {}", program_id_from_config);

                let sol_config = csv_solana::config::SolanaConfig {
                    network: sol_network,
                    rpc_url: rpc_url.clone(),
                    csv_program_id: program_id_from_config,
                    keypair: keypair_base58,
                    commitment: Some("confirmed".to_string()),
                    max_retries: 3,
                    timeout_seconds: 30,
                };
                let rpc = Box::new(csv_solana::node::SolanaNode::new(&rpc_url));
                _builder.solana_from_config(sol_config, rpc).await.map(Some)
            }
            _ => Ok(None), // Skip unsupported chains
        }
    }

    /// Emit an event to all event stream subscribers.
    #[cfg(feature = "tokio")]
    #[allow(dead_code)]
    pub(crate) fn emit_event(&self, event: crate::events::Event) {
        // Best-effort: ignore if no receivers
        let _ = self.event_tx.send(event);
    }

    /// Emit an event (no-op when tokio feature is disabled)
    #[cfg(not(feature = "tokio"))]
    #[allow(dead_code)]
    pub(crate) fn emit_event(&self, _event: crate::events::Event) {
        // No-op: event system requires tokio feature
    }

    // Internal: create a cheap clone reference for managers
    fn clone_ref(&self) -> ClientRef {
        ClientRef {
            enabled_chains: self.enabled_chains.clone(),
            wallet: self.wallet.clone(),
            store: Arc::clone(&self.store),
            config: self.config.clone(),
            event_tx: self.event_tx.clone(),
            chain_runtime: Some(self.chain_runtime.clone()),
        }
    }
}

/// A shareable reference to the client's state, used by managers.
///
/// This is an internal type that allows managers to hold a reference
/// to the client without the full `CsvClient` struct.
#[allow(dead_code)]
pub(crate) struct ClientRef {
    pub(crate) enabled_chains: HashSet<ChainId>,
    #[allow(dead_code)]
    pub(crate) wallet: Option<Wallet>,
    #[allow(dead_code)]
    pub(crate) store: Arc<std::sync::Mutex<StoreHandle>>,
    #[allow(dead_code)]
    pub(crate) config: Config,
    #[cfg(feature = "tokio")]
    pub(crate) event_tx: broadcast::Sender<crate::events::Event>,
    #[cfg(not(feature = "tokio"))]
    pub(crate) event_tx: (),
    /// Chain runtime for unified chain operations.
    #[allow(dead_code)]
    pub(crate) chain_runtime: Option<crate::runtime::ChainRuntime>,
}

impl ClientRef {
    /// Create a new empty ClientRef (used by RuntimeManager for testing)
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        #[cfg(feature = "tokio")]
        use tokio::sync::broadcast;
        #[cfg(feature = "tokio")]
        let event_tx = broadcast::channel(256).0;
        #[cfg(not(feature = "tokio"))]
        let event_tx = ();

        Self {
            enabled_chains: HashSet::new(),
            wallet: None,
            store: Arc::new(std::sync::Mutex::new(crate::client::StoreHandle::InMemory(
                InMemorySealStore::new(),
            ))),
            config: Config::default(),
            event_tx,
            chain_runtime: None,
        }
    }

    pub(crate) fn is_chain_enabled(&self, chain: ChainId) -> bool {
        self.enabled_chains.contains(&chain)
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn emit_event(&self, event: crate::events::Event) {
        let _ = self.event_tx.send(event);
    }

    #[cfg(not(feature = "tokio"))]
    pub(crate) fn emit_event(&self, _event: crate::events::Event) {
        // No-op: event system requires tokio feature
    }
}
