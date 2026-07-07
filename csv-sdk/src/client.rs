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

// Import adapter registry for cross-chain transfers
use csv_runtime::adapter_registry::AdapterRegistryImpl;

#[cfg(feature = "runtime-coordinator")]
use csv_adapter_factory::{
    AdapterConfig, AdapterFactory, AdapterResult as FactoryAdapterResult, AptosFactory,
    BitcoinFactory, EthereumFactory, NetworkType as FactoryNetworkType, RpcEndpoint, RpcProtocol,
    SolanaFactory, SuiFactory,
};
#[cfg(not(feature = "runtime-coordinator"))]
use csv_keys::memory::SecretKey;
#[cfg(feature = "runtime-coordinator")]
use csv_protocol::secret::SharedSecretHandle;

#[cfg(feature = "runtime-coordinator")]
// Type alias for factory result
/// Result type returned by the adapter factory
pub type AdapterResult = FactoryAdapterResult;

#[cfg(not(feature = "runtime-coordinator"))]
// Type alias for legacy result (no factory support)
pub type AdapterResult = std::sync::Arc<dyn csv_protocol::chain_adapter_traits::ChainBackend>;

#[cfg(feature = "runtime-coordinator")]
use csv_runtime::TransferCoordinator;

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
    pub fn get_sanad(&self, sanad_id: &str) -> Result<Option<SanadRecord>, CsvError> {
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
    pub fn consume_sanad(&mut self, sanad_id: &str, consumed_at: u64) -> Result<(), CsvError> {
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
    pub fn has_sanad(&self, sanad_id: &str) -> Result<bool, CsvError> {
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
    /// Adapter registry for cross-chain transfers.
    pub(crate) adapter_registry: Arc<std::sync::Mutex<AdapterRegistryImpl>>,
    /// Transfer coordinator for production-grade cross-chain transfer execution.
    #[cfg(feature = "runtime-coordinator")]
    pub(crate) transfer_coordinator: Option<Arc<TransferCoordinator>>,
    /// Private keys for chain adapters (chain name -> typed SharedSecretHandle)
    pub(crate) private_keys:
        Option<std::collections::HashMap<String, csv_protocol::secret::SharedSecretHandle>>,
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
        let mut manager = TransferManager::new(
            Arc::new(self.clone_ref()),
            Arc::new(self.chain_runtime.clone()),
        )
        .with_adapter_registry(self.adapter_registry.clone());

        #[cfg(feature = "runtime-coordinator")]
        if let Some(coordinator) = self.transfer_coordinator.as_ref() {
            manager = manager.with_coordinator(coordinator.clone());
        }

        manager
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

    /// Register a chain adapter for cross-chain transfers.
    ///
    /// This method allows manual registration of chain adapters that implement
    /// the `ChainAdapter` trait from `csv_adapter_core`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    /// use csv_bitcoin::runtime_adapter::BitcoinRuntimeAdapter;
    ///
    /// let client = CsvClient::builder()
    ///     .with_chain("bitcoin")
    ///     .build()?;
    ///
    /// // Register Bitcoin adapter for cross-chain transfers
    /// let bitcoin_adapter = Box::new(BitcoinRuntimeAdapter::new(
    ///     bitcoin::Network::Regtest,
    ///     wallet,
    ///     rpc,
    /// )) as Box<dyn csv_adapter_core::ChainAdapter>;
    ///
    /// client.register_adapter(bitcoin_adapter)?;
    /// # Ok::<_, csv_sdk::CsvError>(())
    /// ```
    pub fn register_adapter(
        &self,
        adapter: Box<dyn csv_adapter_core::ChainAdapter>,
    ) -> Result<(), CsvError> {
        self.adapter_registry
            .lock()
            .map_err(|e| CsvError::Generic(format!("Failed to lock adapter registry: {}", e)))?
            .register_adapter(adapter)
            .map_err(|e| CsvError::Generic(format!("Failed to register adapter: {}", e)))
    }

    /// Get the adapter registry for cross-chain transfers.
    ///
    /// This provides access to the `AdapterRegistry` which can be used by
    /// the `TransferCoordinator` for cross-chain transfer operations.
    pub fn adapter_registry(&self) -> Arc<std::sync::Mutex<AdapterRegistryImpl>> {
        self.adapter_registry.clone()
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

    /// Get a reference to the TransferCoordinator if enabled.
    ///
    /// The TransferCoordinator provides production-grade cross-chain transfer
    /// execution with replay protection, durable recovery, lease enforcement,
    /// and canonical verification.
    ///
    /// Returns `None` if the client was built without the runtime-coordinator feature
    /// or if `with_runtime_coordinator()` was not called during client construction.
    #[cfg(feature = "runtime-coordinator")]
    pub fn coordinator(&self) -> Option<&Arc<TransferCoordinator>> {
        self.transfer_coordinator.as_ref()
    }

    /// Register a sanad_id -> seal mapping on the Bitcoin adapter for cross-chain lock lookups.
    /// This is needed because the wallet is created fresh each time and doesn't persist UTXOs.
    #[cfg(feature = "bitcoin")]
    pub fn register_sanad_seal(
        &self,
        chain: &str,
        sanad_id: [u8; 32],
        txid: Vec<u8>,
        vout: u32,
    ) -> Result<(), CsvError> {
        if let Some(adapter) = self
            .adapter_registry
            .lock()
            .map_err(|e| CsvError::ProtocolError {
                chain: csv_hash::ChainId::new(chain),
                message: format!("Failed to lock adapter registry: {}", e),
            })?
            .get(chain)
            && let Some(sanad_ops) = (**adapter)
                .as_any()
                .downcast_ref::<csv_bitcoin::BitcoinChainSanadOps>()
        {
            sanad_ops.register_sanad_seal(sanad_id, txid, vout);
            return Ok(());
        }
        Err(CsvError::ProtocolError {
            chain: csv_hash::ChainId::new(chain),
            message: format!("Bitcoin adapter not found for chain: {}", chain),
        })
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
    ///   Only needed if performing transactions that require signing.
    ///   The private keys are NOT stored in config.
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
    /// Build an adapter for a specific chain.
    #[allow(unused_variables)]
    pub async fn build_adapter_for_chain(
        chain: ChainId,
        _config: &crate::config::Config,
        network: NetworkType,
        private_keys: Option<
            std::collections::HashMap<String, csv_protocol::secret::SharedSecretHandle>,
        >,
    ) -> Result<Option<AdapterResult>, CsvError> {
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
                            std::env::var("BITCOIN_ALCHEMY_SIGNET_HTTP_RPC").unwrap_or_else(|_| {
                                "https://bitcoin-signet.g.alchemy.com/v2/".to_string()
                            })
                        } else {
                            std::env::var("BITCOIN_ANKR_SIGNET_HTTP_RPC")
                                .unwrap_or_else(|_| "https://rpc.ankr.com/btc".to_string())
                        }
                    });
                let rpc_url = config_rpc_url;
                let chain_config = _config.chains.get("bitcoin");
                let mut utxos = Vec::new();
                let mut sanad_seals = Vec::new();
                if let Some(cc) = chain_config {
                    log::info!("SDK: Chain config has {} UTXOs", cc.utxos.len());
                    // Convert UTXO records from SDK config to Bitcoin adapter config
                    for utxo in &cc.utxos {
                        log::info!(
                            "SDK: Converting UTXO: txid={}, vout={}, value={}",
                            utxo.txid,
                            utxo.vout,
                            utxo.value
                        );
                        utxos.push(csv_adapter_factory::UtxoConfig {
                            txid: utxo.txid.clone(),
                            vout: utxo.vout,
                            value: utxo.value,
                            account: utxo.account,
                            index: utxo.index,
                            script_pubkey: utxo.script_pubkey.clone(),
                        });
                    }
                    log::info!(
                        "SDK: Converted {} UTXOs to Bitcoin adapter config",
                        utxos.len()
                    );
                    // Convert sanad seal records from SDK config to Bitcoin adapter config
                    for seal in &cc.sanad_seals {
                        sanad_seals.push(csv_adapter_factory::SanadSealConfig {
                            sanad_id: seal.sanad_id.clone(),
                            anchor_txid: seal.anchor_txid.clone(),
                            vout: seal.vout,
                            commitment: seal.commitment.clone(),
                        });
                    }
                }

                // Extract Bitcoin seed from chain config if available (64-byte BIP-39 seed)
                let bitcoin_seed_hex = chain_config.and_then(|c| c.seed.clone());

                // Extract Bitcoin private key from private_keys if available (32-byte)
                let bitcoin_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("bitcoin"))
                    .and_then(|k| k.as_bytes().map(|b| b.to_vec()));

                // Create RPC endpoint configuration. Address scanning + queries
                // need a REST indexer; the transport is chosen explicitly from
                // config (never sniffed). For Alchemy's Blockbook UTXO API, point
                // the endpoint at the Blockbook base with the Blockbook protocol —
                // that one client serves scan, gettxout, fees and broadcast.
                let indexer_backend = chain_config.and_then(|c| c.rpc.indexer_backend.clone());
                let indexer_url = chain_config.and_then(|c| c.rpc.indexer_url.clone());
                let (endpoint_url, protocol) = match indexer_backend.as_deref() {
                    Some("blockbook") | Some("alchemy") => (
                        indexer_url.clone().unwrap_or_else(|| rpc_url.clone()),
                        RpcProtocol::Blockbook,
                    ),
                    // esplora / default: prefer an explicit indexer_url if set.
                    _ => (
                        indexer_url.clone().unwrap_or_else(|| rpc_url.clone()),
                        RpcProtocol::Rest,
                    ),
                };
                let rpc_endpoint = RpcEndpoint {
                    url: endpoint_url,
                    protocol,
                    api_key: chain_config.and_then(|c| c.rpc.api_key.clone()),
                    priority: 0,
                };

                // Create adapter config for factory
                let factory_network = if _is_testnet {
                    FactoryNetworkType::Testnet
                } else {
                    FactoryNetworkType::Mainnet
                };

                let adapter_config = AdapterConfig {
                    chain_id: chain.clone(),
                    network: factory_network,
                    rpc_endpoints: vec![rpc_endpoint],
                    secret_key: bitcoin_private_key
                        .and_then(|bytes| bytes.try_into().map(|arr: [u8; 32]| arr).ok())
                        .map(SharedSecretHandle::from_bytes)
                        .unwrap_or_default(),
                    seed: bitcoin_seed_hex,
                    account: chain_config.map(|c| c.account).unwrap_or(0),
                    index: chain_config.map(|c| c.index).unwrap_or(0),
                    contract_address: None,
                    program_id: None,
                    utxos,
                    sanad_seals,
                };

                // Use factory to create adapter
                let factory = BitcoinFactory;
                let result = factory.create_adapter(adapter_config).await.map_err(|e| {
                    CsvError::ProtocolError {
                        chain: chain.clone(),
                        message: format!("Factory failed to create Bitcoin adapter: {}", e),
                    }
                })?;

                // Register ChainAdapter in adapter_registry for TransferCoordinator
                if result.chain_adapter.is_some() {
                    log::info!("SDK: Created Bitcoin ChainAdapter for TransferCoordinator");
                }

                Ok(Some(result))
            }
            #[cfg(all(feature = "bitcoin", not(feature = "rpc")))]
            "bitcoin" => {
                log::warn!("Bitcoin adapter requires 'rpc' feature for RPC client; skipping");
                Ok(None)
            }
            #[cfg(all(feature = "ethereum", feature = "runtime-coordinator"))]
            "ethereum" => {
                log::info!("Building Ethereum adapter for {:?} network", network);
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
                let chain_config = _config.chains.get("ethereum");

                let address = chain_config
                    .and_then(|chain| chain.contract_address.as_deref())
                    .ok_or_else(|| {
                        CsvError::ConfigError(
                            "Ethereum seal contract address must be configured".to_string(),
                        )
                    })?;

                // Extract Ethereum private key from private_keys if available
                let eth_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("ethereum"))
                    .and_then(|k| k.as_bytes().map(|b| b.to_vec()));

                // Create RPC endpoint configuration
                let rpc_endpoint = RpcEndpoint {
                    url: rpc_url.clone(),
                    protocol: RpcProtocol::JsonRpc,
                    api_key: chain_config.and_then(|c| c.rpc.api_key.clone()),
                    priority: 0,
                };

                // Create adapter config for factory
                let factory_network = if _is_testnet {
                    FactoryNetworkType::Testnet
                } else {
                    FactoryNetworkType::Mainnet
                };

                let adapter_config = AdapterConfig {
                    chain_id: chain.clone(),
                    network: factory_network,
                    rpc_endpoints: vec![rpc_endpoint],
                    secret_key: eth_private_key
                        .and_then(|bytes| bytes.try_into().map(|arr: [u8; 32]| arr).ok())
                        .map(SharedSecretHandle::from_bytes)
                        .unwrap_or_default(),
                    seed: None,
                    account: 0,
                    index: 0,
                    contract_address: Some(address.to_string()),
                    program_id: None,
                    utxos: vec![],
                    sanad_seals: vec![],
                };

                // Use factory to create adapter
                let factory = EthereumFactory;
                let result = factory.create_adapter(adapter_config).await.map_err(|e| {
                    CsvError::ProtocolError {
                        chain: chain.clone(),
                        message: format!("Factory failed to create Ethereum adapter: {}", e),
                    }
                })?;

                // Register ChainAdapter in adapter_registry for TransferCoordinator
                if result.chain_adapter.is_some() {
                    log::info!("SDK: Created Ethereum ChainAdapter for TransferCoordinator");
                }

                Ok(Some(result))
            }
            #[cfg(all(feature = "ethereum", not(feature = "runtime-coordinator")))]
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
                let eth_config = csv_ethereum::config::EthereumConfig {
                    network: eth_network,
                    finality_depth: if _is_testnet { 15 } else { 12 },
                    use_checkpoint_finality: !_is_testnet,
                    rpc_url: rpc_url.clone(),
                    private_key: private_keys
                        .as_ref()
                        .and_then(|keys| keys.get("ethereum"))
                        .and_then(|key| key.as_bytes())
                        .map(|bytes| SecretKey::new(*bytes)),
                    contract_address: Some(csv_seal_address),
                };
                let mut rpc = csv_ethereum::node::EthereumNode::new(&rpc_url, csv_seal_address)
                    .await
                    .map_err(|e| CsvError::ProtocolError {
                        chain: ChainId::new("ethereum"),
                        message: format!("Failed to create Ethereum RPC client: {}", e),
                    })?;

                // Configure signer if private key is provided
                let eth_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("ethereum"))
                    .and_then(|k| k.as_bytes())
                    .map(hex::encode);
                if let Some(private_key) = eth_private_key {
                    rpc = rpc
                        .with_signer(&private_key)
                        .map_err(|e| CsvError::ProtocolError {
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
            #[cfg(all(feature = "sui", feature = "runtime-coordinator"))]
            "sui" => {
                log::info!("Building Sui adapter for {:?} network", network);
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
                let chain_config = _config.chains.get("sui");

                let contract_address = chain_config
                    .and_then(|chain| chain.contract_address.as_deref())
                    .ok_or_else(|| {
                        CsvError::ConfigError("Sui seal package ID must be configured".to_string())
                    })?;

                // Extract Sui private key from private_keys if available
                let sui_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("sui"))
                    .and_then(|k| k.as_bytes().map(|b| b.to_vec()));

                // Create RPC endpoint configuration
                let rpc_endpoint = RpcEndpoint {
                    url: rpc_url.clone(),
                    protocol: RpcProtocol::Grpc,
                    api_key: chain_config.and_then(|c| c.rpc.api_key.clone()),
                    priority: 0,
                };

                // Create adapter config for factory
                let factory_network = if _is_testnet {
                    FactoryNetworkType::Testnet
                } else {
                    FactoryNetworkType::Mainnet
                };

                let adapter_config = AdapterConfig {
                    chain_id: chain.clone(),
                    network: factory_network,
                    rpc_endpoints: vec![rpc_endpoint],
                    secret_key: sui_private_key
                        .as_ref()
                        .and_then(|bytes| bytes.as_slice().try_into().map(|arr: [u8; 32]| arr).ok())
                        .map(SharedSecretHandle::from_bytes)
                        .unwrap_or_default(),
                    seed: None,
                    account: 0,
                    index: 0,
                    contract_address: Some(contract_address.to_string()),
                    program_id: None,
                    utxos: vec![],
                    sanad_seals: vec![],
                };

                // Use factory to create adapter
                let factory = SuiFactory;
                let result = factory.create_adapter(adapter_config).await.map_err(|e| {
                    CsvError::ProtocolError {
                        chain: chain.clone(),
                        message: format!("Factory failed to create Sui adapter: {}", e),
                    }
                })?;

                // Register ChainAdapter in adapter_registry for TransferCoordinator
                if result.chain_adapter.is_some() {
                    log::info!("SDK: Created Sui ChainAdapter for TransferCoordinator");
                }

                Ok(Some(result))
            }
            #[cfg(all(feature = "sui", not(feature = "runtime-coordinator")))]
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
                // Bind the shared thin-registry `Registry` object id (RFC-0012
                // §9.2 `destinationContract`) from the deployment manifest. It is
                // distinct from the package id; when unset the adapter fails
                // closed at mint time rather than defaulting.
                sui_config.seal_contract.registry_id =
                    csv_protocol::deployment_manifest::get_sui_registry_id().ok();
                // Convert hex string to Vec<u8> for Sui and derive signer address
                let sui_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("sui"))
                    .and_then(|k| k.as_bytes())
                    .copied();
                let signer_address = if let Some(pk) = sui_private_key {
                    sui_config.signer_private_key = Some(SecretKey::new(pk));
                    let key_bytes = pk;
                    {
                        use ed25519_dalek::SigningKey;
                        let signing_key = SigningKey::from_bytes(&key_bytes);
                        let public_key = signing_key.verifying_key();
                        let pubkey_bytes = public_key.as_bytes();

                        // Sui address is derived from public key using Blake2b with 0x00 prefix
                        use blake2::Blake2b;
                        use blake2::Digest as Blake2Digest;
                        let mut hasher = Blake2b::new();
                        hasher.update([0x00]); // Sui address prefix
                        hasher.update(pubkey_bytes);
                        let hash: [u8; 32] = hasher.finalize().into();
                        let signer_addr = format!("0x{}", hex::encode(hash));
                        sui_config.signer_address = Some(signer_addr.clone());

                        // Parse signer address bytes for RPC client
                        let signer_addr_bytes = hex::decode(signer_addr.trim_start_matches("0x"))
                            .map_err(|e| {
                            CsvError::ConfigError(format!("Invalid signer address: {}", e))
                        })?;
                        let signer_addr_array: [u8; 32] =
                            signer_addr_bytes.try_into().map_err(|_| {
                                CsvError::ConfigError("Signer address must be 32 bytes".to_string())
                            })?;
                        Some(signer_addr_array)
                    }
                } else {
                    sui_config.signer_private_key = None;
                    None
                };

                // Create SuiNode
                let node = csv_sui::node::SuiNode::new(&rpc_url).map_err(|e| {
                    CsvError::ConfigError(format!("Failed to create Sui node: {}", e))
                })?;

                _builder
                    .sui_from_config(sui_config, std::sync::Arc::new(node))
                    .await
                    .map(Some)
            }
            #[cfg(all(feature = "aptos", feature = "runtime-coordinator"))]
            "aptos" => {
                log::info!("Building Aptos adapter for {:?} network", network);
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
                let chain_config = _config.chains.get("aptos");

                // Extract Aptos private key from private_keys if available
                let aptos_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("aptos"))
                    .and_then(|k| k.as_bytes().map(|b| b.to_vec()));

                // Create RPC endpoint configuration. Address scanning + queries
                // need a REST indexer; the transport is chosen explicitly from
                // config (never sniffed). For Alchemy's Blockbook UTXO API, point
                // the endpoint at the Blockbook base with the Blockbook protocol —
                // that one client serves scan, gettxout, fees and broadcast.
                let indexer_backend = chain_config.and_then(|c| c.rpc.indexer_backend.clone());
                let indexer_url = chain_config.and_then(|c| c.rpc.indexer_url.clone());
                let (endpoint_url, protocol) = match indexer_backend.as_deref() {
                    Some("blockbook") | Some("alchemy") => (
                        indexer_url.clone().unwrap_or_else(|| rpc_url.clone()),
                        RpcProtocol::Blockbook,
                    ),
                    // esplora / default: prefer an explicit indexer_url if set.
                    _ => (
                        indexer_url.clone().unwrap_or_else(|| rpc_url.clone()),
                        RpcProtocol::Rest,
                    ),
                };
                let rpc_endpoint = RpcEndpoint {
                    url: endpoint_url,
                    protocol,
                    api_key: chain_config.and_then(|c| c.rpc.api_key.clone()),
                    priority: 0,
                };

                // Create adapter config for factory
                let factory_network = if _is_testnet {
                    FactoryNetworkType::Testnet
                } else {
                    FactoryNetworkType::Mainnet
                };

                let adapter_config = AdapterConfig {
                    chain_id: chain.clone(),
                    network: factory_network,
                    rpc_endpoints: vec![rpc_endpoint],
                    secret_key: aptos_private_key
                        .as_ref()
                        .and_then(|bytes| bytes.as_slice().try_into().map(|arr: [u8; 32]| arr).ok())
                        .map(SharedSecretHandle::from_bytes)
                        .unwrap_or_default(),
                    seed: None,
                    account: 0,
                    index: 0,
                    contract_address: chain_config.and_then(|c| c.contract_address.clone()),
                    program_id: None,
                    utxos: vec![],
                    sanad_seals: vec![],
                };

                // Use factory to create adapter
                let factory = AptosFactory;
                let result = factory.create_adapter(adapter_config).await.map_err(|e| {
                    CsvError::ProtocolError {
                        chain: chain.clone(),
                        message: format!("Factory failed to create Aptos adapter: {}", e),
                    }
                })?;

                // Register ChainAdapter in adapter_registry for TransferCoordinator
                if result.chain_adapter.is_some() {
                    log::info!("SDK: Created Aptos ChainAdapter for TransferCoordinator");
                }

                Ok(Some(result))
            }
            #[cfg(all(feature = "aptos", not(feature = "runtime-coordinator")))]
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
                let aptos_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("aptos"))
                    .and_then(|k| k.as_bytes())
                    .copied();
                let signer_address = if let Some(pk) = aptos_private_key {
                    let key_bytes = pk;
                    {
                        use ed25519_dalek::SigningKey;
                        use sha3::{Digest, Sha3_256};
                        log::info!(
                            "SDK LAYER: Private key (first 8 bytes): 0x{}",
                            hex::encode(&key_bytes[..8])
                        );
                        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| {
                            CsvError::ConfigError("Invalid Aptos private key length".to_string())
                        })?;
                        let signing_key = SigningKey::from_bytes(&key_array);
                        let public_key = signing_key.verifying_key();
                        let public_key_bytes = public_key.as_bytes();

                        log::info!(
                            "SDK LAYER: Public key (first 8 bytes): 0x{}",
                            hex::encode(&public_key_bytes[..8])
                        );

                        // Aptos address derivation: sha3-256(public_key || 0x00), take last 32 bytes
                        let mut hasher = Sha3_256::new();
                        hasher.update(public_key_bytes);
                        hasher.update(&[0x00u8]); // Scheme byte for Ed25519
                        let hash = hasher.finalize();
                        let mut addr_array = [0u8; 32];
                        addr_array.copy_from_slice(&hash[..32]);

                        log::info!(
                            "SDK LAYER: Derived Aptos signer address: 0x{}",
                            hex::encode(addr_array)
                        );
                        Some(addr_array)
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
                    private_key: aptos_private_key.map(SecretKey::new),
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
            #[cfg(all(feature = "solana", feature = "runtime-coordinator"))]
            "solana" => {
                log::info!("Building Solana adapter for {:?} network", network);
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
                let chain_config = _config.chains.get("solana");

                let program_id = chain_config
                    .and_then(|chain| chain.program_id.as_deref())
                    .or_else(|| chain_config.and_then(|chain| chain.contract_address.as_deref()))
                    .ok_or_else(|| {
                        CsvError::ConfigError(
                            "Solana CSV program ID must be configured".to_string(),
                        )
                    })?;

                // Extract Solana private key from private_keys if available
                let solana_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("solana"))
                    .and_then(|k| k.as_bytes().map(|b| b.to_vec()));

                // Create RPC endpoint configuration
                let rpc_endpoint = RpcEndpoint {
                    url: rpc_url.clone(),
                    protocol: RpcProtocol::JsonRpc,
                    api_key: chain_config.and_then(|c| c.rpc.api_key.clone()),
                    priority: 0,
                };

                // Create adapter config for factory
                let factory_network = if _is_testnet {
                    FactoryNetworkType::Testnet
                } else {
                    FactoryNetworkType::Mainnet
                };

                let adapter_config = AdapterConfig {
                    chain_id: chain.clone(),
                    network: factory_network,
                    rpc_endpoints: vec![rpc_endpoint],
                    secret_key: solana_private_key
                        .as_ref()
                        .and_then(|bytes| bytes.as_slice().try_into().map(|arr: [u8; 32]| arr).ok())
                        .map(SharedSecretHandle::from_bytes)
                        .unwrap_or_default(),
                    seed: None,
                    account: 0,
                    index: 0,
                    contract_address: None,
                    program_id: Some(program_id.to_string()),
                    utxos: vec![],
                    sanad_seals: vec![],
                };

                // Use factory to create adapter
                let factory = SolanaFactory;
                let result = factory.create_adapter(adapter_config).await.map_err(|e| {
                    CsvError::ProtocolError {
                        chain: chain.clone(),
                        message: format!("Factory failed to create Solana adapter: {}", e),
                    }
                })?;

                // Register ChainAdapter in adapter_registry for TransferCoordinator
                if result.chain_adapter.is_some() {
                    log::info!("SDK: Created Solana ChainAdapter for TransferCoordinator");
                }

                Ok(Some(result))
            }
            #[cfg(all(feature = "solana", not(feature = "runtime-coordinator")))]
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
                let solana_private_key = private_keys
                    .as_ref()
                    .and_then(|keys| keys.get("solana"))
                    .and_then(|k| k.as_bytes())
                    .copied()
                    .map(SecretKey::new);

                let program_id_from_config = _config
                    .chains
                    .get("solana")
                    .and_then(|chain| chain.program_id.clone())
                    .ok_or_else(|| {
                        CsvError::ConfigError(
                            "Solana CSV program ID must be configured".to_string(),
                        )
                    })?;
                log::info!(
                    "SDK: Solana program_id from config: {}",
                    program_id_from_config
                );

                let sol_config = csv_solana::config::SolanaConfig {
                    network: sol_network,
                    rpc_url: rpc_url.clone(),
                    csv_program_id: program_id_from_config,
                    keypair: solana_private_key,
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
            private_keys: self.private_keys.clone(),
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
    /// Private keys for chain adapters (chain name -> typed SharedSecretHandle)
    #[allow(dead_code)]
    pub(crate) private_keys:
        Option<std::collections::HashMap<String, csv_protocol::secret::SharedSecretHandle>>,
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
            private_keys: None,
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
