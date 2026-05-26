//! Unified CSV client with builder pattern.
//!
//! The [`CsvClient`] is the main entry point for all CSV operations.
//! It provides access to managers for sanads, transfers, proofs, wallet,
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
//!     let proofs = client.proofs();
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
use crate::proofs::ProofManager;
use crate::runtime::ChainRuntime;
use crate::sanads::SanadsManager;
use crate::transfers::TransferManager;
use crate::wallet::Wallet;
use crate::wallet::WalletManager;
use csv_core::store::{InMemorySealStore, SanadRecord, SanadStore};

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
                .map_err(|e: csv_core::store::StoreError| CsvError::StoreError(e.to_string())),
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

    /// Get a [`ProofManager`] for generating and verifying proofs.
    pub fn proofs(&self) -> ProofManager {
        ProofManager::new(Arc::new(self.clone_ref()))
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
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
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
    ///     client.init_adapters(NetworkType::Testnet).await?;
    ///
    ///     // Now you can use the runtime
    ///     let balance = client.chain_runtime()
    ///         .get_balance("bitcoin", "bc1...")
    ///         .await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn init_adapters(&self, network: NetworkType) -> Result<(), CsvError> {
        let mut failed_chains: Vec<String> = Vec::new();

        for chain in &self.enabled_chains {
            let adapter_result =
                Self::build_adapter_for_chain(chain.clone(), &self.config, network).await;

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

    /// Build an adapter for a specific chain.
    async fn build_adapter_for_chain(
        chain: ChainId,
        _config: &crate::config::Config,
        network: NetworkType,
    ) -> Result<Option<std::sync::Arc<dyn csv_protocol::backend::ChainBackend>>, CsvError> {
        let _builder = crate::runtime::AdapterBuilder::new();
        let _is_testnet = matches!(network, NetworkType::Testnet);

        match chain.as_str() {
            #[cfg(all(feature = "bitcoin", feature = "rpc"))]
            "bitcoin" => {
                log::info!("Building Bitcoin adapter for {:?} network", network);
                let rpc_url = _config
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
                let btc_network = if _is_testnet {
                    csv_bitcoin::Network::Signet
                } else {
                    csv_bitcoin::Network::Mainnet
                };
                log::info!("Building Bitcoin adapter with RPC URL: {}", rpc_url);
                let btc_config = csv_bitcoin::config::BitcoinConfig {
                    network: btc_network,
                    finality_depth: 6,
                    publication_timeout_seconds: 3600,
                    rpc_url: rpc_url.clone(),
                    xpub: _config.chains.get("bitcoin").and_then(|c| c.xpub.clone()),
                };
                // Create RPC client - this uses reqwest::blocking which needs its own runtime
                // We must create it outside any async context to avoid runtime conflicts
                let rpc = std::thread::spawn(move || {
                    Box::new(csv_bitcoin::mempool_rpc::MempoolSignetRpc::with_url(
                        rpc_url,
                    )) as Box<dyn csv_bitcoin::rpc::BitcoinRpc + Send + Sync>
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
                    lock_contract_address: None,
                    mint_contract_address: None,
                };
                let csv_seal_address = [0u8; 20]; // Default, should be configured
                let rpc = csv_ethereum::node::EthereumNode::new(&rpc_url, csv_seal_address)
                    .await
                    .map_err(|e| CsvError::ProtocolError {
                        chain: ChainId::new("ethereum"),
                        message: format!("Failed to create Ethereum RPC client: {}", e),
                    })?;
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
                // Seal contract package ID is required but not available - using placeholder
                sui_config.seal_contract.package_id = Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                );
                let rpc = csv_sui::node::SuiNode::new(&rpc_url);
                _builder
                    .sui_from_config(sui_config, Box::new(rpc) as Box<dyn csv_sui::rpc::SuiRpc>)
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
                let aptos_config = csv_aptos::AptosConfig {
                    network: if _is_testnet {
                        csv_aptos::config::AptosNetwork::Testnet
                    } else {
                        csv_aptos::config::AptosNetwork::Mainnet
                    },
                    rpc_url: rpc_url.clone(),
                    ..Default::default()
                };
                let rpc = csv_aptos::node::AptosNode::new(&rpc_url);
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
                let sol_config = csv_solana::config::SolanaConfig {
                    network: sol_network,
                    rpc_url: rpc_url.clone(),
                    csv_program_id: "CsvProgram11111111111111111111111111111111111".to_string(),
                    keypair: None,
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
