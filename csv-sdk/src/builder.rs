//! Fluent builder implementations for [`CsvClient`](crate::client::CsvClient).
//!
//! The builder pattern allows constructing a client with any combination
//! of chain support, wallet, and storage backend.
//!
//! # Example
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let client = CsvClient::builder()
//!         .with_chain(ChainId::new("bitcoin"))
//!         .with_chain(ChainId::new("ethereum"))
//!         .with_store_backend(StoreBackend::InMemory)
//!         .build()?;
//!     Ok(())
//! }
//! ```

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use crate::local_store::InMemorySealStore;
use csv_hash::chain_id::ChainId;

use crate::config::Config;
use crate::error::CsvError;
use crate::wallet::Wallet;

use csv_runtime::adapter_registry::AdapterRegistryImpl;

#[cfg(feature = "runtime-coordinator")]
use csv_runtime::event_bus::EventBus;
#[cfg(all(feature = "runtime-coordinator", target_arch = "wasm32"))]
use csv_runtime::{event_persistence::InMemoryEventStore, execution_journal::InMemoryJournal};
#[cfg(all(feature = "runtime-coordinator", not(target_arch = "wasm32")))]
use csv_runtime::{event_persistence::RedbEventStore, execution_journal::RedbExecutionJournal};
#[cfg(all(feature = "runtime-coordinator", target_arch = "wasm32"))]
use csv_storage::InMemoryReplayDb;
#[cfg(all(feature = "runtime-coordinator", not(target_arch = "wasm32")))]
use csv_storage::RedbReplayDb;
#[cfg(feature = "runtime-coordinator")]
use csv_verifier::{CanonicalVerifierImpl, VerifierConfig};

#[cfg(feature = "runtime-coordinator")]
type RuntimeStores = (
    Box<dyn csv_storage::ReplayDatabase>,
    Box<dyn csv_runtime::EventStore>,
    Box<dyn csv_runtime::ExecutionJournal>,
);

/// Storage backend for seal and anchor persistence.
#[derive(Debug, Clone)]
pub enum StoreBackend {
    /// In-memory store (non-persistent, for testing).
    InMemory,
}

/// Internal state for the client builder.
#[derive(Default)]
struct BuilderState {
    enabled_chains: HashSet<ChainId>,
    wallet: Option<Wallet>,
    store_backend: Option<StoreBackend>,
    config: Option<Config>,
    private_keys:
        Option<std::collections::HashMap<String, csv_protocol::secret::SharedSecretHandle>>,
    #[cfg(feature = "runtime-coordinator")]
    enable_runtime_coordinator: bool,
}

/// Fluent builder for constructing a [`CsvClient`](crate::client::CsvClient).
///
/// Use [`CsvClient::builder()`](crate::client::CsvClient::builder) to create a new builder.
pub struct ClientBuilder {
    state: BuilderState,
}

impl ClientBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            state: BuilderState::default(),
        }
    }

    /// Enable a specific chain adapter.
    ///
    /// This method can be called multiple times to enable multiple chains.
    ///
    /// # Arguments
    ///
    /// * `chain` — The chain to enable (e.g., `"bitcoin"`).
    ///
    /// # Note
    ///
    /// The corresponding feature flag must be enabled in `Cargo.toml`.
    /// For example, `"bitcoin"` requires the `"bitcoin"` feature.
    pub fn with_chain(mut self, chain: ChainId) -> Self {
        self.state.enabled_chains.insert(chain);
        self
    }

    /// Enable all supported chains (requires `all-chains` feature).
    pub fn with_all_chains(self) -> Self {
        self.with_chain(ChainId::new("bitcoin"))
            .with_chain(ChainId::new("ethereum"))
            .with_chain(ChainId::new("sui"))
            .with_chain(ChainId::new("aptos"))
            .with_chain(ChainId::new("solana"))
    }

    /// Attach a wallet to the client.
    ///
    /// The wallet is used for signing transactions and deriving addresses.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    ///
    /// let wallet = Wallet::generate();
    /// let client = CsvClient::builder()
    ///     .with_wallet(wallet)
    ///     .build()?;
    /// # Ok::<_, csv_sdk::CsvError>(())
    /// ```
    pub fn with_wallet(mut self, wallet: Wallet) -> Self {
        self.state.wallet = Some(wallet);
        self
    }

    /// Set the storage backend.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    ///
    /// let client = CsvClient::builder()
    ///     .with_store_backend(StoreBackend::InMemory)
    ///     .build()?;
    /// # Ok::<_, csv_sdk::CsvError>(())
    /// ```
    pub fn with_store_backend(mut self, backend: StoreBackend) -> Self {
        self.state.store_backend = Some(backend);
        self
    }

    /// Load configuration from a [`Config`] struct.
    ///
    /// This overrides any previously set chain or store settings.
    pub fn with_config(mut self, config: Config) -> Self {
        // Enable chains from config before moving config into state
        for (name, chain_cfg) in &config.chains {
            if chain_cfg.enabled
                && let Ok(chain) = name.parse::<ChainId>()
            {
                self.state.enabled_chains.insert(chain);
            }
        }
        self.state.config = Some(config);
        self
    }

    /// Set private keys for chain adapters.
    ///
    /// This is required for chains that need to sign transactions (e.g., Bitcoin).
    /// The keys are passed as a HashMap mapping chain names to typed SecretHandle.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use csv_sdk::prelude::*;
    /// use csv_wallet::{SecretHandle, KeyPurpose};
    /// use std::collections::HashMap;
    ///
    /// let mut keys = HashMap::new();
    /// let secret_handle = SecretHandle::new(vec![...], KeyPurpose::Signing, "bitcoin".to_string());
    /// keys.insert("bitcoin".to_string(), secret_handle);
    ///
    /// let client = CsvClient::builder()
    ///     .with_chain("bitcoin")
    ///     .with_private_keys(keys)
    ///     .build()?;
    /// # Ok::<_, csv_sdk::CsvError>(())
    /// ```
    pub fn with_private_keys(
        mut self,
        keys: std::collections::HashMap<String, csv_protocol::secret::SharedSecretHandle>,
    ) -> Self {
        self.state.private_keys = Some(keys);
        self
    }

    /// Enable the runtime coordinator for cross-chain transfer execution.
    ///
    /// When enabled, the client will initialize a full TransferCoordinator with
    /// ReplayDatabase, EventBus, EventStore, ExecutionJournal, CoordinatorLease,
    /// and CanonicalVerifier for production-grade transfer execution.
    ///
    /// This requires the "runtime-coordinator" feature to be enabled.
    #[cfg(feature = "runtime-coordinator")]
    pub fn with_runtime_coordinator(mut self) -> Self {
        self.state.enable_runtime_coordinator = true;
        self
    }

    /// Build the [`CsvClient`](crate::client::CsvClient), validating all settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No chains are enabled
    /// - A chain is enabled but its feature flag is not compiled
    /// - The store backend cannot be initialized
    pub async fn build(self) -> Result<crate::client::CsvClient, CsvError> {
        if self.state.enabled_chains.is_empty() {
            return Err(CsvError::BuilderError(
                "At least one chain must be enabled. Use .with_chain() to enable a chain."
                    .to_string(),
            ));
        }

        // Validate that enabled chains have their feature flags
        for chain in &self.state.enabled_chains {
            Self::check_chain_feature(chain.clone())?;
        }

        // Apply config overrides if present
        let config = self.state.config.unwrap_or_default();

        // Initialize store backend
        let store = match self.state.store_backend.unwrap_or(StoreBackend::InMemory) {
            StoreBackend::InMemory => {
                crate::client::StoreHandle::InMemory(InMemorySealStore::new())
            }
        };

        let store_arc = Arc::new(std::sync::Mutex::new(store));
        #[cfg(feature = "tokio")]
        let event_tx = tokio::sync::broadcast::channel(256).0;
        #[cfg(not(feature = "tokio"))]
        let event_tx = ();

        // Create the chain runtime
        // Note: ClientRef initially has no chain_runtime to avoid circular dependency
        let client_ref = Arc::new(crate::client::ClientRef {
            enabled_chains: self.state.enabled_chains.clone(),
            wallet: self.state.wallet.clone(),
            store: store_arc.clone(),
            config: config.clone(),
            event_tx: event_tx.clone(),
            chain_runtime: None,
            private_keys: self.state.private_keys.clone(),
        });
        let chain_runtime = crate::runtime::ChainRuntime::new(client_ref.clone());

        // Create adapter registry for cross-chain transfers
        let adapter_registry = Arc::new(std::sync::Mutex::new(AdapterRegistryImpl::new()));

        // Initialize runtime coordinator if enabled
        #[cfg(feature = "runtime-coordinator")]
        let transfer_coordinator = if self.state.enable_runtime_coordinator {
            // Initialize runtime components.
            let (replay_db, event_store, execution_journal) = Self::runtime_stores(&config)?;
            let event_bus = EventBus::new();
            // TransferCoordinator constructs the production verifier per source
            // chain at verification time. This stored verifier remains only for
            // constructor/API compatibility, so configure it to fail closed if
            // it is ever used directly.
            let verifier = CanonicalVerifierImpl::new(VerifierConfig {
                max_anchor_age_blocks: Some(0),
                ..VerifierConfig::default()
            });

            // For single-instance deployments (CLI, SDK), do not configure a distributed coordinator lease.
            // The assert_single_active_coordinator check will be skipped when coordinator_lease is None,
            // which is correct for single-instance deployments. Distributed lease backends should be
            // configured explicitly for HA deployments via TransferCoordinator::set_coordinator_lease.
            let mut coordinator = csv_runtime::TransferCoordinator::with_stores(
                replay_db,
                event_bus,
                event_store,
                execution_journal,
                verifier,
                Box::new(csv_runtime::distributed_coordinator_lease::InMemoryLease::new())
                    as Box<dyn csv_runtime::CoordinatorLease>,
            );

            // Clear coordinator lease for single-instance deployments to skip the distributed lease check
            coordinator.clear_coordinator_lease();

            Some(Arc::new(coordinator))
        } else {
            None
        };

        #[cfg(not(feature = "runtime-coordinator"))]
        let transfer_coordinator: Option<Arc<csv_runtime::TransferCoordinator>> = None;

        // Automatically create and register adapters for all enabled chains
        let network_type = if config.network == crate::config::Network::Testnet {
            crate::client::NetworkType::Testnet
        } else {
            crate::client::NetworkType::Mainnet
        };

        #[cfg(all(feature = "runtime-coordinator", not(target_arch = "wasm32")))]
        for chain in &self.state.enabled_chains {
            if let Some(result) = crate::client::CsvClient::build_adapter_for_chain(
                chain.clone(),
                &config,
                network_type,
                self.state.private_keys.clone(),
            )
            .await?
            {
                chain_runtime
                    .register_adapter(chain.clone(), result.chain_backend.clone())
                    .await;
                log::info!(
                    "Automatically initialized ChainBackend for chain: {:?}",
                    chain
                );

                // Register ChainAdapter in adapter_registry for TransferCoordinator
                if let Some(chain_adapter) = result.chain_adapter {
                    let _ = adapter_registry
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .register_adapter(chain_adapter);
                    log::info!(
                        "Automatically registered ChainAdapter for chain: {:?}",
                        chain
                    );
                }
            }
        }

        // On wasm32 this legacy arm also serves runtime-coordinator builds: chain
        // backends register for read paths, but the coordinator's adapter registry
        // stays empty, so transfer dispatch fails closed until remote dispatch to a
        // native host lands (WASM-REMOTE-001).
        #[cfg(not(all(feature = "runtime-coordinator", not(target_arch = "wasm32"))))]
        for chain in &self.state.enabled_chains {
            if let Some(result) = crate::client::CsvClient::build_adapter_for_chain(
                chain.clone(),
                &config,
                network_type,
                self.state.private_keys.clone(),
            )
            .await?
            {
                chain_runtime
                    .register_adapter(chain.clone(), result.clone())
                    .await;
                log::info!(
                    "Automatically initialized ChainBackend for chain: {:?}",
                    chain
                );
            }
        }

        Ok(crate::client::CsvClient {
            enabled_chains: self.state.enabled_chains,
            wallet: self.state.wallet,
            store: store_arc,
            config,
            event_tx,
            chain_runtime,
            adapter_registry,
            private_keys: self.state.private_keys,
            #[cfg(feature = "runtime-coordinator")]
            transfer_coordinator,
        })
    }

    #[cfg(feature = "runtime-coordinator")]
    fn runtime_stores(config: &Config) -> Result<RuntimeStores, CsvError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let runtime_dir = Self::runtime_data_dir(config);
            std::fs::create_dir_all(&runtime_dir).map_err(|e| {
                CsvError::StoreError(format!(
                    "failed to create runtime data directory {}: {e}",
                    runtime_dir.display()
                ))
            })?;

            // redb databases are single files (the old RocksDB backends were
            // directories named replay/events/journal).
            let replay_path = runtime_dir.join("replay.redb");
            let events_path = runtime_dir.join("events.redb");
            let journal_path = runtime_dir.join("journal.redb");

            let replay_db = RedbReplayDb::open(&replay_path.to_string_lossy())
                .map_err(|e| CsvError::StoreError(format!("failed to open replay DB: {e}")))?;
            let event_store = RedbEventStore::open(&events_path.to_string_lossy())
                .map_err(|e| CsvError::StoreError(format!("failed to open event store: {e}")))?;
            let execution_journal = RedbExecutionJournal::open(&journal_path.to_string_lossy())
                .map_err(|e| {
                    CsvError::StoreError(format!("failed to open execution journal: {e}"))
                })?;

            Ok((
                Box::new(replay_db) as Box<dyn csv_storage::ReplayDatabase>,
                Box::new(event_store) as Box<dyn csv_runtime::EventStore>,
                Box::new(execution_journal) as Box<dyn csv_runtime::ExecutionJournal>,
            ))
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = config;
            Ok((
                Box::new(InMemoryReplayDb::new()) as Box<dyn csv_storage::ReplayDatabase>,
                Box::new(InMemoryEventStore::new()) as Box<dyn csv_runtime::EventStore>,
                Box::new(InMemoryJournal::new(10000)) as Box<dyn csv_runtime::ExecutionJournal>,
            ))
        }
    }

    #[cfg(feature = "runtime-coordinator")]
    fn runtime_data_dir(config: &Config) -> PathBuf {
        let base = config
            .data_dir
            .as_deref()
            .map(Self::expand_path)
            .unwrap_or_else(|| {
                let mut path = Config::default_path();
                path.pop();
                path.push("data");
                path
            });

        base.join("runtime")
    }

    #[cfg(feature = "runtime-coordinator")]
    fn expand_path(path: &str) -> PathBuf {
        if let Some(stripped) = path.strip_prefix("~/") {
            #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
            if let Some(home) = dirs::home_dir() {
                return home.join(stripped);
            }
        }

        PathBuf::from(path)
    }

    /// Check that the required feature flag is enabled for a chain.
    fn check_chain_feature(chain: ChainId) -> Result<(), CsvError> {
        match chain.as_str() {
            "bitcoin" => {
                #[cfg(not(feature = "bitcoin"))]
                return Err(CsvError::BuilderError(
                    "Bitcoin adapter requires the 'bitcoin' feature flag".to_string(),
                ));
                #[cfg(feature = "bitcoin")]
                Ok(())
            }
            "ethereum" => {
                #[cfg(not(feature = "ethereum"))]
                return Err(CsvError::BuilderError(
                    "Ethereum adapter requires the 'ethereum' feature flag".to_string(),
                ));
                #[cfg(feature = "ethereum")]
                Ok(())
            }
            "sui" => {
                #[cfg(not(feature = "sui"))]
                return Err(CsvError::BuilderError(
                    "Sui adapter requires the 'sui' feature flag".to_string(),
                ));
                #[cfg(feature = "sui")]
                Ok(())
            }
            "aptos" => {
                #[cfg(not(feature = "aptos"))]
                return Err(CsvError::BuilderError(
                    "Aptos adapter requires the 'aptos' feature flag".to_string(),
                ));
                #[cfg(feature = "aptos")]
                Ok(())
            }
            "solana" => {
                #[cfg(not(feature = "solana"))]
                return Err(CsvError::BuilderError(
                    "Solana adapter requires the 'solana' feature flag".to_string(),
                ));
                #[cfg(feature = "solana")]
                Ok(())
            }
            // Future chains added via #[non_exhaustive]
            _ => Ok(()),
        }
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
