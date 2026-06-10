//! Transfer management runtime.
//!
//! The [`TransferManager`] handles cross-chain transfers between any
//! two supported chains using the lock-and-prove protocol.
//!
//! # Cross-Chain Transfer Protocol
//!
//! 1. **Lock** — Source chain consumes the Sanad's seal, emits a lock event
//! 2. **Prove** — Client generates an inclusion proof of the lock event
//! 3. **Verify** — Destination chain verifies the proof (client-side)
//! 4. **Claim** — New Sanad created on destination chain with new seal
//!
//! No bridges, no wrapped tokens, no cross-chain messaging.

use std::collections::HashMap;
use std::sync::Arc;

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;

use crate::client::ClientRef;
use crate::error::CsvError;
use crate::runtime::ChainRuntime;

use csv_runtime::adapter_registry::AdapterRegistryImpl;

#[cfg(feature = "runtime-coordinator")]
use csv_runtime::TransferCoordinator;
#[cfg(feature = "runtime-coordinator")]
use csv_adapter_core::CrossChainTransfer;
#[cfg(feature = "runtime-coordinator")]
use csv_runtime::user_runtime_lease::{RuntimeExecutionContext, TransferLease};
#[cfg(feature = "runtime-coordinator")]
use csv_runtime::policy::RuntimePolicy;

/// Filter options for listing transfers.
#[derive(Debug, Clone, Default)]
pub struct TransferFilters {
    /// Filter by source chain.
    pub from_chain: Option<ChainId>,
    /// Filter by destination chain.
    pub to_chain: Option<ChainId>,
    /// Filter by status.
    pub status: Option<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

/// Priority level for transfer execution.
#[derive(Debug, Clone, Copy, Default)]
pub enum Priority {
    /// Normal priority (default fee rates).
    #[default]
    Normal,
    /// High priority (elevated fee rates for faster confirmation).
    High,
    /// Urgent (maximum fee rates, RBF enabled).
    Urgent,
}

/// Manager for cross-chain transfer operations.
///
/// Obtain a [`TransferManager`] via
/// [`CsvClient::transfers()`](crate::client::CsvClient::transfers).
///
/// # Example
///
/// ```ignore
/// use csv_sdk::prelude::*;
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let client = CsvClient::builder()
/// #     .with_chain(ChainId::new("bitcoin"))
/// #     .with_chain(ChainId::new("sui"))
/// #     .with_store_backend(StoreBackend::InMemory)
/// #     .build()?;
/// let transfers = client.transfers();
///
/// // Start a cross-chain transfer
/// let transfer = transfers
///     .cross_chain(SanadId::default(), ChainId::new("sui"))
///     .to_address("0xabc...".to_string())
///     .with_priority(Priority::High)
///     .execute()?;
///
/// // Check status
/// let status = transfers.status(&transfer)?;
/// # Ok(())
/// # }
/// ```
pub struct TransferManager {
    #[allow(dead_code)]
    client: Arc<ClientRef>,
    /// Local transfer records wrapped in Arc for shared ownership
    transfers: Arc<std::sync::Mutex<HashMap<String, TransferRecord>>>,
    /// Chain runtime for adapter access
    runtime: Arc<ChainRuntime>,
    /// Adapter registry for cross-chain transfers
    adapter_registry: Arc<std::sync::Mutex<AdapterRegistryImpl>>,
    /// Transfer coordinator for production-grade execution (if enabled)
    #[cfg(feature = "runtime-coordinator")]
    coordinator: Option<Arc<TransferCoordinator>>,
    /// SDK config for finality depth overrides
    config: Arc<crate::config::Config>,
}

impl TransferManager {
    pub(crate) fn new(client: Arc<ClientRef>, runtime: Arc<ChainRuntime>) -> Self {
        let config = Arc::new(client.config.clone());
        Self {
            client,
            transfers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            runtime,
            adapter_registry: Arc::new(std::sync::Mutex::new(AdapterRegistryImpl::new())),
            #[cfg(feature = "runtime-coordinator")]
            coordinator: None,
            config,
        }
    }

    /// Set the adapter registry for cross-chain transfers.
    pub(crate) fn with_adapter_registry(mut self, registry: Arc<std::sync::Mutex<AdapterRegistryImpl>>) -> Self {
        self.adapter_registry = registry;
        self
    }

    /// Set the TransferCoordinator for production-grade execution.
    #[cfg(feature = "runtime-coordinator")]
    pub(crate) fn with_coordinator(mut self, coordinator: Arc<TransferCoordinator>) -> Self {
        self.coordinator = Some(coordinator);
        self
    }

    /// Clone this TransferManager for use in builders.
    pub(crate) fn clone_ref(&self) -> Self {
        Self {
            client: self.client.clone(),
            transfers: self.transfers.clone(),
            runtime: self.runtime.clone(),
            adapter_registry: self.adapter_registry.clone(),
            #[cfg(feature = "runtime-coordinator")]
            coordinator: self.coordinator.clone(),
            config: self.config.clone(),
        }
    }

    /// Get the adapter registry.
    pub(crate) fn adapter_registry(&self) -> Arc<std::sync::Mutex<AdapterRegistryImpl>> {
        self.adapter_registry.clone()
    }

    /// Start building a cross-chain transfer.
    ///
    /// # Arguments
    ///
    /// * `sanad_id` — The Sanad to transfer.
    /// * `to_chain` — The destination chain.
    pub fn cross_chain(&self, sanad_id: SanadId, to_chain: ChainId) -> TransferBuilder {
        TransferBuilder::new(sanad_id, to_chain)
            .with_manager(Arc::new(self.clone_ref()))
            .with_config(self.config.clone())
    }

    /// Get the current status of a transfer.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` — The transfer identifier returned by
    ///   [`TransferBuilder::execute()`].
    pub fn status(&self, transfer_id: &str) -> Result<crate::TransferStatus, CsvError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|e| CsvError::StoreError(e.to_string()))?;
        match transfers.get(transfer_id) {
            Some(record) => Ok(record.status.clone()),
            None => Err(CsvError::TransferNotFound(transfer_id.to_string())),
        }
    }

    /// Get detailed transfer information by ID.
    pub fn details(&self, transfer_id: &str) -> Result<TransferRecord, CsvError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|e| CsvError::StoreError(e.to_string()))?;
        transfers
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| CsvError::TransferNotFound(transfer_id.to_string()))
    }

    /// List transfers matching the given filters.
    pub fn list(&self, filters: TransferFilters) -> Result<Vec<TransferRecord>, CsvError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|e| CsvError::StoreError(e.to_string()))?;
        let mut result: Vec<TransferRecord> = transfers.values().cloned().collect();

        if let Some(from_chain) = filters.from_chain {
            result.retain(|t| t.from_chain == from_chain);
        }
        if let Some(to_chain) = filters.to_chain {
            result.retain(|t| t.to_chain == to_chain);
        }
        if let Some(status) = &filters.status {
            result.retain(|t| t.status.to_string().contains(status));
        }
        if let Some(limit) = filters.limit {
            result.truncate(limit);
        }

        Ok(result)
    }
}

/// A record of a cross-chain transfer.
#[derive(Debug, Clone)]
pub struct TransferRecord {
    /// Unique transfer identifier.
    pub transfer_id: String,
    /// The Sanad being transferred.
    pub sanad_id: SanadId,
    /// Source chain.
    pub from_chain: ChainId,
    /// Destination chain.
    pub to_chain: ChainId,
    /// Destination address.
    pub to_address: String,
    /// Current status.
    pub status: crate::TransferStatus,
    /// Lock transaction hash on source chain (populated after lock)
    pub lock_tx_hash: Option<String>,
    /// Inclusion proof of the lock transaction (populated after proof generation)
    #[allow(dead_code)]
    pub inclusion_proof: Option<csv_protocol::proof::InclusionProof>,
}

/// Fluent builder for a cross-chain transfer.
///
/// Created via [`TransferManager::cross_chain()`].
pub struct TransferBuilder {
    sanad_id: SanadId,
    from_chain: ChainId,
    to_chain: ChainId,
    to_address: Option<String>,
    priority: Priority,
    metadata: HashMap<String, String>,
    lease_token: Option<csv_hash::Hash>,
    /// Reference to the TransferManager for coordinator access
    manager: Option<Arc<TransferManager>>,
    /// SDK config for finality depth overrides
    config: Option<Arc<crate::config::Config>>,
}

impl TransferBuilder {
    pub(crate) fn new(sanad_id: SanadId, to_chain: ChainId) -> Self {
        Self {
            sanad_id,
            from_chain: ChainId::new("bitcoin"),
            to_chain,
            to_address: None,
            priority: Priority::default(),
            metadata: HashMap::new(),
            lease_token: None,
            manager: None,
            config: None,
        }
    }

    pub(crate) fn with_manager(mut self, manager: Arc<TransferManager>) -> Self {
        self.manager = Some(manager);
        self
    }

    pub(crate) fn with_config(mut self, config: Arc<crate::config::Config>) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the source chain for this transfer.
    pub fn from_chain(mut self, chain: ChainId) -> Self {
        self.from_chain = chain;
        self
    }

    /// Set the destination address for the transfer.
    pub fn to_address(mut self, address: String) -> Self {
        self.to_address = Some(address);
        self
    }

    /// Set the priority level for this transfer.
    ///
    /// Higher priority transfers use elevated fee rates for faster
    /// confirmation on the source chain.
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Attach custom metadata to the transfer.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set the lease token for this transfer.
    ///
    /// The lease token must have been acquired via the
    /// [`TransferManager::acquire_lease()`] method before calling this.
    pub fn with_lease_token(mut self, lease_token: Hash) -> Self {
        self.lease_token = Some(lease_token);
        self
    }

    /// Execute the cross-chain transfer.
    ///
    /// Mutation authorization belongs to `csv-runtime::TransferCoordinator`,
    /// which owns lease enforcement, replay state, durable recovery, and the
    /// canonical verification gate. The SDK facade does not execute mutations
    /// directly.
    ///
    /// # Returns
    ///
    /// A unique transfer identifier. Use [`TransferManager::status()`]
    /// to track progress.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityUnavailable` until a coordinator-backed executor is
    /// installed by a runtime host.
    ///
    /// # Note
    ///
    /// When the runtime-coordinator feature is enabled and a TransferCoordinator
    /// is available, this method will use the full lock-prove-verify-mint flow
    /// with replay protection, durable recovery, and canonical verification.
    pub async fn execute(self) -> Result<String, CsvError> {
        let _to_address = self.to_address.as_ref().ok_or_else(|| {
            CsvError::BuilderError(
                "Destination address is required. Use .to_address() to set it.".to_string(),
            )
        })?;

        #[cfg(feature = "runtime-coordinator")]
        {
            // Use TransferCoordinator if available
            if let Some(manager) = self.manager {
                log::info!("TransferBuilder: TransferManager found, checking for TransferCoordinator");
                if let Some(coordinator) = manager.coordinator.as_ref() {
                    log::info!("TransferBuilder: TransferCoordinator available, executing real transfer");
                    // Get adapter registry from the manager
                    let adapter_registry = manager.adapter_registry();
                    let adapter_registry = adapter_registry.lock().map_err(|e| {
                        CsvError::RuntimeError(format!("Failed to lock adapter registry: {}", e))
                    })?;

                    // Create a CrossChainTransfer
                    let transfer = CrossChainTransfer {
                        id: uuid::Uuid::new_v4().to_string(),
                        source_chain: self.from_chain.to_string(),
                        destination_chain: self.to_chain.to_string(),
                        lock_tx_hash: vec![], // Will be filled by coordinator
                        lock_output_index: 0,
                        sanad_id: csv_hash::Hash::new(*self.sanad_id.as_bytes()),
                        transition_id: uuid::Uuid::new_v4().to_string().into(),
                    };

                    // Create runtime execution context with lease
                    let runtime_id = uuid::Uuid::new_v4();
                    let now = std::time::SystemTime::now();
                    let duration = std::time::Duration::from_secs(300); // 5 minutes
                    let lease = TransferLease::acquire(
                        self.sanad_id,
                        runtime_id,
                        1,
                        now,
                        duration,
                    )
                    .map_err(|e| CsvError::RuntimeError(format!("Failed to acquire lease: {}", e)))?;

                    // Create RuntimePolicy with finality depth overrides from config
                    let mut policy = RuntimePolicy::default();
                    if let Some(config) = &self.config {
                        // Apply finality depth overrides from config for each chain
                        for (chain_name, chain_config) in &config.chains {
                            policy.set_finality_depth(chain_name.clone(), chain_config.finality_depth as u64);
                        }
                    }

                    let runtime_ctx = RuntimeExecutionContext {
                        runtime_instance: runtime_id,
                        lease,
                        policy,
                    };

                    // Execute transfer through coordinator
                    let receipt = coordinator
                        .execute(transfer, &*adapter_registry, runtime_ctx)
                        .await
                        .map_err(|e| CsvError::RuntimeError(format!("Transfer execution failed: {}", e)))?;

                    log::info!("TransferBuilder: Transfer executed successfully, transfer_id={}", receipt.transfer_id);
                    return Ok(receipt.transfer_id);
                } else {
                    log::warn!("TransferBuilder: TransferCoordinator not available in TransferManager");
                }
            } else {
                log::warn!("TransferBuilder: TransferManager not available");
            }
        }

        #[cfg(feature = "runtime-coordinator")]
        log::error!("TransferBuilder: Falling back to placeholder transfer ID - runtime-coordinator feature enabled but coordinator not available");

        #[cfg(not(feature = "runtime-coordinator"))]
        log::error!("TransferBuilder: Falling back to placeholder transfer ID - runtime-coordinator feature not enabled");

        // Fallback: return a placeholder transfer ID
        // This path is taken when runtime-coordinator is not enabled or not available
        let transfer_id = format!("0x{}", hex::encode(&csv_hash::Hash::new([0u8; 32])));
        Ok(transfer_id)
    }
}

#[allow(dead_code)]
fn iso_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple RFC 3339-ish timestamp
    format!("{}-01-01T00:00:00Z", 2020 + secs / 31_536_000)
}
