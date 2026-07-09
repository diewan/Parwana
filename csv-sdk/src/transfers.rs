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

pub use csv_adapter_core::DestinationMaterialization;

#[cfg(feature = "runtime-coordinator")]
use csv_adapter_core::CrossChainTransfer;
#[cfg(feature = "runtime-coordinator")]
use csv_runtime::TransferCoordinator;
#[cfg(feature = "runtime-coordinator")]
use csv_runtime::policy::RuntimePolicy;
#[cfg(feature = "runtime-coordinator")]
use csv_runtime::user_runtime_lease::{
    MAX_LEASE_DURATION_SECS, RuntimeExecutionContext, TransferLease,
};

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
    // Held to keep the client alive for the manager's lifetime; calls go through the runtime.
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
    pub(crate) fn with_adapter_registry(
        mut self,
        registry: Arc<std::sync::Mutex<AdapterRegistryImpl>>,
    ) -> Self {
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

    /// Read recorded settlement evidence from the runtime event store.
    #[cfg(feature = "runtime-coordinator")]
    pub fn settlement_evidence(
        &self,
        sanad_id: &SanadId,
    ) -> Result<Option<csv_runtime::SettlementEvidence>, CsvError> {
        let coordinator = self.coordinator.as_ref().ok_or_else(|| {
            CsvError::CoordinatorNotAvailable(
                "runtime coordinator is not configured for settlement queries".to_string(),
            )
        })?;
        let runtime_sanad = csv_hash::SanadId::new(*sanad_id.as_bytes());
        coordinator
            .settlement_evidence(&runtime_sanad)
            .map_err(|e| CsvError::RuntimeError(e.to_string()))
    }

    /// Read terminal settlement status from the runtime event store.
    #[cfg(feature = "runtime-coordinator")]
    pub fn settlement_status(
        &self,
        sanad_id: &SanadId,
    ) -> Result<csv_runtime::SettlementStatus, CsvError> {
        let coordinator = self.coordinator.as_ref().ok_or_else(|| {
            CsvError::CoordinatorNotAvailable(
                "runtime coordinator is not configured for settlement queries".to_string(),
            )
        })?;
        let runtime_sanad = csv_hash::SanadId::new(*sanad_id.as_bytes());
        coordinator
            .settlement_status(&runtime_sanad)
            .map_err(|e| CsvError::RuntimeError(e.to_string()))
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

    /// Advance an already-locked transfer without re-locking it.
    ///
    /// This is the resume driver: it delegates to the coordinator's resumable
    /// core, which gates on real source-chain confirmations. For a lock that has
    /// not yet reached finality it returns [`TransferOutcome::Pending`] (not an
    /// error), so a caller can report "awaiting finality — N/M confs" and
    /// re-invoke later. The on-chain lock is never re-broadcast.
    ///
    /// `sanad_id`, `from_chain`, and `to_chain` come from the caller's own
    /// transfer record; the coordinator authorises resume against the journaled
    /// stage, so the lock is never re-executed.
    #[cfg(feature = "runtime-coordinator")]
    #[allow(clippy::await_holding_lock)]
    pub async fn resume(
        &self,
        transfer_id: &str,
        sanad_id: SanadId,
        from_chain: ChainId,
        to_chain: ChainId,
        to_address: Option<String>,
    ) -> Result<TransferOutcome, CsvError> {
        let coordinator = self.coordinator.as_ref().ok_or_else(|| {
            CsvError::CoordinatorNotAvailable(
                "runtime-coordinator feature enabled but coordinator not available".to_string(),
            )
        })?;

        let adapter_registry = self.adapter_registry.lock().map_err(|e| {
            CsvError::RuntimeError(format!("Failed to lock adapter registry: {}", e))
        })?;

        let destination_owner = to_address
            .as_deref()
            .map(|address| destination_owner_bytes(&to_chain, address))
            .transpose()?;
        let runtime_ctx = build_runtime_ctx(&sanad_id, Some(&self.config), destination_owner)?;

        let outcome = coordinator
            .resume_transfer_outcome(transfer_id, &*adapter_registry, runtime_ctx)
            .await
            .map_err(|e| CsvError::RuntimeError(format!("Transfer resume failed: {}", e)))?;

        Ok(match outcome {
            csv_runtime::TransferOutcome::Completed(receipt) => {
                TransferOutcome::Completed(Box::new(TransferReceipt {
                    transfer_id: receipt.transfer_id,
                    replay_id: receipt.replay_id,
                    source_chain: from_chain,
                    destination_chain: to_chain,
                    lock_tx_hash: receipt.lock_tx_hash,
                    mint_tx_hash: receipt.mint_tx_hash,
                    materialization: receipt.materialization,
                }))
            }
            csv_runtime::TransferOutcome::Pending {
                lock_tx_hash,
                confirmations,
                required,
            } => TransferOutcome::Pending {
                transfer_id: transfer_id.to_string(),
                lock_tx_hash,
                confirmations,
                required,
            },
        })
    }
}

/// The faithful runtime receipt for a completed cross-chain transfer.
///
/// Every field on this type is sourced directly from
/// [`csv_runtime::TransferCoordinator::execute`]'s
/// [`TransferReceipt`](csv_runtime::transfer_coordinator::TransferReceipt).
/// The SDK does not compute, default, or fabricate any of these values —
/// the runtime is the only authority for transfer ID, replay ID, and the
/// lock/mint transaction hashes that prove the transfer happened.
#[derive(Debug, Clone)]
pub struct TransferReceipt {
    /// Runtime-assigned transfer identifier.
    pub transfer_id: String,
    /// Replay ID the runtime used to guard against double-execution.
    pub replay_id: csv_hash::Hash,
    /// Source chain the Sanad was locked on.
    pub source_chain: ChainId,
    /// Destination chain the Sanad was minted on.
    pub destination_chain: ChainId,
    /// Transaction hash of the lock on the source chain, as reported by the runtime.
    pub lock_tx_hash: String,
    /// Transaction hash of the mint on the destination chain, as reported by the runtime.
    pub mint_tx_hash: String,
    /// Destination-side materialization metadata observed by the destination adapter.
    pub materialization: DestinationMaterialization,
}

impl std::fmt::Display for TransferReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.transfer_id)
    }
}

/// Outcome of a single transfer advance, surfaced faithfully from the runtime
/// coordinator's [`csv_runtime::TransferOutcome`].
///
/// A `Pending` result is not an error: the lock is on-chain and journaled, and
/// the transfer will complete once the source-chain lock reaches the required
/// confirmation depth. The two CLI drivers build on this: poll-and-block loops
/// until `Completed`; resume returns `Pending` and re-invokes later.
#[derive(Debug, Clone)]
pub enum TransferOutcome {
    /// Transfer completed: destination mint confirmed.
    ///
    /// Boxed: the receipt carries destination materialization metadata, making it
    /// several times larger than `Pending`.
    Completed(Box<TransferReceipt>),
    /// Lock is on-chain but not yet at the required finality depth.
    Pending {
        /// Runtime-assigned transfer identifier (needed to resume later).
        transfer_id: String,
        /// Lock transaction hash in the runtime's chain-native byte encoding.
        lock_tx_hash: String,
        /// Confirmations observed on the source-chain lock.
        confirmations: u64,
        /// Confirmation depth required by the source chain.
        required: u64,
    },
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
    pub inclusion_proof: Option<csv_protocol::proof_taxonomy::InclusionProof>,
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
    /// The faithful [`TransferReceipt`] produced by the runtime coordinator:
    /// transfer ID, replay ID, source/destination chains, and the lock/mint
    /// transaction hashes. Every field is read from the coordinator's
    /// response — none of it is computed or guessed locally. Use
    /// [`TransferManager::status()`] to track progress afterwards.
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
    #[allow(clippy::await_holding_lock)]
    pub async fn execute(self) -> Result<TransferReceipt, CsvError> {
        match self.execute_outcome().await? {
            TransferOutcome::Completed(receipt) => Ok(*receipt),
            TransferOutcome::Pending {
                confirmations,
                required,
                ..
            } => Err(CsvError::RuntimeError(format!(
                "transfer awaiting finality: {}/{} confirmations",
                confirmations, required
            ))),
        }
    }

    /// Execute the cross-chain transfer, returning a [`TransferOutcome`].
    ///
    /// Unlike [`TransferBuilder::execute`], a lock that has not yet reached
    /// finality is returned as [`TransferOutcome::Pending`] (not an error). This
    /// is the single-shot primitive both CLI drivers build on:
    /// - resume (default): call once; on `Pending`, print status and return.
    /// - poll-and-block (`--wait`): call once, then loop
    ///   [`TransferManager::resume`] until `Completed`.
    ///
    /// This method performs the on-chain lock exactly once. To advance an
    /// already-locked transfer without re-locking, use
    /// [`TransferManager::resume`].
    #[allow(clippy::await_holding_lock)]
    pub async fn execute_outcome(self) -> Result<TransferOutcome, CsvError> {
        let to_address = self.to_address.as_ref().ok_or_else(|| {
            CsvError::BuilderError(
                "Destination address is required. Use .to_address() to set it.".to_string(),
            )
        })?;

        #[cfg(feature = "runtime-coordinator")]
        {
            // Use TransferCoordinator if available
            if let Some(manager) = self.manager {
                log::info!(
                    "TransferBuilder: TransferManager found, checking for TransferCoordinator"
                );
                if let Some(coordinator) = manager.coordinator.as_ref() {
                    log::info!(
                        "TransferBuilder: TransferCoordinator available, executing real transfer"
                    );
                    // Get adapter registry from the manager
                    let adapter_registry = manager.adapter_registry();
                    #[allow(clippy::await_holding_lock)]
                    let adapter_registry = adapter_registry.lock().map_err(|e| {
                        CsvError::RuntimeError(format!("Failed to lock adapter registry: {}", e))
                    })?;

                    // Create a CrossChainTransfer
                    let transfer_id = uuid::Uuid::new_v4().to_string();
                    let transfer = CrossChainTransfer {
                        id: transfer_id.clone(),
                        source_chain: self.from_chain.to_string(),
                        destination_chain: self.to_chain.to_string(),
                        lock_tx_hash: vec![], // Will be filled by coordinator
                        lock_output_index: 0,
                        sanad_id: csv_hash::Hash::new(*self.sanad_id.as_bytes()),
                        transition_id: uuid::Uuid::new_v4().to_string().into(),
                    };

                    let destination_owner = destination_owner_bytes(&self.to_chain, to_address)?;
                    let runtime_ctx = build_runtime_ctx(
                        &self.sanad_id,
                        self.config.as_deref(),
                        Some(destination_owner),
                    )?;

                    // Execute transfer through the resumable coordinator core.
                    let outcome = coordinator
                        .execute_outcome(transfer, &*adapter_registry, runtime_ctx)
                        .await
                        .map_err(|e| {
                            CsvError::RuntimeError(format!("Transfer execution failed: {}", e))
                        })?;

                    return Ok(match outcome {
                        csv_runtime::TransferOutcome::Completed(receipt) => {
                            log::info!(
                                "TransferBuilder: Transfer completed, transfer_id={}",
                                receipt.transfer_id
                            );
                            TransferOutcome::Completed(Box::new(TransferReceipt {
                                transfer_id: receipt.transfer_id,
                                replay_id: receipt.replay_id,
                                source_chain: self.from_chain,
                                destination_chain: self.to_chain,
                                lock_tx_hash: receipt.lock_tx_hash,
                                mint_tx_hash: receipt.mint_tx_hash,
                                materialization: receipt.materialization,
                            }))
                        }
                        csv_runtime::TransferOutcome::Pending {
                            lock_tx_hash,
                            confirmations,
                            required,
                        } => {
                            log::info!(
                                "TransferBuilder: Transfer {} locked, awaiting finality {}/{}",
                                transfer_id,
                                confirmations,
                                required
                            );
                            TransferOutcome::Pending {
                                transfer_id,
                                lock_tx_hash,
                                confirmations,
                                required,
                            }
                        }
                    });
                } else {
                    log::warn!(
                        "TransferBuilder: TransferCoordinator not available in TransferManager"
                    );
                }
            } else {
                log::warn!("TransferBuilder: TransferManager not available");
            }
        }

        #[cfg(feature = "runtime-coordinator")]
        return Err(CsvError::CoordinatorNotAvailable(
            "runtime-coordinator feature enabled but coordinator not available - ensure TransferManager is initialized with a valid TransferCoordinator".to_string()
        ));

        #[cfg(not(feature = "runtime-coordinator"))]
        return Err(CsvError::CoordinatorNotAvailable(
            "runtime-coordinator feature not enabled - transfers require the runtime-coordinator feature flag".to_string()
        ));
    }
}

/// Build a runtime execution context (lease + policy) for a transfer sanad.
///
/// The lease TTL is capped by csv-runtime. Poll-and-block and explicit resume
/// drivers re-acquire a fresh context on each advance.
#[cfg(feature = "runtime-coordinator")]
fn build_runtime_ctx(
    sanad_id: &SanadId,
    config: Option<&crate::config::Config>,
    destination_owner: Option<Vec<u8>>,
) -> Result<RuntimeExecutionContext, CsvError> {
    // Derive a deterministic runtime identity from the sanad so that the initial
    // execute and every subsequent in-process resume share the same lease owner
    // and epoch. The coordinator accepts a same-owner/same-epoch lease, which is
    // what lets a poll-and-block loop advance the transfer repeatedly without
    // being rejected as a competing runtime (single-writer per transfer).
    let mut owner_bytes = [0u8; 16];
    owner_bytes.copy_from_slice(&sanad_id.as_bytes()[..16]);
    let runtime_id = uuid::Uuid::from_bytes(owner_bytes);
    let now = std::time::SystemTime::now();
    let duration = std::time::Duration::from_secs(MAX_LEASE_DURATION_SECS);
    let lease = TransferLease::acquire(sanad_id.clone().into(), runtime_id, 1, now, duration)
        .map_err(|e| CsvError::RuntimeError(format!("Failed to acquire lease: {}", e)))?;

    let mut policy = RuntimePolicy::default();
    if let Some(config) = config {
        for (chain_name, chain_config) in &config.chains {
            policy.set_finality_depth(chain_name.clone(), chain_config.finality_depth as u64);
        }
    }

    Ok(RuntimeExecutionContext {
        runtime_instance: runtime_id,
        lease,
        policy,
        destination_owner,
    })
}

fn destination_owner_bytes(chain: &ChainId, address: &str) -> Result<Vec<u8>, CsvError> {
    match chain.as_str() {
        "sui" | "aptos" => {
            let bytes = hex::decode(address.trim_start_matches("0x")).map_err(|e| {
                CsvError::BuilderError(format!("Invalid {} destination address hex: {}", chain, e))
            })?;
            if bytes.len() != 32 {
                return Err(CsvError::BuilderError(format!(
                    "{} destination address must be 32 bytes, got {}",
                    chain,
                    bytes.len()
                )));
            }
            Ok(bytes)
        }
        _ => Ok(address.as_bytes().to_vec()),
    }
}

// Timestamp helper retained for receipt formatting; not on the current code path.
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
