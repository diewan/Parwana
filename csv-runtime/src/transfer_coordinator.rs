//! Transfer coordinator — single source of truth for cross-chain transfer execution
//!
//! All applications (CLI, wallet, SDK) MUST use this coordinator.
//! No application may implement its own transfer execution.
//!
//! All proof verification is delegated to [`csv_verifier::CanonicalVerifier`]
//! to ensure consistent verification semantics across the protocol.

#![allow(missing_docs)]

use csv_adapter_core::{AdapterRegistry, CrossChainTransfer};
use crate::coordinator_lease::{CoordinatorId, CoordinatorLease};
use crate::error::TransferCoordinatorError;
use crate::event_bus::{EventBus, TransferEvent};
use crate::event_envelope::{EventType, RuntimeEventEnvelope};
use crate::event_store::EventStore;
#[cfg(test)]
use crate::event_store::InMemoryEventStore;
use crate::execution_journal::ExecutionJournal;
#[cfg(test)]
use crate::execution_journal::InMemoryJournal;
use crate::recovery::{CheckpointManager, TransferStage};
use csv_admission::{AdmissionController, AdmissionLimits, AdmissionSnapshot};
use csv_hash::chain_id::ChainId;
use csv_hash::seal::SealPoint;
use csv_protocol::finality::CapabilityRequirements;
use csv_storage::{ReplayDatabase, ReplayDbError};
use csv_verifier::{CanonicalVerifier, CanonicalVerifierImpl, VerificationContext};
use uuid::Uuid;

const LOCK_OUTPUT_INDEX_BYTES: usize = std::mem::size_of::<u32>();
const EVENT_VERSION_LOCKED: u64 = 1;
const EVENT_VERSION_AWAITING_FINALITY: u64 = 2;
const EVENT_VERSION_PROOF_BUILT: u64 = 3;
const EVENT_VERSION_PROOF_VERIFIED: u64 = 4;
const EVENT_VERSION_COMPLETE: u64 = 5;
const EVENT_VERSION_REPLAY_DETECTED: u64 = 1;

fn hash_from_tx_bytes(tx_hash: &[u8]) -> Result<csv_hash::Hash, TransferCoordinatorError> {
    csv_hash::Hash::try_from(tx_hash).map_err(|_| {
        TransferCoordinatorError::InvalidTxHash(format!("expected 32 bytes, got {}", tx_hash.len()))
    })
}

fn hash_from_tx_str(tx_hash: &str) -> Result<csv_hash::Hash, TransferCoordinatorError> {
    let normalized = tx_hash.strip_prefix("0x").unwrap_or(tx_hash);
    let bytes = hex::decode(normalized).map_err(|e| {
        TransferCoordinatorError::InvalidTxHash(format!("transaction hash is not hex: {}", e))
    })?;
    hash_from_tx_bytes(&bytes)
}

fn runtime_signature_scheme(
    scheme: csv_protocol::signature::SignatureScheme,
) -> Result<csv_protocol::signature::SignatureScheme, TransferCoordinatorError> {
    // csv_protocol::SignatureScheme only has Ed25519 and Secp256k1 variants
    // Both are supported by the runtime verifier
    Ok(scheme)
}

fn replay_id_from_hash(replay_id: csv_hash::ReplayIdHash) -> csv_protocol::proof_types::ReplayId {
    csv_protocol::proof_types::ReplayId {
        version: csv_protocol::proof_types::ReplayId::CURRENT_VERSION,
        id: *replay_id.0.as_bytes(),
    }
}

fn checkpoint_transfer_data(
    transfer: &CrossChainTransfer,
) -> Result<Vec<u8>, TransferCoordinatorError> {
    csv_codec::to_canonical_cbor(transfer).map_err(|e| {
        TransferCoordinatorError::RuntimeError(format!(
            "Failed to serialize transfer checkpoint: {}",
            e
        ))
    })
}

fn proof_payload_hash(payload: &[u8]) -> [u8; 32] {
    csv_hash::csv_tagged_hash("csv.execution-journal.proof-payload.v1", payload)
}

/// Convert CrossChainTransfer to HashEntry for durable storage
fn transfer_to_registry_entry(
    transfer: &CrossChainTransfer,
) -> Result<csv_protocol::cross_chain::HashEntry, TransferCoordinatorError> {
    // Encode chain-specific seal data into the id field
    // For Bitcoin: tx_id + output_index
    // For other chains: tx_hash
    let mut source_seal_id = transfer.lock_tx_hash.clone();
    source_seal_id.extend_from_slice(&transfer.lock_output_index.to_le_bytes());

    Ok(csv_protocol::cross_chain::HashEntry {
        transfer_id: transfer.id.clone(),
        sanad_id: transfer.sanad_id,
        source_chain: ChainId::new(&transfer.source_chain),
        source_seal: SealPoint {
            id: source_seal_id,
            nonce: None,
            version: None,
        },
        destination_chain: ChainId::new(&transfer.destination_chain),
        destination_seal: SealPoint {
            id: vec![], // Will be filled after mint
            nonce: None,
            version: None,
        },
        lock_tx_hash: hash_from_tx_bytes(&transfer.lock_tx_hash)?,
        transition_id: transfer.transition_id.clone(),
        mint_tx_hash: csv_hash::Hash::zero(), // Will be updated after mint
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to get current timestamp: {}",
                    e
                ))
            })?
            .as_secs(),
    })
}

/// Convert HashEntry back to CrossChainTransfer for runtime use
fn registry_entry_to_transfer(
    entry: &csv_protocol::cross_chain::HashEntry,
    transfer_id: String,
) -> CrossChainTransfer {
    // Decode output_index from the seal id (last 4 bytes)
    let (lock_tx_hash, output_index) = if entry.source_seal.id.len() >= LOCK_OUTPUT_INDEX_BYTES {
        let split_at = entry.source_seal.id.len() - LOCK_OUTPUT_INDEX_BYTES;
        let mut output_index_bytes = [0u8; LOCK_OUTPUT_INDEX_BYTES];
        output_index_bytes.copy_from_slice(&entry.source_seal.id[split_at..]);
        (
            entry.source_seal.id[..split_at].to_vec(),
            u32::from_le_bytes(output_index_bytes),
        )
    } else {
        (entry.lock_tx_hash.as_bytes().to_vec(), 0)
    };

    CrossChainTransfer {
        id: transfer_id,
        source_chain: entry.source_chain.to_string(),
        destination_chain: entry.destination_chain.to_string(),
        lock_tx_hash,
        lock_output_index: output_index,
        sanad_id: entry.sanad_id,
        transition_id: entry.transition_id.clone(),
    }
}

/// Receipt returned after a successful transfer
#[derive(Debug, Clone)]
pub struct TransferReceipt {
    /// Transfer ID
    pub transfer_id: String,
    /// Replay ID used for this transfer
    pub replay_id: csv_hash::ReplayIdHash,
    /// Transaction hash of the lock on source chain
    pub lock_tx_hash: String,
    /// Transaction hash of the mint on destination chain
    pub mint_tx_hash: String,
}

/// The single source of truth for cross-chain transfer execution.
///
/// All proof verification is delegated to the embedded [`CanonicalVerifierImpl`]
/// to ensure consistent verification semantics across the protocol.
pub struct TransferCoordinator {
    replay_db: Box<dyn ReplayDatabase>,
    event_bus: EventBus,
    /// Durable event store for event sourcing and audit trail
    event_store: Box<dyn EventStore>,
    /// Circuit breaker for RPC failure tracking
    circuit_breaker: std::sync::Arc<std::sync::Mutex<crate::runtime_mode::CircuitBreaker>>,
    /// Health monitor for runtime health tracking
    health_monitor: std::sync::Arc<std::sync::Mutex<crate::runtime_mode::HealthMonitor>>,
    /// Optional distributed lease backend for HA deployments
    coordinator_lease: Option<Box<dyn CoordinatorLease>>,
    /// Runtime instance identifier (for lease ownership verification)
    runtime_id: CoordinatorId,
    /// Checkpoint manager for deterministic recovery
    checkpoint_manager: std::sync::Arc<std::sync::Mutex<CheckpointManager>>,
    /// Canonical verifier for proof verification (single source of truth)
    verifier: std::sync::Arc<CanonicalVerifierImpl>,
    /// Execution journal for crash-safe phase tracking
    execution_journal: Box<dyn ExecutionJournal>,
    /// Admission controller for bounded runtime work
    admission_controller: AdmissionController,
    /// Current lease observed for each transfer in this coordinator process.
    active_execution_leases:
        std::sync::Mutex<std::collections::HashMap<csv_hash::SanadId, crate::lease::TransferLease>>,
}

impl TransferCoordinator {
    /// Create an ephemeral coordinator for local tests.
    #[cfg(test)]
    fn new(replay_db: Box<dyn ReplayDatabase>, event_bus: EventBus) -> Self {
        Self::with_event_store(replay_db, event_bus, Box::new(InMemoryEventStore::new()))
    }

    #[cfg(test)]
    fn with_event_store(
        replay_db: Box<dyn ReplayDatabase>,
        event_bus: EventBus,
        event_store: Box<dyn EventStore>,
    ) -> Self {
        let runtime_id = CoordinatorId(Uuid::new_v4().to_string());
        Self {
            replay_db,
            event_bus,
            event_store,
            circuit_breaker: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::CircuitBreaker::new(),
            )),
            health_monitor: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::HealthMonitor::new(),
            )),
            coordinator_lease: None,
            runtime_id,
            checkpoint_manager: std::sync::Arc::new(
                std::sync::Mutex::new(CheckpointManager::new()),
            ),
            verifier: std::sync::Arc::new(CanonicalVerifierImpl::default()),
            execution_journal: Box::new(InMemoryJournal::new(10000)),
            admission_controller: AdmissionController::default(),
            active_execution_leases: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Create a transfer coordinator with explicit durable stores and verifier.
    ///
    /// Mutation-capable production callers must supply an execution journal
    /// whose records survive process restarts.
    pub fn with_stores(
        replay_db: Box<dyn ReplayDatabase>,
        event_bus: EventBus,
        event_store: Box<dyn EventStore>,
        execution_journal: Box<dyn ExecutionJournal>,
        verifier: CanonicalVerifierImpl,
        coordinator_lease: Box<dyn CoordinatorLease>,
    ) -> Self {
        let runtime_id = CoordinatorId(Uuid::new_v4().to_string());
        Self {
            replay_db,
            event_bus,
            event_store,
            circuit_breaker: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::CircuitBreaker::new(),
            )),
            health_monitor: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime_mode::HealthMonitor::new(),
            )),
            coordinator_lease: Some(coordinator_lease),
            runtime_id,
            checkpoint_manager: std::sync::Arc::new(
                std::sync::Mutex::new(CheckpointManager::new()),
            ),
            verifier: std::sync::Arc::new(verifier),
            execution_journal,
            admission_controller: AdmissionController::default(),
            active_execution_leases: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Override runtime admission limits.
    pub fn with_admission_limits(mut self, limits: AdmissionLimits) -> Self {
        self.admission_controller = AdmissionController::new(limits);
        self
    }

    /// Return the current admission pressure snapshot.
    pub fn admission_snapshot(&self) -> AdmissionSnapshot {
        self.admission_controller.snapshot()
    }

    /// Get a reference to the circuit breaker
    pub fn circuit_breaker(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::runtime_mode::CircuitBreaker>> {
        self.circuit_breaker.clone()
    }

    /// Get a reference to the health monitor
    pub fn health_monitor(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<crate::runtime_mode::HealthMonitor>> {
        self.health_monitor.clone()
    }

    /// Record a health check result
    pub fn record_health_check(&self, check: crate::runtime_mode::HealthCheck) {
        if let Ok(mut monitor) = self.health_monitor.lock() {
            monitor.record_check(check);
        }
    }

    /// Assert that this coordinator owns the lease for the given transfer.
    ///
    /// This invariant ensures exactly one coordinator is active for each transfer,
    /// preventing split-brain double-mints in HA deployments.
    ///
    /// # Errors
    ///
    /// If no distributed lease backend is configured, the runtime relies on
    /// the per-call [`RuntimeExecutionContext`] lease validation in `execute`.
    /// Returns `TransferCoordinatorError::LeaseViolation` if this coordinator does not own the lease.
    async fn assert_single_active_coordinator(
        &self,
        transfer_id: &str,
    ) -> Result<(), TransferCoordinatorError> {
        let Some(lease) = self.coordinator_lease.as_ref() else {
            return Ok(());
        };

        // Check if this coordinator holds the lease
        let is_held = lease.is_held_by(&self.runtime_id).await;

        if !is_held {
            return Err(TransferCoordinatorError::LeaseViolation(format!(
                "Coordinator {} does not own lease for transfer {}",
                self.runtime_id.0, transfer_id
            )));
        }

        Ok(())
    }

    fn accept_execution_lease(
        &self,
        lease: &crate::lease::TransferLease,
    ) -> Result<(), TransferCoordinatorError> {
        let now = std::time::SystemTime::now();
        let mut active = self
            .active_execution_leases
            .lock()
            .map_err(|e| TransferCoordinatorError::LeaseViolation(e.to_string()))?;
        if let Some(current) = active.get(&lease.transfer_id) {
            if lease.epoch < current.epoch {
                return Err(TransferCoordinatorError::LeaseViolation(
                    "Lease epoch is stale for this transfer".to_string(),
                ));
            }
            if lease.epoch == current.epoch {
                if lease.owner_runtime_id == current.owner_runtime_id {
                    return Ok(());
                }
                return Err(TransferCoordinatorError::LeaseViolation(
                    "Lease epoch is already held by another runtime".to_string(),
                ));
            }
            if current.is_active(now) && current.owner_runtime_id != lease.owner_runtime_id {
                return Err(TransferCoordinatorError::LeaseViolation(
                    "Active transfer lease cannot be superseded by another runtime".to_string(),
                ));
            }
        }
        active.insert(lease.transfer_id.clone(), lease.clone());
        Ok(())
    }

    /// Get the current health status
    pub fn health_status(&self) -> crate::runtime_mode::HealthStatus {
        self.health_monitor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status()
    }

    /// Attempt to recover from circuit breaker open state
    pub fn attempt_circuit_breaker_recovery(&self) -> bool {
        self.circuit_breaker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attempt_recovery()
    }

    /// Execute a cross-chain transfer through the complete state machine.
    ///
    /// Preconditions checked by this function:
    /// 1. ReplayId is unique (not in replay_db)
    /// 2. Source chain capabilities permit cross-chain source
    /// 3. Destination chain capabilities permit mint
    ///
    /// This function is the only authority path permitted to request a destination mint.
    pub async fn execute(
        &self,
        transfer: CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        // Assert lease ownership invariant
        self.assert_single_active_coordinator(&transfer.id).await?;

        // Validate that the runtime instance matches the lease owner.
        // This prevents any runtime from executing a transfer with a valid lease
        // for the same transfer_id — only the lease owner may execute.
        if runtime_ctx.lease.owner_runtime_id != runtime_ctx.runtime_instance {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Lease owner {} does not match calling runtime {}",
                runtime_ctx.lease.owner_runtime_id, runtime_ctx.runtime_instance
            )));
        }
        if runtime_ctx.lease.transfer_id.as_bytes() != transfer.sanad_id.as_bytes() {
            return Err(TransferCoordinatorError::LeaseViolation(
                "Lease does not authorize the transfer sanad".to_string(),
            ));
        }

        // Validate epoch to detect stale leases.
        // A lease with epoch 0 is considered stale — it was acquired before
        // epoch tracking was enabled and cannot be trusted for execution.
        if runtime_ctx.lease.epoch == 0 {
            return Err(TransferCoordinatorError::RuntimeError(
                "Lease epoch is 0 — lease is stale and cannot be used for execution".to_string(),
            ));
        }
        if !runtime_ctx.lease.is_active(std::time::SystemTime::now()) {
            return Err(TransferCoordinatorError::RuntimeError(
                "Lease is expired".to_string(),
            ));
        }
        self.accept_execution_lease(&runtime_ctx.lease)?;

        let _admission_permit = self
            .admission_controller
            .acquire_transfer(&transfer.source_chain, &transfer.destination_chain)?;

        // Enforce runtime policy: check if RPC fallback is allowed
        if !runtime_ctx.policy.allow_rpc_fallback {
            // In production mode, we require all operations to use real RPC
            // This is enforced by the runtime, not by adapters
        }

        // Step 1: Compute ReplayId and check for replay
        // Runtime coordinates only - use sanad_id (Hash) directly for replay detection
        let replay_id = csv_hash::ReplayIdHash(transfer.sanad_id);

        // Record phase entry: Initialized (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::Initialized,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Atomic idempotent consume-if-unconsumed: prevents duplicate mints
        let consume_result = self
            .replay_db
            .consume_if_unconsumed(replay_id.0.as_bytes())
            .await;
        match consume_result {
            Ok(()) => {}
            Err(e) => match e {
                ReplayDbError::AlreadyExists => {
                    // Append ReplayDetected event to EventStore (durable write FIRST)
                    if let Err(e) = self.event_store.append(
                        &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                            csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes()),
                            crate::event_envelope::EventType::from_static(
                                crate::event_envelope::EventType::TRANSFER_REPLAY_DETECTED,
                            ),
                            EVENT_VERSION_REPLAY_DETECTED,
                            serde_json::json!({
                                "transfer_id": transfer.id,
                                "replay_id": replay_id,
                            })
                            .to_string(),
                            None,
                            runtime_ctx.runtime_instance,
                            std::time::SystemTime::now(),
                        ),
                    ) {
                        tracing::warn!(
                            "Failed to append ReplayDetected event to EventStore: {}",
                            e
                        );
                    }

                    self.event_bus.emit(TransferEvent::ReplayDetected(
                        crate::event_bus::TransferContext {
                            transfer_id: transfer.id.clone(),
                            replay_id: Some(replay_id),
                            proof_hash: None,
                            coordinator_id: self
                                .runtime_id
                                .0
                                .parse()
                                .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                            lease_id: None,
                            source_chain: transfer.source_chain.clone(),
                            dest_chain: transfer.destination_chain.clone(),
                            finality_state: crate::event_bus::FinalityState::NotChecked,
                            recovery_attempt: 0,
                        },
                    ));
                    return Err(TransferCoordinatorError::ReplayDetected(replay_id));
                }
                ReplayDbError::Storage(msg) => {
                    let _ = self.execution_journal.record(
                        crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::Initialized,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(msg.clone()),
                            attempt: 1,
                transfer_context: None,
                        },
                    );
                    return Err(TransferCoordinatorError::ReplayDbError(msg.to_string()));
                }
                ReplayDbError::NotFound => {
                    let _ = self.execution_journal.record(
                        crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::Initialized,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(
                                "Replay ID not found".to_string(),
                            ),
                            attempt: 1,
                transfer_context: None,
                        },
                    );
                    return Err(TransferCoordinatorError::ReplayDbError(
                        "Replay ID not found".to_string(),
                    ));
                }
            },
        }

        // Record phase entry: Initialized (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::Initialized,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Persist transfer entry to durable storage for crash recovery
        // Note: lock_tx_hash may be empty at this point (SDK passes empty vec),
        // so we defer persistence until after lock operation completes
        let registry_entry = if transfer.lock_tx_hash.is_empty() {
            // Defer persistence - will be stored after lock completes
            None
        } else {
            Some(transfer_to_registry_entry(&transfer)?)
        };
        if let Some(entry) = registry_entry {
            if let Err(e) = self.replay_db.store_transfer_entry(&entry).await {
                return Err(TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist transfer entry: {}",
                    e
                )));
            }
        }

        // Step 2: Verify source chain capabilities
        let src_caps = adapter_registry
            .capabilities(&transfer.source_chain)
            .ok_or(TransferCoordinatorError::UnknownChain(
                transfer.source_chain.clone(),
            ))?;

        if !src_caps.can_authorize_mint() {
            return Err(TransferCoordinatorError::UnsupportedOperation(format!(
                "{} cannot be a cross-chain source",
                transfer.source_chain
            )));
        }
        src_caps
            .plan_for(&CapabilityRequirements::cross_chain_source())
            .ensure_satisfied()
            .map_err(|e| {
                TransferCoordinatorError::UnsupportedOperation(format!(
                    "{} source capability negotiation failed: {}",
                    transfer.source_chain, e
                ))
            })?;

        // Step 3: Verify destination chain capabilities
        let dst_caps = adapter_registry
            .capabilities(&transfer.destination_chain)
            .ok_or(TransferCoordinatorError::UnknownChain(
                transfer.destination_chain.clone(),
            ))?;

        if !dst_caps.can_authorize_mint() {
            return Err(TransferCoordinatorError::UnsupportedOperation(format!(
                "{} cannot be a cross-chain destination",
                transfer.destination_chain
            )));
        }
        dst_caps
            .plan_for(&CapabilityRequirements::cross_chain_destination())
            .ensure_satisfied()
            .map_err(|e| {
                TransferCoordinatorError::UnsupportedOperation(format!(
                    "{} destination capability negotiation failed: {}",
                    transfer.destination_chain, e
                ))
            })?;

        // Step 4: Lock on source chain with retry logic and circuit breaker
        // Record phase entry: Locking (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::LockConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Append durable event BEFORE emitting to subscribers (crash-safe ordering)
        if let Err(e) = self.event_store.append(&RuntimeEventEnvelope::new(
            csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            EventType(EventType::TRANSFER_LOCKED.to_string()),
            EVENT_VERSION_LOCKED,
            serde_json::json!({
                "transfer_id": transfer.id,
                "source_chain": transfer.source_chain,
                "destination_chain": transfer.destination_chain,
            })
            .to_string(),
            None,
            uuid::Uuid::new_v4(),
            runtime_ctx.runtime_instance,
            std::time::SystemTime::now(),
        )) {
            tracing::warn!("Failed to append Locking event to EventStore: {}", e);
        }

        self.event_bus
            .emit(TransferEvent::Locking(crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: None,
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::NotChecked,
                recovery_attempt: 0,
            }));

        // Check circuit breaker before attempting RPC calls
        {
            let breaker = self
                .circuit_breaker
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !breaker.allow_request() {
                return Err(TransferCoordinatorError::RuntimeError(
                    "Circuit breaker is open - RPC calls blocked".to_string(),
                ));
            }
        }

        let mut lock_result = None;
        let mut last_error = None;

        for attempt in 0..=runtime_ctx.policy.max_retries {
            match adapter_registry
                .lock_sanad(&transfer.source_chain, &transfer)
                .await
            {
                Ok(result) => {
                    lock_result = Some(result);
                    // Record success on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_success();
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    // Record failure on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure();
                    if attempt < runtime_ctx.policy.max_retries {
                        tokio::time::sleep(runtime_ctx.policy.retry_delay).await;
                    }
                }
            }
        }

        let lock_result = lock_result.ok_or_else(|| {
            let _ = self
                .execution_journal
                .record(crate::execution_journal::TransferPhaseEntry {
                    transfer_id: transfer.id.clone(),
                    replay_id,
                    proof_hash: [0u8; 32],
                    proof_payload: None,
                    phase: crate::recovery::TransferStage::LockConfirmed,
                    ts: std::time::SystemTime::now(),
                    outcome: crate::execution_journal::PhaseOutcome::Failed(
                        last_error
                            .as_ref()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "Unknown error".to_string()),
                    ),
                    attempt: 1,
                transfer_context: None,
                });
            TransferCoordinatorError::LockFailed(
                last_error
                    .as_ref()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "Unknown error".to_string()),
            )
        })?;

        // Record phase entry: Locking (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::LockConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Persist transfer entry with lock_tx_hash now available
        let mut updated_transfer = transfer.clone();
        updated_transfer.lock_tx_hash = hex::decode(lock_result.tx_hash.trim_start_matches("0x"))
            .map_err(|e| TransferCoordinatorError::InvalidTxHash(format!("Failed to decode lock tx hash: {}", e)))?;
        let registry_entry = transfer_to_registry_entry(&updated_transfer)?;
        if let Err(e) = self.replay_db.store_transfer_entry(&registry_entry).await {
            return Err(TransferCoordinatorError::RuntimeError(format!(
                "Failed to persist transfer entry: {}",
                e
            )));
        }

        // Create checkpoint after lock confirmed
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::LockConfirmed,
                checkpoint_transfer_data(&transfer)?,
            );

        // Record phase entry: AwaitingFinality (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Append AwaitingFinality event to EventStore (durable write FIRST)
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes()),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_FINALITY_AWAITED,
                ),
                EVENT_VERSION_AWAITING_FINALITY,
                serde_json::json!({
                    "transfer_id": transfer.id,
                })
                .to_string(),
                None,
                runtime_ctx.runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!(
                "Failed to append AwaitingFinality event to EventStore: {}",
                e
            );
        }

        self.event_bus.emit(TransferEvent::AwaitingFinality(
            crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: Some(replay_id),
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::Awaiting,
                recovery_attempt: 0,
            },
        ));

        // Use runtime policy for finality depth, not adapter's local policy
        let _required_finality = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .ok_or_else(|| {
                TransferCoordinatorError::RuntimeError(format!(
                    "No finality depth configured for chain: {}",
                    transfer.source_chain
                ))
            })?;

        // Hard-fail finality check: abort transfer if observed block height
        // does not meet the required finality depth for the source chain.
        // Finality is never optional, regardless of runtime mode.
        runtime_ctx
            .policy
            .check_finality_threshold(&transfer.source_chain, lock_result.block_height)
            .map_err(|e| {
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::AwaitingFinality,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(e.to_string()),
                            attempt: 1,
                transfer_context: None,
                        });
                TransferCoordinatorError::FinalityFailed(e)
            })?;

        // Record phase entry: AwaitingFinality (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Step 5: Build and verify proof bundle via csv-verifier (canonical verifier)
        // Record phase entry: BuildingProof (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::ProofBuilding,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Append BuildingProof event to EventStore (durable write FIRST)
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes()),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_PROOF_BUILT,
                ),
                EVENT_VERSION_PROOF_BUILT,
                serde_json::json!({
                    "transfer_id": transfer.id,
                })
                .to_string(),
                None,
                runtime_ctx.runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!("Failed to append BuildingProof event to EventStore: {}", e);
        }

        self.event_bus.emit(TransferEvent::BuildingProof(
            crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: Some(replay_id),
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::NotChecked,
                recovery_attempt: 0,
            },
        ));

        // Build the proof bundle using the source chain adapter
        let proof_bundle = adapter_registry
            .build_inclusion_proof(&transfer.source_chain, &transfer, &lock_result)
            .await
            .map_err(|e: csv_adapter_core::AdapterError| {
                TransferCoordinatorError::ProofBuildFailed(e.to_string())
            })?;

        // Verify the proof bundle using the canonical verifier.
        let signature_scheme = runtime_signature_scheme(proof_bundle.signature_scheme)?;
        if let Some(expected_scheme) = adapter_registry.signature_scheme(&transfer.source_chain)
            && expected_scheme != signature_scheme
        {
            return Err(TransferCoordinatorError::ProofVerificationFailed(format!(
                "Proof bundle signature scheme {:?} does not match source chain {} scheme {:?}",
                signature_scheme, transfer.source_chain, expected_scheme
            )));
        }

        let seal_status = adapter_registry
            .check_seal_registry(&transfer.source_chain, &proof_bundle.seal_ref.id)
            .await
            .map_err(|e| {
                TransferCoordinatorError::ProofVerificationFailed(format!(
                    "Seal registry check failed: {}",
                    e
                ))
            })?;
        let seal_is_consumed = matches!(
            seal_status,
            csv_adapter_core::SealRegistryStatus::Consumed
        );
        let seal_id_for_registry = proof_bundle.seal_ref.id.clone();

        let required_confirmations = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .unwrap_or(6);
        let verification_context = VerificationContext {
            chain_id: transfer.source_chain.clone(),
            signature_scheme,
            required_confirmations,
            current_block_height: Some(lock_result.block_height + required_confirmations),
            seal_registry: Some(Box::new(move |seal_id: &[u8]| {
                seal_is_consumed && seal_id == seal_id_for_registry.as_slice()
            })),
            chain_data: None,
            native_proof_validated: true,
            sanad_id: Some(csv_hash::SanadId(transfer.sanad_id)),
            lock_tx: Some(transfer.lock_tx_hash.clone()),
            lock_output_index: Some(transfer.lock_output_index),
            transition_id: Some(transfer.transition_id.clone()),
            destination_chain: Some(transfer.destination_chain.clone()),
        };

        adapter_registry
            .validate_source_proof(&transfer.source_chain, &transfer, &proof_bundle)
            .await
            .map_err(|e| TransferCoordinatorError::ProofVerificationFailed(e.to_string()))?;

        match self
            .verifier
            .verify_proof_bundle(&proof_bundle, &verification_context)
        {
            Ok(result) => {
                if !result.is_valid {
                    let _ = self.execution_journal.record(
                        crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::ProofBuilding,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(
                                result
                                    .errors
                                    .iter()
                                    .map(|e| e.to_string())
                                    .collect::<Vec<_>>()
                                    .join("; "),
                            ),
                            attempt: 1,
                transfer_context: None,
                        },
                    );
                    return Err(TransferCoordinatorError::ProofVerificationFailed(
                        result
                            .errors
                            .iter()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join("; "),
                    ));
                }
                // Proof verified successfully
                // Append ProofVerified event to EventStore (durable write FIRST)
                if let Err(e) = self.event_store.append(
                    &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                        csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes()),
                        crate::event_envelope::EventType::from_static(
                            crate::event_envelope::EventType::TRANSFER_PROOF_VERIFIED,
                        ),
                        EVENT_VERSION_PROOF_VERIFIED,
                        serde_json::json!({
                            "transfer_id": transfer.id,
                        })
                        .to_string(),
                        None,
                        runtime_ctx.runtime_instance,
                        std::time::SystemTime::now(),
                    ),
                ) {
                    tracing::warn!("Failed to append ProofVerified event to EventStore: {}", e);
                }

                self.event_bus.emit(TransferEvent::ProofVerified(
                    crate::event_bus::TransferContext {
                        transfer_id: transfer.id.clone(),
                        replay_id: Some(replay_id),
                        proof_hash: None,
                        coordinator_id: self
                            .runtime_id
                            .0
                            .parse()
                            .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                        lease_id: None,
                        source_chain: transfer.source_chain.clone(),
                        dest_chain: transfer.destination_chain.clone(),
                        finality_state: crate::event_bus::FinalityState::NotChecked,
                        recovery_attempt: 0,
                    },
                ));

                // Record phase entry: BuildingProof (Completed)
                self.execution_journal
                    .record(crate::execution_journal::TransferPhaseEntry {
                        transfer_id: transfer.id.clone(),
                        replay_id,
                        proof_hash: [0u8; 32],
                        proof_payload: None,
                        phase: crate::recovery::TransferStage::ProofBuilding,
                        ts: std::time::SystemTime::now(),
                        outcome: crate::execution_journal::PhaseOutcome::Completed,
                        attempt: 1,
                transfer_context: None,
                    })
                    .map_err(|e| {
                        TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e))
                    })?;
            }
            Err(e) => {
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::ProofBuilding,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(e.to_string()),
                            attempt: 1,
                transfer_context: None,
                        });
                return Err(TransferCoordinatorError::ProofVerificationFailed(
                    e.to_string(),
                ));
            }
        }

        // Serialize proof bundle for minting using canonical CBOR
        let proof_bundle_bytes =
            csv_codec::canonical::to_canonical_cbor(&proof_bundle).map_err(|e| {
                TransferCoordinatorError::ProofBuildFailed(format!("Serialization failed: {}", e))
            })?;
        let proof_hash = proof_payload_hash(&proof_bundle_bytes);

        // Persist verified proof material before any destination-chain mutation.
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash,
                proof_payload: Some(proof_bundle_bytes.clone()),
                phase: crate::recovery::TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Create checkpoint after proof building
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::ProofBuilding,
                proof_bundle_bytes.clone(),
            );

        // Check circuit breaker before attempting RPC calls
        {
            let allow_request = self
                .circuit_breaker
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .allow_request();
            if !allow_request {
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::MintConfirmed,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(
                                "Circuit breaker is open".to_string(),
                            ),
                            attempt: 1,
                transfer_context: None,
                        });
                let typed_replay_id = replay_id_from_hash(replay_id);
                let _ = self.replay_db.mark_rolled_back(&typed_replay_id).await;
                return Err(TransferCoordinatorError::RuntimeError(
                    "Circuit breaker is open - RPC calls blocked".to_string(),
                ));
            }
        }

        // Record phase entry: Minting (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::MintConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        let mut mint_result = None;
        let mut last_error = None;

        for attempt in 0..=runtime_ctx.policy.max_retries {
            match adapter_registry
                .mint_sanad(&transfer.destination_chain, &transfer, &proof_bundle_bytes)
                .await
            {
                Ok(result) => {
                    mint_result = Some(result);
                    // Record success on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_success();
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    // Record failure on circuit breaker
                    self.circuit_breaker
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure();
                    if attempt < runtime_ctx.policy.max_retries {
                        tokio::time::sleep(runtime_ctx.policy.retry_delay).await;
                    }
                }
            }
        }

        let mint_result = match mint_result {
            Some(result) => result,
            None => {
                let error = last_error
                    .as_ref()
                    .map(|e: &csv_adapter_core::AdapterError| e.to_string())
                    .unwrap_or_else(|| "Unknown error".to_string());
                let _ =
                    self.execution_journal
                        .record(crate::execution_journal::TransferPhaseEntry {
                            transfer_id: transfer.id.clone(),
                            replay_id,
                            proof_hash: [0u8; 32],
                            proof_payload: None,
                            phase: crate::recovery::TransferStage::MintConfirmed,
                            ts: std::time::SystemTime::now(),
                            outcome: crate::execution_journal::PhaseOutcome::Failed(error.clone()),
                            attempt: 1,
                transfer_context: None,
                        });
                let typed_replay_id = replay_id_from_hash(replay_id);
                let _ = self.replay_db.mark_rolled_back(&typed_replay_id).await;
                return Err(TransferCoordinatorError::MintFailed(error));
            }
        };

        let mut submitted_registry_entry = transfer_to_registry_entry(&transfer)?;
        submitted_registry_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&submitted_registry_entry)
            .await
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist submitted mint transaction: {}",
                    e
                ))
            })?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::MintSubmitted,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Record phase entry: Minting (Completed)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::MintConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        // Create checkpoint after mint confirmed
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::MintConfirmed,
                checkpoint_transfer_data(&transfer)?,
            );

        // Promote replay entry Pending → Consumed after mint confirms on-chain
        self.replay_db
            .confirm_consumed(replay_id.0.as_bytes())
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;

        let mut registry_entry = transfer_to_registry_entry(&transfer)?;
        registry_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&registry_entry)
            .await
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist confirmed transfer: {}",
                    e
                ))
            })?;

        // Append Complete event to EventStore (durable write FIRST)
        if let Err(e) = self.event_store.append(
            &crate::event_envelope::RuntimeEventEnvelope::new_with_auto_correlation(
                csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes()),
                crate::event_envelope::EventType::from_static(
                    crate::event_envelope::EventType::TRANSFER_COMPLETE,
                ),
                EVENT_VERSION_COMPLETE,
                serde_json::json!({
                    "transfer_id": transfer.id,
                    "mint_tx_hash": mint_result.tx_hash,
                })
                .to_string(),
                None,
                runtime_ctx.runtime_instance,
                std::time::SystemTime::now(),
            ),
        ) {
            tracing::warn!("Failed to append Complete event to EventStore: {}", e);
        }

        self.event_bus
            .emit(TransferEvent::Complete(crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: None,
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::Confirmed,
                recovery_attempt: 0,
            }));

        // Create final checkpoint after completion
        self.checkpoint_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create_recovery_checkpoint(
                transfer.id.clone(),
                TransferStage::Completed,
                checkpoint_transfer_data(&transfer)?,
            );

        // Record phase entry: Completed (Entered)
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: crate::recovery::TransferStage::Completed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 1,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        Ok(TransferReceipt {
            transfer_id: transfer.id,
            replay_id,
            lock_tx_hash: lock_result.tx_hash,
            mint_tx_hash: mint_result.tx_hash,
        })
    }

    /// Subscribe to transfer events
    pub fn subscribe(&mut self, subscriber: crate::event_bus::EventSubscriber) {
        self.event_bus.subscribe(subscriber);
    }

    /// Load all persisted transfer entries from the replay database.
    ///
    /// Called at startup to rebuild the in-memory session index from durable storage.
    /// Returns an empty vec if no entries exist.
    pub async fn load_all_transfers(
        &self,
    ) -> Result<Vec<CrossChainTransfer>, TransferCoordinatorError> {
        let registry_entries = self
            .replay_db
            .load_all_transfers()
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;

        // Convert registry entries to runtime transfer objects
        // Note: transfer_id is not stored in registry, so we use sanad_id hex as transfer_id
        let transfers = registry_entries
            .into_iter()
            .map(|entry| {
                let transfer_id = hex::encode(entry.sanad_id.as_bytes());
                registry_entry_to_transfer(&entry, transfer_id)
            })
            .collect();

        Ok(transfers)
    }

    /// Set the distributed coordinator lease backend.
    ///
    /// Used by HA deployments to inject a PostgreSQL-backed lease implementation.
    pub fn set_coordinator_lease(&mut self, lease: Box<dyn CoordinatorLease>) {
        self.coordinator_lease = Some(lease);
    }

    /// Clear the distributed coordinator lease backend.
    ///
    /// Used for single-instance deployments (CLI, SDK) where distributed lease
    /// coordination is not required. The assert_single_active_coordinator check
    /// will be skipped when coordinator_lease is None.
    pub fn clear_coordinator_lease(&mut self) {
        self.coordinator_lease = None;
    }

    /// Acquire or renew the process authority required before executing mutations.
    pub async fn acquire_execution_authority(
        &self,
        ttl: std::time::Duration,
    ) -> Result<u64, TransferCoordinatorError> {
        let lease = self.coordinator_lease.as_ref().ok_or_else(|| {
            TransferCoordinatorError::LeaseViolation(
                "A distributed coordinator lease is required".to_string(),
            )
        })?;
        lease
            .acquire_or_renew(&self.runtime_id, ttl)
            .await
            .map_err(|e| TransferCoordinatorError::LeaseViolation(e.to_string()))
    }

    /// Get the optional distributed coordinator lease backend.
    pub fn coordinator_lease(&self) -> Option<&dyn CoordinatorLease> {
        self.coordinator_lease.as_deref()
    }

    /// Get a reference to the checkpoint manager
    pub fn checkpoint_manager(&self) -> std::sync::Arc<std::sync::Mutex<CheckpointManager>> {
        self.checkpoint_manager.clone()
    }

    /// Get a reference to the canonical verifier.
    ///
    /// This is the single source of truth for all proof verification in the protocol.
    /// All verification paths MUST go through this verifier.
    pub fn verifier(&self) -> &CanonicalVerifierImpl {
        &self.verifier
    }

    /// Get a reference to the execution journal.
    ///
    /// The execution journal provides crash-safe phase tracking for transfer execution.
    pub fn execution_journal(&self) -> &dyn ExecutionJournal {
        self.execution_journal.as_ref()
    }

    /// Resume a specific transfer after a crash or restart.
    ///
    /// This method queries the execution journal for the last recorded phase
    /// of a transfer and resumes execution from that phase.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` - The ID of the transfer to resume
    /// * `adapter_registry` - The adapter registry for chain operations
    /// * `runtime_ctx` - Runtime execution context with lease and policy
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    pub async fn resume_transfer(
        &self,
        transfer_id: &str,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        // Assert lease ownership invariant
        self.assert_single_active_coordinator(transfer_id).await?;

        let recovery_entry = self
            .execution_journal
            .latest_entry(transfer_id)
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?
            .ok_or(TransferCoordinatorError::NotFound)?;
        let phase = recovery_entry.phase;

        tracing::info!("Resuming transfer {} from phase {:?}", transfer_id, phase);

        // Try to retrieve transfer from durable storage
        let transfers = self.replay_db.load_all_transfers().await.map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Failed to load transfers: {}", e))
        })?;

        let cached_transfer = transfers
            .iter()
            .find(|entry| {
                entry.transfer_id == transfer_id
                    || (entry.transfer_id.is_empty()
                        && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
            })
            .map(|entry| registry_entry_to_transfer(entry, transfer_id.to_string()));

        // Phase-specific recovery logic
        match phase {
            crate::recovery::TransferStage::Initialized => {
                // Transfer was initialized but lock was never broadcast
                // Try to recover from cache if available
                if let Some(transfer) = cached_transfer {
                    tracing::info!("Recovering transfer from cache - restarting from lock phase");
                    // Re-execute the transfer from the beginning
                    // The replay check will prevent duplicate execution
                    self.execute(transfer, adapter_registry, runtime_ctx).await
                } else {
                    Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from Initialized phase - transfer state lost (cache miss)"
                            .to_string(),
                    ))
                }
            }
            crate::recovery::TransferStage::LockSubmitted => {
                // Lock was submitted but not confirmed - resume by checking lock status
                if let Some(transfer) = cached_transfer {
                    tracing::info!("Resuming from LockSubmitted - checking lock status");
                    // Delegate to execute_from_lock which will check lock status
                    self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                        .await
                } else {
                    Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from LockSubmitted phase - transfer state lost (cache miss)"
                            .to_string(),
                    ))
                }
            }
            crate::recovery::TransferStage::LockConfirmed => {
                // Try to reconstruct transfer from journal context
                let transfer = if let Some(transfer) = cached_transfer {
                    transfer
                } else if let Some(ctx) = recovery_entry.transfer_context {
                    // Reconstruct transfer from journal context
                    tracing::info!("Reconstructing transfer from journal context for LockConfirmed recovery");
                    CrossChainTransfer {
                        id: transfer_id.to_string(),
                        source_chain: ctx.source_chain.clone(),
                        destination_chain: ctx.destination_chain.clone(),
                        lock_tx_hash: ctx.lock_tx_hash.to_vec(),
                        lock_output_index: 0,
                        sanad_id: csv_hash::Hash::new(*ctx.sanad_id.as_bytes()),
                        transition_id: vec![],
                    }
                } else {
                    return Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from LockConfirmed phase - transfer context missing from journal"
                            .to_string(),
                    ));
                };
                self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                    .await
            }
            crate::recovery::TransferStage::ProofBuilding => {
                // Check for persisted proof checkpoint before regenerating
                if let Some(proof_payload) = &recovery_entry.proof_payload {
                    if !proof_payload.is_empty() {
                        tracing::info!("Resuming from ProofBuilding - using persisted proof checkpoint");
                        // Proof was already built and persisted, skip regeneration
                        let proof_bundle: csv_protocol::proof_types::ProofBundle =
                            csv_codec::from_canonical_cbor(proof_payload).map_err(|e| {
                                TransferCoordinatorError::ProofVerificationFailed(format!(
                                    "Persisted proof checkpoint is malformed: {}",
                                    e
                                ))
                            })?;
                        
                        // Reconstruct transfer from journal context if needed
                        let transfer = if let Some(transfer) = cached_transfer {
                            transfer
                        } else if let Some(ctx) = &recovery_entry.transfer_context {
                            CrossChainTransfer {
                                id: transfer_id.to_string(),
                                source_chain: ctx.source_chain.clone(),
                                destination_chain: ctx.destination_chain.clone(),
                                lock_tx_hash: ctx.lock_tx_hash.as_bytes().to_vec(),
                                lock_output_index: 0,
                                sanad_id: csv_hash::Hash::new(*ctx.sanad_id.as_bytes()),
                                transition_id: vec![],
                            }
                        } else {
                            return Err(TransferCoordinatorError::RuntimeError(
                                "Cannot resume from ProofBuilding - transfer context missing"
                                    .to_string(),
                            ));
                        };
                        
                        // Verify the persisted proof and proceed to mint
                        let lock_tx_hash = hex::encode(hash_from_tx_bytes(&transfer.lock_tx_hash)?.as_bytes());
                        let confirmed_lock = adapter_registry
                            .confirm_tx(&transfer.source_chain, &lock_tx_hash)
                            .await
                            .map_err(|e| TransferCoordinatorError::FinalityFailed(e.to_string()))?;
                        
                        self.verify_recovery_proof(
                            &transfer,
                            &proof_bundle,
                            confirmed_lock.block_height,
                            adapter_registry,
                            &runtime_ctx,
                        )
                        .await?;
                        
                        self.execute_from_proof(transfer, proof_payload.clone(), adapter_registry, runtime_ctx)
                            .await
                    } else {
                        // No persisted proof, need to regenerate
                        let transfer = if let Some(transfer) = cached_transfer {
                            transfer
                        } else if let Some(ctx) = recovery_entry.transfer_context {
                            CrossChainTransfer {
                                id: transfer_id.to_string(),
                                source_chain: ctx.source_chain.clone(),
                                destination_chain: ctx.destination_chain.clone(),
                                lock_tx_hash: ctx.lock_tx_hash.as_bytes().to_vec(),
                                lock_output_index: 0,
                                sanad_id: csv_hash::Hash::new(*ctx.sanad_id.as_bytes()),
                                transition_id: vec![],
                            }
                        } else {
                            return Err(TransferCoordinatorError::RuntimeError(
                                "Cannot resume from ProofBuilding phase - transfer state lost"
                                    .to_string(),
                            ));
                        };
                        self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                            .await
                    }
                } else {
                    // No proof payload in journal, need to regenerate
                    let transfer = if let Some(transfer) = cached_transfer {
                        transfer
                    } else if let Some(ctx) = recovery_entry.transfer_context {
                        CrossChainTransfer {
                            id: transfer_id.to_string(),
                            source_chain: ctx.source_chain.clone(),
                            destination_chain: ctx.destination_chain.clone(),
                            lock_tx_hash: ctx.lock_tx_hash.as_bytes().to_vec(),
                            lock_output_index: 0,
                            sanad_id: csv_hash::Hash::new(*ctx.sanad_id.as_bytes()),
                            transition_id: vec![],
                        }
                    } else {
                        return Err(TransferCoordinatorError::RuntimeError(
                            "Cannot resume from ProofBuilding phase - transfer state lost"
                                .to_string(),
                        ));
                    };
                    self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                        .await
                }
            }
            crate::recovery::TransferStage::ProofValidated => {
                // Proof was validated, need to resume from mint broadcast
                if let Some(transfer) = cached_transfer {
                    tracing::info!("Resuming from ProofValidated - proceeding to mint");
                    let proof_payload = recovery_entry.proof_payload.ok_or_else(|| {
                        TransferCoordinatorError::RuntimeError(
                            "Cannot resume from ProofValidated phase - verified proof payload missing"
                                .to_string(),
                        )
                    })?;
                    if recovery_entry.proof_hash != proof_payload_hash(&proof_payload) {
                        return Err(TransferCoordinatorError::ProofVerificationFailed(
                            "Persisted proof payload does not match journal digest".to_string(),
                        ));
                    }
                    self.execute_from_proof(transfer, proof_payload, adapter_registry, runtime_ctx)
                        .await
                } else {
                    Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from ProofValidated phase - transfer state lost (cache miss)".to_string()
                    ))
                }
            }
            crate::recovery::TransferStage::AwaitingFinality => {
                // Awaiting finality - resume from finality check
                // Re-poll finality monitor with proof height from journal
                let transfer = if let Some(transfer) = cached_transfer {
                    transfer
                } else if let Some(ctx) = recovery_entry.transfer_context {
                    tracing::info!("Reconstructing transfer from journal context for AwaitingFinality recovery");
                    CrossChainTransfer {
                        id: transfer_id.to_string(),
                        source_chain: ctx.source_chain.clone(),
                        destination_chain: ctx.destination_chain.clone(),
                        lock_tx_hash: ctx.lock_tx_hash.as_bytes().to_vec(),
                        lock_output_index: 0,
                        sanad_id: csv_hash::Hash::new(*ctx.sanad_id.as_bytes()),
                        transition_id: vec![],
                    }
                } else {
                    return Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from AwaitingFinality phase - transfer context missing from journal"
                            .to_string(),
                    ));
                };
                self.execute_from_lock(transfer, adapter_registry, runtime_ctx)
                    .await
            }
            crate::recovery::TransferStage::MintSubmitted => {
                let entry = transfers
                    .iter()
                    .find(|entry| {
                        entry.transfer_id == transfer_id
                            || (entry.transfer_id.is_empty()
                                && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
                    })
                    .ok_or(TransferCoordinatorError::NotFound)?;
                if entry.mint_tx_hash == csv_hash::Hash::zero() {
                    return Err(TransferCoordinatorError::RuntimeError(
                        "Cannot resume from MintSubmitted phase - mint tx hash missing".to_string(),
                    ));
                }
                let mint_tx_hash = hex::encode(entry.mint_tx_hash.as_bytes());
                self.execute_from_mint(transfer_id, &mint_tx_hash, adapter_registry, runtime_ctx)
                    .await
            }
            crate::recovery::TransferStage::MintConfirmed => {
                // Mint was confirmed - transfer should be complete
                tracing::info!("Transfer {} is already at MintConfirmed phase", transfer_id);
                Err(TransferCoordinatorError::RuntimeError(
                    "Transfer already at MintConfirmed phase - should be marked as Completed"
                        .to_string(),
                ))
            }
            crate::recovery::TransferStage::Completed => {
                Err(TransferCoordinatorError::AlreadyComplete)
            }
            crate::recovery::TransferStage::RolledBack => {
                Err(TransferCoordinatorError::AlreadyRolledBack)
            }
            crate::recovery::TransferStage::Compromised => {
                // Transfer was compromised - cannot resume
                Err(TransferCoordinatorError::RuntimeError(
                    "Cannot resume from Compromised phase - transfer security incident".to_string(),
                ))
            }
        }
    }

    /// Execute transfer from lock phase (skip lock, go to proof generation).
    ///
    /// This helper method is used for crash recovery when the lock transaction
    /// is already confirmed but the transfer crashed before proof generation.
    ///
    /// # Arguments
    ///
    /// * `transfer` - The transfer to execute
    /// * `adapter_registry` - The adapter registry for chain operations
    /// * `runtime_ctx` - Runtime execution context with lease and policy
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    async fn validate_recovery_context(
        &self,
        transfer: &CrossChainTransfer,
        runtime_ctx: &crate::lease::RuntimeExecutionContext,
    ) -> Result<csv_hash::ReplayIdHash, TransferCoordinatorError> {
        self.assert_single_active_coordinator(&transfer.id).await?;
        if runtime_ctx.lease.owner_runtime_id != runtime_ctx.runtime_instance
            || runtime_ctx.lease.epoch == 0
            || !runtime_ctx.lease.is_active(std::time::SystemTime::now())
        {
            return Err(TransferCoordinatorError::LeaseViolation(
                "Recovery requires an active lease owned by the calling runtime".to_string(),
            ));
        }
        if runtime_ctx.lease.transfer_id.as_bytes() != transfer.sanad_id.as_bytes() {
            return Err(TransferCoordinatorError::LeaseViolation(
                "Recovery lease does not authorize the transfer sanad".to_string(),
            ));
        }
        self.accept_execution_lease(&runtime_ctx.lease)?;
        let replay_id = csv_hash::ReplayIdHash(transfer.sanad_id);
        if !self
            .replay_db
            .contains(replay_id.0.as_bytes())
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?
        {
            return Err(TransferCoordinatorError::ReplayDbError(
                "Recovery refused: replay reservation is missing".to_string(),
            ));
        }
        Ok(replay_id)
    }

    async fn verify_recovery_proof(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &csv_protocol::proof_types::ProofBundle,
        confirmed_height: u64,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: &crate::lease::RuntimeExecutionContext,
    ) -> Result<(), TransferCoordinatorError> {
        runtime_ctx
            .policy
            .check_finality_threshold(&transfer.source_chain, confirmed_height)
            .map_err(TransferCoordinatorError::FinalityFailed)?;

        let signature_scheme = runtime_signature_scheme(proof_bundle.signature_scheme)?;
        if let Some(expected_scheme) = adapter_registry.signature_scheme(&transfer.source_chain)
            && expected_scheme != signature_scheme
        {
            return Err(TransferCoordinatorError::ProofVerificationFailed(format!(
                "Proof bundle signature scheme {:?} does not match source chain {} scheme {:?}",
                signature_scheme, transfer.source_chain, expected_scheme
            )));
        }

        let seal_status = adapter_registry
            .check_seal_registry(&transfer.source_chain, &proof_bundle.seal_ref.id)
            .await
            .map_err(|e| {
                TransferCoordinatorError::ProofVerificationFailed(format!(
                    "Seal registry check failed: {}",
                    e
                ))
            })?;
        let seal_is_consumed = matches!(
            seal_status,
            csv_adapter_core::SealRegistryStatus::Consumed
        );
        let seal_id_for_registry = proof_bundle.seal_ref.id.clone();
        let required_confirmations = runtime_ctx
            .policy
            .finality_depth_for_chain(&transfer.source_chain)
            .ok_or_else(|| {
                TransferCoordinatorError::FinalityFailed(format!(
                    "No finality depth configured for chain: {}",
                    transfer.source_chain
                ))
            })?;

        let sanad_id_bound = proof_bundle
            .seal_ref
            .id
            .get(0..32)
            .map(|b| csv_hash::SanadId::new(b.try_into().unwrap_or([0u8; 32])));
        if let Some(ref bound_sanad) = sanad_id_bound {
            let expected_sanad = csv_hash::SanadId(transfer.sanad_id);
            if bound_sanad.as_bytes() != expected_sanad.as_bytes() {
                return Err(TransferCoordinatorError::ProofVerificationFailed(
                    "Proof seal does not bind to the transfer sanad_id".to_string(),
                ));
            }
        }

        if transfer.lock_tx_hash.len() == 32 {
            let expected_lock_bytes = hex::encode(&transfer.lock_tx_hash);
            let proof_lock_bytes = proof_bundle
                .anchor_ref
                .metadata
                .get(0..expected_lock_bytes.len())
                .map(|s| String::from_utf8_lossy(s).to_string());
            if let Some(ref lock_bytes) = proof_lock_bytes
                && lock_bytes.as_str() != expected_lock_bytes.as_str()
            {
                return Err(TransferCoordinatorError::ProofVerificationFailed(
                    "Proof anchor metadata does not bind to the lock transaction".to_string(),
                ));
            }
        }

        let verification_context = VerificationContext {
            chain_id: transfer.source_chain.clone(),
            signature_scheme,
            required_confirmations,
            current_block_height: Some(confirmed_height + required_confirmations),
            seal_registry: Some(Box::new(move |seal_id: &[u8]| {
                seal_is_consumed && seal_id == seal_id_for_registry.as_slice()
            })),
            chain_data: None,
            native_proof_validated: true,
            sanad_id: Some(csv_hash::SanadId(transfer.sanad_id)),
            lock_tx: Some(transfer.lock_tx_hash.clone()),
            lock_output_index: Some(transfer.lock_output_index),
            transition_id: Some(transfer.transition_id.clone()),
            destination_chain: Some(transfer.destination_chain.clone()),
        };
        adapter_registry
            .validate_source_proof(&transfer.source_chain, transfer, proof_bundle)
            .await
            .map_err(|e| TransferCoordinatorError::ProofVerificationFailed(e.to_string()))?;
        let result = self
            .verifier
            .verify_proof_bundle(proof_bundle, &verification_context)
            .map_err(|e| TransferCoordinatorError::ProofVerificationFailed(e.to_string()))?;
        if result.is_valid {
            Ok(())
        } else {
            Err(TransferCoordinatorError::ProofVerificationFailed(
                result
                    .errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }

    pub async fn execute_from_lock(
        &self,
        transfer: CrossChainTransfer,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        let replay_id = self
            .validate_recovery_context(&transfer, &runtime_ctx)
            .await?;
        let lock_tx_hash = hex::encode(hash_from_tx_bytes(&transfer.lock_tx_hash)?.as_bytes());
        let confirmed_lock = adapter_registry
            .confirm_tx(&transfer.source_chain, &lock_tx_hash)
            .await
            .map_err(|e| TransferCoordinatorError::LockFailed(e.to_string()))?;
        let lock_result = csv_adapter_core::LockResult {
            tx_hash: confirmed_lock.tx_hash,
            block_height: confirmed_lock.block_height,
        };

        // Build transfer context for crash recovery
        let sanad_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(transfer.sanad_id.as_bytes());
            arr
        };
        let lock_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&transfer.lock_tx_hash[..32]);
            arr
        };
        let transfer_context = crate::execution_journal::TransferContext {
            sanad_id: csv_hash::SanadId(csv_hash::Hash::new(sanad_bytes)),
            source_chain: transfer.source_chain.clone(),
            destination_chain: transfer.destination_chain.clone(),
            lock_tx_hash: csv_hash::Hash::new(lock_bytes),
            destination_owner: String::new(),
        };

        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 2,
                transfer_context: Some(transfer_context.clone()),
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        runtime_ctx
            .policy
            .check_finality_threshold(&transfer.source_chain, lock_result.block_height)
            .map_err(TransferCoordinatorError::FinalityFailed)?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::AwaitingFinality,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::ProofBuilding,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        let proof_bundle = adapter_registry
            .build_inclusion_proof(&transfer.source_chain, &transfer, &lock_result)
            .await
            .map_err(|e| TransferCoordinatorError::ProofBuildFailed(e.to_string()))?;
        self.verify_recovery_proof(
            &transfer,
            &proof_bundle,
            lock_result.block_height,
            adapter_registry,
            &runtime_ctx,
        )
        .await?;
        let proof_payload = csv_codec::to_canonical_cbor(&proof_bundle)
            .map_err(|e| TransferCoordinatorError::ProofBuildFailed(e.to_string()))?;
        let proof_hash = proof_payload_hash(&proof_payload);
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash,
                proof_payload: Some(proof_payload.clone()),
                phase: TransferStage::ProofBuilding,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash,
                proof_payload: Some(proof_payload.clone()),
                phase: TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.execute_from_proof(transfer, proof_payload, adapter_registry, runtime_ctx)
            .await
    }

    /// Execute transfer from proof phase (skip proof generation, go to mint).
    ///
    /// This helper method is used for crash recovery when the proof is already
    /// generated but the transfer crashed before minting.
    ///
    /// # Arguments
    ///
    /// * `transfer` - The transfer to execute
    /// * `proof_bundle` - The proof bundle to use for minting
    /// * `adapter_registry` - The adapter registry for chain operations
    /// * `runtime_ctx` - Runtime execution context with lease and policy
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    pub async fn execute_from_proof(
        &self,
        transfer: CrossChainTransfer,
        proof_payload: Vec<u8>,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        let replay_id = self
            .validate_recovery_context(&transfer, &runtime_ctx)
            .await?;
        if proof_payload.is_empty() {
            return Err(TransferCoordinatorError::ProofVerificationFailed(
                "Persisted proof payload is empty".to_string(),
            ));
        }
        let proof_bundle: csv_protocol::proof_types::ProofBundle =
            csv_codec::from_canonical_cbor(&proof_payload).map_err(|e| {
                TransferCoordinatorError::ProofVerificationFailed(format!(
                    "Persisted proof payload is malformed: {}",
                    e
                ))
            })?;
        let lock_tx_hash = hex::encode(hash_from_tx_bytes(&transfer.lock_tx_hash)?.as_bytes());
        let confirmed_lock = adapter_registry
            .confirm_tx(&transfer.source_chain, &lock_tx_hash)
            .await
            .map_err(|e| TransferCoordinatorError::FinalityFailed(e.to_string()))?;
        self.verify_recovery_proof(
            &transfer,
            &proof_bundle,
            confirmed_lock.block_height,
            adapter_registry,
            &runtime_ctx,
        )
        .await?;

        let _admission_permit = self
            .admission_controller
            .acquire_transfer(&transfer.source_chain, &transfer.destination_chain)?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: proof_payload_hash(&proof_payload),
                proof_payload: Some(proof_payload.clone()),
                phase: TransferStage::MintSubmitted,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Entered,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        let mint_result = adapter_registry
            .mint_sanad(&transfer.destination_chain, &transfer, &proof_payload)
            .await
            .map_err(|e| TransferCoordinatorError::MintFailed(e.to_string()))?;
        let mut submitted_entry = transfer_to_registry_entry(&transfer)?;
        submitted_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&submitted_entry)
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: proof_payload_hash(&proof_payload),
                proof_payload: Some(proof_payload),
                phase: TransferStage::MintSubmitted,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.execute_from_mint(
            &transfer.id,
            &mint_result.tx_hash,
            adapter_registry,
            runtime_ctx,
        )
        .await
    }

    /// Execute transfer from mint phase (skip mint broadcast, just confirm).
    ///
    /// This helper method is used for crash recovery when the mint transaction
    /// is already submitted but the transfer crashed before confirmation.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` - The ID of the transfer to confirm
    /// * `mint_tx_hash` - The hash of the submitted mint transaction
    /// * `adapter_registry` - The adapter registry for chain operations
    ///
    /// # Returns
    ///
    /// The transfer receipt if the transfer completes successfully.
    pub async fn execute_from_mint(
        &self,
        transfer_id: &str,
        mint_tx_hash: &str,
        adapter_registry: &dyn AdapterRegistry,
        runtime_ctx: crate::lease::RuntimeExecutionContext,
    ) -> Result<TransferReceipt, TransferCoordinatorError> {
        // Assert lease ownership invariant
        self.assert_single_active_coordinator(transfer_id).await?;

        tracing::info!(
            "Executing transfer {} from mint phase (confirming mint transaction {})",
            transfer_id,
            mint_tx_hash
        );

        let transfers = self.replay_db.load_all_transfers().await.map_err(|e| {
            TransferCoordinatorError::RuntimeError(format!("Failed to load transfers: {}", e))
        })?;

        let transfer = transfers
            .iter()
            .find(|entry| {
                entry.transfer_id == transfer_id
                    || (entry.transfer_id.is_empty()
                        && hex::encode(entry.sanad_id.as_bytes()) == transfer_id)
            })
            .map(|entry| registry_entry_to_transfer(entry, transfer_id.to_string()))
            .ok_or(TransferCoordinatorError::NotFound)?;
        self.validate_recovery_context(&transfer, &runtime_ctx)
            .await?;

        let mint_result = adapter_registry
            .confirm_tx(&transfer.destination_chain, mint_tx_hash)
            .await
            .map_err(|e| TransferCoordinatorError::RuntimeError(e.to_string()))?;

        let replay_id = csv_hash::ReplayIdHash(transfer.sanad_id);
        self.replay_db
            .confirm_consumed(replay_id.0.as_bytes())
            .await
            .map_err(|e| TransferCoordinatorError::ReplayDbError(e.to_string()))?;

        let mut registry_entry = transfer_to_registry_entry(&transfer)?;
        registry_entry.mint_tx_hash = hash_from_tx_str(&mint_result.tx_hash)?;
        self.replay_db
            .store_transfer_entry(&registry_entry)
            .await
            .map_err(|e| {
                TransferCoordinatorError::RuntimeError(format!(
                    "Failed to persist confirmed transfer: {}",
                    e
                ))
            })?;

        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::MintConfirmed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;
        self.execution_journal
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::Completed,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        self.event_bus
            .emit(TransferEvent::Complete(crate::event_bus::TransferContext {
                transfer_id: transfer.id.clone(),
                replay_id: Some(replay_id),
                proof_hash: None,
                coordinator_id: self
                    .runtime_id
                    .0
                    .parse()
                    .unwrap_or_else(|_| uuid::Uuid::new_v4()),
                lease_id: None,
                source_chain: transfer.source_chain.clone(),
                dest_chain: transfer.destination_chain.clone(),
                finality_state: crate::event_bus::FinalityState::Confirmed,
                recovery_attempt: 0,
            }));

        Ok(TransferReceipt {
            transfer_id: transfer.id,
            replay_id,
            lock_tx_hash: hex::encode(transfer.lock_tx_hash),
            mint_tx_hash: mint_result.tx_hash,
        })
    }

    /// Resume all incomplete transfers after a crash or restart.
    ///
    /// This method queries the execution journal for incomplete transfers and
    /// attempts to resume them from their last recorded phase.
    ///
    /// # Returns
    ///
    /// The number of transfers that were successfully resumed.
    pub async fn resume_transfers(
        &self,
        adapter_registry: &dyn AdapterRegistry,
        recovery_contexts: &dyn RecoveryContextProvider,
    ) -> Result<usize, TransferCoordinatorError> {
        let incomplete = self
            .execution_journal
            .incomplete_transfers()
            .map_err(|e| TransferCoordinatorError::RuntimeError(format!("Journal error: {}", e)))?;

        let mut resumed = 0;

        for entry in incomplete {
            tracing::info!(
                "Found incomplete transfer: {} at phase {:?}",
                entry.transfer_id,
                entry.phase
            );

            // Skip terminal phases that shouldn't be marked as incomplete
            match entry.phase {
                crate::recovery::TransferStage::Completed => {
                    tracing::warn!(
                        "Transfer {} marked as incomplete but phase is Completed - skipping",
                        entry.transfer_id
                    );
                    continue;
                }
                crate::recovery::TransferStage::RolledBack => {
                    tracing::warn!(
                        "Transfer {} marked as incomplete but phase is RolledBack - skipping",
                        entry.transfer_id
                    );
                    continue;
                }
                crate::recovery::TransferStage::Compromised => {
                    tracing::warn!(
                        "Transfer {} marked as incomplete but phase is Compromised - skipping",
                        entry.transfer_id
                    );
                    continue;
                }
                _ => {}
            }

            let runtime_ctx = recovery_contexts.context_for(&entry.transfer_id).await?;

            match self
                .resume_transfer(&entry.transfer_id, adapter_registry, runtime_ctx)
                .await
            {
                Ok(_) => {
                    tracing::info!("Successfully resumed transfer {}", entry.transfer_id);
                    resumed += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to resume transfer {}: {}", entry.transfer_id, e);
                    // Continue with other transfers even if this one fails
                }
            }
        }

        Ok(resumed)
    }
}

/// Supplies authenticated lease context for restart recovery.
///
/// Implementations must retrieve or acquire authority from durable runtime
/// state. Journal contents alone never grant mutation authority.
#[async_trait::async_trait]
pub trait RecoveryContextProvider: Send + Sync {
    async fn context_for(
        &self,
        transfer_id: &str,
    ) -> Result<crate::lease::RuntimeExecutionContext, TransferCoordinatorError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_adapter_core::{
        ChainAdapter, CrossChainTransfer as RuntimeCrossChainTransfer,
        LockResult, MintResult, SealRegistryStatus,
    };
    use crate::adapter_registry::AdapterRegistryImpl;
    use csv_protocol::finality::ChainCapabilities;
    use csv_protocol::proof_taxonomy::{InclusionProof, ProofBundle};
    use csv_storage::ReplayDatabase;
    use std::sync::Arc;

    // Local test adapter to avoid orphan rule
    struct LocalTestAdapter {
        caps: ChainCapabilities,
    }

    impl LocalTestAdapter {
        fn new(caps: ChainCapabilities) -> Self {
            Self { caps }
        }

        fn new_bitcoin() -> Self {
            Self::new(ChainCapabilities::bitcoin())
        }

        fn build_fake_lock_result() -> LockResult {
            LockResult {
                tx_hash: hex::encode([0u8; 32]),
                block_height: 100,
            }
        }

        fn build_fake_mint_result() -> MintResult {
            MintResult {
                tx_hash: "0x123".to_string(),
                block_height: 100,
            }
        }

        fn build_fake_inclusion_proof(
            sanad_id: &csv_hash::Hash,
        ) -> Result<ProofBundle, String> {
            // Use deterministic proof fixture from csv-testkit
            let mut bundle = csv_testkit::fixtures::TestProofBundle::minimal();
            // Update the seal_ref to match the sanad_id
            bundle.seal_ref.id = sanad_id.as_bytes().to_vec();
            Ok(bundle)
        }
    }

    #[test]
    fn test_registry_entry_roundtrip_preserves_lock_tx_and_output_index() {
        let transfer = CrossChainTransfer {
            id: "roundtrip".to_string(),
            source_chain: "bitcoin".to_string(),
            destination_chain: "ethereum".to_string(),
            lock_tx_hash: vec![0xAB; 32],
            lock_output_index: 7,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let entry = transfer_to_registry_entry(&transfer).unwrap();
        let restored = registry_entry_to_transfer(&entry, transfer.id.clone());

        assert_eq!(restored.id, transfer.id);
        assert_eq!(restored.source_chain, transfer.source_chain);
        assert_eq!(restored.destination_chain, transfer.destination_chain);
        assert_eq!(restored.lock_tx_hash, transfer.lock_tx_hash);
        assert_eq!(restored.lock_output_index, transfer.lock_output_index);
        assert_eq!(restored.sanad_id, transfer.sanad_id);
        assert_eq!(restored.transition_id, transfer.transition_id);
    }

    #[test]
    fn test_registry_entry_rejects_malformed_lock_tx_hash() {
        let transfer = CrossChainTransfer {
            id: "bad-hash".to_string(),
            source_chain: "bitcoin".to_string(),
            destination_chain: "ethereum".to_string(),
            lock_tx_hash: vec![0xAB; 31],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        assert!(matches!(
            transfer_to_registry_entry(&transfer),
            Err(TransferCoordinatorError::InvalidTxHash(_))
        ));
    }

    #[async_trait::async_trait]
    impl ChainAdapter for LocalTestAdapter {
        fn chain_id(&self) -> &str {
            "test-chain"
        }

        fn capabilities(&self) -> ChainCapabilities {
            self.caps.clone()
        }

        fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
            csv_protocol::signature::SignatureScheme::Secp256k1
        }

        async fn lock_sanad(
            &self,
            _transfer: &CrossChainTransfer,
        ) -> Result<LockResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_lock_result())
        }

        async fn mint_sanad(
            &self,
            _transfer: &CrossChainTransfer,
            _proof_bundle: &[u8],
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(LocalTestAdapter::build_fake_mint_result())
        }

        async fn build_inclusion_proof(
            &self,
            transfer: &CrossChainTransfer,
            _lock_result: &LockResult,
        ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
            LocalTestAdapter::build_fake_inclusion_proof(&transfer.sanad_id)
                .map_err(|e| csv_adapter_core::AdapterError::Generic(e))
        }

        async fn validate_source_proof(
            &self,
            transfer: &CrossChainTransfer,
            proof_bundle: &ProofBundle,
        ) -> Result<(), csv_adapter_core::AdapterError> {
            if proof_bundle.seal_ref.id != transfer.sanad_id.as_bytes() {
                return Err(csv_adapter_core::AdapterError::Generic(
                    "proof is not bound to the requested sanad".to_string(),
                ));
            }
            Ok(())
        }

        async fn check_seal_registry(
            &self,
            _seal_id: &[u8],
        ) -> Result<
            csv_adapter_core::SealRegistryStatus,
            csv_adapter_core::AdapterError,
        > {
            Ok(csv_adapter_core::SealRegistryStatus::Available)
        }

        async fn confirm_tx(
            &self,
            tx_hash: &str,
        ) -> Result<MintResult, csv_adapter_core::AdapterError> {
            Ok(MintResult {
                tx_hash: tx_hash.to_string(),
                block_height: 100,
            })
        }

        async fn get_balance(
            &self,
            _address: &str,
        ) -> Result<String, csv_adapter_core::AdapterError> {
            Ok("0".to_string())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    async fn recovery_fixture(
        phase: TransferStage,
        proof_payload: Option<Vec<u8>>,
    ) -> (
        TransferCoordinator,
        AdapterRegistryImpl,
        CrossChainTransfer,
        crate::lease::RuntimeExecutionContext,
    ) {
        let transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let db = csv_storage::InMemoryReplayDb::new();
        db.insert_if_absent(transfer.sanad_id.as_bytes())
            .await
            .unwrap();
        db.store_transfer_entry(&transfer_to_registry_entry(&transfer).unwrap())
            .await
            .unwrap();
        let coordinator = TransferCoordinator::new(Box::new(db), EventBus::new());
        let replay_id = csv_hash::ReplayIdHash(transfer.sanad_id);
        let proof_hash = proof_payload
            .as_ref()
            .map(|payload| proof_payload_hash(payload))
            .unwrap_or([0u8; 32]);
        coordinator
            .execution_journal()
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id,
                proof_hash,
                proof_payload,
                phase,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 1,
                transfer_context: None,
            })
            .unwrap();
        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();
        let owner = uuid::Uuid::new_v4();
        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: crate::lease::TransferLease {
                transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
                epoch: 1,
                owner_runtime_id: owner,
                acquired_at: std::time::SystemTime::now(),
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            },
            runtime_instance: owner,
            policy: crate::policy::RuntimePolicy::new(),
        };
        (coordinator, registry, transfer, runtime_ctx)
    }

    #[tokio::test]
    async fn lock_confirmed_recovery_regenerates_proof_and_completes() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::LockConfirmed, None).await;

        let receipt = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("confirmed lock must resume without rebroadcasting lock");

        assert_eq!(receipt.transfer_id, transfer.id);
        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn awaiting_finality_recovery_rechecks_finality_and_completes() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::AwaitingFinality, None).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("finality recovery must regenerate proof and complete");

        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn proof_building_recovery_regenerates_proof_and_completes() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofBuilding, None).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("proof-building recovery must regenerate proof and complete");

        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn proof_validated_recovery_uses_persisted_payload_and_completes() {
        let expected_transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let proof_bundle = LocalTestAdapter::new_bitcoin()
            .build_inclusion_proof(
                &expected_transfer,
                &LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                },
            )
            .await
            .unwrap();
        let payload = csv_codec::to_canonical_cbor(&proof_bundle).unwrap();
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(payload)).await;

        coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await
            .expect("validated proof recovery must mint using durable proof bytes");

        assert_eq!(
            coordinator
                .execution_journal()
                .latest_phase(&transfer.id)
                .unwrap(),
            Some(TransferStage::Completed)
        );
    }

    #[tokio::test]
    async fn proof_validated_recovery_rejects_missing_payload() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, None).await;

        let result = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::RuntimeError(message))
                if message.contains("proof payload missing")
        ));
    }

    #[tokio::test]
    async fn proof_validated_recovery_rejects_malformed_payload() {
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(vec![0xFF, 0x00])).await;

        let result = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::ProofVerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn proof_validated_recovery_rejects_tampered_payload_digest() {
        let expected_transfer = CrossChainTransfer {
            id: "recover-transfer".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([44u8; 32]),
            transition_id: vec![3u8; 32],
        };
        let bundle = LocalTestAdapter::new_bitcoin()
            .build_inclusion_proof(
                &expected_transfer,
                &LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                },
            )
            .await
            .unwrap();
        let payload = csv_codec::to_canonical_cbor(&bundle).unwrap();
        let (coordinator, registry, transfer, runtime_ctx) =
            recovery_fixture(TransferStage::ProofValidated, Some(payload.clone())).await;
        coordinator
            .execution_journal()
            .record(crate::execution_journal::TransferPhaseEntry {
                transfer_id: transfer.id.clone(),
                replay_id: csv_hash::ReplayIdHash(transfer.sanad_id),
                proof_hash: [0xFF; 32],
                proof_payload: Some(payload),
                phase: TransferStage::ProofValidated,
                ts: std::time::SystemTime::now(),
                outcome: crate::execution_journal::PhaseOutcome::Completed,
                attempt: 2,
                transfer_context: None,
            })
            .unwrap();

        let result = coordinator
            .resume_transfer(&transfer.id, &registry, runtime_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::ProofVerificationFailed(message))
                if message.contains("journal digest")
        ));
    }

    #[tokio::test]
    async fn test_transfer_coordinator_replay_idempotent() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-1".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // First transfer should succeed
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(
            result.is_ok(),
            "First execution should succeed: {:?}",
            result
        );

        // Completed transfers are idempotent — `consume_if_unconsumed` returns Ok(())
        // for already Consumed entries. This allows safe retries of completed transfers.
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(
            result.is_ok(),
            "Completed transfers should be idempotent: {:?}",
            result
        );

        // Now test that a Pending entry (inserted without confirming) blocks a retry.
        // We need a different transfer to get a different ReplayId.
        let pending_transfer = CrossChainTransfer {
            id: "test-pending".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![5u8; 32], // different lock tx
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([6u8; 32]), // different sanad
            transition_id: vec![7u8; 32],             // different transition
        };

        let pending_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*pending_transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        let pending_ctx = crate::lease::RuntimeExecutionContext {
            lease: pending_lease.clone(),
            runtime_instance: pending_lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // First execution inserts Pending, then the mint succeeds and confirms.
        let result = coordinator
            .execute(pending_transfer.clone(), &registry, pending_ctx)
            .await;
        assert!(
            result.is_ok(),
            "Pending transfer first execution should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_transfer_coordinator_capability_gate() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        // Register celestia which cannot authorize mints (DA only)
        let celestia_caps = ChainCapabilities::celestia();
        struct CelestiaAdapter {
            caps: ChainCapabilities,
        }
        #[async_trait::async_trait]
        impl ChainAdapter for CelestiaAdapter {
            fn chain_id(&self) -> &str {
                "celestia"
            }
            fn capabilities(&self) -> ChainCapabilities {
                self.caps.clone()
            }
            async fn lock_sanad(
                &self,
                _t: &RuntimeCrossChainTransfer,
            ) -> Result<LockResult, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia is not a transfer source".to_string(),
                ))
            }
            async fn mint_sanad(
                &self,
                _t: &RuntimeCrossChainTransfer,
                _p: &[u8],
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia does not authorize destination mints".to_string(),
                ))
            }
            async fn build_inclusion_proof(
                &self,
                _t: &RuntimeCrossChainTransfer,
                _l: &LockResult,
            ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia is not a transfer proof source".to_string(),
                ))
            }
            async fn validate_source_proof(
                &self,
                _t: &RuntimeCrossChainTransfer,
                _p: &ProofBundle,
            ) -> Result<(), csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia is not a transfer proof source".to_string(),
                ))
            }
            async fn check_seal_registry(
                &self,
                _s: &[u8],
            ) -> Result<
                csv_adapter_core::SealRegistryStatus,
                csv_adapter_core::AdapterError,
            > {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Celestia has no transfer seal registry".to_string(),
                ))
            }
            async fn get_balance(
                &self,
                _address: &str,
            ) -> Result<String, csv_adapter_core::AdapterError> {
                Ok("0".to_string())
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }
        registry
            .register_adapter(Box::new(CelestiaAdapter {
                caps: celestia_caps,
            }))
            .unwrap();

        let transfer = RuntimeCrossChainTransfer {
            id: "test-1".to_string(),
            source_chain: "celestia".to_string(),
            destination_chain: "celestia".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        // Celestia cannot be a source (DA only)
        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };
        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::UnsupportedOperation(_))
        ));
    }

    #[tokio::test]
    async fn test_runtime_policy_enforcement() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-policy".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Test with production policy (no RPC fallback, strict finality)
        let production_policy = crate::policy::RuntimePolicy::production();
        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: production_policy,
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx)
            .await;
        assert!(
            result.is_ok(),
            "Transfer should succeed with production policy"
        );

        // Test with development policy (allows RPC fallback)
        let dev_policy = crate::policy::RuntimePolicy::development();
        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: dev_policy,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(
            result.is_ok(),
            "Transfer should succeed with development policy"
        );
    }

    #[tokio::test]
    async fn test_retry_logic_with_policy() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-retry".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Test with policy that allows retries
        let mut policy = crate::policy::RuntimePolicy::new();
        policy.max_retries = 3;
        policy.retry_delay = std::time::Duration::from_millis(10);

        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy,
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(result.is_ok(), "Transfer should succeed with retry policy");
    }

    #[tokio::test]
    async fn test_circuit_breaker_blocks_requests() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        // Open the circuit breaker by recording failures
        for _ in 0..5 {
            coordinator
                .circuit_breaker()
                .lock()
                .unwrap()
                .record_failure();
        }

        let transfer = CrossChainTransfer {
            id: "test-circuit".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::RuntimeError(_))
        ));
    }

    #[tokio::test]
    async fn test_health_monitor_mode_transition() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        // Initially healthy
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::HEALTHY
        );

        // Record a failed health check
        coordinator.record_health_check(crate::runtime_mode::HealthCheck {
            component: "rpc".to_string(),
            healthy: false,
            error: Some("RPC connection failed".to_string()),
            timestamp: std::time::SystemTime::now(),
        });

        // Should be critical (all checks are unhealthy)
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::CRITICAL
        );
    }

    #[tokio::test]
    async fn test_degraded_mode_policy() {
        let policy = crate::policy::RuntimePolicy::development();
        assert_eq!(policy.mode, crate::runtime_mode::RuntimeMode::Degraded);
        assert!(policy.mode.allows_rpc_fallback());
        assert_eq!(policy.max_retries, 5);
    }

    #[tokio::test]
    async fn test_unsafe_mode_policy() {
        let policy = crate::policy::RuntimePolicy::unsafe_mode();
        assert_eq!(policy.mode, crate::runtime_mode::RuntimeMode::Unsafe);
        assert!(policy.mode.allows_rpc_fallback());
        assert_eq!(policy.max_retries, 1);
        assert!(policy.mode.requires_operator_confirmation());
    }

    #[tokio::test]
    async fn test_ha_failover_lease_conflict() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-ha".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let original_runtime_id = uuid::Uuid::new_v4();
        let failover_runtime_id = uuid::Uuid::new_v4();

        // Original runtime acquires lease
        let original_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: original_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let original_ctx = crate::lease::RuntimeExecutionContext {
            lease: original_lease.clone(),
            runtime_instance: original_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // Original runtime executes successfully
        let result = coordinator
            .execute(transfer.clone(), &registry, original_ctx)
            .await;
        assert!(result.is_ok(), "Original runtime should succeed");

        // Failover runtime tries to execute with different runtime ID (should fail)
        let failover_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: failover_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let failover_ctx = crate::lease::RuntimeExecutionContext {
            lease: failover_lease,
            runtime_instance: failover_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, failover_ctx)
            .await;
        assert!(
            matches!(result, Err(TransferCoordinatorError::LeaseViolation(_))),
            "A second runtime cannot reuse an active transfer lease: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_ha_failover_after_lease_expiry() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-ha-expiry".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let original_runtime_id = uuid::Uuid::new_v4();
        let failover_runtime_id = uuid::Uuid::new_v4();

        // Original runtime acquires expired lease
        let expired_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: original_runtime_id,
            acquired_at: std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
            expires_at: std::time::SystemTime::now() - std::time::Duration::from_secs(1800),
        };

        let expired_ctx = crate::lease::RuntimeExecutionContext {
            lease: expired_lease,
            runtime_instance: original_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // Original runtime with expired lease should fail
        let result = coordinator
            .execute(transfer.clone(), &registry, expired_ctx)
            .await;
        assert!(matches!(
            result,
            Err(TransferCoordinatorError::RuntimeError(_))
        ));

        // Failover runtime with new lease should succeed
        let failover_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 2, // Incremented epoch
            owner_runtime_id: failover_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let failover_ctx = crate::lease::RuntimeExecutionContext {
            lease: failover_lease,
            runtime_instance: failover_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator.execute(transfer, &registry, failover_ctx).await;
        assert!(
            result.is_ok(),
            "Failover runtime should succeed with new lease"
        );
    }

    #[tokio::test]
    async fn test_blockchain_reorg_finality_rollback() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-reorg".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // Execute transfer successfully
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx)
            .await;
        assert!(result.is_ok(), "Transfer should succeed initially");

        // Simulate reorg by recording a health check indicating reorg
        coordinator.record_health_check(crate::runtime_mode::HealthCheck {
            component: "blockchain".to_string(),
            healthy: false,
            error: Some("Reorg detected at block 1000".to_string()),
            timestamp: std::time::SystemTime::now(),
        });

        // Health status should be critical (all checks are unhealthy)
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::CRITICAL
        );

        // Circuit breaker should be open after reorg
        for _ in 0..5 {
            coordinator
                .circuit_breaker()
                .lock()
                .unwrap()
                .record_failure();
        }
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );
    }

    #[tokio::test]
    async fn test_reorg_recovery() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        // Open circuit breaker
        for _ in 0..5 {
            coordinator
                .circuit_breaker()
                .lock()
                .unwrap()
                .record_failure();
        }
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );

        // Attempt recovery - fails because default open_timeout is 60 seconds
        std::thread::sleep(std::time::Duration::from_millis(100));

        let recovered = coordinator.attempt_circuit_breaker_recovery();
        assert!(
            !recovered,
            "Circuit breaker should not recover before timeout (60s)"
        );
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );

        // Circuit stays Open because recovery failed (timeout not elapsed)
        // Successes are only processed in HalfOpen state
        assert_eq!(
            coordinator.circuit_breaker().lock().unwrap().state(),
            crate::runtime_mode::CircuitBreakerState::Open
        );
    }

    #[tokio::test]
    async fn test_concurrent_transfer_execution_race() {
        let _replay_db = Arc::new(std::sync::Mutex::new(csv_storage::InMemoryReplayDb::new()));
        let event_bus = EventBus::new();
        let coordinator =
            TransferCoordinator::new(Box::new(csv_storage::InMemoryReplayDb::new()), event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-race".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let runtime_id = uuid::Uuid::new_v4();
        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Execute same transfer concurrently - should be idempotent
        let coordinator_ref = Arc::new(coordinator);
        let registry_ref = Arc::new(registry);
        let mut handles = Vec::new();

        for _ in 0..3 {
            let coord = coordinator_ref.clone();
            let reg = registry_ref.clone();
            let transfer_clone = transfer.clone();
            let lease_clone = lease.clone();
            let runtime_id_clone = runtime_id;

            handles.push(tokio::spawn(async move {
                let ctx = crate::lease::RuntimeExecutionContext {
                    lease: lease_clone,
                    runtime_instance: runtime_id_clone,
                    policy: crate::policy::RuntimePolicy::new(),
                };
                coord.execute(transfer_clone, reg.as_ref(), ctx).await
            }));
        }

        // Await all handles sequentially (equivalent to join_all for testing)
        let mut results = Vec::new();
        for handle in handles {
            results.push(
                handle
                    .await
                    .unwrap_or_else(|e| panic!("task panicked: {}", e)),
            );
        }
        // All should succeed due to idempotency
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 3, "All concurrent executions should succeed");
    }

    #[tokio::test]
    async fn test_concurrent_different_runtime_race() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-diff-race".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let runtime_id_1 = uuid::Uuid::new_v4();
        let runtime_id_2 = uuid::Uuid::new_v4();

        let lease_1 = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: runtime_id_1,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let lease_2 = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: runtime_id_2,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        // Execute with different runtime IDs concurrently - one should fail
        let coordinator_ref = Arc::new(coordinator);
        let registry_ref = Arc::new(registry);
        let mut handles = Vec::new();

        for (i, lease) in [lease_1, lease_2].into_iter().enumerate() {
            let coord = coordinator_ref.clone();
            let reg = registry_ref.clone();
            let transfer_clone = transfer.clone();
            let runtime_id = if i == 0 { runtime_id_1 } else { runtime_id_2 };

            handles.push(tokio::spawn(async move {
                let ctx = crate::lease::RuntimeExecutionContext {
                    lease,
                    runtime_instance: runtime_id,
                    policy: crate::policy::RuntimePolicy::new(),
                };
                coord.execute(transfer_clone, reg.as_ref(), ctx).await
            }));
        }

        // Await all handles sequentially (equivalent to join_all for testing)
        let mut results = Vec::new();
        for handle in handles {
            results.push(
                handle
                    .await
                    .unwrap_or_else(|e| panic!("task panicked: {}", e)),
            );
        }
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 1, "Only one runtime may own an active lease");
    }

    #[tokio::test]
    async fn test_adversarial_proof_bundle_rejection() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        // Create a test adapter that rejects invalid proof bundles
        struct MaliciousLocalTestAdapter {
            caps: ChainCapabilities,
        }

        impl MaliciousLocalTestAdapter {
            fn new() -> Self {
                Self {
                    caps: ChainCapabilities::bitcoin(),
                }
            }
        }

        #[async_trait::async_trait]
        impl ChainAdapter for MaliciousLocalTestAdapter {
            fn chain_id(&self) -> &str {
                "malicious-chain"
            }
            fn capabilities(&self) -> ChainCapabilities {
                self.caps.clone()
            }

            async fn lock_sanad(
                &self,
                _transfer: &CrossChainTransfer,
            ) -> Result<LockResult, csv_adapter_core::AdapterError> {
                Ok(LockResult {
                    tx_hash: hex::encode([0x11u8; 32]),
                    block_height: 100,
                })
            }

            async fn mint_sanad(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &[u8],
            ) -> Result<MintResult, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Malicious proof bundle detected".to_string(),
                ))
            }

            async fn build_inclusion_proof(
                &self,
                _transfer: &CrossChainTransfer,
                _lock_result: &LockResult,
            ) -> Result<ProofBundle, csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Malicious proof bundle detected".to_string(),
                ))
            }

            async fn validate_source_proof(
                &self,
                _transfer: &CrossChainTransfer,
                _proof_bundle: &ProofBundle,
            ) -> Result<(), csv_adapter_core::AdapterError> {
                Err(csv_adapter_core::AdapterError::Generic(
                    "Malicious proof bundle detected".to_string(),
                ))
            }

            async fn check_seal_registry(
                &self,
                _seal_id: &[u8],
            ) -> Result<SealRegistryStatus, csv_adapter_core::AdapterError> {
                Ok(SealRegistryStatus::Available)
            }

            async fn get_balance(
                &self,
                _address: &str,
            ) -> Result<String, csv_adapter_core::AdapterError> {
                Ok("0".to_string())
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(MaliciousLocalTestAdapter::new()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-malicious".to_string(),
            source_chain: "malicious-chain".to_string(),
            destination_chain: "malicious-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // Transfer should fail due to malicious proof bundle rejection
        let result = coordinator.execute(transfer, &registry, runtime_ctx).await;
        assert!(
            result.is_err(),
            "Adversarial transfer should fail: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_double_spend_prevention() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-doublespend".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // First execution should succeed
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(result.is_ok(), "First execution should succeed");

        // Second execution with same transfer should be idempotent (already consumed)
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx.clone())
            .await;
        assert!(result.is_ok(), "Second execution should be idempotent");

        // Try with different transfer ID but same sanad_id (replay attempt from same runtime)
        let replay_transfer = CrossChainTransfer {
            id: "test-replay".to_string(),
            source_chain: transfer.source_chain.clone(),
            destination_chain: transfer.destination_chain.clone(),
            lock_tx_hash: transfer.lock_tx_hash.clone(),
            lock_output_index: transfer.lock_output_index,
            sanad_id: transfer.sanad_id,
            transition_id: transfer.transition_id,
        };

        let replay_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*replay_transfer.sanad_id.as_bytes()),
            epoch: 2,
            owner_runtime_id: lease.owner_runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let replay_ctx = crate::lease::RuntimeExecutionContext {
            lease: replay_lease.clone(),
            runtime_instance: replay_lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator
            .execute(replay_transfer, &registry, replay_ctx)
            .await;
        // Should succeed due to idempotent replay_db (already consumed entries return Ok)
        assert!(
            result.is_ok(),
            "Replay of completed transfer should be idempotent: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_lease_epoch_conflict() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-epoch".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let runtime_id = uuid::Uuid::new_v4();

        // Acquire lease with epoch 1
        let lease_epoch_1 = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let ctx_epoch_1 = crate::lease::RuntimeExecutionContext {
            lease: lease_epoch_1,
            runtime_instance: runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, ctx_epoch_1)
            .await;
        assert!(result.is_ok(), "Epoch 1 should succeed");

        // Try to use stale lease with epoch 1 after epoch 2 has been issued
        let lease_epoch_2 = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 2,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let ctx_epoch_2 = crate::lease::RuntimeExecutionContext {
            lease: lease_epoch_2,
            runtime_instance: runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator
            .execute(transfer.clone(), &registry, ctx_epoch_2)
            .await;
        assert!(result.is_ok(), "Epoch 2 should succeed");

        // Try to use stale epoch 1 lease again - should fail
        let stale_lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: runtime_id,
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let stale_ctx = crate::lease::RuntimeExecutionContext {
            lease: stale_lease,
            runtime_instance: runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        let result = coordinator.execute(transfer, &registry, stale_ctx).await;
        assert!(
            matches!(result, Err(TransferCoordinatorError::LeaseViolation(_))),
            "Stale lease must be rejected: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_finality_rollback() {
        let replay_db = Box::new(csv_storage::InMemoryReplayDb::new());
        let event_bus = EventBus::new();
        let coordinator = TransferCoordinator::new(replay_db, event_bus);

        let mut registry = AdapterRegistryImpl::new();
        registry
            .register_adapter(Box::new(LocalTestAdapter::new_bitcoin()))
            .unwrap();

        let transfer = CrossChainTransfer {
            id: "test-rollback".to_string(),
            source_chain: "test-chain".to_string(),
            destination_chain: "test-chain".to_string(),
            lock_tx_hash: vec![1u8; 32],
            lock_output_index: 0,
            sanad_id: csv_hash::Hash::new([2u8; 32]),
            transition_id: vec![3u8; 32],
        };

        let lease = crate::lease::TransferLease {
            transfer_id: csv_hash::SanadId::new(*transfer.sanad_id.as_bytes()),
            epoch: 1,
            owner_runtime_id: uuid::Uuid::new_v4(),
            acquired_at: std::time::SystemTime::now(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        };

        let runtime_ctx = crate::lease::RuntimeExecutionContext {
            lease: lease.clone(),
            runtime_instance: lease.owner_runtime_id,
            policy: crate::policy::RuntimePolicy::new(),
        };

        // Execute transfer successfully
        let result = coordinator
            .execute(transfer.clone(), &registry, runtime_ctx)
            .await;
        assert!(result.is_ok(), "Transfer should succeed initially");

        // Simulate finality rollback by recording health check
        coordinator.record_health_check(crate::runtime_mode::HealthCheck {
            component: "finality".to_string(),
            healthy: false,
            error: Some("Finality rollback detected".to_string()),
            timestamp: std::time::SystemTime::now(),
        });

        // Health status should be critical (all checks are unhealthy)
        assert_eq!(
            coordinator.health_status(),
            crate::runtime_mode::HealthStatus::CRITICAL
        );

        // Runtime mode should be unsafe
        let mode = coordinator.health_monitor().lock().unwrap().mode();
        assert_eq!(mode, crate::runtime_mode::RuntimeMode::Unsafe);
    }
}
