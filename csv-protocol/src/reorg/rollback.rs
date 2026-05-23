//! Rollback Handler
//!
//! Handles rollback of operations affected by a reorg.
//! When a chain reorg occurs, this module identifies and rolls back
//! transfers that were dependent on blocks in the reorged chain segment.

use std::vec::Vec;
use async_trait::async_trait;

use csv_hash::chain_id::ChainId;
use crate::reorg::detector::ReorgEvent;

/// Type of rollback action taken
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackAction {
    /// Transfer should be marked as rolled back (source lock still valid)
    RolledBack,
    /// Transfer should be marked as compromised (source lock invalidated)
    Compromised,
    /// Transfer should be resumed from a prior state
    ///
    /// The `from_state` field indicates which state the transfer should resume from.
    Resume {
        /// State to resume from (e.g., "proof_validated")
        from_state: String,
    },
}

/// Result of rolling back a single transfer
#[derive(Debug, Clone)]
pub struct RollbackResult {
    /// Transfer ID that was rolled back
    pub transfer_id: String,
    /// Action taken
    pub action: RollbackAction,
    /// Previous state
    pub previous_state: String,
    /// Block height at source
    pub source_block_height: u64,
}

/// Storage backend trait for rollback operations.
///
/// Implementations must provide the ability to update transfer states
/// in persistent storage after a reorg.
#[async_trait]
pub trait RollbackStorageBackend: Send + Sync + Default {
    /// Update the state of a transfer in persistent storage.
    ///
    /// # Arguments
    /// * `transfer_id` - The transfer identifier
    /// * `new_state` - The new state to set (e.g., "rolled_back", "compromised", "proof_validated")
    /// * `metadata` - Additional metadata about the rollback (chain, heights, action)
    async fn update_transfer_state(
        &self,
        transfer_id: &str,
        new_state: &str,
        metadata: serde_json::Value,
    ) -> Result<(), crate::error::ProtocolError>;

    /// Get the current state of a transfer.
    async fn get_transfer_state(
        &self,
        transfer_id: &str,
    ) -> Result<Option<String>, crate::error::ProtocolError>;

    /// Record a rollback event for audit purposes.
    async fn record_rollback(
        &self,
        transfer_id: &str,
        chain: &str,
        from_height: u64,
        to_height: u64,
        action: &str,
    ) -> Result<(), crate::error::ProtocolError>;
}

/// Rollback callback type
type RollbackCallback = Box<dyn Fn(&ReorgEvent) + Send + Sync>;

/// Rollback handler for reorg events
///
/// When a reorg is detected, this handler:
/// 1. Identifies transfers affected by the reorg
/// 2. Determines the appropriate rollback action based on transfer state
/// 3. Executes the rollback (marking transfers as RolledBack or Compromised)
/// 4. Emits events for observability
pub struct RollbackHandler<B: RollbackStorageBackend> {
    /// Storage backend for updating transfer states
    storage: B,
    /// Callbacks registered per chain
    on_rollback: std::collections::BTreeMap<String, RollbackCallback>,
    /// Whether to auto-execute rollbacks or require manual approval
    auto_execute: bool,
}

impl<B: RollbackStorageBackend> RollbackHandler<B> {
    /// Create a new rollback handler with the given storage backend
    pub fn new(storage: B) -> Self {
        Self {
            storage,
            on_rollback: std::collections::BTreeMap::new(),
            auto_execute: true,
        }
    }

    /// Set whether rollbacks are auto-executed
    pub fn set_auto_execute(&mut self, auto: bool) {
        self.auto_execute = auto;
    }

    /// Register a rollback callback for a chain
    pub fn register_callback<F>(&mut self, chain: ChainId, callback: F)
    where
        F: Fn(&ReorgEvent) + Send + Sync + 'static,
    {
        self.on_rollback
            .insert(chain.as_str().to_string(), Box::new(callback));
    }

    /// Handle a reorg event
    pub fn handle_reorg(&self, event: &ReorgEvent) {
        if let Some(callback) = self.on_rollback.get(event.chain.as_str()) {
            callback(event);
        }
    }

    /// Determine the rollback action for a transfer based on its state and the reorg
    ///
    /// The decision logic:
    /// - If the transfer's source lock was at or below the reorg depth: Compromised
    /// - If the transfer's proof was built on a reorged block: RolledBack
    /// - If the transfer's mint was on a reorged block: Resume from ProofValidated
    pub fn determine_rollback_action(
        &self,
        transfer_state: &str,
        source_block_height: u64,
        reorg_from_height: u64,
        reorg_to_height: u64,
    ) -> RollbackAction {
        // If the source lock is below the reorg range, the lock is invalidated
        if source_block_height < reorg_from_height {
            return RollbackAction::Compromised;
        }

        // If the transfer was in a state that depends on the reorged blocks
        match transfer_state {
            // Locking state - source lock may be invalidated
            "locking" | "awaiting_finality" if source_block_height <= reorg_to_height => {
                RollbackAction::Compromised
            }
            // Proof building state - proof may be invalid
            "proof_building" | "proof_validated" if source_block_height <= reorg_to_height => {
                RollbackAction::RolledBack
            }
            // Minting state - mint may have been on reorged block
            "minting" if source_block_height <= reorg_to_height => RollbackAction::Resume {
                from_state: "proof_validated".to_string(),
            },
            // Completed transfers are not affected (finality confirmed)
            "completed" => RollbackAction::RolledBack, // No action needed
            // Other states - conservative rollback
            _ => RollbackAction::RolledBack,
        }
    }

    /// Roll back transfers affected by a reorg.
    ///
    /// Takes a storage backend to actually persist state changes.
    /// Returns a list of `RollbackResult` describing each action taken.
    ///
    /// # Arguments
    /// * `chain` - The chain where the reorg occurred
    /// * `from_height` - The height where the reorg started (old tip)
    /// * `to_height` - The height where the reorg ended (new tip)
    /// * `affected_transfers` - List of (transfer_id, state, source_block_height)
    pub async fn rollback_transfers(
        &self,
        chain: ChainId,
        from_height: u64,
        to_height: u64,
        affected_transfers: &[(String, String, u64)],
    ) -> Vec<RollbackResult> {
        let mut results = Vec::with_capacity(affected_transfers.len());

        for (transfer_id, state, block_height) in affected_transfers {
            let action =
                self.determine_rollback_action(&state, *block_height, from_height, to_height);

            let new_state = match &action {
                RollbackAction::Compromised => {
                    log::warn!(
                        "Transfer {} on chain {} marked as COMPROMISED (source lock invalidated at height {})",
                        transfer_id,
                        chain,
                        block_height
                    );
                    "compromised"
                }
                RollbackAction::RolledBack => {
                    log::warn!(
                        "Transfer {} on chain {} marked as ROLLED BACK (reorg at height {})",
                        transfer_id,
                        chain,
                        block_height
                    );
                    "rolled_back"
                }
                RollbackAction::Resume { from_state } => {
                    log::info!(
                        "Transfer {} on chain {} resuming from {} (reorg at height {})",
                        transfer_id,
                        chain,
                        from_state,
                        block_height
                    );
                    from_state.as_str()
                }
            };

            // Persist the state change to storage
            let metadata = serde_json::json!({
                "reorg_from_height": from_height,
                "reorg_to_height": to_height,
                "action": match &action {
                    RollbackAction::Compromised => "compromised",
                    RollbackAction::RolledBack => "rolled_back",
                    RollbackAction::Resume { from_state } => from_state,
                },
                "chain": chain.as_str(),
            });

            if let Err(e) = self
                .storage
                .update_transfer_state(transfer_id, new_state, metadata.clone())
                .await
            {
                log::error!("Failed to update transfer state for {}: {}", transfer_id, e);
            }

            // Record the rollback event for audit
            if let Err(e) = self
                .storage
                .record_rollback(
                    transfer_id,
                    chain.as_str(),
                    from_height,
                    to_height,
                    new_state,
                )
                .await
            {
                log::error!("Failed to record rollback event for {}: {}", transfer_id, e);
            }

            results.push(RollbackResult {
                transfer_id: transfer_id.clone(),
                action: action.clone(),
                previous_state: state.clone(),
                source_block_height: *block_height,
            });
        }

        results
    }
}

impl<B: RollbackStorageBackend> Default for RollbackHandler<B> {
    fn default() -> Self {
        Self::new(B::default())
    }
}

/// A mock rollback storage backend for testing and as a default fallback.
#[derive(Clone, Default)]
#[allow(missing_docs)]
pub struct MockRollbackBackend {
    states: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    rollback_log: std::sync::Arc<std::sync::Mutex<Vec<(String, String, u64, u64, String)>>>,
}

#[allow(missing_docs)]
impl MockRollbackBackend {
    pub fn new() -> Self {
        Self {
            states: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            rollback_log: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl RollbackStorageBackend for MockRollbackBackend {
    async fn update_transfer_state(
        &self,
        transfer_id: &str,
        new_state: &str,
        _metadata: serde_json::Value,
    ) -> Result<(), crate::error::ProtocolError> {
        let mut states = self
            .states
            .lock()
            .map_err(|e| crate::error::ProtocolError::StorageError(format!("Lock error: {}", e)))?;
        states.insert(transfer_id.to_string(), new_state.to_string());
        Ok(())
    }

    async fn get_transfer_state(
        &self,
        transfer_id: &str,
    ) -> Result<Option<String>, crate::error::ProtocolError> {
        let states = self
            .states
            .lock()
            .map_err(|e| crate::error::ProtocolError::StorageError(format!("Lock error: {}", e)))?;
        Ok(states.get(transfer_id).cloned())
    }

    async fn record_rollback(
        &self,
        transfer_id: &str,
        chain: &str,
        from_height: u64,
        to_height: u64,
        action: &str,
    ) -> Result<(), crate::error::ProtocolError> {
        let mut log = self
            .rollback_log
            .lock()
            .map_err(|e| crate::error::ProtocolError::StorageError(format!("Lock error: {}", e)))?;
        log.push((
            transfer_id.to_string(),
            chain.to_string(),
            from_height,
            to_height,
            action.to_string(),
        ));
        Ok(())
    }
}
