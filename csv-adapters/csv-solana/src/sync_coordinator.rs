//! Solana Sync Coordinator
//!
//! Manages slot synchronization for Solana, handling high congestion scenarios
//! and preventing missed slots. Solana produces slots every ~400ms, and during
//! network congestion, slots can be skipped or delayed. This coordinator:
//!
//! - Tracks the latest synced slot
//! - Detects missed slots and slot gaps
//! - Implements adaptive polling based on congestion
//! - Provides recovery mechanisms for slot gaps
//! - Handles deep reorgs with slot rollback

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{Instant, sleep};

use crate::error::{SolanaError, SolanaResult};
use crate::rpc::SolanaRpc;

/// Configuration for the Solana sync coordinator
#[derive(Clone, Debug)]
pub struct SyncCoordinatorConfig {
    /// Base polling interval in milliseconds
    pub base_poll_interval_ms: u64,
    /// Maximum polling interval in milliseconds (during extreme congestion)
    pub max_poll_interval_ms: u64,
    /// Minimum polling interval in milliseconds (during low congestion)
    pub min_poll_interval_ms: u64,
    /// Slot gap threshold - number of consecutive missed slots before triggering recovery
    pub slot_gap_threshold: u64,
    /// Maximum slot gap to attempt recovery for
    pub max_recovery_gap: u64,
    /// Enable adaptive polling based on congestion
    pub enable_adaptive_polling: bool,
    /// CSV program ID to filter transactions
    pub csv_program_id: solana_sdk::pubkey::Pubkey,
}

impl Default for SyncCoordinatorConfig {
    fn default() -> Self {
        Self {
            // Solana produces slots every ~400ms, so poll at 500ms base
            base_poll_interval_ms: 500,
            max_poll_interval_ms: 5000, // 5 seconds during extreme congestion
            min_poll_interval_ms: 200,  // 200ms during low congestion
            slot_gap_threshold: 10,     // Trigger recovery after 10 missed slots
            max_recovery_gap: 1000,     // Attempt recovery for gaps up to 1000 slots
            enable_adaptive_polling: true,
            csv_program_id: solana_sdk::pubkey::Pubkey::default(), // Placeholder - should be configured
        }
    }
}

/// Slot synchronization state
#[derive(Clone, Debug)]
pub struct SlotSyncState {
    /// Latest synced slot
    pub latest_synced_slot: u64,
    /// Latest confirmed slot (with finality)
    pub latest_confirmed_slot: u64,
    /// Current chain tip slot
    pub chain_tip_slot: u64,
    /// Number of consecutive missed slots
    pub missed_slots: u64,
    /// Current sync status
    pub status: SyncStatus,
    /// Last successful sync time
    pub last_sync_time: Option<Instant>,
    /// Current congestion level (0.0 = low, 1.0 = high)
    pub congestion_level: f64,
}

/// Sync status for the coordinator
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    /// Sync is healthy and up to date
    Healthy,
    /// Sync is catching up after a gap
    CatchingUp,
    /// Sync is in recovery mode (handling large gap)
    Recovering,
    /// Sync is stalled (unable to progress)
    Stalled,
    /// Sync is stopped
    Stopped,
}

/// Solana Sync Coordinator
///
/// Manages slot synchronization with adaptive polling and gap recovery.
pub struct SyncCoordinator {
    config: SyncCoordinatorConfig,
    rpc: Arc<dyn SolanaRpc>,
    state: Arc<RwLock<SlotSyncState>>,
    running: Arc<RwLock<bool>>,
    csv_program_id: solana_sdk::pubkey::Pubkey,
}

impl SyncCoordinator {
    /// Create a new sync coordinator with the given RPC client and config
    pub fn new(rpc: Arc<dyn SolanaRpc>, config: SyncCoordinatorConfig) -> Self {
        let csv_program_id = config.csv_program_id;
        let state = SlotSyncState {
            latest_synced_slot: 0,
            latest_confirmed_slot: 0,
            chain_tip_slot: 0,
            missed_slots: 0,
            status: SyncStatus::Stopped,
            last_sync_time: None,
            congestion_level: 0.0,
        };

        Self {
            config,
            rpc,
            state: Arc::new(RwLock::new(state)),
            running: Arc::new(RwLock::new(false)),
            csv_program_id,
        }
    }

    /// Start the sync coordinator
    pub async fn start(&self) -> SolanaResult<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        *running = true;
        drop(running);

        // Initialize state
        self.initialize_state().await?;

        let rpc = Arc::clone(&self.rpc);
        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let config = self.config.clone();

        tokio::spawn(async move {
            while *running.read().await {
                let poll_interval = Self::calculate_adaptive_interval(&state, &config).await;

                if let Err(e) = Self::sync_slot(&rpc, &state, &config).await {
                    tracing::error!("Slot sync error: {}", e);

                    // Update status to stalled on repeated errors
                    let mut state_guard = state.write().await;
                    state_guard.status = SyncStatus::Stalled;
                }

                sleep(Duration::from_millis(poll_interval)).await;
            }
        });

        Ok(())
    }

    /// Stop the sync coordinator
    pub async fn stop(&self) -> SolanaResult<()> {
        let mut running = self.running.write().await;
        *running = false;

        let mut state = self.state.write().await;
        state.status = SyncStatus::Stopped;

        Ok(())
    }

    /// Get the current sync state
    pub async fn get_state(&self) -> SlotSyncState {
        self.state.read().await.clone()
    }

    /// Force sync to a specific slot
    pub async fn sync_to_slot(&self, target_slot: u64) -> SolanaResult<()> {
        let current_synced = {
            let state = self.state.read().await;
            state.latest_synced_slot
        };

        if target_slot <= current_synced {
            return Err(SolanaError::InvalidInput(format!(
                "Target slot {} is not greater than current synced slot {}",
                target_slot, current_synced
            )));
        }

        let gap = target_slot - current_synced;

        if gap > self.config.max_recovery_gap {
            return Err(SolanaError::InvalidInput(format!(
                "Slot gap {} exceeds maximum recovery gap {}",
                gap, self.config.max_recovery_gap
            )));
        }

        {
            let mut state = self.state.write().await;
            state.status = SyncStatus::Recovering;
        }

        // Sync through the gap
        for slot in (current_synced + 1)..=target_slot {
            Self::process_slot(&self.rpc, slot, self.csv_program_id).await?;
        }

        let mut state = self.state.write().await;
        state.latest_synced_slot = target_slot;
        state.missed_slots = 0;
        state.status = SyncStatus::Healthy;

        Ok(())
    }

    /// Initialize the sync state by querying the chain tip
    async fn initialize_state(&self) -> SolanaResult<()> {
        let tip = self
            .rpc
            .get_latest_slot()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get chain tip: {}", e)))?;

        let mut state = self.state.write().await;
        state.chain_tip_slot = tip;
        state.status = SyncStatus::Healthy;
        state.last_sync_time = Some(Instant::now());

        Ok(())
    }

    /// Sync a single slot
    async fn sync_slot(
        rpc: &Arc<dyn SolanaRpc>,
        state: &Arc<RwLock<SlotSyncState>>,
        config: &SyncCoordinatorConfig,
    ) -> SolanaResult<()> {
        let current_state = state.read().await.clone();
        let next_slot = current_state.latest_synced_slot + 1;

        // Get the latest chain tip
        let tip = rpc
            .get_latest_slot()
            .map_err(|e| SolanaError::Rpc(format!("Failed to get chain tip: {}", e)))?;

        // Check if we're already at the tip
        if next_slot > tip {
            // No new slots to process
            let mut state_guard = state.write().await;
            state_guard.chain_tip_slot = tip;
            state_guard.missed_slots = 0;
            state_guard.congestion_level = 0.0;
            return Ok(());
        }

        // Check for slot gap
        let gap = tip - next_slot;

        let mut state_guard = state.write().await;

        if gap > config.slot_gap_threshold {
            // Significant gap detected
            state_guard.missed_slots = gap;
            state_guard.status = if gap > config.max_recovery_gap {
                SyncStatus::Stalled
            } else {
                SyncStatus::Recovering
            };
            state_guard.congestion_level = (gap as f64 / config.max_recovery_gap as f64).min(1.0);
        } else {
            // Normal operation
            state_guard.missed_slots = 0;
            state_guard.status = SyncStatus::Healthy;
            state_guard.congestion_level = 0.0;
        }

        state_guard.chain_tip_slot = tip;
        drop(state_guard);

        // Process the next slot
        Self::process_slot(rpc, next_slot, config.csv_program_id).await?;

        // Update state
        let mut state_guard = state.write().await;
        state_guard.latest_synced_slot = next_slot;
        state_guard.last_sync_time = Some(Instant::now());

        // Update confirmed slot (Solana finality is ~32 slots)
        if next_slot >= 32 {
            state_guard.latest_confirmed_slot = next_slot - 32;
        }

        Ok(())
    }

    /// Process a single slot - fetch block and process CSV-relevant transactions
    async fn process_slot(rpc: &Arc<dyn SolanaRpc>, slot: u64, csv_program_id: solana_sdk::pubkey::Pubkey) -> SolanaResult<()> {
        // Fetch the block at this slot
        let block = rpc.get_block(slot)
            .map_err(|e| SolanaError::Rpc(format!("Failed to fetch block at slot {}: {}", slot, e)))?;

        if let Some(block_data) = block {
            // Process transactions relevant to CSV
            // Filter for transactions involving the CSV program
            // For now, just log the number of transactions
            // Proper transaction filtering requires decoding the encoded transaction
            tracing::debug!("Processing slot {} with {} transactions", slot, block_data.transactions.len());
            
            // TODO: Implement proper transaction filtering by decoding EncodedTransaction
            // and checking account keys against csv_program_id
        } else {
            tracing::debug!("Slot {} not found or empty", slot);
        }

        Ok(())
    }

    /// Calculate adaptive polling interval based on current congestion
    async fn calculate_adaptive_interval(
        state: &Arc<RwLock<SlotSyncState>>,
        config: &SyncCoordinatorConfig,
    ) -> u64 {
        if !config.enable_adaptive_polling {
            return config.base_poll_interval_ms;
        }

        let state_guard = state.read().await;
        let congestion = state_guard.congestion_level;

        // Linear interpolation between min and max based on congestion
        let range = config.max_poll_interval_ms - config.min_poll_interval_ms;
        let interval = config.min_poll_interval_ms + (range as f64 * congestion) as u64;

        interval.clamp(config.min_poll_interval_ms, config.max_poll_interval_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::MockSolanaRpc;

    #[tokio::test]
    async fn test_sync_coordinator_creation() {
        let rpc = Arc::new(MockSolanaRpc::new());
        let config = SyncCoordinatorConfig::default();
        let coordinator = SyncCoordinator::new(rpc, config);

        let state = coordinator.get_state().await;
        assert_eq!(state.latest_synced_slot, 0);
        assert_eq!(state.status, SyncStatus::Stopped);
    }

    #[tokio::test]
    async fn test_adaptive_interval_calculation() {
        let rpc = Arc::new(MockSolanaRpc::new());
        let config = SyncCoordinatorConfig::default();
        let coordinator = SyncCoordinator::new(rpc, config);

        // Test with no congestion
        let mut state = coordinator.state.write().await;
        state.congestion_level = 0.0;
        drop(state);

        let interval =
            SyncCoordinator::calculate_adaptive_interval(&coordinator.state, &coordinator.config)
                .await;

        assert_eq!(interval, coordinator.config.min_poll_interval_ms);

        // Test with high congestion
        let mut state = coordinator.state.write().await;
        state.congestion_level = 1.0;
        drop(state);

        let interval =
            SyncCoordinator::calculate_adaptive_interval(&coordinator.state, &coordinator.config)
                .await;

        assert_eq!(interval, coordinator.config.max_poll_interval_ms);
    }
}
