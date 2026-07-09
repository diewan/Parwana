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

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{Instant, sleep};

use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::EncodedTransactionWithStatusMeta;
use solana_transaction_status::option_serializer::OptionSerializer;

use crate::anchor_client::discriminators;
use crate::error::{SolanaError, SolanaResult};
use crate::rpc::SolanaRpc;

/// A recognized csv-seal instruction, classified by its Anchor discriminator.
///
/// Only instructions the on-chain program actually exposes are represented. An
/// instruction addressed to the CSV program whose discriminator matches none of
/// these is reported as [`CsvInstructionKind::Unrecognized`] rather than being
/// guessed at or dropped silently — an unrecognized discriminator on the CSV
/// program is a signal worth surfacing (program upgrade, or a caller on a newer
/// IDL than this adapter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsvInstructionKind {
    /// `initialize_registry`
    InitializeRegistry,
    /// `create_seal`
    CreateSeal,
    /// `consume_seal`
    ConsumeSeal,
    /// `lock_sanad`
    LockSanad,
    /// `mint_sanad`
    MintSanad,
    /// `refund_sanad`
    RefundSanad,
    /// `register_nullifier`
    RegisterNullifier,
    /// `record_sanad_metadata`
    RecordSanadMetadata,
    /// `transfer_sanad`
    TransferSanad,
    /// Addressed to the CSV program, but the discriminator is not one we know.
    Unrecognized,
}

impl CsvInstructionKind {
    /// Classify instruction data by its leading 8-byte Anchor discriminator.
    ///
    /// Returns `None` when the data is shorter than a discriminator: chain data
    /// is untrusted, and a truncated instruction must be ignored rather than
    /// indexed into or padded.
    fn from_instruction_data(data: &[u8]) -> Option<Self> {
        let discriminator: [u8; 8] = data.get(..8)?.try_into().ok()?;

        // Built per call rather than cached: the discriminator helpers hash a
        // fixed string, and a slot's instruction count is small.
        let table = [
            (
                discriminators::initialize_registry(),
                Self::InitializeRegistry,
            ),
            (discriminators::create_seal(), Self::CreateSeal),
            (discriminators::consume_seal(), Self::ConsumeSeal),
            (discriminators::lock_sanad(), Self::LockSanad),
            (discriminators::mint_sanad(), Self::MintSanad),
            (discriminators::refund_sanad(), Self::RefundSanad),
            (
                discriminators::register_nullifier(),
                Self::RegisterNullifier,
            ),
            (
                discriminators::record_sanad_metadata(),
                Self::RecordSanadMetadata,
            ),
            (discriminators::transfer_sanad(), Self::TransferSanad),
        ];

        Some(
            table
                .iter()
                .find(|(expected, _)| *expected == discriminator)
                .map(|(_, kind)| *kind)
                .unwrap_or(Self::Unrecognized),
        )
    }
}

/// A CSV-program instruction observed in a synced slot.
///
/// This is the typed result surfaced by [`SyncCoordinator::process_slot`], so
/// downstream consumers do not have to re-decode blocks. It deliberately carries
/// no decoded instruction arguments: argument decoding belongs to the callers
/// that know the account layout, and this type must stay cheap to produce for
/// every slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsvSyncObservation {
    /// Slot the transaction was included in.
    pub slot: u64,
    /// First signature of the transaction (its canonical identifier).
    pub signature: String,
    /// Which csv-seal instruction was invoked.
    pub kind: CsvInstructionKind,
    /// Index of the instruction within the transaction message.
    pub instruction_index: usize,
    /// Whether the transaction executed successfully. A failed transaction had
    /// no on-chain effect; consumers must not treat it as a state transition.
    pub succeeded: bool,
}

/// Resolve the transaction's full account-key list in index order.
///
/// Solana orders keys as: static keys, then loaded writable addresses, then
/// loaded readonly addresses. Address-lookup-table keys live in the transaction
/// *meta*, not the message, so a versioned transaction that invokes the CSV
/// program via a lookup table is only discoverable by appending them here.
///
/// Malformed base58 in the loaded addresses is skipped rather than fatal — chain
/// data is untrusted, and one bad key must not abort the whole slot.
fn resolve_account_keys(
    static_keys: &[Pubkey],
    meta: Option<&solana_transaction_status::UiTransactionStatusMeta>,
) -> Vec<Pubkey> {
    let mut keys: Vec<Pubkey> = static_keys.to_vec();

    if let Some(meta) = meta
        && let OptionSerializer::Some(loaded) = &meta.loaded_addresses
    {
        for encoded in loaded.writable.iter().chain(loaded.readonly.iter()) {
            if let Ok(key) = encoded.parse::<Pubkey>() {
                keys.push(key);
            }
        }
    }

    keys
}

/// Extract every CSV-program instruction from one encoded transaction.
///
/// Returns an empty vector for transactions that do not touch the CSV program,
/// that cannot be decoded, or that carry no signature. All chain data is treated
/// as untrusted: account indexes are bounds-checked, and short instruction data
/// is ignored.
pub fn observations_from_transaction(
    slot: u64,
    tx_with_meta: &EncodedTransactionWithStatusMeta,
    csv_program_id: &Pubkey,
) -> Vec<CsvSyncObservation> {
    let Some(tx) = tx_with_meta.transaction.decode() else {
        // Json/Accounts encodings carry no raw message; nothing to classify.
        return Vec::new();
    };

    let meta = tx_with_meta.meta.as_ref();
    let account_keys = resolve_account_keys(tx.message.static_account_keys(), meta);

    // Cheap rejection before walking instructions.
    if !account_keys.iter().any(|key| key == csv_program_id) {
        return Vec::new();
    }

    let Some(signature) = tx.signatures.first() else {
        return Vec::new();
    };
    let signature = signature.to_string();
    let succeeded = meta.map(|m| m.err.is_none()).unwrap_or(false);

    tx.message
        .instructions()
        .iter()
        .enumerate()
        .filter_map(|(instruction_index, instruction)| {
            // Bounds-check the program-id index against the resolved key list.
            let program_id = account_keys.get(instruction.program_id_index as usize)?;
            if program_id != csv_program_id {
                return None;
            }

            let kind = CsvInstructionKind::from_instruction_data(&instruction.data)?;

            Some(CsvSyncObservation {
                slot,
                signature: signature.clone(),
                kind,
                instruction_index,
                succeeded,
            })
        })
        .collect()
}

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
    pub csv_program_id: Pubkey,
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
            // Must be the deployed csv-seal program. `Pubkey::default()` is NOT a
            // harmless placeholder here: it is the all-zero key, which is the
            // System Program's address, so every SOL transfer in a slot would be
            // matched as a CSV instruction (SOL-SYNC-DECODE-001).
            csv_program_id: default_csv_program_id(),
        }
    }
}

/// The deployed csv-seal program id used when no explicit id is configured.
fn default_csv_program_id() -> Pubkey {
    use std::str::FromStr;
    Pubkey::from_str(crate::anchor_client::CSV_SEAL_PROGRAM_ID)
        .unwrap_or_else(|_| Pubkey::new_from_array([0xFF; 32]))
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

/// Maximum number of unread observations retained by the coordinator.
///
/// The background sync loop has no consumer of its own, so the buffer is bounded
/// and drops the oldest entries once full rather than growing without limit. A
/// consumer that cares about every observation must drain faster than the chain
/// produces CSV instructions.
const MAX_BUFFERED_OBSERVATIONS: usize = 4096;

/// Solana Sync Coordinator
///
/// Manages slot synchronization with adaptive polling and gap recovery.
pub struct SyncCoordinator {
    config: SyncCoordinatorConfig,
    rpc: Arc<dyn SolanaRpc>,
    state: Arc<RwLock<SlotSyncState>>,
    running: Arc<RwLock<bool>>,
    csv_program_id: Pubkey,
    observations: Arc<RwLock<VecDeque<CsvSyncObservation>>>,
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
            observations: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Take every buffered CSV observation, leaving the buffer empty.
    pub async fn drain_observations(&self) -> Vec<CsvSyncObservation> {
        self.observations.write().await.drain(..).collect()
    }

    /// Append observations to the bounded buffer, evicting the oldest on overflow.
    async fn buffer_observations(
        observations: &Arc<RwLock<VecDeque<CsvSyncObservation>>>,
        new: Vec<CsvSyncObservation>,
    ) {
        if new.is_empty() {
            return;
        }

        let mut buffer = observations.write().await;
        for observation in new {
            if buffer.len() == MAX_BUFFERED_OBSERVATIONS {
                buffer.pop_front();
                tracing::warn!(
                    "CSV sync observation buffer full ({}); dropping oldest observation",
                    MAX_BUFFERED_OBSERVATIONS
                );
            }
            buffer.push_back(observation);
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
        let observations = Arc::clone(&self.observations);

        tokio::spawn(async move {
            while *running.read().await {
                let poll_interval = Self::calculate_adaptive_interval(&state, &config).await;

                if let Err(e) = Self::sync_slot(&rpc, &state, &config, &observations).await {
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
            let observations = Self::process_slot(&self.rpc, slot, self.csv_program_id).await?;
            Self::buffer_observations(&self.observations, observations).await;
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
        observations: &Arc<RwLock<VecDeque<CsvSyncObservation>>>,
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
        let slot_observations = Self::process_slot(rpc, next_slot, config.csv_program_id).await?;
        Self::buffer_observations(observations, slot_observations).await;

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

    /// Process a single slot: fetch the block, decode its transactions, and
    /// surface every instruction addressed to the CSV program.
    ///
    /// Non-CSV transactions are ignored. Transactions that cannot be decoded are
    /// skipped rather than treated as errors — an undecodable transaction from
    /// another program is not a sync failure.
    async fn process_slot(
        rpc: &Arc<dyn SolanaRpc>,
        slot: u64,
        csv_program_id: Pubkey,
    ) -> SolanaResult<Vec<CsvSyncObservation>> {
        // Fetch the block at this slot
        let block = rpc.get_block(slot).map_err(|e| {
            SolanaError::Rpc(format!("Failed to fetch block at slot {}: {}", slot, e))
        })?;

        let Some(block_data) = block else {
            tracing::debug!("Slot {} not found or empty", slot);
            return Ok(Vec::new());
        };

        let observations: Vec<CsvSyncObservation> = block_data
            .transactions
            .iter()
            .flat_map(|tx| observations_from_transaction(slot, tx, &csv_program_id))
            .collect();

        tracing::debug!(
            "Processed slot {}: {} transactions, {} CSV instructions",
            slot,
            block_data.transactions.len(),
            observations.len()
        );

        Ok(observations)
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
    use crate::anchor_client::CSV_SEAL_PROGRAM_ID;
    use crate::rpc::MockSolanaRpc;
    use base64::Engine as _;
    use solana_sdk::instruction::{AccountMeta, Instruction};
    use std::str::FromStr;

    fn csv_program() -> Pubkey {
        Pubkey::from_str(CSV_SEAL_PROGRAM_ID).expect("valid program id")
    }

    /// Build a base64-encoded transaction carrying `instructions`, with a
    /// successful (err: None) status meta and no loaded addresses.
    fn encoded_tx(instructions: &[Instruction]) -> EncodedTransactionWithStatusMeta {
        use solana_sdk::message::Message;
        use solana_sdk::transaction::Transaction;

        let payer = Pubkey::new_unique();
        let message = Message::new(instructions, Some(&payer));
        let tx = Transaction::new_unsigned(message);
        let versioned = solana_sdk::transaction::VersionedTransaction::from(tx);
        let bytes = bincode::serialize(&versioned).expect("serialize tx");
        let blob = base64::engine::general_purpose::STANDARD.encode(bytes);

        EncodedTransactionWithStatusMeta {
            transaction: solana_transaction_status::EncodedTransaction::Binary(
                blob,
                solana_transaction_status::TransactionBinaryEncoding::Base64,
            ),
            meta: Some(successful_meta()),
            version: None,
        }
    }

    fn successful_meta() -> solana_transaction_status::UiTransactionStatusMeta {
        solana_transaction_status::UiTransactionStatusMeta {
            err: None,
            status: Ok(()),
            fee: 5000,
            pre_balances: vec![],
            post_balances: vec![],
            inner_instructions: OptionSerializer::None,
            log_messages: OptionSerializer::None,
            pre_token_balances: OptionSerializer::None,
            post_token_balances: OptionSerializer::None,
            rewards: OptionSerializer::None,
            loaded_addresses: OptionSerializer::None,
            return_data: OptionSerializer::None,
            compute_units_consumed: OptionSerializer::None,
            cost_units: OptionSerializer::None,
        }
    }

    fn instruction(program_id: Pubkey, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id,
            accounts: vec![AccountMeta::new(Pubkey::new_unique(), false)],
            data,
        }
    }

    /// SOL-SYNC-DECODE-001: a CSV `mint_sanad` instruction is classified.
    #[test]
    fn csv_transaction_is_surfaced_with_its_instruction_kind() {
        let mut data = discriminators::mint_sanad().to_vec();
        data.extend_from_slice(&[0xAB; 32]); // arbitrary args
        let tx = encoded_tx(&[instruction(csv_program(), data)]);

        let observations = observations_from_transaction(42, &tx, &csv_program());

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, CsvInstructionKind::MintSanad);
        assert_eq!(observations[0].slot, 42);
        assert_eq!(observations[0].instruction_index, 0);
        assert!(observations[0].succeeded);
    }

    /// SOL-SYNC-DECODE-001: transactions that never touch the CSV program are ignored.
    #[test]
    fn non_csv_transaction_is_ignored() {
        let other = Pubkey::new_unique();
        let mut data = discriminators::mint_sanad().to_vec();
        data.extend_from_slice(&[0xAB; 32]);
        let tx = encoded_tx(&[instruction(other, data)]);

        assert!(observations_from_transaction(42, &tx, &csv_program()).is_empty());
    }

    /// A block mixing CSV and non-CSV transactions surfaces only the CSV ones,
    /// and only the CSV instructions within them.
    #[test]
    fn mixed_block_surfaces_only_csv_instructions() {
        let other = Pubkey::new_unique();

        let csv_tx = encoded_tx(&[
            instruction(other, vec![1, 2, 3]),
            instruction(csv_program(), discriminators::create_seal().to_vec()),
            instruction(csv_program(), discriminators::consume_seal().to_vec()),
        ]);
        let noise_tx = encoded_tx(&[instruction(other, vec![9; 16])]);

        let transactions = [csv_tx, noise_tx];
        let observations: Vec<_> = transactions
            .iter()
            .flat_map(|tx| observations_from_transaction(7, tx, &csv_program()))
            .collect();

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].kind, CsvInstructionKind::CreateSeal);
        assert_eq!(observations[0].instruction_index, 1);
        assert_eq!(observations[1].kind, CsvInstructionKind::ConsumeSeal);
        assert_eq!(observations[1].instruction_index, 2);
    }

    /// Malformed/short instruction data must be ignored, never panic or index
    /// out of bounds.
    #[test]
    fn short_instruction_data_is_ignored_without_panic() {
        for len in 0..8usize {
            let tx = encoded_tx(&[instruction(csv_program(), vec![0xFF; len])]);
            assert!(
                observations_from_transaction(1, &tx, &csv_program()).is_empty(),
                "instruction data of {len} bytes must be ignored"
            );
        }
    }

    /// An 8-byte discriminator we do not know is reported, not silently dropped:
    /// on the CSV program it signals an upgrade or a newer IDL.
    #[test]
    fn unknown_discriminator_on_csv_program_is_reported() {
        let tx = encoded_tx(&[instruction(csv_program(), vec![0xFF; 8])]);

        let observations = observations_from_transaction(1, &tx, &csv_program());

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].kind, CsvInstructionKind::Unrecognized);
    }

    /// A failed transaction had no on-chain effect and must be flagged as such.
    #[test]
    fn failed_transaction_is_marked_unsuccessful() {
        let mut tx = encoded_tx(&[instruction(
            csv_program(),
            discriminators::lock_sanad().to_vec(),
        )]);
        if let Some(meta) = tx.meta.as_mut() {
            meta.err = Some(solana_sdk::transaction::TransactionError::AccountNotFound.into());
        }

        let observations = observations_from_transaction(3, &tx, &csv_program());

        assert_eq!(observations.len(), 1);
        assert!(!observations[0].succeeded);
    }

    /// SOL-SYNC-DECODE-001: the default program id must not be the all-zero key,
    /// which is the System Program — every SOL transfer would match the filter.
    #[test]
    fn default_program_id_is_csv_seal_not_system_program() {
        let config = SyncCoordinatorConfig::default();
        assert_eq!(config.csv_program_id, csv_program());
        assert_ne!(config.csv_program_id, Pubkey::default());
    }

    #[tokio::test]
    async fn observation_buffer_is_bounded_and_drains() {
        let observations = Arc::new(RwLock::new(VecDeque::new()));
        let make = |slot: u64| CsvSyncObservation {
            slot,
            signature: format!("sig{slot}"),
            kind: CsvInstructionKind::CreateSeal,
            instruction_index: 0,
            succeeded: true,
        };

        let overflow: Vec<_> = (0..(MAX_BUFFERED_OBSERVATIONS as u64 + 5))
            .map(make)
            .collect();
        SyncCoordinator::buffer_observations(&observations, overflow).await;

        let buffer = observations.read().await;
        assert_eq!(buffer.len(), MAX_BUFFERED_OBSERVATIONS);
        // Oldest five were evicted, so the front is slot 5.
        assert_eq!(buffer.front().map(|o| o.slot), Some(5));
    }

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
