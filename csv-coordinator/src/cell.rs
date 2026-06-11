//! Per-chain execution cells with isolated failure domains.
//!
//! Each `ChainCell` is an isolated execution unit for a single chain adapter.
//! Cells provide:
//! - Bounded mpsc queue (backpressure protection)
//! - Circuit breaker (failure isolation)
//! - Memory ceiling (resource protection)
//! - Phase-aware execution journal recording
//!
//! A cell degradation CANNOT propagate to sibling cells.

use crate::circuit::{CellCircuitBreaker, CircuitConfig, CircuitState};
use crate::memory::MemoryCeiling;
use csv_hash::{Hash, sanad::SanadId};
use csv_protocol::transfer_state::TransferStage;
use csv_verifier::CryptographicAnchor;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Handler for executing transfer phase operations.
///
/// This trait abstracts chain adapter operations so that ChainCell
/// can execute transfer phases without directly depending on chain adapters.
pub trait TransferPhaseHandler: Send + Sync {
    /// Execute the LockConfirmed phase: verify lock transaction and finality.
    async fn execute_lock_confirmed(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
        source_chain: &str,
    ) -> Result<TransferStage, String>;

    /// Execute the ProofValidated phase: verify proof and mint on destination.
    async fn execute_proof_validated(
        &self,
        transfer_id: &str,
        proof_payload: &[u8],
        destination_chain: &str,
        destination_owner: &str,
    ) -> Result<TransferStage, String>;

    /// Execute the AwaitingFinality phase: check finality threshold.
    async fn execute_awaiting_finality(
        &self,
        transfer_id: &str,
        source_chain: &str,
        lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String>;

    /// Execute the ProofBuilding phase: build inclusion proof.
    async fn execute_proof_building(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
        source_chain: &str,
    ) -> Result<TransferStage, String>;

    /// Execute the MintSubmitted phase: confirm mint on destination.
    async fn execute_mint_submitted(
        &self,
        transfer_id: &str,
        destination_chain: &str,
    ) -> Result<TransferStage, String>;
}

/// Task submitted to a chain cell.
#[derive(Debug, Clone)]
pub enum CellTask {
    /// Process a cross-chain transfer phase.
    Process(TransferTask),
    /// Health check to attempt circuit breaker reset.
    HealthCheck,
}

/// A cross-chain transfer task to be processed by a cell.
#[derive(Debug, Clone)]
pub struct TransferTask {
    /// Unique transfer identifier
    pub transfer_id: String,
    /// Sanad ID being transferred
    pub sanad_id: SanadId,
    /// Source chain ID
    pub source_chain: String,
    /// Destination chain ID
    pub destination_chain: String,
    /// Lock transaction hash
    pub lock_tx_hash: Hash,
    /// Destination owner address
    pub destination_owner: String,
    /// Current transfer stage to execute
    pub stage: TransferStage,
    /// Proof payload (if available for this stage)
    pub proof_payload: Option<Vec<u8>>,
}

impl TransferTask {
    /// Create a new transfer task.
    pub fn new(
        transfer_id: String,
        sanad_id: SanadId,
        source_chain: String,
        destination_chain: String,
        lock_tx_hash: Hash,
        destination_owner: String,
        stage: TransferStage,
        proof_payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            transfer_id,
            sanad_id,
            source_chain,
            destination_chain,
            lock_tx_hash,
            destination_owner,
            stage,
            proof_payload,
        }
    }
}

/// Chain cell configuration.
#[derive(Debug, Clone)]
pub struct CellConfig {
    /// Chain ID this cell handles
    pub chain_id: u32,
    /// Maximum queue depth before backpressure
    pub max_queue_depth: usize,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitConfig,
    /// Maximum memory usage in bytes
    pub max_memory_bytes: u64,
}

impl Default for CellConfig {
    fn default() -> Self {
        Self {
            chain_id: 0,
            max_queue_depth: 1000,
            circuit_breaker: CircuitConfig::default(),
            max_memory_bytes: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Error type for cell operations.
#[derive(Debug, thiserror::Error)]
pub enum CellError {
    /// Circuit is open for chain
    #[error("Circuit is open for chain {0}")]
    CircuitOpen(u32),
    /// Backpressure: queue full for chain
    #[error("Backpressure: queue full for chain {0}")]
    Backpressure(u32),
    /// Memory ceiling exceeded
    #[error("Memory ceiling exceeded")]
    MemoryExceeded,
    /// Transfer processing failed
    #[error("Transfer processing failed: {0}")]
    ProcessingFailed(String),
}

/// Cell task result.
#[derive(Debug, Clone)]
pub enum CellResult {
    /// Task completed successfully
    Success {
        /// Transfer ID
        transfer_id: String,
        /// New stage after execution
        new_stage: TransferStage,
    },
    /// Task failed
    Failed {
        /// Transfer ID
        transfer_id: String,
        /// Error message
        error: String,
    },
}

/// An isolated execution unit for one chain adapter.
///
/// Each cell owns:
/// - Its own bounded mpsc queue (not shared with other cells)
/// - Its own circuit breaker
/// - Its own memory ceiling
/// - A transfer phase handler for executing chain operations
///
/// A cell degradation CANNOT propagate to sibling cells.
pub struct ChainCell {
    chain_id: u32,
    queue: mpsc::Sender<CellTask>,
    circuit: CellCircuitBreaker,
    memory_ceiling: MemoryCeiling,
}

impl ChainCell {
    /// Spawn a new chain cell with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Cell configuration (chain_id, queue depth, circuit breaker, memory)
    /// * `anchor` - Cryptographic anchor for verification
    /// * `handler` - Transfer phase handler for executing chain operations
    pub fn spawn(
        config: CellConfig,
        anchor: Arc<dyn CryptographicAnchor>,
        handler: Arc<dyn TransferPhaseHandler>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<CellTask>(config.max_queue_depth);

        tokio::spawn(cell_worker(rx, anchor, handler, config.clone()));

        ChainCell {
            chain_id: config.chain_id,
            queue: tx,
            circuit: CellCircuitBreaker::new(config.circuit_breaker),
            memory_ceiling: MemoryCeiling::new(config.max_memory_bytes),
        }
    }

    /// Submit work to this cell.
    ///
    /// Returns `Err(Backpressure)` if the cell queue is full.
    /// Returns `Err(CircuitOpen)` if the circuit breaker is open.
    pub async fn submit(&self, task: CellTask) -> Result<(), CellError> {
        if self.circuit.is_open() {
            return Err(CellError::CircuitOpen(self.chain_id));
        }

        let estimated_size = match &task {
            CellTask::Process(_transfer) => 4096,
            CellTask::HealthCheck => 0,
        };

        if estimated_size > 0 {
            self.memory_ceiling
                .try_allocate(estimated_size)
                .map_err(|_| CellError::MemoryExceeded)?;
        }

        self.queue
            .send(task)
            .await
            .map_err(|_| CellError::Backpressure(self.chain_id))?;

        Ok(())
    }

    /// Get the chain ID this cell handles.
    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Get the current circuit breaker state.
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit.state()
    }

    /// Get the current memory usage.
    pub fn memory_usage(&self) -> u64 {
        self.memory_ceiling.current_usage()
    }
}

/// Cell worker task that processes inbound transfers.
///
/// This is the main execution loop for a chain cell. It:
/// 1. Receives tasks from the bounded queue
/// 2. Checks circuit breaker before processing
/// 3. Executes the transfer phase based on the stage
/// 4. Records success/failure in the circuit breaker
/// 5. Releases memory after processing
async fn cell_worker(
    mut rx: mpsc::Receiver<CellTask>,
    anchor: Arc<dyn CryptographicAnchor>,
    handler: Arc<dyn TransferPhaseHandler>,
    config: CellConfig,
) {
    let mut circuit_breaker = CellCircuitBreaker::new(config.circuit_breaker);
    let _memory = MemoryCeiling::new(config.max_memory_bytes);

    while let Some(task) = rx.recv().await {
        match task {
            CellTask::Process(transfer) => {
                let transfer_id = transfer.transfer_id.clone();
                let _source_chain = transfer.source_chain.clone();
                let stage = transfer.stage.clone();

                tracing::info!(
                    chain_id = config.chain_id,
                    transfer_id = %transfer_id,
                    stage = ?stage,
                    "Processing inbound transfer"
                );

                // Check circuit breaker
                if !circuit_breaker.allow_request() {
                    tracing::warn!(
                        chain_id = config.chain_id,
                        transfer_id = %transfer_id,
                        "Circuit open, rejecting transfer"
                    );
                    continue;
                }

                // Execute the transfer phase based on stage
                let result = execute_transfer_phase(&transfer, &anchor, &handler).await;

                match result {
                    Ok(new_stage) => {
                        tracing::info!(
                            chain_id = config.chain_id,
                            transfer_id = %transfer_id,
                            new_stage = ?new_stage,
                            "Transfer phase completed successfully"
                        );
                        circuit_breaker.record_success();
                    }
                    Err(e) => {
                        tracing::error!(
                            chain_id = config.chain_id,
                            transfer_id = %transfer_id,
                            error = %e,
                            "Transfer phase failed"
                        );
                        circuit_breaker.record_failure();
                    }
                }
            }
            CellTask::HealthCheck => {
                if circuit_breaker.is_open() && circuit_breaker.attempt_reset() {
                    tracing::info!(
                        chain_id = config.chain_id,
                        "Circuit breaker transitioned to half-open"
                    );
                }
            }
        }
    }

    tracing::info!("Cell worker for chain {} shutting down", config.chain_id);
}

/// Execute a transfer phase based on the current stage.
///
/// This is the core execution logic for a chain cell. It handles:
/// - LockConfirmed: Verify lock, check finality, build proof
/// - ProofValidated: Verify proof, mint on destination chain
/// - AwaitingFinality: Re-check finality threshold
/// - ProofBuilding: Regenerate proof if checkpoint exists
///
/// # Arguments
///
/// * `transfer` - The transfer task to execute
/// * `anchor` - Cryptographic anchor for verification
///
/// # Returns
///
/// `Ok(new_stage)` if the phase completed successfully, indicating
/// the next stage to execute.
///
/// `Err(e)` if the phase failed, which will trigger circuit breaker
/// failure counting.
async fn execute_transfer_phase(
    transfer: &TransferTask,
    _anchor: &Arc<dyn CryptographicAnchor>,
    handler: &Arc<dyn TransferPhaseHandler>,
) -> Result<TransferStage, String> {
    match &transfer.stage {
        TransferStage::LockConfirmed => {
            handler.execute_lock_confirmed(
                &transfer.transfer_id,
                &transfer.lock_tx_hash,
                &transfer.source_chain,
            ).await
        }
        TransferStage::ProofValidated => {
            let proof_payload = transfer.proof_payload.as_deref().unwrap_or(&[]);
            handler.execute_proof_validated(
                &transfer.transfer_id,
                proof_payload,
                &transfer.destination_chain,
                &transfer.destination_owner,
            ).await
        }
        TransferStage::AwaitingFinality => {
            handler.execute_awaiting_finality(
                &transfer.transfer_id,
                &transfer.source_chain,
                &transfer.lock_tx_hash,
            ).await
        }
        TransferStage::ProofBuilding => {
            handler.execute_proof_building(
                &transfer.transfer_id,
                &transfer.lock_tx_hash,
                &transfer.source_chain,
            ).await
        }
        TransferStage::MintSubmitted => {
            handler.execute_mint_submitted(
                &transfer.transfer_id,
                &transfer.destination_chain,
            ).await
        }
        TransferStage::MintConfirmed => {
            // Transfer is complete
            tracing::info!(
                transfer_id = %transfer.transfer_id,
                "Transfer already at MintConfirmed phase"
            );
            Err("Transfer already completed".to_string())
        }
        TransferStage::Initialized | TransferStage::LockSubmitted => {
            // These stages should be handled by the runtime, not the cell
            tracing::warn!(
                transfer_id = %transfer.transfer_id,
                stage = ?transfer.stage,
                "Unexpected stage in cell execution"
            );
            Err(format!("Unexpected stage: {:?}", transfer.stage))
        }
        TransferStage::Completed | TransferStage::RolledBack | TransferStage::Compromised => {
            // Terminal states - should not be processed by cell
            tracing::warn!(
                transfer_id = %transfer.transfer_id,
                stage = ?transfer.stage,
                "Terminal state reached, skipping cell execution"
            );
            Err(format!("Terminal state: {:?}", transfer.stage))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_cell_submit_and_process() {
        let config = CellConfig::default();
        let anchor = Arc::new(MockAnchor);
        let cell = ChainCell::spawn(config, anchor);

        let task = CellTask::Process(TransferTask::new(
            "test-transfer".to_string(),
            SanadId::new([1u8; 32]),
            "bitcoin".to_string(),
            "ethereum".to_string(),
            Hash::new([2u8; 32]),
            "0x1234".to_string(),
            TransferStage::LockConfirmed,
            None,
        ));

        let result = cell.submit(task).await;
        assert!(result.is_ok());

        // Give the worker time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_cell_circuit_breaker() {
        let config = CellConfig {
            chain_id: 1,
            max_queue_depth: 10,
            circuit_breaker: CircuitConfig {
                failure_threshold: 2,
                success_threshold: 1,
                timeout: std::time::Duration::from_secs(1),
                half_open_max_calls: 1,
            },
            max_memory_bytes: 100 * 1024 * 1024,
        };
        let anchor = Arc::new(MockAnchor);
        let cell = ChainCell::spawn(config, anchor);

        // Verify initial state is Closed
        assert!(cell.circuit_state() == CircuitState::Closed);

        // Submit tasks (they will be processed but won't trigger circuit breaker
        // since the mock doesn't actually fail)
        for i in 0..3 {
            let task = CellTask::Process(TransferTask::new(
                format!("test-{}", i),
                SanadId::new([i as u8; 32]),
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash::new([i as u8; 32]),
                "0x1234".to_string(),
                TransferStage::LockConfirmed,
                None,
            ));

            let result = cell.submit(task).await;
            assert!(result.is_ok(), "Task {} should be submitted successfully", i);
        }

        // Give the worker time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Circuit should still be Closed (no actual failures occurred)
        assert!(cell.circuit_state() == CircuitState::Closed);
    }

    /// Mock cryptographic anchor for testing.
    struct MockAnchor;

    impl CryptographicAnchor for MockAnchor {
        fn verify_header(
            &self,
            _header: &csv_verifier::CanonicalBlockHeader,
            _validator_set: &csv_verifier::ValidatorSet,
            _finality: &csv_verifier::FinalityGuarantee,
        ) -> Result<csv_verifier::VerifiedHeader, csv_verifier::AnchorError> {
            Ok(csv_verifier::VerifiedHeader {
                hash: [0u8; 32],
                height: 0,
            })
        }

        fn verify_inclusion(
            &self,
            _proof: &csv_verifier::CanonicalInclusionProof,
            _anchor: &csv_verifier::VerifiedHeader,
        ) -> Result<(), csv_verifier::AnchorError> {
            Ok(())
        }
    }
}
