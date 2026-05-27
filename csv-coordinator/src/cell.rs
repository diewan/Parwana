use std::sync::Arc;
use tokio::sync::mpsc;
use csv_verifier::CryptographicAnchor;
use crate::circuit::{CellCircuitBreaker, CircuitConfig};
use crate::memory::MemoryCeiling;

/// Task submitted to a chain cell.
#[derive(Debug, Clone)]
pub enum CellTask {
    Process(InboundTransfer),
    HealthCheck,
}

/// Inbound transfer request.
#[derive(Debug, Clone)]
pub struct InboundTransfer {
    pub transfer_id: [u8; 32],
    pub source_chain: u32,
    pub dest_chain: u32,
}

impl InboundTransfer {
    pub fn new(transfer_id: [u8; 32], source_chain: u32, dest_chain: u32) -> Self {
        Self {
            transfer_id,
            source_chain,
            dest_chain,
        }
    }
}

/// Chain cell configuration.
#[derive(Debug, Clone)]
pub struct CellConfig {
    pub chain_id: u32,
    pub max_queue_depth: usize,
    pub circuit_breaker: CircuitConfig,
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
    #[error("Circuit is open for chain {0}")]
    CircuitOpen(u32),
    #[error("Backpressure: queue full for chain {0}")]
    Backpressure(u32),
    #[error("Memory ceiling exceeded")]
    MemoryExceeded,
    #[error("Transfer processing requires an authenticated proof execution request")]
    MissingVerifiedMaterial,
}

/// An isolated execution unit for one chain adapter.
/// 
/// Each cell owns:
/// - Its own bounded mpsc queue (not shared with other cells)
/// - Its own circuit breaker
/// - Its own memory ceiling
/// 
/// A cell degradation CANNOT propagate to sibling cells.
pub struct ChainCell {
    chain_id: u32,
    queue: mpsc::Sender<CellTask>,
    circuit: CellCircuitBreaker,
    memory_ceiling: MemoryCeiling,
}

impl ChainCell {
    pub fn spawn(config: CellConfig, anchor: Arc<dyn CryptographicAnchor>) -> Self {
        let (tx, rx) = mpsc::channel::<CellTask>(config.max_queue_depth);

        // Spawn cell worker task
        tokio::spawn(cell_worker(rx, anchor, config.clone()));

        ChainCell {
            chain_id: config.chain_id,
            queue: tx,
            circuit: CellCircuitBreaker::new(config.circuit_breaker),
            memory_ceiling: MemoryCeiling::new(config.max_memory_bytes),
        }
    }

    /// Submit work to this cell.
    /// Returns Err(Backpressure) if cell queue is full.
    pub async fn submit(&self, task: CellTask) -> Result<(), CellError> {
        if self.circuit.is_open() {
            return Err(CellError::CircuitOpen(self.chain_id));
        }
        if matches!(task, CellTask::Process(_)) {
            return Err(CellError::MissingVerifiedMaterial);
        }

        self.queue
            .try_send(task)
            .map_err(|_| CellError::Backpressure(self.chain_id))
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn circuit_state(&self) -> crate::circuit::CircuitState {
        self.circuit.state()
    }

    pub fn memory_usage(&self) -> u64 {
        self.memory_ceiling.current_usage()
    }
}

/// Cell worker task that processes inbound transfers.
async fn cell_worker(
    mut rx: mpsc::Receiver<CellTask>,
    _anchor: Arc<dyn CryptographicAnchor>,
    config: CellConfig,
) {
    let mut circuit_breaker = CellCircuitBreaker::new(config.circuit_breaker);

    while let Some(task) = rx.recv().await {
        match task {
            CellTask::Process(_) => unreachable!("process tasks are rejected before enqueue"),
            CellTask::HealthCheck => {
                // Perform health check
                if circuit_breaker.is_open() {
                    circuit_breaker.attempt_reset();
                }
            }
        }
    }

    tracing::info!("Cell worker for chain {} shutting down", config.chain_id);
}
