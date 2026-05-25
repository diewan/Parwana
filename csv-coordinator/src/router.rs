use std::collections::HashMap;
use std::sync::Arc;
use csv_verifier::CryptographicAnchor;
use crate::cell::{ChainCell, CellConfig, CellTask, CellError, InboundTransfer};

/// Error type for router operations.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("Unknown chain: {0}")]
    UnknownChain(u32),
    #[error("Cell error: {0}")]
    Cell(#[from] CellError),
}

/// Routes incoming transfer requests to the correct chain cell.
/// Owns one ChainCell per registered chain.
/// Degradation of any single cell does NOT affect other cells.
pub struct TransferRouter {
    cells: HashMap<u32, ChainCell>,
}

impl TransferRouter {
    pub fn new() -> Self {
        Self {
            cells: HashMap::new(),
        }
    }

    /// Register a chain cell with the router.
    pub fn register_cell(&mut self, chain_id: u32, anchor: Arc<dyn CryptographicAnchor>) {
        let config = CellConfig {
            chain_id,
            ..Default::default()
        };
        let cell = ChainCell::spawn(config, anchor);
        self.cells.insert(chain_id, cell);
    }

    /// Route a transfer to the appropriate chain cell.
    pub async fn route(&self, transfer: InboundTransfer) -> Result<(), RouterError> {
        let cell = self
            .cells
            .get(&transfer.source_chain)
            .ok_or(RouterError::UnknownChain(transfer.source_chain))?;

        cell.submit(CellTask::Process(transfer))
            .await
            .map_err(RouterError::Cell)
    }

    /// Get the number of registered cells.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Check if a chain is registered.
    pub fn has_chain(&self, chain_id: u32) -> bool {
        self.cells.contains_key(&chain_id)
    }
}

impl Default for TransferRouter {
    fn default() -> Self {
        Self::new()
    }
}
