//! Default implementation of TransferPhaseHandler using chain adapters.
//!
//! This module provides a concrete implementation of the TransferPhaseHandler
//! trait that delegates to chain adapters for executing transfer phases.

use crate::cell::TransferPhaseHandler;
use csv_hash::Hash;
use csv_protocol::transfer_state::TransferStage;
use std::collections::HashMap;
use std::sync::Arc;

/// Default handler that delegates to chain adapters.
///
/// This handler maintains a registry of chain adapters and delegates
/// transfer phase execution to the appropriate adapter based on the chain ID.
pub struct DefaultTransferHandler {
    /// Chain adapter registry keyed by chain ID
    adapters: HashMap<String, Arc<dyn ChainAdapter>>,
}

/// Chain adapter trait for transfer phase operations.
///
/// This trait abstracts the chain-specific operations needed for
/// cross-chain transfer execution.
pub trait ChainAdapter: Send + Sync {
    /// Verify lock transaction and check finality.
    async fn verify_lock_confirmed(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String>;

    /// Verify proof and mint on destination chain.
    async fn verify_proof_and_mint(
        &self,
        transfer_id: &str,
        proof_payload: &[u8],
        destination_owner: &str,
    ) -> Result<TransferStage, String>;

    /// Check finality threshold.
    async fn check_finality(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String>;

    /// Build inclusion proof.
    async fn build_proof(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String>;

    /// Confirm mint transaction.
    async fn confirm_mint(
        &self,
        transfer_id: &str,
    ) -> Result<TransferStage, String>;
}

impl DefaultTransferHandler {
    /// Create a new default handler with the given chain adapters.
    pub fn new(adapters: HashMap<String, Arc<dyn ChainAdapter>>) -> Self {
        Self { adapters }
    }

    /// Create an empty handler (for testing).
    pub fn empty() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    /// Register a chain adapter.
    pub fn register_adapter(&mut self, chain_id: String, adapter: Arc<dyn ChainAdapter>) {
        self.adapters.insert(chain_id, adapter);
    }

    /// Get the adapter for a given chain.
    fn get_adapter(&self, chain: &str) -> Option<Arc<dyn ChainAdapter>> {
        self.adapters.get(chain).cloned()
    }
}

#[async_trait::async_trait]
impl TransferPhaseHandler for DefaultTransferHandler {
    async fn execute_lock_confirmed(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
        source_chain: &str,
    ) -> Result<TransferStage, String> {
        let adapter = self.get_adapter(source_chain)
            .ok_or_else(|| format!("No adapter registered for chain: {}", source_chain))?;

        adapter.verify_lock_confirmed(transfer_id, lock_tx_hash).await
    }

    async fn execute_proof_validated(
        &self,
        transfer_id: &str,
        proof_payload: &[u8],
        destination_chain: &str,
        destination_owner: &str,
    ) -> Result<TransferStage, String> {
        let adapter = self.get_adapter(destination_chain)
            .ok_or_else(|| format!("No adapter registered for chain: {}", destination_chain))?;

        adapter.verify_proof_and_mint(transfer_id, proof_payload, destination_owner).await
    }

    async fn execute_awaiting_finality(
        &self,
        transfer_id: &str,
        source_chain: &str,
        lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String> {
        let adapter = self.get_adapter(source_chain)
            .ok_or_else(|| format!("No adapter registered for chain: {}", source_chain))?;

        adapter.check_finality(transfer_id, lock_tx_hash).await
    }

    async fn execute_proof_building(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
        source_chain: &str,
    ) -> Result<TransferStage, String> {
        let adapter = self.get_adapter(source_chain)
            .ok_or_else(|| format!("No adapter registered for chain: {}", source_chain))?;

        adapter.build_proof(transfer_id, lock_tx_hash).await
    }

    async fn execute_mint_submitted(
        &self,
        transfer_id: &str,
        destination_chain: &str,
    ) -> Result<TransferStage, String> {
        let adapter = self.get_adapter(destination_chain)
            .ok_or_else(|| format!("No adapter registered for chain: {}", destination_chain))?;

        adapter.confirm_mint(transfer_id).await
    }
}

/// Mock chain adapter for testing.
///
/// This adapter simulates successful execution for all phases.
pub struct MockChainAdapter {
    chain_id: String,
}

impl MockChainAdapter {
    /// Create a new mock adapter for the given chain.
    pub fn new(chain_id: String) -> Self {
        Self { chain_id }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for MockChainAdapter {
    async fn verify_lock_confirmed(
        &self,
        _transfer_id: &str,
        _lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String> {
        // Simulate successful lock confirmation
        Ok(TransferStage::ProofBuilding)
    }

    async fn verify_proof_and_mint(
        &self,
        _transfer_id: &str,
        _proof_payload: &[u8],
        _destination_owner: &str,
    ) -> Result<TransferStage, String> {
        // Simulate successful proof validation and mint
        Ok(TransferStage::MintSubmitted)
    }

    async fn check_finality(
        &self,
        _transfer_id: &str,
        _lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String> {
        // Simulate finality check passing
        Ok(TransferStage::ProofBuilding)
    }

    async fn build_proof(
        &self,
        _transfer_id: &str,
        _lock_tx_hash: &Hash,
    ) -> Result<TransferStage, String> {
        // Simulate successful proof building
        Ok(TransferStage::ProofValidated)
    }

    async fn confirm_mint(
        &self,
        _transfer_id: &str,
    ) -> Result<TransferStage, String> {
        // Simulate successful mint confirmation
        Ok(TransferStage::MintConfirmed)
    }
}
