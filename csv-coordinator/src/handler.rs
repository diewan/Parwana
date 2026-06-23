//! Default implementation of TransferPhaseHandler using chain adapters.
//!
//! This module provides a concrete implementation of the TransferPhaseHandler
//! trait that delegates to chain adapters for executing transfer phases.

use crate::cell::TransferPhaseHandler;
use csv_hash::Hash;
use csv_protocol::transfer_state::TransferStage;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
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
    fn verify_lock_confirmed(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>>;

    /// Verify proof and mint on destination chain.
    fn verify_proof_and_mint(
        &self,
        transfer_id: &str,
        proof_payload: &[u8],
        destination_owner: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>>;

    /// Check finality threshold.
    fn check_finality(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>>;

    /// Build inclusion proof.
    fn build_proof(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>>;

    /// Confirm mint transaction.
    fn confirm_mint(
        &self,
        transfer_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>>;
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
    fn execute_lock_confirmed(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
        source_chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        let adapter = match self.get_adapter(source_chain) {
            Some(a) => a.clone(),
            None => {
                let error = format!("No adapter registered for chain: {}", source_chain);
                return Box::pin(async move { Err(error) });
            },
        };
        let transfer_id = transfer_id.to_string();
        let lock_tx_hash = *lock_tx_hash;
        Box::pin(async move {
            adapter.verify_lock_confirmed(&transfer_id, &lock_tx_hash).await
        })
    }

    fn execute_proof_validated(
        &self,
        transfer_id: &str,
        proof_payload: &[u8],
        destination_chain: &str,
        destination_owner: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        let adapter = match self.get_adapter(destination_chain) {
            Some(a) => a.clone(),
            None => {
                let error = format!("No adapter registered for chain: {}", destination_chain);
                return Box::pin(async move { Err(error) });
            },
        };
        let transfer_id = transfer_id.to_string();
        let proof_payload = proof_payload.to_vec();
        let destination_owner = destination_owner.to_string();
        Box::pin(async move {
            adapter.verify_proof_and_mint(&transfer_id, &proof_payload, &destination_owner).await
        })
    }

    fn execute_awaiting_finality(
        &self,
        transfer_id: &str,
        source_chain: &str,
        lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        let adapter = match self.get_adapter(source_chain) {
            Some(a) => a.clone(),
            None => {
                let error = format!("No adapter registered for chain: {}", source_chain);
                return Box::pin(async move { Err(error) });
            },
        };
        let transfer_id = transfer_id.to_string();
        let lock_tx_hash = *lock_tx_hash;
        Box::pin(async move {
            adapter.check_finality(&transfer_id, &lock_tx_hash).await
        })
    }

    fn execute_proof_building(
        &self,
        transfer_id: &str,
        lock_tx_hash: &Hash,
        source_chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        let adapter = match self.get_adapter(source_chain) {
            Some(a) => a.clone(),
            None => {
                let error = format!("No adapter registered for chain: {}", source_chain);
                return Box::pin(async move { Err(error) });
            },
        };
        let transfer_id = transfer_id.to_string();
        let lock_tx_hash = *lock_tx_hash;
        Box::pin(async move {
            adapter.build_proof(&transfer_id, &lock_tx_hash).await
        })
    }

    fn execute_mint_submitted(
        &self,
        transfer_id: &str,
        destination_chain: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        let adapter = match self.get_adapter(destination_chain) {
            Some(a) => a.clone(),
            None => {
                let error = format!("No adapter registered for chain: {}", destination_chain);
                return Box::pin(async move { Err(error) });
            },
        };
        let transfer_id = transfer_id.to_string();
        Box::pin(async move {
            adapter.confirm_mint(&transfer_id).await
        })
    }
}

/// Mock chain adapter for testing.
///
/// This adapter simulates successful execution for all phases.
pub struct MockChainAdapter {
    /// Chain identifier for this mock adapter
    #[allow(dead_code)]
    chain_id: String,
}

impl MockChainAdapter {
    /// Create a new mock adapter for the given chain.
    pub fn new(chain_id: String) -> Self {
        Self { chain_id }
    }
}

impl ChainAdapter for MockChainAdapter {
    fn verify_lock_confirmed(
        &self,
        _transfer_id: &str,
        _lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        Box::pin(async move {
            // Simulate successful lock confirmation
            Ok(TransferStage::ProofBuilding)
        })
    }

    fn verify_proof_and_mint(
        &self,
        _transfer_id: &str,
        _proof_payload: &[u8],
        _destination_owner: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        Box::pin(async move {
            // Simulate successful proof validation and mint
            Ok(TransferStage::MintSubmitted)
        })
    }

    fn check_finality(
        &self,
        _transfer_id: &str,
        _lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        Box::pin(async move {
            // Simulate finality check passing
            Ok(TransferStage::ProofBuilding)
        })
    }

    fn build_proof(
        &self,
        _transfer_id: &str,
        _lock_tx_hash: &Hash,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        Box::pin(async move {
            // Simulate successful proof building
            Ok(TransferStage::ProofValidated)
        })
    }

    fn confirm_mint(
        &self,
        _transfer_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<TransferStage, String>> + Send + '_>> {
        Box::pin(async move {
            // Simulate successful mint confirmation
            Ok(TransferStage::MintConfirmed)
        })
    }
}
