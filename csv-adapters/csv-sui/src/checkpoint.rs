//! Sui checkpoint finality verifier
//!
//! This module provides checkpoint verification for Sui,
//! verifying that transactions are in checkpoints certified by 2f+1 validators.
//!
//! Sui uses Narwhal consensus, which provides deterministic finality:
//! once a checkpoint is certified by 2f+1 validators, it cannot be reverted.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::CheckpointConfig;
use crate::error::{SuiError, SuiResult};
use crate::node::SuiNode;

/// Checkpoint information with certification details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// The checkpoint sequence number
    pub sequence_number: u64,
    /// The epoch this checkpoint belongs to
    pub epoch: u64,
    /// The digest of the checkpoint
    pub digest: [u8; 32],
    /// Total number of transactions in the checkpoint
    pub total_transactions: u64,
    /// Whether the checkpoint is certified
    pub is_certified: bool,
}

impl CheckpointInfo {
    /// Returns true if this checkpoint is certified.
    pub fn is_finalized(&self) -> bool {
        self.is_certified
    }
}

/// Trait for checkpoint verification operations
#[async_trait]
pub trait CheckpointVerifierTrait: Send + Sync {
    /// Check if a checkpoint is certified.
    async fn is_checkpoint_certified(
        &self,
        checkpoint_seq: u64,
    ) -> SuiResult<CheckpointInfo>;

    /// Check if a transaction's checkpoint is finalized.
    async fn is_tx_finalized(&self, tx_checkpoint: u64) -> SuiResult<bool>;

    /// Get the latest certified checkpoint.
    async fn latest_certified_checkpoint(&self) -> SuiResult<Option<u64>>;

    /// Get the current epoch from the network.
    async fn current_epoch(&self) -> SuiResult<u64>;

    /// Verify that an epoch boundary has passed.
    async fn is_epoch_passed(&self, expected_epoch: u64) -> SuiResult<bool>;
}

/// Checkpoint finality verifier for Sui
#[derive(Clone)]
pub struct CheckpointVerifier {
    /// Configuration for checkpoint verification
    config: CheckpointConfig,
    /// Sui gRPC client for checkpoint queries
    node: Arc<SuiNode>,
}

impl CheckpointVerifier {
    /// Create a new checkpoint verifier with default configuration.
    pub fn new(node: Arc<SuiNode>) -> Self {
        Self::with_config(CheckpointConfig::default(), node)
    }

    /// Create a new checkpoint verifier with custom configuration.
    pub fn with_config(config: CheckpointConfig, node: Arc<SuiNode>) -> Self {
        Self { config, node }
    }

    /// Get the verifier configuration.
    pub fn config(&self) -> &CheckpointConfig {
        &self.config
    }

    /// Get the Sui node client.
    pub fn node(&self) -> &Arc<SuiNode> {
        &self.node
    }
}

#[async_trait]
impl CheckpointVerifierTrait for CheckpointVerifier {
    /// Check if a checkpoint is certified.
    ///
    /// In Sui, a checkpoint is certified when it receives signatures from
    /// 2f+1 validators. Once certified, the checkpoint cannot be reverted.
    ///
    /// # Arguments
    /// * `checkpoint_seq` - The checkpoint sequence number to check
    ///
    /// # Returns
    /// `Ok(CheckpointInfo)` with certification details, or `Err` on failure.
    async fn is_checkpoint_certified(
        &self,
        checkpoint_seq: u64,
    ) -> SuiResult<CheckpointInfo> {
        use sui_rpc::api::ReadApi;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::CheckpointFailed(format!("Failed to lock client: {}", e))
        })?;
        
        // Use sui-rust-sdk to get checkpoint by sequence number
        let checkpoint = client_guard
            .get_checkpoint_by_sequence_number(checkpoint_seq)
            .await
            .map_err(|e| SuiError::CheckpointFailed(format!("Failed to get checkpoint: {}", e)))?;
        
        let digest_bytes = checkpoint.digest.to_vec();
        let mut digest = [0u8; 32];
        if digest_bytes.len() >= 32 {
            digest.copy_from_slice(&digest_bytes[..32]);
        }
        
        Ok(CheckpointInfo {
            sequence_number: checkpoint.sequence_number,
            epoch: checkpoint.epoch,
            digest,
            total_transactions: checkpoint.network_total_transactions as u64,
            is_certified: checkpoint.checkpoint_commitments.is_some(),
        })
    }

    /// Check if a transaction's checkpoint is finalized.
    async fn is_tx_finalized(&self, tx_checkpoint: u64) -> SuiResult<bool> {
        let info = self.is_checkpoint_certified(tx_checkpoint).await?;
        Ok(info.is_finalized())
    }

    /// Get the latest certified checkpoint.
    async fn latest_certified_checkpoint(&self) -> SuiResult<Option<u64>> {
        use sui_rpc::api::ReadApi;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::CheckpointFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let latest_checkpoint = client_guard
            .get_latest_checkpoint()
            .await
            .map_err(|e| SuiError::CheckpointFailed(format!("Failed to get latest checkpoint: {}", e)))?;
        
        Ok(Some(latest_checkpoint.sequence_number))
    }

    /// Get the current epoch from the network.
    async fn current_epoch(&self) -> SuiResult<u64> {
        use sui_rpc::api::ReadApi;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::CheckpointFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let latest_checkpoint = client_guard
            .get_latest_checkpoint()
            .await
            .map_err(|e| SuiError::CheckpointFailed(format!("Failed to get latest checkpoint: {}", e)))?;
        
        Ok(latest_checkpoint.epoch)
    }

    /// Verify that an epoch boundary has passed.
    async fn is_epoch_passed(&self, expected_epoch: u64) -> SuiResult<bool> {
        let current = self.current_epoch().await?;
        Ok(current >= expected_epoch)
    }
}

impl Default for CheckpointVerifier {
    fn default() -> Self {
        // Default requires a node, so this is a placeholder
        // In practice, users should call CheckpointVerifier::new(node)
        panic!("CheckpointVerifier::default() requires a SuiNode. Use CheckpointVerifier::new(node) instead.")
    }
}
