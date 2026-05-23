//! Sui checkpoint finality verifier
//!
//! This module provides checkpoint verification for Sui,
//! verifying that transactions are in checkpoints certified by 2f+1 validators.
//!
//! Sui uses Narwhal consensus, which provides deterministic finality:
//! once a checkpoint is certified by 2f+1 validators, it cannot be reverted.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::CheckpointConfig;
use crate::error::{SuiError, SuiResult};
use crate::rpc::SuiRpc;

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
        rpc: &dyn SuiRpc,
    ) -> SuiResult<CheckpointInfo>;

    /// Check if a transaction's checkpoint is finalized.
    async fn is_tx_finalized(&self, tx_checkpoint: u64, rpc: &dyn SuiRpc) -> SuiResult<bool>;

    /// Get the latest certified checkpoint.
    async fn latest_certified_checkpoint(&self, rpc: &dyn SuiRpc) -> SuiResult<Option<u64>>;

    /// Get the current epoch from the network.
    async fn current_epoch(&self, rpc: &dyn SuiRpc) -> SuiResult<u64>;

    /// Verify that an epoch boundary has passed.
    async fn is_epoch_passed(&self, expected_epoch: u64, rpc: &dyn SuiRpc) -> SuiResult<bool>;
}

/// Checkpoint finality verifier for Sui
#[derive(Clone)]
pub struct CheckpointVerifier {
    /// Configuration for checkpoint verification
    config: CheckpointConfig,
}

impl CheckpointVerifier {
    /// Create a new checkpoint verifier with default configuration.
    pub fn new() -> Self {
        Self::with_config(CheckpointConfig::default())
    }

    /// Create a new checkpoint verifier with custom configuration.
    pub fn with_config(config: CheckpointConfig) -> Self {
        Self { config }
    }

    /// Get the verifier configuration.
    pub fn config(&self) -> &CheckpointConfig {
        &self.config
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
    /// * `rpc` - RPC client for fetching checkpoint data
    ///
    /// # Returns
    /// `Ok(CheckpointInfo)` with certification details, or `Err` on failure.
    async fn is_checkpoint_certified(
        &self,
        checkpoint_seq: u64,
        rpc: &dyn SuiRpc,
    ) -> SuiResult<CheckpointInfo> {
        // Check timeout
        let start = std::time::Instant::now();

        let cp = rpc.get_checkpoint(checkpoint_seq).await.map_err(|e| {
            if start.elapsed().as_millis() > self.config.timeout_ms as u128 {
                SuiError::timeout(
                    &format!("checkpoint_{}", checkpoint_seq),
                    self.config.timeout_ms,
                )
            } else {
                SuiError::CheckpointFailed(format!("Failed to get checkpoint: {}", e))
            }
        })?;

        match cp {
            Some(cp) => {
                let is_certified = if self.config.require_certified {
                    cp.certified
                } else {
                    true
                };

                Ok(CheckpointInfo {
                    sequence_number: cp.sequence_number,
                    epoch: cp.epoch,
                    digest: cp.digest,
                    total_transactions: cp.network_total_transactions,
                    is_certified,
                })
            }
            None => Err(SuiError::CheckpointFailed(format!(
                "Checkpoint {} not found",
                checkpoint_seq
            ))),
        }
    }

    /// Check if a transaction's checkpoint is finalized.
    async fn is_tx_finalized(&self, tx_checkpoint: u64, rpc: &dyn SuiRpc) -> SuiResult<bool> {
        let info = self.is_checkpoint_certified(tx_checkpoint, rpc).await?;
        Ok(info.is_finalized())
    }

    /// Get the latest certified checkpoint.
    async fn latest_certified_checkpoint(&self, rpc: &dyn SuiRpc) -> SuiResult<Option<u64>> {
        let latest = rpc
            .get_latest_checkpoint_sequence_number()
            .await
            .map_err(|e| {
                SuiError::CheckpointFailed(format!("Failed to get latest checkpoint: {}", e))
            })?;

        // Walk backwards to find the first certified checkpoint
        let max_lookback = self.config.max_epoch_lookback;
        let start = latest.saturating_sub(max_lookback * 1000); // Approximate checkpoints per epoch

        for seq in (start..=latest).rev() {
            if let Some(cp) = rpc.get_checkpoint(seq).await.ok().flatten() {
                if cp.certified {
                    return Ok(Some(seq));
                }
            }
        }
        Ok(None)
    }

    /// Get the current epoch from the network.
    async fn current_epoch(&self, rpc: &dyn SuiRpc) -> SuiResult<u64> {
        let latest = self.latest_certified_checkpoint(rpc).await?;
        match latest {
            Some(seq) => {
                let cp = rpc.get_checkpoint(seq).await.map_err(|e| {
                    SuiError::CheckpointFailed(format!("Failed to get checkpoint: {}", e))
                })?;
                Ok(cp.map(|c| c.epoch).unwrap_or(0))
            }
            None => Ok(0),
        }
    }

    /// Verify that an epoch boundary has passed.
    async fn is_epoch_passed(&self, expected_epoch: u64, rpc: &dyn SuiRpc) -> SuiResult<bool> {
        let current = self.current_epoch(rpc).await?;
        Ok(current >= expected_epoch)
    }
}

impl Default for CheckpointVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{MockSuiRpc, SuiCheckpoint};

    #[tokio::test]
    async fn test_certified_checkpoint() {
        let rpc = MockSuiRpc::new(1000);
        rpc.add_checkpoint(SuiCheckpoint {
            sequence_number: 500,
            digest: [1u8; 32],
            epoch: 1,
            network_total_transactions: 50000,
            certified: true,
        });
        rpc.add_checkpoint(SuiCheckpoint {
            sequence_number: 501,
            digest: [2u8; 32],
            epoch: 1,
            network_total_transactions: 50100,
            certified: false,
        });

        let verifier = CheckpointVerifier::new();
        let result = verifier.is_checkpoint_certified(500, &rpc).await.unwrap();
        assert!(result.is_certified);
        assert_eq!(result.sequence_number, 500);
        assert_eq!(result.epoch, 1);

        let result = verifier.is_checkpoint_certified(501, &rpc).await.unwrap();
        assert!(!result.is_certified);

        assert!(verifier.is_checkpoint_certified(999, &rpc).await.is_err());
    }

    #[tokio::test]
    async fn test_tx_finalization() {
        let rpc = MockSuiRpc::new(1000);
        rpc.add_checkpoint(SuiCheckpoint {
            sequence_number: 500,
            digest: [1u8; 32],
            epoch: 1,
            network_total_transactions: 50000,
            certified: true,
        });

        let verifier = CheckpointVerifier::new();
        assert!(verifier.is_tx_finalized(500, &rpc).await.unwrap());
        assert!(verifier.is_tx_finalized(600, &rpc).await.is_err());
    }

    #[tokio::test]
    async fn test_latest_certified() {
        let rpc = MockSuiRpc::new(1000);
        rpc.add_checkpoint(SuiCheckpoint {
            sequence_number: 998,
            digest: [1u8; 32],
            epoch: 1,
            network_total_transactions: 99800,
            certified: true,
        });
        rpc.add_checkpoint(SuiCheckpoint {
            sequence_number: 999,
            digest: [2u8; 32],
            epoch: 1,
            network_total_transactions: 99900,
            certified: false,
        });
        rpc.add_checkpoint(SuiCheckpoint {
            sequence_number: 1000,
            digest: [3u8; 32],
            epoch: 1,
            network_total_transactions: 100000,
            certified: false,
        });

        let verifier = CheckpointVerifier::new();
        let latest = verifier.latest_certified_checkpoint(&rpc).await.unwrap();
        assert_eq!(latest, Some(998));
    }

    #[test]
    fn test_checkpoint_config() {
        let config = CheckpointConfig {
            require_certified: false,
            max_epoch_lookback: 3,
            timeout_ms: 10_000,
        };
        let verifier = CheckpointVerifier::with_config(config);
        assert!(!verifier.config().require_certified);
        assert_eq!(verifier.config().max_epoch_lookback, 3);
    }

    #[test]
    fn test_checkpoint_info() {
        let info = CheckpointInfo {
            sequence_number: 100,
            epoch: 1,
            digest: [1u8; 32],
            total_transactions: 10000,
            is_certified: true,
        };

        assert!(info.is_finalized());
        assert_eq!(info.sequence_number, 100);
    }
}
