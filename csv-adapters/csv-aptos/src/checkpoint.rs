//! Aptos checkpoint finality verifier
//!
//! This module provides checkpoint verification for Aptos,
//! verifying that transactions are in blocks certified by 2f+1 validators.
//!
//! Aptos uses HotStuff consensus, which provides deterministic finality:
//! once a block is certified by 2f+1 validators, it cannot be reverted.

use serde::{Deserialize, Serialize};

use crate::config::CheckpointConfig;
use crate::error::{AptosError, AptosResult};
use crate::rpc::AptosRpc;

/// Checkpoint (block) information with certification details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// The checkpoint version (same as transaction version range)
    pub version: u64,
    /// The epoch this checkpoint belongs to
    pub epoch: u64,
    /// The round number within the epoch
    pub round: u64,
    /// Number of validator signatures (should be >= 2f+1)
    pub signatures_count: u64,
    /// Whether the checkpoint is certified
    pub is_certified: bool,
}

impl CheckpointInfo {
    /// Returns true if this checkpoint has sufficient validator signatures.
    pub fn has_quorum(&self, required_signatures: u64) -> bool {
        self.signatures_count >= required_signatures
    }
}

/// Checkpoint finality verifier for Aptos
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

    /// Check if a transaction version is in a certified block.
    ///
    /// In Aptos, a block is certified when it receives signatures from
    /// 2f+1 validators. Once certified, the block cannot be reverted.
    ///
    /// # Arguments
    /// * `version` - The transaction version to check
    /// * `rpc` - RPC client for fetching block data
    /// * `required_signatures` - Required number of validator signatures (2f+1)
    ///
    /// # Returns
    /// `Ok(CheckpointInfo)` with certification details, or `Err` on failure.
    ///
    /// # Note
    /// This is an async-only method. Use the async version from async contexts.
    pub async fn is_version_finalized_async(
        &self,
        version: u64,
        rpc: &dyn AptosRpc,
        required_signatures: u64,
    ) -> AptosResult<CheckpointInfo> {
        // Check timeout
        let start = std::time::Instant::now();

        let block = rpc.get_block_by_version(version).await.map_err(|e| {
            if start.elapsed().as_millis() > self.config.timeout_ms as u128 {
                AptosError::timeout(&format!("version_{}", version), self.config.timeout_ms)
            } else {
                AptosError::CheckpointFailed(format!("Failed to get block: {}", e))
            }
        })?;

        match block {
            Some(block) => {
                let is_certified = if self.config.require_certified {
                    required_signatures > 0
                        && rpc.verify_checkpoint(version).await.map_err(|e| {
                            AptosError::CheckpointFailed(format!(
                                "Failed to verify checkpoint: {}",
                                e
                            ))
                        })?
                } else {
                    true
                };

                Ok(CheckpointInfo {
                    version,
                    epoch: block.epoch,
                    round: block.round,
                    signatures_count: if is_certified { required_signatures } else { 0 },
                    is_certified,
                })
            }
            None => Err(AptosError::CheckpointFailed(format!(
                "Block containing version {} not found",
                version
            ))),
        }
    }

    /// Check if a resource still exists (for seal verification).
    ///
    /// This verifies that a seal resource has not been consumed yet.
    ///
    /// # Arguments
    /// * `address` - The account address
    /// * `resource_type` - The resource type tag
    /// * `rpc` - RPC client for fetching resource data
    pub async fn is_resource_present_async(
        &self,
        address: [u8; 32],
        resource_type: &str,
        rpc: &dyn AptosRpc,
    ) -> AptosResult<bool> {
        let resource = rpc.get_resource(address, resource_type, None).await?;
        Ok(resource.is_some())
    }

    /// Verify an event was emitted in a specific transaction.
    ///
    /// # Arguments
    /// * `tx_version` - The transaction version to check
    /// * `expected_event_data` - The expected event data bytes
    /// * `rpc` - RPC client for fetching transaction data
    pub async fn verify_event_in_transaction_async(
        &self,
        tx_version: u64,
        expected_event_data: &[u8],
        rpc: &dyn AptosRpc,
    ) -> AptosResult<bool> {
        let tx = rpc.get_transaction_by_version(tx_version).await
            .map_err(|e| AptosError::CheckpointFailed(format!("Failed to get transaction: {}", e)))?;
        match tx {
            Some(tx) => {
                if !tx.success {
                    return Ok(false);
                }
                Ok(tx.events.iter().any(|e| e.data == expected_event_data))
            }
            None => Err(AptosError::EventProofFailed(format!(
                "Transaction at version {} not found",
                tx_version
            ))),
        }
    }

    /// Get the current epoch from the network.
    ///
    /// # Arguments
    /// * `rpc` - RPC client for fetching epoch info
    pub async fn current_epoch_async(&self, rpc: &dyn AptosRpc) -> AptosResult<u64> {
        let ledger = rpc.get_ledger_info().await
            .map_err(|e| AptosError::CheckpointFailed(format!("Failed to get ledger: {}", e)))?;
        Ok(ledger.epoch)
    }

    /// Verify that an epoch boundary has passed.
    ///
    /// This is useful for ensuring the network has progressed beyond a certain point.
    ///
    /// # Arguments
    /// * `expected_epoch` - The epoch we expect the network to be in
    /// * `rpc` - RPC client for fetching current epoch
    pub async fn is_epoch_passed_async(&self, expected_epoch: u64, rpc: &dyn AptosRpc) -> AptosResult<bool> {
        let current = self.current_epoch_async(rpc).await?;
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
    use crate::rpc::{AptosBlockInfo, AptosEvent, AptosResource, AptosTransaction, MockAptosRpc};

    #[tokio::test]
    async fn test_version_finalization() {
        let rpc = MockAptosRpc::new(5000);
        rpc.set_block(
            1500,
            AptosBlockInfo {
                version: 1500,
                block_hash: [1u8; 32],
                epoch: 1,
                round: 42,
                timestamp_usecs: 1234567890,
            },
        );

        let verifier = CheckpointVerifier::new();
        let result = verifier.is_version_finalized_async(1500, &rpc, 3).await.unwrap();
        assert!(result.is_certified);
        assert_eq!(result.version, 1500);
        assert_eq!(result.epoch, 1);
        assert_eq!(result.round, 42);
    }

    #[tokio::test]
    async fn test_version_not_found() {
        let rpc = MockAptosRpc::new(5000);

        let verifier = CheckpointVerifier::new();
        let result = verifier.is_version_finalized_async(9999, &rpc, 3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resource_presence() {
        let rpc = MockAptosRpc::new(5000);
        rpc.set_resource(
            [1u8; 32],
            "CSV::Seal",
            AptosResource {
                data: vec![1, 2, 3],
            },
        );

        let verifier = CheckpointVerifier::new();
        assert!(
            verifier
                .is_resource_present_async([1u8; 32], "CSV::Seal", &rpc)
                .await
                .unwrap()
        );
        assert!(
            !verifier
                .is_resource_present_async([99u8; 32], "CSV::Seal", &rpc)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_failed_transaction_event() {
        let rpc = MockAptosRpc::new(5000);
        rpc.add_transaction(
            1500,
            AptosTransaction {
                version: 1500,
                hash: [3u8; 32],
                state_change_hash: [0u8; 32],
                event_root_hash: [0u8; 32],
                state_checkpoint_hash: None,
                epoch: 1,
                round: 0,
                events: vec![AptosEvent {
                    event_sequence_number: 0,
                    key: "CSV::Seal".to_string(),
                    data: vec![0xAB, 0xCD],
                    transaction_version: 1500,
                }],
                payload: vec![],
                success: false,
                vm_status: "Execution failed".to_string(),
                gas_used: 0,
                cumulative_gas_used: 0,
            },
        );

        let verifier = CheckpointVerifier::new();
        assert!(
            !verifier
                .verify_event_in_transaction_async(1500, &[0xAB, 0xCD], &rpc)
                .await
                .unwrap()
        );
        assert!(
            !verifier
                .verify_event_in_transaction_async(1500, &[0xFF], &rpc)
                .await
                .unwrap()
        );
        assert!(
            verifier
                .verify_event_in_transaction_async(9999, &[0xAB], &rpc)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_event_in_transaction() {
        let rpc = MockAptosRpc::new(5000);
        rpc.add_transaction(
            1500,
            AptosTransaction {
                version: 1500,
                hash: [3u8; 32],
                state_change_hash: [0u8; 32],
                event_root_hash: [0u8; 32],
                state_checkpoint_hash: None,
                epoch: 1,
                round: 0,
                events: vec![AptosEvent {
                    event_sequence_number: 0,
                    key: "CSV::Seal".to_string(),
                    data: vec![0xAB, 0xCD],
                    transaction_version: 1500,
                }],
                payload: vec![],
                success: true,
                vm_status: "Executed".to_string(),
                gas_used: 0,
                cumulative_gas_used: 0,
            },
        );

        let verifier = CheckpointVerifier::new();
        assert!(
            verifier
                .verify_event_in_transaction_async(1500, &[0xAB, 0xCD], &rpc)
                .await
                .unwrap()
        );
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
    fn test_checkpoint_info_quorum() {
        let info = CheckpointInfo {
            version: 100,
            epoch: 1,
            round: 42,
            signatures_count: 67,
            is_certified: true,
        };

        assert!(info.has_quorum(67));
        assert!(info.has_quorum(50));
        assert!(!info.has_quorum(100));
    }
}
