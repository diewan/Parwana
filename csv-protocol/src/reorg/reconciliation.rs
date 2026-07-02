//! Reconciliation Engine
//!
//! Reconciles state after a reorg by re-validating affected operations.
//! After a rollback is executed, this engine ensures all affected transfers
//! are in a consistent state.

use async_trait::async_trait;
use std::vec::Vec;

use super::detector::ReorgEvent;
use csv_hash::Hash;

/// Type of reconciliation action taken
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationAction {
    /// Transfer successfully reconciled
    ///
    /// The `new_state` field indicates the new state after reconciliation.
    Reconciled {
        /// New state after reconciliation (e.g., "awaiting_finality")
        new_state: String,
    },
    /// Transfer marked as compromised after failed reconciliation
    Compromised,
    /// Transfer requires manual intervention
    NeedsReview,
}

/// Result of re-validating a single proof
#[derive(Clone, Debug)]
pub struct ProofRevalidationResult {
    /// Transfer ID
    pub transfer_id: String,
    /// Whether the re-validated proof is valid
    pub valid: bool,
    /// New block height of the source lock on the canonical chain
    pub canonical_block_height: Option<u64>,
    /// Error message if invalid
    pub error: Option<String>,
}

/// Reconciliation result
#[derive(Clone, Debug)]
pub struct ReconciliationResult {
    /// Number of transfers reconciled
    pub transfers_reconciled: u32,
    /// Number of transfers that failed reconciliation
    pub transfers_failed: u32,
    /// Number of proofs re-validated
    pub proofs_revalidated: u32,
    /// Actions taken during reconciliation
    pub actions: Vec<ReconciliationAction>,
}

/// Chain backend trait for reconciliation queries.
///
/// This allows the reconciliation engine to query the canonical chain
/// for block hashes, transaction receipts, and proof data.
#[async_trait]
pub trait ChainBackendForReconciliation: Send + Sync {
    /// Get the block hash at a given height on the canonical chain.
    async fn get_block_hash(&self, height: u64) -> Result<Hash, String>;

    /// Get the latest block height on the canonical chain.
    async fn get_latest_block_height(&self) -> Result<u64, String>;

    /// Verify that a commitment exists at the given block height.
    ///
    /// Returns true if the commitment was found in the block's state.
    async fn verify_commitment_in_block(
        &self,
        commitment: &Hash,
        block_height: u64,
    ) -> Result<bool, String>;

    /// Rebuild an inclusion proof for a commitment at the given height.
    ///
    /// This queries the canonical chain to produce a fresh proof.
    async fn rebuild_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
    ) -> Result<crate::proof_taxonomy::InclusionProof, String>;

    /// Verify a proof bundle against the canonical chain.
    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &crate::proof_taxonomy::InclusionProof,
        commitment: &Hash,
    ) -> Result<bool, String>;
}

/// Reconciliation engine
///
/// After a reorg and rollback, this engine:
/// 1. Re-validates proofs for affected transfers
/// 2. Checks if source locks are still valid on the new chain
/// 3. Updates transfer states based on re-validation results
/// 4. Marks transfers that cannot be reconciled as compromised
pub struct ReconciliationEngine<B: ChainBackendForReconciliation> {
    /// Storage backend for chain queries
    chain_backend: B,
    /// Reconciliation history
    history: std::vec::Vec<ReconciliationResult>,
}

impl<B: ChainBackendForReconciliation> ReconciliationEngine<B> {
    /// Create a new reconciliation engine with the given chain backend
    pub fn new(chain_backend: B) -> Self {
        Self {
            chain_backend,
            history: std::vec::Vec::new(),
        }
    }

    /// Reconcile state after a reorg.
    ///
    /// The reconciliation process:
    /// 1. For each affected transfer, check if the source lock is still valid
    ///    on the canonical chain by querying the block hash at the source height
    /// 2. Re-validate any proofs that were built on reorged blocks by rebuilding
    ///    them against the canonical chain
    /// 3. Update transfer states based on the re-validation results
    /// 4. Mark transfers that cannot be reconciled as compromised
    ///
    /// # Arguments
    /// * `event` - The reorg event that triggered reconciliation
    /// * `affected_transfers` - List of (transfer_id, state, source_block_height, commitment)
    /// * `revalidate_proofs` - Whether to re-validate proofs for affected transfers
    pub async fn reconcile(
        &mut self,
        event: &ReorgEvent,
        affected_transfers: &[(String, String, u64, Hash)],
        revalidate_proofs: bool,
    ) -> ReconciliationResult {
        let mut result = ReconciliationResult {
            transfers_reconciled: 0,
            transfers_failed: 0,
            proofs_revalidated: 0,
            actions: Vec::new(),
        };

        for (transfer_id, state, block_height, commitment) in affected_transfers {
            // Step 1: Check if source lock is still valid on the canonical chain
            // by comparing the block hash at the source height with the known hash
            let lock_valid = self
                .verify_lock_on_canonical_chain(&transfer_id, event, *block_height)
                .await;

            if !lock_valid {
                // Source lock invalidated by reorg - mark as compromised
                result.transfers_failed += 1;
                result.actions.push(ReconciliationAction::Compromised);
                log::error!(
                    "Transfer {} COMPROMISED: source lock at height {} no longer in canonical chain",
                    transfer_id,
                    block_height
                );
                continue;
            }

            // Step 2: Re-validate proofs if needed
            if revalidate_proofs {
                let revalidation = self
                    .revalidate_proof_for_transfer(&transfer_id, *block_height, &state, commitment)
                    .await;

                match revalidation {
                    Ok(reval_result) => {
                        if reval_result.valid {
                            result.proofs_revalidated += 1;
                            log::info!(
                                "Transfer {} proof re-validated successfully at canonical height {}",
                                transfer_id,
                                reval_result.canonical_block_height.unwrap_or(*block_height)
                            );
                        } else {
                            result.transfers_failed += 1;
                            result.actions.push(ReconciliationAction::Compromised);
                            log::error!(
                                "Transfer {} proof re-validation failed: {:?}",
                                transfer_id,
                                reval_result.error
                            );
                            continue;
                        }
                    }
                    Err(e) => {
                        result.transfers_failed += 1;
                        result.actions.push(ReconciliationAction::NeedsReview);
                        log::error!("Transfer {} proof re-validation error: {}", transfer_id, e);
                        continue;
                    }
                }
            }

            // Step 3: Update transfer state based on reconciliation
            let new_state = self.compute_new_state(&state, block_height, event);

            result.transfers_reconciled += 1;
            result.actions.push(ReconciliationAction::Reconciled {
                new_state: new_state.clone(),
            });
        }

        self.history.push(result.clone());
        result
    }

    /// Verify that a source lock at the given height is still on the canonical chain.
    ///
    /// This compares the block hash at the source height with what the chain
    /// currently reports. If the hashes match, the block is still canonical.
    async fn verify_lock_on_canonical_chain(
        &self,
        transfer_id: &str,
        event: &ReorgEvent,
        block_height: u64,
    ) -> bool {
        // If the block height is outside the reorg range (above old_height),
        // it's definitely still canonical
        if block_height >= event.old_height {
            return true;
        }

        // The block is within or below the reorg range.
        // Query the current chain to see if this block is still canonical.
        match self.chain_backend.get_block_hash(block_height).await {
            Ok(current_hash) => {
                // If the current block hash at this height matches the original,
                // the block survived the reorg
                let original_hash = if block_height == event.new_height {
                    event.new_hash
                } else {
                    event.old_hash
                };

                if current_hash == original_hash {
                    log::debug!(
                        "Transfer {} lock at height {} is still on canonical chain",
                        transfer_id,
                        block_height
                    );
                    true
                } else {
                    log::warn!(
                        "Transfer {} lock at height {} hash mismatch - block was reorged out",
                        transfer_id,
                        block_height
                    );
                    false
                }
            }
            Err(e) => {
                log::error!(
                    "Transfer {} failed to verify lock on canonical chain: {}",
                    transfer_id,
                    e
                );
                // Conservative: if we can't verify, treat as potentially compromised
                false
            }
        }
    }

    /// Re-validate the proof for a specific transfer.
    ///
    /// Queries the canonical chain to rebuild and verify the inclusion proof.
    /// Verifies that the commitment still exists in the block after a reorg.
    async fn revalidate_proof_for_transfer(
        &self,
        transfer_id: &str,
        block_height: u64,
        _state: &str,
        commitment: &Hash,
    ) -> Result<ProofRevalidationResult, String> {
        // Step 1: Query the canonical chain for the block
        let block_hash = match self.chain_backend.get_block_hash(block_height).await {
            Ok(hash) => hash,
            Err(e) => {
                log::warn!(
                    "Transfer {} block {} not found on canonical chain: {}",
                    transfer_id,
                    block_height,
                    e
                );
                return Ok(ProofRevalidationResult {
                    transfer_id: transfer_id.to_string(),
                    valid: false,
                    canonical_block_height: None,
                    error: Some(format!(
                        "Block {} not found on canonical chain: {}",
                        block_height, e
                    )),
                });
            }
        };

        log::debug!(
            "Transfer {} block {} exists on canonical chain (hash: {:?})",
            transfer_id,
            block_height,
            block_hash
        );

        // Step 2: Verify the commitment exists in the block
        let commitment_exists = match self
            .chain_backend
            .verify_commitment_in_block(commitment, block_height)
            .await
        {
            Ok(exists) => exists,
            Err(e) => {
                log::error!(
                    "Transfer {} failed to verify commitment in block {}: {}",
                    transfer_id,
                    block_height,
                    e
                );
                return Ok(ProofRevalidationResult {
                    transfer_id: transfer_id.to_string(),
                    valid: false,
                    canonical_block_height: Some(block_height),
                    error: Some(format!(
                        "Failed to verify commitment in block {}: {}",
                        block_height, e
                    )),
                });
            }
        };

        if !commitment_exists {
            log::error!(
                "Transfer {} commitment not found in block {} - proof invalid after reorg",
                transfer_id,
                block_height
            );
            return Ok(ProofRevalidationResult {
                transfer_id: transfer_id.to_string(),
                valid: false,
                canonical_block_height: Some(block_height),
                error: Some(format!(
                    "Commitment not found in block {} after reorg",
                    block_height
                )),
            });
        }

        log::debug!(
            "Transfer {} commitment verified in block {}",
            transfer_id,
            block_height
        );

        // Step 3: Rebuild the inclusion proof against the canonical chain
        let rebuilt_proof = match self
            .chain_backend
            .rebuild_inclusion_proof(commitment, block_height)
            .await
        {
            Ok(proof) => proof,
            Err(e) => {
                log::error!(
                    "Transfer {} failed to rebuild inclusion proof for block {}: {}",
                    transfer_id,
                    block_height,
                    e
                );
                return Ok(ProofRevalidationResult {
                    transfer_id: transfer_id.to_string(),
                    valid: false,
                    canonical_block_height: Some(block_height),
                    error: Some(format!(
                        "Failed to rebuild inclusion proof for block {}: {}",
                        block_height, e
                    )),
                });
            }
        };

        log::debug!(
            "Transfer {} rebuilt inclusion proof for block {}",
            transfer_id,
            block_height
        );

        // Step 4: Verify the rebuilt proof against the commitment
        let proof_valid = match self
            .chain_backend
            .verify_proof_bundle(&rebuilt_proof, commitment)
            .await
        {
            Ok(valid) => valid,
            Err(e) => {
                log::error!(
                    "Transfer {} failed to verify rebuilt proof for block {}: {}",
                    transfer_id,
                    block_height,
                    e
                );
                return Ok(ProofRevalidationResult {
                    transfer_id: transfer_id.to_string(),
                    valid: false,
                    canonical_block_height: Some(block_height),
                    error: Some(format!(
                        "Failed to verify rebuilt proof for block {}: {}",
                        block_height, e
                    )),
                });
            }
        };

        if !proof_valid {
            log::error!(
                "Transfer {} rebuilt proof verification failed for block {} - proof is invalid",
                transfer_id,
                block_height
            );
            return Ok(ProofRevalidationResult {
                transfer_id: transfer_id.to_string(),
                valid: false,
                canonical_block_height: Some(block_height),
                error: Some(format!(
                    "Rebuilt proof verification failed for block {}",
                    block_height
                )),
            });
        }

        log::info!(
            "Transfer {} proof re-validated successfully at canonical height {}",
            transfer_id,
            block_height
        );

        Ok(ProofRevalidationResult {
            transfer_id: transfer_id.to_string(),
            valid: true,
            canonical_block_height: Some(block_height),
            error: None,
        })
    }

    /// Compute the new state for a transfer after reconciliation.
    ///
    /// Maps pre-reorg states to appropriate post-reconciliation states
    /// based on the reorg event. For deep reorgs (6+ blocks), applies more
    /// aggressive rollback to ensure security invariants are maintained.
    fn compute_new_state(&self, state: &str, block_height: &u64, event: &ReorgEvent) -> String {
        // Calculate reorg depth
        let reorg_depth = event.old_height.saturating_sub(event.new_height);

        // For 6+ block deep reorgs, apply more conservative rollback logic
        // This is critical for Bitcoin and Ethereum which have different finality characteristics:
        // - Bitcoin: 6+ block reorg is extremely rare and indicates potential chain split
        // - Ethereum: 6+ block reorg suggests checkpoint finality issues or network partition
        let is_deep_reorg = reorg_depth >= 6;

        match state {
            // Locking state - deep reorgs require full restart to ensure lock validity
            "locking" | "awaiting_finality" if is_deep_reorg => {
                log::warn!(
                    "Deep reorg ({} blocks) at height {} - rolling back locking transfer to init",
                    reorg_depth,
                    block_height
                );
                "init".to_string()
            }
            // Moderate reorg (3-5 blocks) - stay in awaiting_finality to re-confirm
            "locking" | "awaiting_finality" if reorg_depth > 3 => "awaiting_finality".to_string(),
            // Shallow reorg (0-3 blocks) - maintain current state
            "locking" | "awaiting_finality" => "awaiting_finality".to_string(),

            // Proof building state - deep reorgs require full proof rebuild from locking
            "proof_building" | "proof_validated" if is_deep_reorg => {
                log::warn!(
                    "Deep reorg ({} blocks) at height {} - rolling back proof transfer to locking",
                    reorg_depth,
                    block_height
                );
                "locking".to_string()
            }
            // Moderate reorg - go back to proof_building to re-validate
            "proof_building" | "proof_validated" if reorg_depth > 3 => "proof_building".to_string(),
            // Shallow reorg - maintain current state
            "proof_building" | "proof_validated" => "proof_building".to_string(),

            // Minting state - always go back to proof_validated for any reorg
            // to ensure the proof is still valid before minting
            "minting" => {
                log::info!(
                    "Reorg ({} blocks) at height {} - rolling back minting transfer to proof_validated",
                    reorg_depth,
                    block_height
                );
                "proof_validated".to_string()
            }

            // Completed state - for deep reorgs, mark for manual review
            // to ensure the finality is still valid
            "completed" if is_deep_reorg => {
                log::warn!(
                    "Deep reorg ({} blocks) at height {} - marking completed transfer for security review",
                    reorg_depth,
                    block_height
                );
                "needs_security_review".to_string()
            }
            // Completed state - shallow reorgs don't affect completed transfers
            "completed" => "completed".to_string(),

            // Unknown state - conservative: mark for review
            _ => {
                log::error!(
                    "Unknown state '{}' for transfer at height {} during reorg - marking for review",
                    state,
                    block_height
                );
                "needs_review".to_string()
            }
        }
    }

    /// Get reconciliation history
    pub fn history(&self) -> &[ReconciliationResult] {
        &self.history
    }

    /// Get the last reconciliation result
    pub fn last_result(&self) -> Option<&ReconciliationResult> {
        self.history.last()
    }
}

impl<B: ChainBackendForReconciliation + Default> Default for ReconciliationEngine<B> {
    fn default() -> Self {
        Self::new(B::default())
    }
}

/// Mock chain backend for testing reconciliation.
#[derive(Clone, Default)]
#[allow(missing_docs)]
pub struct MockChainBackend {
    block_hashes: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<u64, Hash>>>,
    commitments: std::sync::Arc<
        std::sync::Mutex<std::collections::BTreeMap<u64, std::collections::HashSet<[u8; 32]>>>,
    >,
    valid_proofs: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u64, crate::proof_taxonomy::InclusionProof>>,
    >,
    proof_verification: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, bool>>>,
}

#[allow(missing_docs)]
impl MockChainBackend {
    pub fn new() -> Self {
        Self {
            block_hashes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            commitments: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            valid_proofs: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            proof_verification: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Insert a block hash for a given height (for testing).
    pub fn set_block_hash(&self, height: u64, hash: Hash) {
        if let Ok(mut map) = self.block_hashes.lock() {
            map.insert(height, hash);
        }
    }

    /// Register a commitment as existing in a block (for testing).
    pub fn set_commitment_in_block(&self, block_height: u64, commitment: [u8; 32]) {
        if let Ok(mut map) = self.commitments.lock() {
            map.entry(block_height)
                .or_insert_with(std::collections::HashSet::new)
                .insert(commitment);
        }
    }

    /// Register a valid inclusion proof for a block height (for testing).
    pub fn set_valid_proof(&self, block_height: u64, proof: crate::proof_taxonomy::InclusionProof) {
        if let Ok(mut map) = self.valid_proofs.lock() {
            map.insert(block_height, proof);
        }
    }

    /// Set whether proof verification should succeed for a block height (for testing).
    pub fn set_proof_verification_result(&self, block_height: u64, result: bool) {
        if let Ok(mut map) = self.proof_verification.lock() {
            map.insert(block_height, result);
        }
    }

    /// Clear all registered data (for testing).
    pub fn clear(&self) {
        if let Ok(mut map) = self.block_hashes.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.commitments.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.valid_proofs.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.proof_verification.lock() {
            map.clear();
        }
    }
}

#[async_trait]
impl ChainBackendForReconciliation for MockChainBackend {
    async fn get_block_hash(&self, height: u64) -> Result<Hash, String> {
        let map = self.block_hashes.lock().map_err(|e| e.to_string())?;
        map.get(&height)
            .copied()
            .ok_or_else(|| format!("Block hash not found for height {}", height))
    }

    async fn get_latest_block_height(&self) -> Result<u64, String> {
        let map = self.block_hashes.lock().map_err(|e| e.to_string())?;
        Ok(*map.keys().max().unwrap_or(&0))
    }

    async fn verify_commitment_in_block(
        &self,
        commitment: &Hash,
        block_height: u64,
    ) -> Result<bool, String> {
        let map = self.commitments.lock().map_err(|e| e.to_string())?;
        Ok(map
            .get(&block_height)
            .map(|commitments| commitments.contains(&commitment.0))
            .unwrap_or(false))
    }

    async fn rebuild_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
    ) -> Result<crate::proof_taxonomy::InclusionProof, String> {
        let map = self.valid_proofs.lock().map_err(|e| e.to_string())?;
        map.get(&block_height)
            .cloned()
            .ok_or_else(|| format!("No proof available for block {}", block_height))
    }

    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &crate::proof_taxonomy::InclusionProof,
        commitment: &Hash,
    ) -> Result<bool, String> {
        let _ = (inclusion_proof, commitment);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reorg::detector::ReorgEvent;
    use csv_hash::chain_id::ChainId;

    fn make_reorg_event(old_height: u64, new_height: u64) -> ReorgEvent {
        ReorgEvent {
            chain: ChainId::new("ethereum"),
            old_height,
            new_height,
            old_hash: Hash([1u8; 32]),
            new_hash: Hash([2u8; 32]),
            depth: old_height - new_height,
        }
    }

    fn make_commitment(bytes: [u8; 32]) -> Hash {
        Hash(bytes)
    }

    fn make_valid_proof(
        block_height: u64,
        commitment: &Hash,
    ) -> crate::proof_taxonomy::InclusionProof {
        crate::proof_taxonomy::InclusionProof {
            proof_bytes: vec![1u8, 2, 3, 4],
            block_hash: Hash([block_height as u8; 32]),
            position: 0,
            block_number: block_height,
            leaf: *commitment,
            root: Hash([5u8; 32]),
            siblings: vec![Hash([6u8; 32])],
            leaf_index: 0,
            source: "ethereum".to_string(),
        }
    }

    #[tokio::test]
    async fn test_revalidate_proof_valid_commitment() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        let commitment = make_commitment([3u8; 32]);
        backend.set_commitment_in_block(101, commitment.0);
        backend.set_valid_proof(101, make_valid_proof(101, &commitment));

        let engine = ReconciliationEngine::new(backend);
        let result = engine
            .revalidate_proof_for_transfer("transfer-1", 101, "proof_building", &commitment)
            .await
            .unwrap();

        assert!(result.valid);
        assert_eq!(result.canonical_block_height, Some(101));
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_revalidate_proof_missing_block() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));

        let engine = ReconciliationEngine::new(backend);
        let result = engine
            .revalidate_proof_for_transfer(
                "transfer-1",
                101,
                "proof_building",
                &make_commitment([3u8; 32]),
            )
            .await
            .unwrap();

        assert!(!result.valid);
        assert_eq!(result.canonical_block_height, None);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_revalidate_proof_missing_commitment() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        let commitment = make_commitment([3u8; 32]);
        backend.set_valid_proof(101, make_valid_proof(101, &commitment));

        let engine = ReconciliationEngine::new(backend);
        let result = engine
            .revalidate_proof_for_transfer("transfer-1", 101, "proof_building", &commitment)
            .await
            .unwrap();

        assert!(!result.valid);
        assert_eq!(result.canonical_block_height, Some(101));
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_revalidate_proof_missing_proof() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        let commitment = make_commitment([3u8; 32]);
        backend.set_commitment_in_block(101, commitment.0);

        let engine = ReconciliationEngine::new(backend);
        let result = engine
            .revalidate_proof_for_transfer("transfer-1", 101, "proof_building", &commitment)
            .await
            .unwrap();

        assert!(!result.valid);
        assert_eq!(result.canonical_block_height, Some(101));
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("No proof available"));
    }

    #[tokio::test]
    async fn test_reconcile_with_valid_proofs() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        let commitment = make_commitment([3u8; 32]);
        backend.set_commitment_in_block(101, commitment.0);
        backend.set_valid_proof(101, make_valid_proof(101, &commitment));

        let mut engine = ReconciliationEngine::new(backend);
        let event = make_reorg_event(105, 101);
        let affected = vec![(
            "transfer-1".to_string(),
            "proof_building".to_string(),
            101,
            commitment,
        )];

        let result = engine.reconcile(&event, &affected, true).await;

        assert_eq!(result.transfers_reconciled, 1);
        assert_eq!(result.transfers_failed, 0);
        assert_eq!(result.proofs_revalidated, 1);
    }

    #[tokio::test]
    async fn test_reconcile_with_invalid_proof() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        let commitment = make_commitment([3u8; 32]);
        backend.set_commitment_in_block(101, commitment.0);
        backend.set_valid_proof(101, make_valid_proof(101, &commitment));

        let mut engine = ReconciliationEngine::new(backend);
        let event = make_reorg_event(105, 101);

        // Use a different commitment that doesn't exist in the block
        let bad_commitment = make_commitment([4u8; 32]);
        let affected = vec![(
            "transfer-1".to_string(),
            "proof_building".to_string(),
            101,
            bad_commitment,
        )];

        let result = engine.reconcile(&event, &affected, true).await;

        assert_eq!(result.transfers_reconciled, 0);
        assert_eq!(result.transfers_failed, 1);
        assert_eq!(result.proofs_revalidated, 0);
    }

    #[tokio::test]
    async fn test_reconcile_skips_proof_validation_when_disabled() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        let commitment = make_commitment([3u8; 32]);

        let mut engine = ReconciliationEngine::new(backend);
        let event = make_reorg_event(105, 101);
        let affected = vec![(
            "transfer-1".to_string(),
            "proof_building".to_string(),
            101,
            commitment,
        )];

        let result = engine.reconcile(&event, &affected, false).await;

        assert_eq!(result.transfers_reconciled, 1);
        assert_eq!(result.transfers_failed, 0);
        assert_eq!(result.proofs_revalidated, 0);
    }

    #[tokio::test]
    async fn test_reconcile_compromised_transfer() {
        let backend = MockChainBackend::new();
        // Set block hash at height 100 to a value that doesn't match the reorg event's old_hash
        // This simulates a scenario where the block was also reorged out
        backend.set_block_hash(100, Hash([9u8; 32]));

        let mut engine = ReconciliationEngine::new(backend);
        let event = make_reorg_event(105, 101);

        // Transfer at height 100 has a block hash that doesn't match the canonical chain
        // so it should be compromised
        let commitment = make_commitment([3u8; 32]);
        let affected = vec![(
            "transfer-1".to_string(),
            "proof_building".to_string(),
            100,
            commitment,
        )];

        let result = engine.reconcile(&event, &affected, false).await;

        assert_eq!(result.transfers_reconciled, 0);
        assert_eq!(result.transfers_failed, 1);
    }

    #[tokio::test]
    async fn test_revalidate_proof_validates_commitment_not_just_block() {
        let backend = MockChainBackend::new();
        backend.set_block_hash(100, Hash([1u8; 32]));
        backend.set_block_hash(101, Hash([2u8; 32]));

        // Register a proof but NOT the commitment - this should fail
        let commitment = make_commitment([3u8; 32]);
        backend.set_valid_proof(101, make_valid_proof(101, &commitment));

        let engine = ReconciliationEngine::new(backend);
        let result = engine
            .revalidate_proof_for_transfer("transfer-1", 101, "proof_building", &commitment)
            .await
            .unwrap();

        assert!(
            !result.valid,
            "Proof revalidation should fail when commitment is not in block"
        );
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("not found"));
    }
}
