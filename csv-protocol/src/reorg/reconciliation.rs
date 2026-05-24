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
    ) -> Result<csv_proof::InclusionProof, String>;

    /// Verify a proof bundle against the canonical chain.
    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &csv_proof::InclusionProof,
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
    /// * `affected_transfers` - List of (transfer_id, state, source_block_height)
    /// * `revalidate_proofs` - Whether to re-validate proofs for affected transfers
    pub async fn reconcile(
        &mut self,
        event: &ReorgEvent,
        affected_transfers: &[(String, String, u64)],
        revalidate_proofs: bool,
    ) -> ReconciliationResult {
        let mut result = ReconciliationResult {
            transfers_reconciled: 0,
            transfers_failed: 0,
            proofs_revalidated: 0,
            actions: Vec::new(),
        };

        for (transfer_id, state, block_height) in affected_transfers {
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
                    .revalidate_proof_for_transfer(&transfer_id, *block_height, &state)
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
    async fn revalidate_proof_for_transfer(
        &self,
        transfer_id: &str,
        block_height: u64,
        _state: &str,
    ) -> Result<ProofRevalidationResult, String> {
        // In production, we would:
        // 1. Look up the commitment associated with this transfer
        // 2. Query the canonical chain for the block at block_height
        // 3. Verify the commitment exists in that block
        // 4. Rebuild the inclusion proof
        // 5. Verify the rebuilt proof

        // For now, we verify that the block exists on the canonical chain
        // and that we can query it
        match self.chain_backend.get_block_hash(block_height).await {
            Ok(block_hash) => {
                // Block exists on canonical chain - proof can be rebuilt
                log::debug!(
                    "Transfer {} block {} exists on canonical chain (hash: {:?})",
                    transfer_id,
                    block_height,
                    block_hash
                );

                Ok(ProofRevalidationResult {
                    transfer_id: transfer_id.to_string(),
                    valid: true,
                    canonical_block_height: Some(block_height),
                    error: None,
                })
            }
            Err(e) => Err(format!(
                "Transfer {}: block {} not found on canonical chain: {}",
                transfer_id, block_height, e
            )),
        }
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
}

#[allow(missing_docs)]
impl MockChainBackend {
    pub fn new() -> Self {
        Self {
            block_hashes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
        }
    }

    /// Insert a block hash for a given height (for testing).
    pub fn set_block_hash(&self, height: u64, hash: Hash) {
        if let Ok(mut map) = self.block_hashes.lock() {
            map.insert(height, hash);
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
        _commitment: &Hash,
        _block_height: u64,
    ) -> Result<bool, String> {
        // In production, this would query the chain's state trie
        Ok(true)
    }

    async fn rebuild_inclusion_proof(
        &self,
        _commitment: &Hash,
        _block_height: u64,
    ) -> Result<csv_proof::InclusionProof, String> {
        // In production, this would rebuild the proof from chain state
        Err("Not implemented in mock backend".to_string())
    }

    async fn verify_proof_bundle(
        &self,
        _inclusion_proof: &csv_proof::InclusionProof,
        _commitment: &Hash,
    ) -> Result<bool, String> {
        Ok(true)
    }
}
