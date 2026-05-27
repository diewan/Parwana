//! MPC (Multi-Protocol Commitment) Batching for Bitcoin
//!
//! This module implements commitment batching using MPC trees, allowing
//! multiple CSV commitments to share a single on-chain Bitcoin transaction.
//!
//! ## Architecture
//!
//! 1. **Pending Commitments Queue**: Commitments are queued instead of immediately published
//! 2. **MPC Tree Building**: When batch threshold is reached, build CommitMux from leaves
//! 3. **Single Tapret Publication**: Publish one tapret with the MPC root hash
//! 4. **Proof Distribution**: Each queued commitment receives its MuxProof
//!
//! ## Cost Savings
//!
//! Without MPC batching: N commitments = N transactions = N * fee
//! With MPC batching: N commitments = 1 transaction = 1 * fee
//!
//! For 10 commitments at 1000 sat/vB: 10,000 sats → 1,000 sats (90% savings)
//!
//! ## Security Properties
//!
//! - Each leaf is `(protocol_id || commitment_hash)`
//! - Root is published on-chain via Tapret
//! - Each protocol gets a Merkle proof of inclusion
//! - Double-spend prevention still enforced per commitment

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use csv_hash::Hash;
use csv_hash::commit_mux::{CommitMux, MuxLeaf, MuxProof};

use crate::error::{BitcoinError, BitcoinResult};
use crate::types::BitcoinSealPoint;

/// Protocol ID for CSV Bitcoin commitments (32 bytes)
pub const CSV_BTC_PROTOCOL_ID: [u8; 32] = [
    0x43, 0x53, 0x56, 0x2d, 0x42, 0x54, 0x43, 0x00, // "CSV-BTC"
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // version 1
];

/// A pending commitment waiting to be batched
#[derive(Clone, Debug)]
pub struct PendingCommitment {
    /// The commitment hash to publish
    pub commitment: Hash,
    /// The seal that authorizes this commitment
    pub seal: BitcoinSealPoint,
    /// Unique identifier for this commitment request
    pub request_id: String,
    /// Timestamp when this was queued
    pub queued_at: u64,
}

/// Result of a batched publication
#[derive(Clone, Debug)]
pub struct BatchedPublication {
    /// The transaction ID that published the MPC root
    pub txid: [u8; 32],
    /// Block height where published
    pub block_height: u64,
    /// MPC root hash that was published
    pub mpc_root: Hash,
    /// Proofs for each commitment in the batch
    pub proofs: Vec<(String, MuxProof)>, // (request_id, proof)
}

/// MPC Batcher for Bitcoin commitments
///
/// This struct manages the queuing and batching of commitments
/// to optimize on-chain costs through MPC tree aggregation.
pub struct MpcBatcher {
    /// Pending commitments queue (bounded to prevent memory exhaustion)
    pending: Arc<Mutex<VecDeque<PendingCommitment>>>,
    /// Maximum commitments per batch
    batch_size: usize,
    /// Minimum commitments before auto-batch (0 = no auto-batch)
    min_batch_size: usize,
    /// Maximum seconds to wait before forcing a batch (0 = no timeout)
    max_wait_seconds: u64,
    /// Maximum queue depth for backpressure
    max_queue_depth: usize,
}

impl MpcBatcher {
    /// Create a new MPC batcher
    ///
    /// # Arguments
    /// * `batch_size` - Maximum commitments per batch (default: 10)
    /// * `min_batch_size` - Minimum before auto-batch (default: 2)
    /// * `max_wait_seconds` - Timeout for forcing batch (default: 300 = 5 min)
    /// * `max_queue_depth` - Maximum queue depth for backpressure (default: 1000)
    pub fn new(
        batch_size: usize,
        min_batch_size: usize,
        max_wait_seconds: u64,
        max_queue_depth: usize,
    ) -> Self {
        Self {
            pending: Arc::new(Mutex::new(VecDeque::with_capacity(max_queue_depth))),
            batch_size: batch_size.max(2), // At least 2 for batching to make sense
            min_batch_size: min_batch_size.max(1),
            max_wait_seconds,
            max_queue_depth: max_queue_depth.max(1),
        }
    }

    /// Create with default settings (batch up to 10, min 2, 5 min timeout, queue depth 1000)
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(10, 2, 300, 1000)
    }

    /// Create optimized for high-volume (batch up to 50, min 5, 10 min timeout, queue depth 5000)
    pub fn high_volume() -> Self {
        Self::new(50, 5, 600, 5000)
    }

    /// Create for testing (immediate batch of 1, no timeout, queue depth 10)
    pub fn immediate() -> Self {
        Self::new(1, 1, 0, 10)
    }

    /// Queue a commitment for batching
    ///
    /// Returns true if the batch is ready to publish (reached batch_size)
    /// Returns error if queue is full (backpressure)
    pub fn queue(
        &self,
        commitment: Hash,
        seal: BitcoinSealPoint,
        request_id: String,
    ) -> Result<bool, String> {
        let pending_commitment = PendingCommitment {
            commitment,
            seal,
            request_id,
            queued_at: current_timestamp(),
        };

        let mut queue = self.pending.lock().unwrap_or_else(|e| e.into_inner());

        // Enforce backpressure: reject if queue is full
        if queue.len() >= self.max_queue_depth {
            return Err("MPC batcher queue is full - backpressure".to_string());
        }

        queue.push_back(pending_commitment);

        // Check if we have enough for a batch
        Ok(queue.len() >= self.batch_size)
    }

    /// Get count of pending commitments
    pub fn pending_count(&self) -> usize {
        let queue = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        queue.len()
    }

    /// Check if we have enough for a batch
    pub fn has_batch_ready(&self) -> bool {
        let queue = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        queue.len() >= self.min_batch_size
    }

    /// Build MPC tree from current pending commitments
    ///
    /// This consumes the pending queue and returns:
    /// - The MPC tree
    /// - The list of commitments that were included
    ///
    /// Returns None if there are no pending commitments.
    pub fn build_mpc_tree(&self) -> Option<(CommitMux, Vec<PendingCommitment>)> {
        let mut queue = self.pending.lock().unwrap_or_else(|e| e.into_inner());

        let queue_len = queue.len();
        if queue_len == 0 {
            return None;
        }

        // Take up to batch_size commitments
        let batch_size = self.batch_size;
        let to_batch: Vec<PendingCommitment> = queue.drain(..batch_size.min(queue_len)).collect();

        // Build MPC leaves
        let leaves: Vec<MuxLeaf> = to_batch
            .iter()
            .map(|p| MuxLeaf::new(CSV_BTC_PROTOCOL_ID, p.commitment))
            .collect();

        let tree = CommitMux::new(leaves);

        Some((tree, to_batch))
    }

    /// Generate proofs for all commitments in a batch
    ///
    /// # Arguments
    /// * `tree` - The MPC tree containing the commitments
    /// * `commitments` - The pending commitments in the same order as tree leaves
    ///
    /// # Returns
    /// Vector of (request_id, MuxProof) pairs
    pub fn generate_proofs(
        &self,
        tree: &CommitMux,
        commitments: &[PendingCommitment],
    ) -> BitcoinResult<Vec<(String, MuxProof)>> {
        let root = tree.root();
        let mut proofs = Vec::new();

        for (index, commitment) in commitments.iter().enumerate() {
            // Build the Merkle branch for this leaf
            let branch = tree.merkle_branch(index).ok_or_else(|| {
                BitcoinError::MpcError(format!(
                    "Failed to generate Merkle branch for index {}",
                    index
                ))
            })?;

            let proof = MuxProof {
                protocol_id: CSV_BTC_PROTOCOL_ID,
                commitment: commitment.commitment,
                branch,
                leaf_index: index,
            };

            // Verify the proof before returning
            if !proof.verify(&root) {
                return Err(BitcoinError::MpcError(format!(
                    "Generated invalid proof for commitment {}",
                    commitment.request_id
                )));
            }

            proofs.push((commitment.request_id.clone(), proof));
        }

        Ok(proofs)
    }

    /// Clear all pending commitments
    pub fn clear(&self) {
        let mut queue = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        queue.clear();
    }

    /// Get pending commitments without consuming them
    pub fn peek_pending(&self) -> Vec<PendingCommitment> {
        let queue = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        queue.iter().cloned().collect()
    }
}

/// Extension trait for CommitMux to generate Merkle branches
pub trait MpcTreeExt {
    /// Generate the Merkle branch for a leaf at the given index
    fn merkle_branch(
        &self,
        leaf_index: usize,
    ) -> Option<Vec<csv_hash::commit_mux::MerkleBranchNode>>;
}

impl MpcTreeExt for CommitMux {
    fn merkle_branch(
        &self,
        leaf_index: usize,
    ) -> Option<Vec<csv_hash::commit_mux::MerkleBranchNode>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        // Collect all leaf hashes
        let mut current_level: Vec<csv_hash::Hash> = self.leaves.iter().map(|l| l.hash()).collect();

        let mut branch = Vec::new();
        let mut current_index = leaf_index;

        // Build the tree level by level
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let left = chunk[0];

                if chunk.len() == 1 {
                    // Odd node - promote to next level
                    next_level.push(left);
                } else {
                    let sanad = chunk[1];

                    // Check if this pair contains our target
                    let pair_start_index = next_level.len() * 2;
                    if current_index == pair_start_index {
                        // Target is left, sibling is sanad
                        branch.push(csv_hash::commit_mux::MerkleBranchNode {
                            hash: sanad,
                            is_left: false,
                        });
                    } else if current_index == pair_start_index + 1 {
                        // Target is sanad, sibling is left
                        branch.push(csv_hash::commit_mux::MerkleBranchNode {
                            hash: left,
                            is_left: true,
                        });
                    }

                    // Hash the pair for next level
                    use csv_hash::tagged_hash::csv_tagged_hash;
                    let mut data = [0u8; 64];
                    data[..32].copy_from_slice(left.as_bytes());
                    data[32..].copy_from_slice(sanad.as_bytes());
                    let parent_hash = csv_tagged_hash("mpc-internal", &data);
                    next_level.push(csv_hash::Hash::new(parent_hash));
                }
            }

            // Update index for next level
            current_index /= 2;
            current_level = next_level;
        }

        Some(branch)
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpc_batcher_queue() {
        let batcher = MpcBatcher::new(2, 1, 0, 1000);

        let commitment = Hash::new([1u8; 32]);
        let seal = BitcoinSealPoint::new([0u8; 32], 0, None);

        assert!(
            !batcher
                .queue(commitment, seal.clone(), "test-1".to_string())
                .unwrap()
        );
        assert_eq!(batcher.pending_count(), 1);

        // Second commitment should trigger batch ready
        assert!(
            batcher
                .queue(commitment, seal, "test-2".to_string())
                .unwrap()
        );
        assert_eq!(batcher.pending_count(), 2);
    }

    #[test]
    fn test_mpc_tree_building() {
        let batcher = MpcBatcher::new(10, 1, 0, 1000);

        // Queue 3 commitments
        for i in 0..3 {
            let commitment = Hash::new([i as u8; 32]);
            let seal = BitcoinSealPoint::new([0u8; 32], i, None);
            batcher
                .queue(commitment, seal, format!("test-{}", i))
                .unwrap();
        }

        // Build tree
        let (tree, commitments) = batcher.build_mpc_tree().unwrap();

        assert_eq!(tree.leaves.len(), 3);
        assert_eq!(commitments.len(), 3);

        // Generate proofs
        let proofs = batcher.generate_proofs(&tree, &commitments).unwrap();
        assert_eq!(proofs.len(), 3);

        // Verify each proof
        let root = tree.root();
        for (_, proof) in proofs {
            assert!(proof.verify(&root));
        }
    }
}
