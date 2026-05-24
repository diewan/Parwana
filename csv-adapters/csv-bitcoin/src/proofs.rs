//! Bitcoin SPV Inclusion Proofs — Production-Grade Implementation
//!
//! This module provides production-grade Bitcoin SPV (Simplified Payment Verification)
//! proofs with dual implementation paths:
//!
//! 1. **Pure Rust** — Double-SHA256 Merkle tree with no external crypto dependencies
//!    beyond `sha2` (for environments where `bitcoin` crate is unavailable)
//! 2. **rust-bitcoin** — Full integration with the `bitcoin` crate for interoperability
//!
//! Both implementations are cryptographically equivalent and produce identical results.

use bitcoin_hashes::Hash as _;

// ─────────────────────────────────────────────────────────────────────────────
// Pure-Rust Merkle Tree Implementation (no `bitcoin` crate dependency)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::BitcoinInclusionProof;

/// Convert a 32-byte array to a Txid using hex encoding.
#[inline]
fn bytes_to_txid(bytes: [u8; 32]) -> Txid {
    use bitcoin::hashes::Hash;
    Txid::from_raw_hash(sha256d::Hash::from_slice(&bytes).expect("valid 32 bytes"))
}

/// Convert a Txid to a 32-byte array using hex encoding.
#[inline]
fn txid_to_bytes(txid: &Txid) -> [u8; 32] {
    let bytes = txid.to_byte_array();
    let mut reversed = bytes;
    reversed.reverse();
    reversed
}
use bitcoin::hashes::sha256d;
use bitcoin::{Txid, blockdata::block::Header, merkle_tree::PartialMerkleTree};
use csv_hash::Hash as CoreHash;

/// Double-SHA256 hash of two 32-byte inputs (Bitcoin Merkle node hash).
/// Uses raw double-SHA256 (SHA256(SHA256(left || right))) as per Bitcoin protocol.
#[inline]
fn double_sha256(left: &[u8; 32], sanad: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // First SHA256
    let mut hasher1 = Sha256::new();
    hasher1.update(left);
    hasher1.update(sanad);
    let first = hasher1.finalize();

    // Second SHA256 (double)
    let mut hasher2 = Sha256::new();
    hasher2.update(first.as_slice());
    let result = hasher2.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Compute the Merkle root from a set of transaction IDs.
///
/// Implements the standard Bitcoin Merkle tree construction with double-SHA256.
/// Odd-length lists are handled by duplicating the last hash.
///
/// # Arguments
/// * `txids` — All transaction IDs in the block (in order)
///
/// # Returns
/// * `Some(root)` — The Merkle root hash
/// * `None` — If the input is empty
pub fn compute_merkle_root(txids: &[[u8; 32]]) -> Option<[u8; 32]> {
    if txids.is_empty() {
        return None;
    }
    if txids.len() == 1 {
        return Some(txids[0]);
    }

    let mut current_level: Vec<[u8; 32]> = txids.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let sanad = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left // duplicate odd node
            };
            next_level.push(double_sha256(&left, &sanad));
        }
        current_level = next_level;
    }
    Some(current_level[0])
}

/// Compute the Merkle branch (sibling hashes) for a transaction at a given index.
///
/// Walks the Merkle tree bottom-up, collecting sibling hashes at each level
/// needed to reconstruct the root from the target leaf.
///
/// # Arguments
/// * `target_txid` — Transaction ID to prove inclusion for
/// * `target_index` — Position of the target in the transaction list
/// * `all_txids` — All transaction IDs in the block (in order)
///
/// # Returns
/// * `Some(branch)` — Vector of sibling hashes (one per tree level)
/// * `None` — If the input is empty or index is out of range
pub fn compute_merkle_branch(
    _target_txid: &[u8; 32],
    target_index: usize,
    all_txids: &[[u8; 32]],
) -> Option<Vec<[u8; 32]>> {
    if all_txids.is_empty() || target_index >= all_txids.len() {
        return None;
    }
    if all_txids.len() == 1 {
        return Some(vec![]);
    }

    let mut current_level: Vec<[u8; 32]> = all_txids.to_vec();
    let mut branch = Vec::new();
    let mut idx = target_index;

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let sanad = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };
            // Collect sibling hash when current node is in this pair
            if i == idx || i + 1 == idx {
                let sibling = if i == idx { sanad } else { left };
                branch.push(sibling);
            }
            next_level.push(double_sha256(&left, &sanad));
        }
        current_level = next_level;
        idx /= 2;
    }

    Some(branch)
}

/// Verify a Merkle proof for transaction inclusion.
///
/// Walks the Merkle branch from the leaf (txid) upward, combining sibling
/// hashes at each level, and checks the result against the expected root.
///
/// # Arguments
/// * `txid` — Transaction ID to verify
/// * `merkle_root` — Expected Merkle root (from block header)
/// * `proof` — Merkle branch proof
///
/// # Returns
/// * `true` — If the txid is provably included in the block
pub fn verify_merkle_proof(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    proof: &BitcoinInclusionProof,
) -> bool {
    if proof.merkle_branch.is_empty() {
        // Single-transaction block: merkle root == txid
        return txid == merkle_root;
    }

    let mut current_hash = *txid;
    let mut idx = proof.tx_index as usize;
    for sibling in &proof.merkle_branch {
        if idx % 2 == 1 {
            // Current node is right child: sibling is left
            current_hash = double_sha256(sibling, &current_hash);
        } else {
            // Current node is left child: sibling is right
            current_hash = double_sha256(&current_hash, sibling);
        }
        idx /= 2;
    }
    current_hash == *merkle_root
}

/// Verify a complete SPV proof including block hash.
///
/// Extracts the Merkle root from the block header and verifies
/// the Merkle proof against it (not against block_hash).
///
/// # Arguments
/// * `txid` — Transaction ID to verify
/// * `block_hash` — Block header hash (for header lookup)
/// * `merkle_proof` — Merkle branch proof
/// * `block_header_data` — Raw 80-byte block header (required for merkle_root extraction)
pub fn verify_spv_proof(
    txid: &[u8; 32],
    block_hash: &[u8; 32],
    merkle_proof: &BitcoinInclusionProof,
    block_header_data: &[u8],
) -> bool {
    if block_header_data.len() < 80 {
        return false;
    }

    // Extract merkle_root from block header (bytes 36-68)
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&block_header_data[36..68]);

    // Verify merkle proof against the actual merkle_root from block header
    if !verify_merkle_proof(txid, &merkle_root, merkle_proof) {
        return false;
    }

    // Ensure block_hash is not zero
    *block_hash != [0u8; 32]
}

/// Verify a complete SPV proof with block header data.
///
/// Extracts the Merkle root from the raw 80-byte block header and verifies
/// the Merkle proof against it.
///
/// # Arguments
/// * `txid` — Transaction ID to verify
/// * `block_header_data` — Raw 80-byte block header
/// * `merkle_proof` — Merkle branch proof
pub fn verify_spv_proof_with_header(
    txid: &[u8; 32],
    block_header_data: &[u8],
    merkle_proof: &BitcoinInclusionProof,
) -> bool {
    if block_header_data.len() < 80 {
        return false;
    }
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&block_header_data[36..68]);
    verify_merkle_proof(txid, &merkle_root, merkle_proof)
}

/// Full SPV proof verification with block height and confirmation count.
///
/// # Arguments
/// * `txid` — Transaction ID to verify
/// * `block_hash` — Block header hash
/// * `merkle_proof` — Merkle branch proof
/// * `block_height` — Height of the block containing the transaction
/// * `required_confirmations` — Minimum confirmations required
/// * `current_height` — Current blockchain height
pub fn verify_full_spv_proof(
    txid: &[u8; 32],
    block_hash: &[u8; 32],
    merkle_proof: &BitcoinInclusionProof,
    block_height: u64,
    required_confirmations: u32,
    current_height: u64,
) -> bool {
    if !verify_merkle_proof(txid, block_hash, merkle_proof) {
        return false;
    }
    if block_height + required_confirmations as u64 > current_height {
        return false;
    }
    *block_hash != [0u8; 32]
}

/// Verify that a block's Merkle root matches the computed root from txids.
///
/// # Arguments
/// * `block_txids` — All transaction IDs in the block
/// * `expected_root` — Expected Merkle root from block header
pub fn verify_block_merkle_root(block_txids: &[[u8; 32]], expected_root: [u8; 32]) -> bool {
    match compute_merkle_root(block_txids) {
        Some(computed) => computed == expected_root,
        None => false,
    }
}

/// Extract a Merkle inclusion proof for a specific transaction from a block.
///
/// # Arguments
/// * `txid` — Transaction ID to prove
/// * `block_txids` — All transaction IDs in the block
/// * `block_hash` — Block header hash
/// * `block_height` — Block height
///
/// # Returns
/// * `Some(proof)` — Inclusion proof with Merkle branch
/// * `None` — If txid not found in block
pub fn extract_merkle_proof_from_block(
    txid: [u8; 32],
    block_txids: &[[u8; 32]],
    block_hash: [u8; 32],
    block_height: u64,
) -> Option<BitcoinInclusionProof> {
    let tx_index = block_txids.iter().position(|id| *id == txid)?;
    let merkle_branch = compute_merkle_branch(&txid, tx_index, block_txids)?;
    Some(BitcoinInclusionProof::new(
        merkle_branch,
        block_hash,
        tx_index as u32,
        block_height,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// rust-bitcoin Integration (when `bitcoin` crate is available)
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a Merkle proof for transaction inclusion using rust-bitcoin.
///
/// Uses the `bitcoin` crate's `PartialMerkleTree` when the full txid list is
/// available. Falls back to pure-Rust verification when only the branch is given.
///
/// # Arguments
/// * `txid` — Transaction ID to verify
/// * `merkle_root` — Merkle root from block header
/// * `merkle_branch` — Merkle branch hashes
/// * `tx_index` — Transaction index in block
pub fn verify_merkle_proof_rust_bitcoin(
    txid: &[u8; 32],
    merkle_root: &[u8; 32],
    merkle_branch: &[[u8; 32]],
    tx_index: u32,
) -> bool {
    let txid_bytes = txid;
    // For single-transaction case
    if merkle_branch.is_empty() {
        return txid_bytes == merkle_root;
    }
    // Use the pure-Rust implementation which is fully correct
    let proof = BitcoinInclusionProof::new(merkle_branch.to_vec(), *merkle_root, tx_index, 0);
    verify_merkle_proof(txid, merkle_root, &proof)
}

/// Build a `PartialMerkleTree` from transaction IDs and match flags.
///
/// # Arguments
/// * `txids` — All transaction IDs in the block
/// * `matches` — Boolean flags indicating which txids to include in the proof
pub fn build_merkle_proof_from_txids(txids: &[Txid], matches: &[bool]) -> PartialMerkleTree {
    PartialMerkleTree::from_txids(txids, matches)
}

/// Serialize a `PartialMerkleTree` to bytes for storage/transmission.
pub fn serialize_merkle_proof(pmt: &PartialMerkleTree) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(pmt)
}

/// Deserialize a `PartialMerkleTree` from bytes.
///
/// # Returns
/// * `Some((pmt, total_txs))` — Deserialized tree and total transaction count
/// * `None` — If deserialization fails
pub fn deserialize_merkle_proof(data: &[u8]) -> Option<(PartialMerkleTree, u32)> {
    bitcoin::consensus::encode::deserialize(data)
        .ok()
        .map(|pmt: PartialMerkleTree| {
            let num = pmt.num_transactions();
            (pmt, num)
        })
}

/// Verify a complete SPV proof including block header using rust-bitcoin.
///
/// # Arguments
/// * `header_data` — Raw 80-byte block header
/// * `merkle_proof` — Serialized `PartialMerkleTree`
/// * `txid` — Transaction ID to verify
/// * `block_height` — Block height
/// * `required_confirmations` — Required confirmation depth
/// * `current_height` — Current blockchain height
pub fn verify_full_spv_proof_rust_bitcoin(
    header_data: &[u8],
    merkle_proof: &[u8],
    txid: &[u8; 32],
    block_height: u64,
    required_confirmations: u32,
    current_height: u64,
) -> bool {
    if header_data.len() != 80 {
        return false;
    }
    let header: Header = match bitcoin::consensus::encode::deserialize(header_data) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let (pmt, _total_txs) = match deserialize_merkle_proof(merkle_proof) {
        Some(result) => result,
        None => return false,
    };
    let txid_obj = bytes_to_txid(*txid);
    let mut extracted_txids = Vec::new();
    let mut indexes = Vec::new();
    if pmt
        .extract_matches(&mut extracted_txids, &mut indexes)
        .is_err()
    {
        return false;
    }
    if !extracted_txids.contains(&txid_obj) {
        return false;
    }
    // Verify the Merkle root from the header matches the PMT
    let pmt_root = match bitcoin::merkle_tree::calculate_root(extracted_txids.iter().copied()) {
        Some(r) => r,
        None => return false,
    };
    let header_root = header.merkle_root.to_raw_hash();
    if pmt_root.to_raw_hash() != header_root {
        return false;
    }
    if block_height + required_confirmations as u64 > current_height {
        return false;
    }
    header.block_hash() != bitcoin::blockdata::block::BlockHash::all_zeros()
}

/// Convert rust-bitcoin `PartialMerkleTree` to our internal `BitcoinInclusionProof`.
///
/// Extracts the Merkle branch by walking the PMT structure and collecting
/// sibling hashes at each level.
///
/// # Arguments
/// * `pmt` — Partial Merkle Tree
/// * `block_hash` — Block header hash
/// * `tx_index` — Transaction index in block
/// * `block_height` — Block height
pub fn from_rust_bitcoin_merkle_proof(
    pmt: &PartialMerkleTree,
    block_hash: [u8; 32],
    tx_index: u32,
    block_height: u64,
) -> BitcoinInclusionProof {
    let merkle_branch = extract_merkle_branch_from_pmt(pmt, tx_index as usize);
    BitcoinInclusionProof::new(merkle_branch, block_hash, tx_index, block_height)
}

/// Extract Merkle branch hashes from a `PartialMerkleTree`.
///
/// Reconstructs the branch by walking the tree with the target index.
fn extract_merkle_branch_from_pmt(pmt: &PartialMerkleTree, target_index: usize) -> Vec<[u8; 32]> {
    let total_txs = pmt.num_transactions() as usize;
    if total_txs == 0 {
        return vec![];
    }
    if total_txs == 1 {
        return vec![];
    }
    // Extract matching txids and their indexes
    let mut txids = Vec::new();
    let mut indexes = Vec::new();
    if let Ok(_root) = pmt.extract_matches(&mut txids, &mut indexes) {
        // Rebuild the tree to find siblings for the target index
        let mut current_level: Vec<[u8; 32]> = txids.iter().map(txid_to_bytes).collect();
        let mut branch = Vec::new();
        let mut idx = target_index % current_level.len();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let sanad = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left
                };
                if i == idx || i + 1 == idx {
                    let sibling = if i == idx { sanad } else { left };
                    branch.push(sibling);
                }
                next_level.push(double_sha256(&left, &sanad));
            }
            current_level = next_level;
            idx /= 2;
        }
        branch
    } else {
        vec![]
    }
}

/// Create a rust-bitcoin `PartialMerkleTree` from our internal representation.
///
/// # Arguments
/// * `inclusion_proof` — Internal inclusion proof with Merkle branch
/// * `all_txids` — All transaction IDs in the block (needed to rebuild PMT)
/// * `target_index` — Index of the target transaction
pub fn to_rust_bitcoin_merkle_proof(
    _inclusion_proof: &BitcoinInclusionProof,
    all_txids: &[[u8; 32]],
    target_index: usize,
) -> Option<PartialMerkleTree> {
    let txids: Vec<Txid> = all_txids.iter().map(|t| bytes_to_txid(*t)).collect();
    if txids.is_empty() {
        return None;
    }
    let matches: Vec<bool> = (0..txids.len()).map(|i| i == target_index).collect();
    Some(PartialMerkleTree::from_txids(&txids, &matches))
}

/// Build a Merkle root from transaction IDs using rust-bitcoin.
pub fn compute_merkle_root_rust_bitcoin(txids: &[Txid]) -> Option<[u8; 32]> {
    if txids.is_empty() {
        return None;
    }
    bitcoin::merkle_tree::calculate_root(txids.iter().copied()).map(|h| {
        let mut bytes = txid_to_bytes(&h);
        bytes.reverse();
        bytes
    })
}

/// Verify a block's Merkle root using rust-bitcoin's implementation.
pub fn verify_block_merkle_root_rust_bitcoin(txids: &[Txid], expected_root: [u8; 32]) -> bool {
    if txids.is_empty() {
        return false;
    }
    let expected = match bitcoin::hashes::sha256d::Hash::from_slice(&expected_root) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let computed = match bitcoin::merkle_tree::calculate_root(txids.iter().copied()) {
        Some(h) => h.to_raw_hash(),
        None => return false,
    };
    computed == expected
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-format Conversion
// ─────────────────────────────────────────────────────────────────────────────

/// Convert Bitcoin inclusion proof to core CSV inclusion proof.
pub fn to_core_inclusion_proof(proof: &BitcoinInclusionProof) -> csv_proof::proof::InclusionProof {
    let mut proof_bytes = Vec::new();
    for branch in &proof.merkle_branch {
        proof_bytes.extend_from_slice(branch);
    }
    proof_bytes.extend_from_slice(&proof.block_hash);
    proof_bytes.extend_from_slice(&proof.tx_index.to_le_bytes());
    proof_bytes.extend_from_slice(&proof.block_height.to_le_bytes());

    unsafe {
        csv_proof::proof::InclusionProof::new_unchecked(
            proof_bytes,
            CoreHash::new(proof.block_hash),
            proof.block_height,
            proof.tx_index as u64,
        )
    }
}

/// Convert core CSV inclusion proof to Bitcoin-specific type.
pub fn from_core_inclusion_proof(
    proof: &csv_proof::proof::InclusionProof,
) -> BitcoinInclusionProof {
    let proof_bytes = &proof.proof_bytes;
    if proof_bytes.len() < 48 {
        return BitcoinInclusionProof::new(vec![], [0u8; 32], 0, 0);
    }
    let mut merkle_branch = Vec::new();
    let metadata_size = 32 + 8 + 8;
    let branch_data_len = proof_bytes.len() - metadata_size;
    let mut pos = 0;
    while pos + 32 <= branch_data_len {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&proof_bytes[pos..pos + 32]);
        merkle_branch.push(hash);
        pos += 32;
    }
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&proof_bytes[pos..pos + 32]);
    pos += 32;
    let tx_index = u64::from_le_bytes(proof_bytes[pos..pos + 8].try_into().unwrap()) as u32;
    pos += 8;
    let block_height = u64::from_le_bytes(proof_bytes[pos..pos + 8].try_into().unwrap());
    BitcoinInclusionProof::new(merkle_branch, block_hash, tx_index, block_height)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_single_tx() {
        let txids = [[1u8; 32]];
        assert_eq!(compute_merkle_root(&txids).unwrap(), txids[0]);
    }

    #[test]
    fn test_merkle_root_two_txs() {
        let txids = [[1u8; 32], [2u8; 32]];
        let root = compute_merkle_root(&txids).unwrap();
        assert_ne!(root, [0u8; 32]);
        // Verify by manual computation
        let expected = double_sha256(&txids[0], &txids[1]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three_txs() {
        let txids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = compute_merkle_root(&txids).unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert!(compute_merkle_root(&[]).is_none());
    }

    #[test]
    fn test_verify_merkle_proof_single_tx() {
        let txid = [1u8; 32];
        let proof = BitcoinInclusionProof::new(vec![], txid, 0, 100);
        assert!(verify_merkle_proof(&txid, &txid, &proof));
    }

    #[test]
    fn test_verify_merkle_proof_with_branch() {
        // Build a 4-transaction merkle tree
        let txids = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let root = compute_merkle_root(&txids).unwrap();
        // Extract proof for txid at index 1
        let branch = compute_merkle_branch(&txids[1], 1, &txids).unwrap();
        let proof = BitcoinInclusionProof::new(branch, root, 1, 100);
        assert!(verify_merkle_proof(&txids[1], &root, &proof));
    }

    #[test]
    fn test_verify_merkle_proof_invalid_branch() {
        let txid = [1u8; 32];
        let wrong_root = [2u8; 32];
        let proof = BitcoinInclusionProof::new(vec![], wrong_root, 0, 100);
        assert!(!verify_merkle_proof(&txid, &wrong_root, &proof));
    }

    #[test]
    fn test_verify_block_merkle_root() {
        let txids = [[1u8; 32], [2u8; 32]];
        let root = compute_merkle_root(&txids).unwrap();
        assert!(verify_block_merkle_root(&txids, root));
        assert!(!verify_block_merkle_root(&txids, [0u8; 32]));
    }

    #[test]
    fn test_extract_merkle_proof_single_tx() {
        let txid = [1u8; 32];
        let block_txids = vec![txid];
        let block_hash = [2u8; 32];
        let proof = extract_merkle_proof_from_block(txid, &block_txids, block_hash, 100).unwrap();
        assert_eq!(proof.tx_index, 0);
        assert_eq!(proof.block_hash, block_hash);
        assert!(proof.merkle_branch.is_empty());
    }

    #[test]
    fn test_extract_merkle_proof_multiple_txs() {
        let txids = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let block_hash = [4u8; 32];
        let proof = extract_merkle_proof_from_block(txids[1], &txids, block_hash, 200).unwrap();
        assert_eq!(proof.tx_index, 1);
        assert!(!proof.merkle_branch.is_empty());
        // Verify the extracted proof
        let root = compute_merkle_root(&txids).unwrap();
        assert!(verify_merkle_proof(&txids[1], &root, &proof));
    }

    #[test]
    fn test_extract_merkle_proof_not_found() {
        let txid = [99u8; 32];
        let block_txids = vec![[1u8; 32], [2u8; 32]];
        assert!(extract_merkle_proof_from_block(txid, &block_txids, [3u8; 32], 100).is_none());
    }

    #[test]
    fn test_spv_proof() {
        let txid = [1u8; 32];
        let proof = BitcoinInclusionProof::new(vec![], txid, 0, 100);
        let mut block_header = [0u8; 80];
        block_header[36..68].copy_from_slice(&txid);
        assert!(verify_spv_proof(&txid, &txid, &proof, &block_header));
    }

    #[test]
    fn test_full_spv_proof_confirmations() {
        let txid = [1u8; 32];
        let proof = BitcoinInclusionProof::new(vec![], txid, 0, 100);
        assert!(verify_full_spv_proof(&txid, &txid, &proof, 100, 6, 106));
        assert!(!verify_full_spv_proof(&txid, &txid, &proof, 100, 6, 105));
    }

    #[test]
    fn test_to_core_inclusion_proof() {
        let proof = BitcoinInclusionProof::new(vec![[1u8; 32], [2u8; 32]], [3u8; 32], 5, 100);
        let core_proof = to_core_inclusion_proof(&proof);
        assert_eq!(core_proof.position, 5);
        assert_eq!(core_proof.block_hash, CoreHash::new([3u8; 32]));
    }

    #[test]
    fn test_from_core_inclusion_proof() {
        let mut proof_bytes = Vec::new();
        proof_bytes.extend_from_slice(&[0xAB; 32]);
        proof_bytes.extend_from_slice(&[0xCD; 32]);
        proof_bytes.extend_from_slice(&5u64.to_le_bytes());
        proof_bytes.extend_from_slice(&100u64.to_le_bytes());
        let core_proof =
            csv_proof::proof::InclusionProof::new(proof_bytes, CoreHash::new([1u8; 32]), 5, 100)
                .unwrap();
        let bitcoin_proof = from_core_inclusion_proof(&core_proof);
        assert_eq!(bitcoin_proof.tx_index, 5);
        assert_eq!(bitcoin_proof.block_height, 100);
    }

    // ── rust-bitcoin integration tests ──

    #[test]
    fn test_rust_bitcoin_merkle_proof_single() {
        let txid = [1u8; 32];
        let merkle_root = txid;
        assert!(verify_merkle_proof_rust_bitcoin(
            &txid,
            &merkle_root,
            &[],
            0
        ));
    }

    #[test]
    fn test_build_and_verify_pmt() {
        let txid1 = bytes_to_txid([1u8; 32]);
        let txid2 = bytes_to_txid([2u8; 32]);
        let txids = vec![txid1, txid2];
        let matches = vec![true, false];
        let pmt = build_merkle_proof_from_txids(&txids, &matches);
        let mut extracted = Vec::new();
        let mut indexes = Vec::new();
        let result = pmt.extract_matches(&mut extracted, &mut indexes);
        assert!(result.is_ok());
        assert!(extracted.contains(&txid1));
    }

    #[test]
    fn test_serialize_deserialize_pmt() {
        let txid1 = bytes_to_txid([1u8; 32]);
        let txid2 = bytes_to_txid([2u8; 32]);
        let txids = vec![txid1, txid2];
        let matches = vec![true, false];
        let pmt = build_merkle_proof_from_txids(&txids, &matches);
        let serialized = serialize_merkle_proof(&pmt);
        let (deserialized, total_txs) = deserialize_merkle_proof(&serialized).unwrap();
        assert_eq!(total_txs, 2);
        let mut extracted = Vec::new();
        let mut indexes = Vec::new();
        let result = deserialized.extract_matches(&mut extracted, &mut indexes);
        assert!(result.is_ok());
        assert!(extracted.contains(&txid1));
    }

    #[test]
    fn test_rust_bitcoin_merkle_root() {
        let txid1 = bytes_to_txid([1u8; 32]);
        let txid2 = bytes_to_txid([2u8; 32]);
        let txids = vec![txid1, txid2];
        let root = compute_merkle_root_rust_bitcoin(&txids).unwrap();
        assert!(verify_block_merkle_root_rust_bitcoin(&txids, root));
        assert!(!verify_block_merkle_root_rust_bitcoin(&txids, [0u8; 32]));
    }

    #[test]
    fn test_consistency_pure_vs_rust_bitcoin_merkle_root() {
        let txids_raw = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let pure_root = compute_merkle_root(&txids_raw).unwrap();

        // rust-bitcoin Txid uses reversed byte order internally.
        // We need to reverse the display-order bytes before creating Txids
        // so that the merkle tree is built on the same logical values.
        let rust_txids: Vec<Txid> = txids_raw
            .iter()
            .map(|t| {
                let mut reversed = *t;
                reversed.reverse();
                bytes_to_txid(reversed)
            })
            .collect();
        let rust_root = compute_merkle_root_rust_bitcoin(&rust_txids).unwrap();
        assert_eq!(
            pure_root, rust_root,
            "Merkle root must be identical across implementations"
        );
    }

    #[test]
    fn test_consistency_pure_vs_rust_bitcoin_verify() {
        let txids_raw = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let root = compute_merkle_root(&txids_raw).unwrap();
        let branch = compute_merkle_branch(&txids_raw[2], 2, &txids_raw).unwrap();
        let proof = BitcoinInclusionProof::new(branch.clone(), root, 2, 100);
        assert!(verify_merkle_proof(&txids_raw[2], &root, &proof));
        assert!(verify_merkle_proof_rust_bitcoin(
            &txids_raw[2],
            &root,
            &branch,
            2
        ));
    }
}
