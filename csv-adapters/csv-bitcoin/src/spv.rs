//! SPV (Simplified Payment Verification) for Bitcoin

use bitcoin::{Txid, hashes::Hash as BitcoinHash};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Block header entry
#[derive(Clone, Debug)]
pub struct BlockHeaderEntry {
    pub hash: [u8; 32],
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub confirmations: u64,
}

/// SPV verifier
pub struct SpvVerifier {
    headers: HashMap<[u8; 32], BlockHeaderEntry>,
    chain_tip: Option<[u8; 32]>,
    chain_tip_height: u64,
}

impl SpvVerifier {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            chain_tip: None,
            chain_tip_height: 0,
        }
    }

    pub fn add_header(&mut self, entry: BlockHeaderEntry) {
        if self.chain_tip.is_none() || entry.height > self.chain_tip_height {
            self.chain_tip = Some(entry.hash);
            self.chain_tip_height = entry.height;
        }
        self.headers.insert(entry.hash, entry);
    }

    pub fn verify_merkle_proof(
        &self,
        txid: &Txid,
        merkle_root: &[u8; 32],
        branch: &[[u8; 32]],
        _index: u32,
    ) -> bool {
        let txid_bytes: [u8; 32] = txid.to_raw_hash().to_byte_array();
        if branch.is_empty() {
            return txid_bytes == *merkle_root;
        }

        let mut current = txid_bytes;
        for sibling in branch {
            let mut hasher = Sha256::new();
            hasher.update(current);
            hasher.update(sibling);
            let first = hasher.finalize_reset();
            let mut hasher2 = Sha256::new();
            hasher2.update(first);
            current = hasher2.finalize().into();
        }
        current == *merkle_root
    }

    pub fn is_block_in_chain(&self, block_hash: &[u8; 32]) -> bool {
        self.headers.contains_key(block_hash)
    }

    pub fn get_confirmations(&self, block_hash: &[u8; 32]) -> Option<u64> {
        self.headers.get(block_hash).map(|h| h.confirmations)
    }

    pub fn chain_tip_height(&self) -> u64 {
        self.chain_tip_height
    }

    pub fn invalidate_block(&mut self, block_hash: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut invalidated = Vec::new();
        if let Some(height) = self.headers.get(block_hash).map(|h| h.height) {
            let hashes: Vec<_> = self
                .headers
                .iter()
                .filter(|(_, h)| h.height >= height)
                .map(|(hash, _)| *hash)
                .collect();
            for hash in &hashes {
                self.headers.remove(hash);
                invalidated.push(*hash);
            }
            if let Some(tip) = self.chain_tip {
                if hashes.contains(&tip) {
                    let new_tip = self
                        .headers
                        .values()
                        .max_by_key(|h| h.height)
                        .map(|h| h.hash);
                    self.chain_tip = new_tip;
                    self.chain_tip_height = self
                        .chain_tip_height
                        .saturating_sub(invalidated.len() as u64);
                }
            }
        }
        invalidated
    }
}

impl Default for SpvVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Standalone merkle proof verification function
pub fn verify_merkle_proof(txid: &Txid, merkle_root: &[u8; 32], branch: &[[u8; 32]]) -> bool {
    let spv = SpvVerifier::new();
    spv.verify_merkle_proof(txid, merkle_root, branch, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as BitcoinHash;

    fn test_hash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    #[test]
    fn test_spv_empty() {
        let spv = SpvVerifier::new();
        assert_eq!(spv.chain_tip_height(), 0);
    }

    #[test]
    fn test_add_header() {
        let mut spv = SpvVerifier::new();
        spv.add_header(BlockHeaderEntry {
            hash: test_hash(1),
            height: 100,
            prev_hash: test_hash(0),
            merkle_root: test_hash(2),
            confirmations: 1,
        });
        assert_eq!(spv.chain_tip_height(), 100);
        assert!(spv.is_block_in_chain(&test_hash(1)));
    }

    #[test]
    fn test_invalidate_block() {
        let mut spv = SpvVerifier::new();
        let h1 = test_hash(1);
        let h2 = test_hash(2);
        spv.add_header(BlockHeaderEntry {
            hash: h1,
            height: 100,
            prev_hash: test_hash(0),
            merkle_root: test_hash(3),
            confirmations: 2,
        });
        spv.add_header(BlockHeaderEntry {
            hash: h2,
            height: 101,
            prev_hash: h1,
            merkle_root: test_hash(3),
            confirmations: 1,
        });

        let invalidated = spv.invalidate_block(&h1);
        assert_eq!(invalidated.len(), 2);
        assert!(!spv.is_block_in_chain(&h1));
    }

    #[test]
    fn test_merkle_proof_single_tx() {
        let spv = SpvVerifier::new();
        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_slice(&[1u8; 32]).unwrap());
        let root = [1u8; 32];
        assert!(spv.verify_merkle_proof(&txid, &root, &[], 0));
    }

    #[test]
    fn test_merkle_proof_wrong_root() {
        let spv = SpvVerifier::new();
        let txid =
            Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_slice(&[1u8; 32]).unwrap());
        let root = [2u8; 32];
        assert!(!spv.verify_merkle_proof(&txid, &root, &[], 0));
    }
}
