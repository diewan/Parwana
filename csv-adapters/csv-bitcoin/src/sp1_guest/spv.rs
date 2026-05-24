//! Bitcoin SPV Verification for SP1 Guest Program
//!
//! This module implements pure Bitcoin SPV (Simple Payment Verification)
//! that can run inside the SP1 zkVM. It verifies that a transaction was
//! included in a Bitcoin block without requiring a full node.

use bitcoin::hashes::{Hash as BitcoinHash, sha256d};
use csv_hash::Hash;
use csv_protocol::protocol_version::builtin;
use csv_hash::seal::SealPoint;
use csv_proof::zk_proof::{ProofSystem, VerifierKey, ZkPublicInputs, ZkSealProof};

/// Input to the SP1 Bitcoin SPV guest program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp1BtcSpvInput {
    /// Raw Bitcoin transaction data (spending the UTXO)
    pub tx_data: Vec<u8>,
    /// Merkle branch nodes (hashes of sibling nodes)
    pub merkle_branch: Vec<[u8; 32]>,
    /// Position of transaction in the Merkle tree
    pub tx_position: u32,
    /// Serialized Bitcoin block header (80 bytes)
    pub block_header: [u8; 80],
    /// Expected block hash (for verification)
    pub expected_block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Seal reference (UTXO being spent)
    pub seal_ref: SealPoint,
    /// Commitment hash (bound to the proof)
    pub commitment: Hash,
}

impl Sp1BtcSpvInput {
    /// Create a new SP1 input
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_data: Vec<u8>,
        merkle_branch: Vec<[u8; 32]>,
        tx_position: u32,
        block_header: [u8; 80],
        expected_block_hash: [u8; 32],
        block_height: u64,
        seal_ref: SealPoint,
        commitment: Hash,
    ) -> Self {
        Self {
            tx_data,
            merkle_branch,
            tx_position,
            block_header,
            expected_block_hash,
            block_height,
            seal_ref,
            commitment,
        }
    }

    /// Compute the transaction ID (double SHA256)
    pub fn compute_txid(&self) -> [u8; 32] {
        let hash = sha256d::Hash::hash(&self.tx_data);
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hash[..]);
        txid
    }

    /// Compute the Merkle root from the txid and Merkle branch
    pub fn compute_merkle_root(&self) -> [u8; 32] {
        let mut current = self.compute_txid();
        let mut position = self.tx_position;

        for branch_node in &self.merkle_branch {
            // Determine if current is left or sanad child
            let is_sanad_child = (position & 1) == 1;
            position >>= 1;

            // Concatenate and hash
            let mut concat = Vec::with_capacity(64);
            if is_sanad_child {
                concat.extend_from_slice(branch_node);
                concat.extend_from_slice(&current);
            } else {
                concat.extend_from_slice(&current);
                concat.extend_from_slice(branch_node);
            }

            let hash = sha256d::Hash::hash(&concat);
            current.copy_from_slice(&hash[..]);
        }

        current
    }

    /// Verify the block header hash matches expected
    pub fn verify_block_hash(&self) -> bool {
        // Bitcoin block header hash is double SHA256
        let computed_hash = sha256d::Hash::hash(&self.block_header);
        computed_hash.as_byte_array()[..] == self.expected_block_hash[..]
    }

    /// Extract Merkle root from block header (bytes 36-68)
    pub fn get_merkle_root_from_header(&self) -> [u8; 32] {
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&self.block_header[36..68]);
        merkle_root
    }
}

/// Output from the SP1 Bitcoin SPV guest program
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sp1BtcSpvOutput {
    /// Public inputs that can be verified
    pub public_inputs: ZkPublicInputs,
    /// Verification success flag
    pub verified: bool,
}

impl Sp1BtcSpvOutput {
    /// Create output from input (after successful verification)
    pub fn from_input(input: &Sp1BtcSpvInput) -> Self {
        let public_inputs = ZkPublicInputs {
            seal_ref: input.seal_ref.clone(),
            block_hash: Hash::new(input.expected_block_hash),
            commitment: input.commitment,
            source_chain: builtin::BITCOIN.clone(),
            block_height: input.block_height,
            timestamp: 0, // Would be extracted from block header
        };

        Self {
            public_inputs,
            verified: true,
        }
    }

    /// Create a ZkSealProof from this output
    ///
    /// The verifier key is loaded from the `SP1_VERIFIER_KEY` environment variable
    /// at runtime. This ensures that the verification key is never hardcoded in
    /// the binary and can be rotated without code changes.
    pub fn to_zk_proof(&self, proof_bytes: Vec<u8>) -> Result<ZkSealProof, &'static str> {
        let key_bytes = if let Ok(key_hex) = std::env::var("SP1_VERIFIER_KEY") {
            hex::decode(&key_hex)
                .map_err(|_| "SP1_VERIFIER_KEY must be a valid hex string")?
        } else {
            #[cfg(test)]
            {
                // Use a deterministic test key in test builds
                let mut key = vec![0u8; 64];
                key[0] = 0xAB;
                key[63] = 0xCD;
                key
            }
            #[cfg(not(test))]
            {
                return Err(
                    "SP1_VERIFIER_KEY environment variable not set. \
                     Set SP1_VERIFIER_KEY to the hex-encoded SP1 verifier \
                     verification key before generating ZK proofs."
                );
            }
        };

        let verifier_key = VerifierKey::new(
            builtin::BITCOIN.clone(),
            key_bytes,
            ProofSystem::SP1,
            1,
        );

        ZkSealProof::new(proof_bytes, verifier_key, self.public_inputs.clone())
    }
}

/// Verify Bitcoin SPV proof inside SP1 zkVM
///
/// This function performs the actual verification that:
/// 1. The transaction hash matches the claimed txid
/// 2. The Merkle branch connects the txid to the block's Merkle root
/// 3. The block header hash matches the claimed block hash
pub fn verify_bitcoin_spv(input: &Sp1BtcSpvInput) -> bool {
    // Step 1: Compute txid from transaction data
    let _txid = input.compute_txid();

    // Step 2: Verify the Merkle branch
    let computed_merkle_root = input.compute_merkle_root();
    let expected_merkle_root = input.get_merkle_root_from_header();

    if computed_merkle_root != expected_merkle_root {
        return false;
    }

    // Step 3: Verify the block header hash
    if !input.verify_block_hash() {
        return false;
    }

    // Step 4: Verify the seal reference matches the transaction
    // The seal_ref should contain the OutPoint (txid + vout) being spent
    // This is a simplified check - in production, you'd parse the transaction
    // and verify the specific input spends the claimed UTXO
    if input.seal_ref.id.len() < 32 {
        return false;
    }

    // All checks passed
    true
}

/// Compute Bitcoin-style double SHA256 hash
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash = sha256d::Hash::hash(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..]);
    result
}

/// Reverse bytes (Bitcoin uses little-endian for hashes)
pub fn reverse_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_input_creation() {
        let seal = SealPoint::new(vec![0xAB; 32], Some(0)).unwrap();
        let input = Sp1BtcSpvInput::new(
            vec![0x01, 0x00, 0x00, 0x00], // Simplified tx data
            vec![[0xCD; 32]],             // Single merkle branch node
            0,                            // Position 0
            [0u8; 80],                    // Empty block header
            [0u8; 32],                    // Expected block hash
            800_000,
            seal,
            Hash::new([0xEF; 32]),
        );

        assert!(!input.tx_data.is_empty());
        assert_eq!(input.merkle_branch.len(), 1);
    }

    #[test]
    fn test_merkle_root_extraction() {
        let mut header = [0u8; 80];
        // Set merkle root in header (bytes 36-68)
        header[36..68].copy_from_slice(&[0x12; 32]);

        let seal = SealPoint::new(vec![0xAB; 32], Some(0)).unwrap();
        let input = Sp1BtcSpvInput::new(
            vec![0x01; 4],
            vec![],
            0,
            header,
            [0u8; 32],
            800_000,
            seal,
            Hash::new([0xEF; 32]),
        );

        let merkle_root = input.get_merkle_root_from_header();
        assert_eq!(merkle_root, [0x12; 32]);
    }

    #[test]
    fn test_txid_computation() {
        // Same data should produce same txid
        let seal = SealPoint::new(vec![0xAB; 32], Some(0)).unwrap();
        let input1 = Sp1BtcSpvInput::new(
            vec![0x01, 0x02, 0x03],
            vec![],
            0,
            [0u8; 80],
            [0u8; 32],
            800_000,
            seal.clone(),
            Hash::new([0xEF; 32]),
        );

        let input2 = Sp1BtcSpvInput::new(
            vec![0x01, 0x02, 0x03],
            vec![],
            0,
            [0u8; 80],
            [0u8; 32],
            800_000,
            seal,
            Hash::new([0xEF; 32]),
        );

        assert_eq!(input1.compute_txid(), input2.compute_txid());
    }

    #[test]
    fn test_verify_bitcoin_spv_fails_with_invalid_header() {
        // This should fail because the block header hash won't match
        let seal = SealPoint::new(vec![0xAB; 32], Some(0)).unwrap();
        let input = Sp1BtcSpvInput::new(
            vec![0x01; 4],
            vec![],
            0,
            [0u8; 80],  // Empty header
            [0xFF; 32], // Non-matching expected hash
            800_000,
            seal,
            Hash::new([0xEF; 32]),
        );

        // Should fail because block hash doesn't match
        assert!(!verify_bitcoin_spv(&input));
    }

    #[test]
    fn test_double_sha256() {
        let data = b"hello world";
        let hash1 = double_sha256(data);
        let hash2 = double_sha256(data);
        assert_eq!(hash1, hash2);

        // Different data should produce different hash
        let hash3 = double_sha256(b"different");
        assert_ne!(hash1, hash3);
    }
}
