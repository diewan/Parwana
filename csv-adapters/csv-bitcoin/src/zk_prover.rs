//! ZK Proof Generation for Bitcoin SPV
//!
//! This module provides SP1-based zero-knowledge proof generation for Bitcoin
//! seal verification. It proves that a Bitcoin UTXO was spent in a specific
//! block without revealing the full transaction data.
//!
//! # Architecture
//!
//! ```text
//! Bitcoin UTXO spend data + Merkle branch + block header
//!     → SP1 zkVM guest program
//!     → ZkSealProof { proof_bytes, public_inputs }
//! ```
//!
//! # Security Properties
//!
//! - Zero-knowledge: Verifier learns only that seal was consumed, not which UTXO
//! - Succinct: Proof size is constant regardless of block height
//! - Verifiable: Anyone can verify without trusting Bitcoin RPC

use bitcoin::hashes::Hash as BitcoinHash;

#[cfg(test)]
use csv_hash::Hash;
use csv_hash::seal::SealPoint;

use csv_proof::zk_proof::{ChainWitness, ProofSystem, ZkError, ZkProver, ZkSealProof};
use csv_protocol::version::builtin;

/// Bitcoin SPV ZK Prover using SP1
///
/// Generates zero-knowledge proofs that a Bitcoin seal was consumed
/// without requiring the verifier to query Bitcoin RPC.
pub struct BitcoinSpvProver {
    /// SP1 prover key (if available)
    // Populated when SP1 is present; consumed once real SP1 proving is wired.
    #[allow(dead_code)]
    prover_key: Option<Vec<u8>>,
    /// Whether SP1 is available on this platform
    sp1_available: bool,
}

impl BitcoinSpvProver {
    /// Create a new Bitcoin SPV prover
    ///
    /// # Note
    /// If SP1 is not available, this will return a prover that generates
    /// placeholder proofs for testing. In production, SP1 must be available.
    pub fn new() -> Self {
        // Check if SP1 prover key is available in environment
        let prover_key = std::env::var("SP1_PROVER_KEY")
            .ok()
            .and_then(|k| hex::decode(k).ok());

        let sp1_available = prover_key.is_some();

        Self {
            prover_key,
            sp1_available,
        }
    }

    /// Check if SP1 prover is available
    pub fn is_available(&self) -> bool {
        self.sp1_available
    }

    /// Generate a mock proof for testing when SP1 is not available
    ///
    /// # Warning
    /// This is for development/testing only. Real proofs require SP1.
    #[cfg(test)]
    fn generate_mock_proof(
        &self,
        seal: &SealPoint,
        witness: &ChainWitness,
    ) -> Result<ZkSealProof, ZkError> {
        use csv_proof::zk_proof::{VerifierKey, ZkPublicInputs};
        use sha2::{Digest, Sha256};

        // Create a deterministic mock proof based on witness hash
        let mut hasher = Sha256::new();
        hasher.update(&seal.id);
        hasher.update(witness.block_hash.as_bytes());
        hasher.update(witness.block_height.to_le_bytes());
        let mock_proof_hash: [u8; 32] = hasher.finalize().into();

        // Mock proof is 128 bytes of hash-derived data
        let mut mock_proof = Vec::with_capacity(128);
        for _ in 0..4 {
            mock_proof.extend_from_slice(&mock_proof_hash[..]);
        }

        let verifier_key = VerifierKey::new(
            builtin::BITCOIN.clone(),
            vec![0u8; 64],
            csv_proof::zk_proof::ProofSystem::SP1,
            1,
        );

        let public_inputs = ZkPublicInputs {
            seal_ref: seal.clone(),
            block_hash: witness.block_hash,
            commitment: Hash::new(mock_proof_hash),
            source_chain: builtin::BITCOIN.clone(),
            block_height: witness.block_height,
            timestamp: witness.timestamp,
        };

        Ok(ZkSealProof {
            proof_bytes: mock_proof,
            verifier_key,
            public_inputs,
        })
    }
}

impl ZkProver for BitcoinSpvProver {
    fn prove_seal_consumption(
        &self,
        seal: &SealPoint,
        witness: &ChainWitness,
    ) -> Result<ZkSealProof, ZkError> {
        // Validate witness is for Bitcoin
        if witness.chain != *builtin::BITCOIN {
            return Err(ZkError::InvalidProof(
                "BitcoinSpvProver only supports Bitcoin chain".to_string(),
            ));
        }

        // Validate witness data is present
        if witness.tx_data.is_empty() {
            return Err(ZkError::InvalidProof(
                "Transaction data required for SPV proof".to_string(),
            ));
        }

        if witness.inclusion_proof.is_empty() {
            return Err(ZkError::InvalidProof(
                "Merkle inclusion proof required for SPV proof".to_string(),
            ));
        }

        // SP1 ZK proof generation
        // In production, real SP1 proving requires:
        //   1. SP1_PROVER_KEY env var
        //   2. SP1 guest program (ELF) loaded at runtime
        //   3. sp1_sdk::ProverClient::prove(elf, stdin)
        //
        // Until the full SP1 pipeline is integrated, always return a hard error
        // in production builds. This prevents silent deployment of fake proofs.
        // The test path uses generate_mock_proof for unit testing only.
        #[cfg(not(test))]
        {
            let _ = (seal, witness);
            return Err(ZkError::VerificationFailed(
                "Real SP1 proving pipeline not yet integrated. \
                 Set SP1_PROVER_KEY and use sp1_sdk::ProverClient for production proofs. \
                 See csv-bitcoin/src/sp1_guest/spv.rs for the guest program."
                    .to_string(),
            ));
        }

        #[cfg(test)]
        {
            self.generate_mock_proof(seal, witness)
        }
    }

    fn proof_system(&self) -> ProofSystem {
        ProofSystem::SP1
    }
}

impl Default for BitcoinSpvProver {
    fn default() -> Self {
        Self::new()
    }
}

/// SP1 guest program input for Bitcoin SPV verification
///
/// This is the input format that would be passed to the SP1 guest program.
#[derive(Debug, Clone)]
pub struct Sp1BtcSpvInput {
    /// Raw Bitcoin transaction data (spending the UTXO)
    pub tx_data: Vec<u8>,
    /// Transaction ID (computed from tx_data)
    pub txid: [u8; 32],
    /// Merkle branch proving tx inclusion in block
    pub merkle_branch: Vec<[u8; 32]>,
    /// Block header (80 bytes)
    pub block_header: [u8; 80],
    /// Block hash (computed from header)
    pub block_hash: [u8; 32],
    /// Position in Merkle tree
    pub tx_position: u32,
}

impl Sp1BtcSpvInput {
    /// Compute the transaction ID from transaction data
    pub fn compute_txid(&self) -> [u8; 32] {
        let hash = bitcoin::hashes::sha256d::Hash::hash(&self.tx_data[..]);
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hash[..]);
        txid
    }

    /// Verify the Merkle branch (SP1 guest would do this)
    pub fn verify_merkle_branch(&self) -> bool {
        // Start with txid
        let mut current = self.compute_txid();

        // Apply each branch node
        for (i, branch_node) in self.merkle_branch.iter().enumerate() {
            // Determine if current is left or sanad based on position bit
            let is_sanad = ((self.tx_position >> i) & 1) == 1;

            // Concatenate and hash
            let mut concat = Vec::with_capacity(64);
            if is_sanad {
                concat.extend_from_slice(branch_node);
                concat.extend_from_slice(&current);
            } else {
                concat.extend_from_slice(&current);
                concat.extend_from_slice(branch_node);
            }

            let hash = bitcoin::hashes::sha256d::Hash::hash(&concat[..]);
            current = hash.as_byte_array()[..]
                .try_into()
                .expect("32 bytes for hash");
        }

        // Final should match Merkle root in block header
        let merkle_root = &self.block_header[36..68];
        current == merkle_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_hash::chain_id::ChainId;

    #[test]
    fn test_bitcoin_spv_prover_creation() {
        let prover = BitcoinSpvProver::new();
        // Without SP1_PROVER_KEY env var, should not be available
        assert!(!prover.is_available());
    }

    #[test]
    fn test_mock_proof_generation() {
        let prover = BitcoinSpvProver::new();

        let seal = SealPoint::new(vec![0xAB; 32], Some(42), None).unwrap();
        let witness = ChainWitness {
            chain: builtin::BITCOIN.clone(),
            block_hash: Hash::new([1u8; 32]),
            block_height: 800_000,
            tx_data: vec![0xCD; 64],
            inclusion_proof: vec![0xEF; 32],
            finality_proof: vec![0x12; 16],
            timestamp: 1_000_000,
        };

        let result = prover.prove_seal_consumption(&seal, &witness);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert!(!proof.proof_bytes.is_empty());
        assert_eq!(proof.verifier_key.chain, *builtin::BITCOIN);
        assert_eq!(proof.verifier_key.proof_system, ProofSystem::SP1);
    }

    #[test]
    fn test_wrong_chain_fails() {
        let prover = BitcoinSpvProver::new();

        let seal = SealPoint::new(vec![0xAB; 32], Some(42), None).unwrap();
        let witness = ChainWitness {
            chain: ChainId::new("ethereum"), // Wrong chain
            block_hash: Hash::new([1u8; 32]),
            block_height: 19_000_000,
            tx_data: vec![0xCD; 64],
            inclusion_proof: vec![0xEF; 32],
            finality_proof: vec![0x12; 16],
            timestamp: 1_000_000,
        };

        let result = prover.prove_seal_consumption(&seal, &witness);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_inclusion_proof_fails() {
        let prover = BitcoinSpvProver::new();

        let seal = SealPoint::new(vec![0xAB; 32], Some(42), None).unwrap();
        let witness = ChainWitness {
            chain: builtin::BITCOIN.clone(),
            block_hash: Hash::new([1u8; 32]),
            block_height: 800_000,
            tx_data: vec![0xCD; 64],
            inclusion_proof: vec![], // Empty
            finality_proof: vec![0x12; 16],
            timestamp: 1_000_000,
        };

        let result = prover.prove_seal_consumption(&seal, &witness);
        assert!(result.is_err());
    }
}
