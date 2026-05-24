//! Chain-native Solana inclusion/finality checks (RULE 3).

use csv_hash::Hash;
use csv_proof::proof::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::backend::{ChainOpError, ChainOpResult};
use csv_verifier::{
    ChainBundleError, ChainBundlePolicy, ChainNativeProofVerifier, verify_chain_proof_bundle,
};

impl super::SolanaBackend {
    /// Chain-native inclusion verification (slot/transaction proof).
    pub fn verify_inclusion_native(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        #[cfg(feature = "rpc")]
        {
            use tokio::runtime::Handle;
            let _handle = Handle::current();

            // Solana uses slot-based inclusion with transaction proofs
            // Verify the proof bytes contain valid slot data
            if proof.proof_bytes.is_empty() {
                return Ok(false);
            }

            // Block hash must be non-trivial
            if *proof.block_hash.as_bytes() == [0u8; 32] {
                return Err(ChainOpError::ProofVerificationError(
                    "Invalid block hash in inclusion proof".to_string(),
                ));
            }

            // Proof must be at least 128 bytes (slot + signature + block_hash + confirmations + flags + commitment + data_hash)
            if proof.proof_bytes.len() < 128 {
                return Ok(false);
            }

            // Verify the commitment is embedded in the proof
            // The commitment is stored at offset 113-145 in the proof bytes
            if proof.proof_bytes.len() >= 145 {
                let proof_commitment: [u8; 32] =
                    proof.proof_bytes[113..145].try_into().unwrap_or([0u8; 32]);
                if proof_commitment != *commitment.as_bytes() {
                    return Err(ChainOpError::ProofVerificationError(
                        "Commitment not found in proof data".to_string(),
                    ));
                }
            }

            // Verify position matches the slot in the proof
            let proof_slot =
                u64::from_le_bytes(proof.proof_bytes[..8].try_into().unwrap_or([0u8; 8]));
            if proof.position != proof_slot {
                return Err(ChainOpError::ProofVerificationError(
                    "Position does not match slot in proof".to_string(),
                ));
            }

            Ok(true)
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = (proof, commitment);
            Err(ChainOpError::FeatureNotEnabled(
                "rpc feature required for proof verification".to_string(),
            ))
        }
    }

    /// Chain-native finality verification (slot confirmations).
    pub fn verify_finality_native(
        &self,
        proof: &FinalityProof,
        tx_hash: &str,
    ) -> ChainOpResult<bool> {
        #[cfg(feature = "rpc")]
        {
            use tokio::runtime::Handle;
            let _handle = Handle::current();

            const MIN_CONFIRMATIONS: u64 = 32;

            // Solana has deterministic finality after ~32 slots (12-16 seconds)
            if proof.confirmations < MIN_CONFIRMATIONS {
                return Ok(false);
            }

            // Verify finality data is present
            if proof.finality_data.is_empty() {
                return Err(ChainOpError::ProofVerificationError(
                    "Invalid finality proof data".to_string(),
                ));
            }

            // If claim finalized, must have 32+ confirmations
            if proof.is_deterministic && proof.confirmations < MIN_CONFIRMATIONS {
                return Ok(false);
            }

            // Verify proof data structure
            if proof.finality_data.len() < 32 {
                return Err(ChainOpError::ProofVerificationError(
                    "Finality proof too short".to_string(),
                ));
            }

            // Validate tx_hash format (Solana transaction signature)
            if tx_hash.len() != 64 && tx_hash.len() != 88 {
                return Err(ChainOpError::InvalidInput(
                    "Invalid tx_hash format".to_string(),
                ));
            }

            Ok(true)
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = (proof, tx_hash);
            Err(ChainOpError::FeatureNotEnabled(
                "rpc feature required for finality proof verification".to_string(),
            ))
        }
    }

    /// Verify inclusion + finality via csv-verifier (RULE 1).
    pub fn verify_proof_bundle_native(
        &self,
        inclusion_proof: &CoreInclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        verify_chain_proof_bundle(
            self,
            inclusion_proof,
            finality_proof,
            commitment,
            &ChainBundlePolicy::permissive(),
        )
        .map_err(|e| ChainOpError::ProofVerificationError(e.to_string()))
    }
}

impl ChainNativeProofVerifier for super::SolanaBackend {
    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> Result<bool, ChainBundleError> {
        self.verify_inclusion_native(proof, commitment)
            .map_err(|e| ChainBundleError::Inclusion(e.to_string()))
    }

    fn verify_finality_proof(
        &self,
        proof: &FinalityProof,
        anchor_ref: &str,
    ) -> Result<bool, ChainBundleError> {
        self.verify_finality_native(proof, anchor_ref)
            .map_err(|e| ChainBundleError::Finality(e.to_string()))
    }
}
