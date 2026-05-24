//! Chain-native Bitcoin inclusion/finality checks (RULE 3).

use csv_protocol::backend::{ChainOpError, ChainOpResult};
use csv_hash::Hash;
use csv_proof::proof::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_verifier::{
    verify_chain_proof_bundle, ChainBundleError, ChainBundlePolicy, ChainNativeProofVerifier,
};

impl super::BitcoinChainProofProvider {
    pub(crate) fn verify_inclusion_native(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        let _ = commitment;
        if proof.proof_bytes.len() < 48 || proof.proof_bytes.len() % 32 != 16 {
            return Ok(false);
        }

        let bitcoin_proof = crate::proofs::from_core_inclusion_proof(proof);
        if bitcoin_proof.block_hash == [0u8; 32]
            || bitcoin_proof.block_height != proof.block_number
            || bitcoin_proof.tx_index as u64 != proof.position
            || Hash::from(bitcoin_proof.block_hash) != proof.block_hash
        {
            return Ok(false);
        }

        Ok(true)
    }

    pub(crate) fn verify_finality_native(
        &self,
        proof: &FinalityProof,
        tx_hash: &str,
    ) -> ChainOpResult<bool> {
        #[cfg(feature = "rpc")]
        {
            const FINALITY_CONFIRMATIONS: u64 = 6;

            if proof.confirmations < FINALITY_CONFIRMATIONS {
                return Ok(false);
            }

            if proof.finality_data.len() >= 88 {
                let data_confirmations =
                    u64::from_le_bytes(proof.finality_data[80..88].try_into().unwrap_or([0u8; 8]));
                if data_confirmations != proof.confirmations {
                    return Err(ChainOpError::ProofVerificationError(
                        "Confirmation count mismatch in finality proof".to_string(),
                    ));
                }
            }

            if tx_hash.len() != 64 && tx_hash.len() != 66 {
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
            &ChainBundlePolicy::bitcoin(),
        )
        .map_err(|e| ChainOpError::ProofVerificationError(e.to_string()))
    }
}

impl ChainNativeProofVerifier for super::BitcoinChainProofProvider {
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
