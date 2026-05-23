//! Chain-native inclusion/finality checks (RULE 3).
//!
//! Protocol bundle composition is delegated to `csv-verifier::verify_chain_proof_bundle`.

use csv_core::backend::ChainOpError;
use csv_core::backend::ChainOpResult;
use csv_hash::Hash;
use csv_proof::proof::{FinalityProof, InclusionProof};
use csv_verifier::{
    verify_chain_proof_bundle, ChainBundleError, ChainBundlePolicy, ChainNativeProofVerifier,
};

#[cfg(feature = "rpc")]
use crate::rpc::RpcBlock;

impl super::EthereumBackend {
    /// Chain-native inclusion verification (RPC/MPT).
    pub fn verify_inclusion_native(
        &self,
        proof: &InclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        #[cfg(feature = "rpc")]
        {
            use tokio::runtime::Handle;
            let handle = Handle::current();

            let block = handle
                .block_on(self.rpc().get_block_by_number(proof.position))
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get block: {}", e)))?
                .ok_or_else(|| {
                    ChainOpError::ProofVerificationError("Block not found".to_string())
                })?;

            let state_root_bytes: &[u8] = block.state_root.as_ref();
            if state_root_bytes != proof.proof_bytes.as_slice() {
                return Ok(false);
            }

            let commitment_bytes = commitment.as_bytes();
            if !proof
                .proof_bytes
                .windows(commitment_bytes.len())
                .any(|window| window == commitment_bytes)
            {
                return Err(ChainOpError::ProofVerificationError(
                    "Commitment not found in proof data".to_string(),
                ));
            }

            if proof.block_hash.as_bytes().is_empty()
                || format!("0x{}", hex::encode(proof.block_hash.as_bytes())).len() < 3
            {
                return Err(ChainOpError::ProofVerificationError(
                    "Invalid transaction hash format".to_string(),
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

    /// Chain-native finality verification.
    pub fn verify_finality_native(
        &self,
        proof: &FinalityProof,
        tx_hash: &str,
    ) -> ChainOpResult<bool> {
        #[cfg(feature = "rpc")]
        {
            use tokio::runtime::Handle;
            let handle = Handle::current();
            let _latest = handle.block_on(self.rpc().block_number()).map_err(|e| {
                ChainOpError::RpcError(format!("Failed to get latest block: {}", e))
            })?;

            if proof.confirmations < self.config.finality_depth && !proof.is_deterministic {
                return Ok(false);
            }

            let block: RpcBlock = serde_json::from_slice(&proof.finality_data).map_err(|_| {
                ChainOpError::InvalidInput("Invalid finality proof data".to_string())
            })?;

            let _tx_hash_bytes = self.parse_tx_hash(tx_hash)?;

            if block.number == 0 {
                return Err(ChainOpError::ProofVerificationError(
                    "Invalid block number in finality proof".to_string(),
                ));
            }

            if block.hash == [0u8; 32] {
                return Err(ChainOpError::ProofVerificationError(
                    "Invalid block hash in finality proof".to_string(),
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
        inclusion_proof: &InclusionProof,
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

impl ChainNativeProofVerifier for super::EthereumBackend {
    fn verify_inclusion_proof(
        &self,
        proof: &InclusionProof,
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
