//! Chain-native Solana inclusion/finality checks (RULE 3).

use csv_hash::Hash;
use csv_protocol::chain_adapter_traits::{ChainOpError, ChainOpResult};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_verifier::{
    ChainBundleError, ChainBundlePolicy, ChainNativeProofVerifier, verify_chain_proof_bundle,
};

/// Validate the runtime's on-chain lock-record evidence.
///
/// The byte layout is deliberately separate from the older generic slot-proof
/// layout: `[signature: 64][slot: 8][Anchor discriminator: 8][sanad_id: 32]`.
fn verify_runtime_lock_proof_layout(
    proof: &CoreInclusionProof,
    sanad_id: &Hash,
) -> ChainOpResult<()> {
    const LOCK_PROOF_MIN_LEN: usize = 64 + 8 + 8 + 32;
    if proof.proof_bytes.len() < LOCK_PROOF_MIN_LEN {
        return Err(ChainOpError::ProofVerificationError(
            "Lock proof is too short to contain a LockRecord sanad ID".to_string(),
        ));
    }

    let proof_sanad_id: [u8; 32] = proof.proof_bytes[80..112]
        .try_into()
        .expect("lock proof length was checked above");
    if proof_sanad_id != *sanad_id.as_bytes() {
        return Err(ChainOpError::ProofVerificationError(
            "Sanad ID not found in locked proof record".to_string(),
        ));
    }

    let proof_slot = u64::from_le_bytes(
        proof.proof_bytes[64..72]
            .try_into()
            .expect("lock proof length was checked above"),
    );
    if proof.position != proof_slot {
        return Err(ChainOpError::ProofVerificationError(
            "Position does not match lock slot in proof".to_string(),
        ));
    }

    Ok(())
}

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

            // The chain-proof trait calls this argument `commitment`, but the
            // cross-chain runtime binds it to transfer.sanad_id.  Check the
            // locked Sanad ID in the on-chain LockRecord at its canonical
            // offset rather than an obsolete synthetic-proof offset.
            verify_runtime_lock_proof_layout(proof, commitment)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_lock_proof(sanad_id: Hash, slot: u64) -> CoreInclusionProof {
        let mut bytes = vec![7u8; 64]; // transaction signature
        bytes.extend_from_slice(&slot.to_le_bytes());
        bytes.extend_from_slice(&[9u8; 8]); // Anchor discriminator
        bytes.extend_from_slice(sanad_id.as_bytes());
        CoreInclusionProof::new(bytes, Hash::new([1u8; 32]), slot, 0).unwrap()
    }

    #[test]
    fn runtime_lock_evidence_binds_sanad_id_and_slot() {
        let sanad_id = Hash::new([3u8; 32]);
        let proof = runtime_lock_proof(sanad_id, 475_386_071);

        assert!(verify_runtime_lock_proof_layout(&proof, &sanad_id).is_ok());
    }

    #[test]
    fn runtime_lock_evidence_rejects_wrong_sanad_id() {
        let proof = runtime_lock_proof(Hash::new([3u8; 32]), 475_386_071);

        assert!(verify_runtime_lock_proof_layout(&proof, &Hash::new([4u8; 32])).is_err());
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
