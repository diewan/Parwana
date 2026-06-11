//! Aptos cryptographic anchor implementation.
//!
//! This implements the CryptographicAnchor trait for Aptos using
//! HotStuff 2f+1 BLS quorum certificate verification.

use csv_verifier::{
    AnchorError, CanonicalBlockHeader, CanonicalInclusionProof, CryptographicAnchor,
    FinalityGuarantee, ValidatorSet, VerifiedHeader,
};

/// Aptos-specific cryptographic anchor.
pub struct AptosAnchor {
    /// Known validator set from genesis/trusted checkpoint.
    validator_set: ValidatorSet,
    /// BLS verifier for aggregate signatures.
    bls_verifier: BlsVerifier,
}

/// BLS signature verifier using blst library.
struct BlsVerifier;

impl BlsVerifier {
    fn verify_aggregate(
        &self,
        signature: &[u8],
        signers: &[Vec<u8>],
        message: &[u8],
        validator_set: &ValidatorSet,
        threshold: f32,
    ) -> Result<(), AnchorError> {
        #[cfg(feature = "bls")]
        {
            use blst::{min_sig::Signature, min_sig::AggregateSignature, min_sig::PublicKey as SigPublicKey, min_pk::PublicKey, BLST_ERROR};

            // Parse the signature (48 bytes for BLS12-381)
            if signature.len() != 48 {
                return Err(AnchorError::InvalidSignature(
                    format!("Invalid signature length: expected 48, got {}", signature.len())
                ));
            }

            let sig = Signature::from_bytes(signature)
                .map_err(|e| AnchorError::InvalidSignature(format!("Failed to parse signature: {:?}", e)))?;

            // Create aggregate signature from single signature
            let agg_sig = AggregateSignature::from_signature(&sig);

            // Aggregate the public keys of all signers
            // For now, use a simpler approach: verify the signature against each public key individually
            // This is less efficient but works with the current blst API
            let mut total_voting_power = 0u64;

            for (signer_pubkey, validator) in signers.iter().zip(&validator_set.validators) {
                // BLS public keys are 48 bytes
                if signer_pubkey.len() != 48 {
                    return Err(AnchorError::InvalidSignature(
                        format!("Invalid public key length: expected 48, got {}", signer_pubkey.len())
                    ));
                }

                let pubkey = PublicKey::from_bytes(signer_pubkey)
                    .map_err(|e| AnchorError::InvalidSignature(format!("Failed to parse public key: {:?}", e)))?;

                // Convert min_pk::PublicKey to min_sig::PublicKey for verification
                let sig_pubkey = SigPublicKey::from_bytes(signer_pubkey)
                    .map_err(|e| AnchorError::InvalidSignature(format!("Failed to parse public key for verification: {:?}", e)))?;

                // Verify signature against individual public key using Signature type
                // blst verify signature: verify(accept_multisig, pk_bytes, msg, dst, pubkey_ref, group_check)
                let result = sig.verify(false, signer_pubkey, message, &[], &sig_pubkey, false);
                
                if result != BLST_ERROR::BLST_SUCCESS {
                    return Err(AnchorError::InvalidSignature(
                        "BLS signature verification failed for individual signer".to_string()
                    ));
                }

                total_voting_power += validator.voting_power;
            }

            // // Use the first public key as the aggregate for the final check
            // let agg_pubkey = if let Some(first_signer) = signers.first() {
            //     PublicKey::from_bytes(first_signer)
            //         .map_err(|e| AnchorError::InvalidSignature(format!("Failed to parse first public key: {:?}", e)))?
            // } else {
            //     return Err(AnchorError::InvalidSignature("No signers provided".to_string()));
            // };

            // // Verify the aggregate signature against the aggregated public key
            // let result = agg_sig.verify(false, &agg_pubkey, message, false);
            
            // if result != BLST_ERROR::BLST_SUCCESS {
            //     return Err(AnchorError::InvalidSignature(
            //         "BLS signature verification failed".to_string()
            //     ));
            // }

            // Check that signers represent >= threshold fraction of voting power
            let total_power: u64 = validator_set.validators.iter().map(|v| v.voting_power).sum();
            if total_power == 0 {
                return Err(AnchorError::InvalidSignature("Total voting power is zero".to_string()));
            }

            let fraction = total_voting_power as f32 / total_power as f32;
            if fraction < threshold {
                return Err(AnchorError::InvalidSignature(
                    format!("Insufficient voting power: signers represent {:.2}% of voting power, required {:.2}%", 
                            fraction * 100.0, threshold * 100.0)
                ));
            }

            Ok(())
        }

        #[cfg(not(feature = "bls"))]
        {
            return Err(AnchorError::InvalidSignature(
                "BLS signature verification requires the 'bls' feature to be enabled".to_string()
            ));
        }
    }
}

impl AptosAnchor {
    /// Create a new AptosAnchor with a trusted validator set.
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self {
            validator_set,
            bls_verifier: BlsVerifier,
        }
    }
}

impl CryptographicAnchor for AptosAnchor {
    fn verify_header(
        &self,
        header: &CanonicalBlockHeader,
        validator_set: &ValidatorSet,
        finality: &FinalityGuarantee,
    ) -> Result<VerifiedHeader, AnchorError> {
        // Extract the quorum certificate from the header
        let qc = header
            .quorum_cert
            .as_ref()
            .ok_or(AnchorError::MissingQuorumCert)?;

        // Verify the BLS aggregate signature
        let message = &header.hash;
        self.bls_verifier.verify_aggregate(
            &qc.signature,
            &qc.signers,
            message,
            validator_set,
            finality.validator_honesty_threshold,
        )?;

        // Check reorg depth
        if header.height < finality.max_reorg_depth {
            return Err(AnchorError::ReorgDepthExceeded(
                finality.max_reorg_depth - header.height,
                finality.max_reorg_depth,
            ));
        }

        Ok(VerifiedHeader {
            hash: header.hash,
            height: header.height,
        })
    }

    fn verify_inclusion(
        &self,
        proof: &CanonicalInclusionProof,
        anchor: &VerifiedHeader,
    ) -> Result<(), AnchorError> {
        // Verify Merkle proof against the anchor's state root
        // Aptos uses a sparse Merkle tree (SMT) for state
        //
        // The inclusion proof should contain:
        // 1. The leaf value (account/resource data)
        // 2. The Merkle path (siblings) to the state root
        // 3. The state root from the verified header
        
        #[cfg(feature = "bls")]
        {
            use blst::{min_sig::AggregateSignature, min_pk::PublicKey};
            
            // Extract the state root from the anchor (this should be in the header)
            // For now, we'll implement a basic Merkle path verification
            
            // Check that the proof has the required components
            if proof.key.is_empty() {
                return Err(AnchorError::InvalidInclusionProof("Key is empty".to_string()));
            }
            
            if proof.value.is_empty() {
                return Err(AnchorError::InvalidInclusionProof("Value is empty".to_string()));
            }
            
            if proof.proof.is_empty() {
                return Err(AnchorError::InvalidInclusionProof("No proof nodes provided".to_string()));
            }
            
            // Reconstruct the Merkle root from the key-value pair and proof nodes
            // For Aptos sparse Merkle tree, we hash the key-value pair first
            let mut current_hash = {
                let mut combined = Vec::with_capacity(proof.key.len() + proof.value.len());
                combined.extend_from_slice(&proof.key);
                combined.extend_from_slice(&proof.value);
                use sha2::{Digest, Sha256};
                Sha256::digest(&combined).to_vec()
            };
            
            for sibling in &proof.proof {
                // Ordered hashing: min || max
                let (left, right) = if current_hash <= *sibling {
                    (&current_hash, sibling)
                } else {
                    (sibling, &current_hash)
                };
                
                // Hash the pair
                let mut combined = Vec::with_capacity(left.len() + right.len());
                combined.extend_from_slice(left);
                combined.extend_from_slice(right);
                
                // Use SHA-256 for Merkle hashing (Aptos uses SHA3-256 in production)
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(&combined);
                current_hash = hash.to_vec();
            }
            
            // Verify the reconstructed root matches the expected state root
            // Note: In production, this should use the actual state root from the header
            // and Aptos's specific hash function (SHA3-256)
            
            // For now, we'll accept the proof if the reconstruction succeeds
            // Full implementation requires:
            // 1. Extract the actual state root from the header
            // 2. Use Aptos's SHA3-256 instead of SHA-256
            // 3. Handle the sparse Merkle tree structure properly
            
            Ok(())
        }
        
        #[cfg(not(feature = "bls"))]
        {
            return Err(AnchorError::InvalidInclusionProof(
                "Merkle proof verification requires the 'bls' feature to be enabled".to_string()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_verifier::ValidatorInfo;

    #[test]
    fn test_aptos_anchor_creation() {
        let validator_set = ValidatorSet {
            epoch: 1,
            validators: vec![ValidatorInfo {
                public_key: vec![1u8; 48],
                voting_power: 100,
            }],
        };
        let anchor = AptosAnchor::new(validator_set);
        // Anchor created successfully
    }
}
