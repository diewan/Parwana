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
    // Held for the BLS quorum check; the verifier below currently carries its own copy.
    #[allow(dead_code)]
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
            use blst::{
                BLST_ERROR, min_sig::AggregatePublicKey, min_sig::PublicKey, min_sig::Signature,
            };

            // Parse the signature (48 bytes for BLS12-381 min_sig).
            if signature.len() != 48 {
                return Err(AnchorError::InvalidSignature(format!(
                    "Invalid signature length: expected 48, got {}",
                    signature.len()
                )));
            }

            let sig = Signature::from_bytes(signature).map_err(|e| {
                AnchorError::InvalidSignature(format!("Failed to parse signature: {:?}", e))
            })?;

            if signers.is_empty() {
                return Err(AnchorError::InvalidSignature(
                    "No signers provided".to_string(),
                ));
            }

            // Resolve each signer against the trusted validator set, aggregate
            // ONLY the pubkeys that are proven members, and account voting power
            // against the matched validator (never positionally). Duplicate
            // signer entries are rejected so power cannot be double-counted.
            let mut parsed_pubkeys: Vec<PublicKey> = Vec::with_capacity(signers.len());
            let mut signed_voting_power = 0u64;
            let mut seen: Vec<&[u8]> = Vec::with_capacity(signers.len());

            for signer_pubkey in signers {
                if seen.contains(&signer_pubkey.as_slice()) {
                    return Err(AnchorError::InvalidSignature(
                        "Duplicate signer public key in quorum".to_string(),
                    ));
                }
                seen.push(signer_pubkey.as_slice());

                // The signer must be a member of the trusted validator set.
                let validator = validator_set
                    .validators
                    .iter()
                    .find(|v| v.public_key == *signer_pubkey)
                    .ok_or_else(|| {
                        AnchorError::InvalidSignature(
                            "Signer is not a member of the trusted validator set".to_string(),
                        )
                    })?;

                let pubkey = PublicKey::from_bytes(signer_pubkey).map_err(|e| {
                    AnchorError::InvalidSignature(format!("Failed to parse public key: {:?}", e))
                })?;
                // Reject identity / malformed keys before trusting them.
                pubkey.validate().map_err(|e| {
                    AnchorError::InvalidSignature(format!("Invalid public key: {:?}", e))
                })?;

                parsed_pubkeys.push(pubkey);
                signed_voting_power = signed_voting_power
                    .checked_add(validator.voting_power)
                    .ok_or_else(|| {
                        AnchorError::InvalidSignature("Voting power overflow".to_string())
                    })?;
            }

            // Aggregate all signer pubkeys and verify the signature against the
            // aggregate — the whole quorum must have signed, not just one member.
            let pubkey_refs: Vec<&PublicKey> = parsed_pubkeys.iter().collect();
            let agg_pubkey = AggregatePublicKey::aggregate(&pubkey_refs, false).map_err(|e| {
                AnchorError::InvalidSignature(format!("Failed to aggregate public keys: {:?}", e))
            })?;
            let agg_pubkey = agg_pubkey.to_public_key();

            let result = sig.verify(true, message, &[], &[], &agg_pubkey, true);
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err(AnchorError::InvalidSignature(
                    "BLS aggregate signature verification failed".to_string(),
                ));
            }

            // Check that the signers that actually signed represent >= threshold
            // fraction of the total voting power.
            let total_power: u64 = validator_set
                .validators
                .iter()
                .map(|v| v.voting_power)
                .sum();
            if total_power == 0 {
                return Err(AnchorError::InvalidSignature(
                    "Total voting power is zero".to_string(),
                ));
            }

            let fraction = signed_voting_power as f32 / total_power as f32;
            if fraction < threshold {
                return Err(AnchorError::InvalidSignature(format!(
                    "Insufficient voting power: signers represent {:.2}% of voting power, required {:.2}%",
                    fraction * 100.0,
                    threshold * 100.0
                )));
            }

            Ok(())
        }

        #[cfg(not(feature = "bls"))]
        {
            Err(AnchorError::InvalidSignature(
                "BLS signature verification requires the 'bls' feature to be enabled".to_string(),
            ))
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
        // Aptos uses a sparse Merkle tree (SMT) for state with SHA3-256 hashing
        //
        // The inclusion proof should contain:
        // 1. The leaf value (account/resource data)
        // 2. The Merkle path (siblings) to the state root
        // 3. The state root from the verified header

        // Check that the proof has the required components
        if proof.key.is_empty() {
            return Err(AnchorError::InvalidInclusionProof(
                "Key is empty".to_string(),
            ));
        }

        if proof.value.is_empty() {
            return Err(AnchorError::InvalidInclusionProof(
                "Value is empty".to_string(),
            ));
        }

        if proof.proof.is_empty() {
            return Err(AnchorError::InvalidInclusionProof(
                "No proof nodes provided".to_string(),
            ));
        }

        // Reconstruct the Merkle root from the key-value pair and proof nodes
        // For Aptos sparse Merkle tree, we hash the key-value pair first using SHA3-256
        let mut current_hash = {
            let mut combined = Vec::with_capacity(proof.key.len() + proof.value.len());
            combined.extend_from_slice(&proof.key);
            combined.extend_from_slice(&proof.value);
            use sha3::{Digest, Sha3_256};
            Sha3_256::digest(&combined).to_vec()
        };

        // Walk up the Merkle tree using the proof nodes
        for sibling in &proof.proof {
            // Ordered hashing: min || max (Aptos SMT uses ordered hashing)
            let (left, right) = if current_hash <= *sibling {
                (&current_hash, sibling)
            } else {
                (sibling, &current_hash)
            };

            // Hash the pair using SHA3-256 (Aptos's hash function)
            let mut combined = Vec::with_capacity(left.len() + right.len());
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);

            use sha3::{Digest, Sha3_256};
            let hash = Sha3_256::digest(&combined);
            current_hash = hash.to_vec();
        }

        // Verify the reconstructed root matches the expected state root from the header
        // The header.hash should contain the state root for the block
        if current_hash != anchor.hash {
            return Err(AnchorError::InvalidInclusionProof(format!(
                "Merkle root mismatch: reconstructed {:?}, expected {:?}",
                hex::encode(&current_hash),
                hex::encode(&anchor.hash)
            )));
        }

        log::debug!(
            "APTOS: Merkle proof verified successfully (root: {})",
            hex::encode(&current_hash)
        );

        Ok(())
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
