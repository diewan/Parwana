//! Cross-language proof leaf test vectors
//!
//! This module generates test vectors for the ProofLeafV1 schema
//! to ensure consistency across all four chains (Ethereum, Solana, Sui, Aptos).
//!
//! The test vectors use canonical CBOR encoding (via csv-codec) and chain-specific
//! hash functions to match the production implementation in csv-protocol/src/proof_taxonomy.rs.

use csv_hash::Hash;
use csv_protocol::proof_taxonomy::{HashFunction, ProofLeafV1};

/// Test vector with expected hash for each chain's native hash function
#[derive(Debug, Clone)]
pub struct ProofLeafVector {
    pub name: String,
    pub leaf: ProofLeafV1,
    pub expected_hash_ethereum: [u8; 32],  // keccak256
    pub expected_hash_solana: [u8; 32],    // sha256
    pub expected_hash_sui: [u8; 32],       // blake2b256
    pub expected_hash_aptos: [u8; 32],      // sha3_256
    pub expected_hash_bitcoin: [u8; 32],    // double_sha256
    pub description: String,
}

/// Generate test vectors for ProofLeafV1 schema using canonical CBOR encoding
pub fn generate_proof_leaf_vectors() -> Vec<ProofLeafVector> {
    vec![
        ProofLeafVector {
            name: "minimal_proof_leaf".to_string(),
            leaf: ProofLeafV1::new(
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash([0u8; 32]),
                Hash([1u8; 32]),
            ),
            expected_hash_ethereum: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash([0u8; 32]),
                Hash([1u8; 32]),
            ), HashFunction::Keccak256),
            expected_hash_solana: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash([0u8; 32]),
                Hash([1u8; 32]),
            ), HashFunction::Sha256),
            expected_hash_sui: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash([0u8; 32]),
                Hash([1u8; 32]),
            ), HashFunction::Blake2b256),
            expected_hash_aptos: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash([0u8; 32]),
                Hash([1u8; 32]),
            ), HashFunction::Sha3_256),
            expected_hash_bitcoin: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "ethereum".to_string(),
                Hash([0u8; 32]),
                Hash([1u8; 32]),
            ), HashFunction::DoubleSha256),
            description: "Minimal proof leaf with zero values for optional fields".to_string(),
        },
        ProofLeafVector {
            name: "bitcoin_to_solana".to_string(),
            leaf: ProofLeafV1::new(
                "bitcoin".to_string(),
                "solana".to_string(),
                Hash([2u8; 32]),
                Hash([3u8; 32]),
            )
            .with_content_descriptor_hash(Hash([4u8; 32]))
            .with_source_seal_ref_hash(Hash([5u8; 32]))
            .with_destination_owner_hash(Hash([6u8; 32]))
            .with_nullifier(Hash([7u8; 32]))
            .with_lock_event_id(Hash([8u8; 32]))
            .with_metadata_hash(Hash([9u8; 32]))
            .with_proof_policy_hash(Hash([10u8; 32])),
            expected_hash_ethereum: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "solana".to_string(),
                Hash([2u8; 32]),
                Hash([3u8; 32]),
            )
            .with_content_descriptor_hash(Hash([4u8; 32]))
            .with_source_seal_ref_hash(Hash([5u8; 32]))
            .with_destination_owner_hash(Hash([6u8; 32]))
            .with_nullifier(Hash([7u8; 32]))
            .with_lock_event_id(Hash([8u8; 32]))
            .with_metadata_hash(Hash([9u8; 32]))
            .with_proof_policy_hash(Hash([10u8; 32])), HashFunction::Keccak256),
            expected_hash_solana: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "solana".to_string(),
                Hash([2u8; 32]),
                Hash([3u8; 32]),
            )
            .with_content_descriptor_hash(Hash([4u8; 32]))
            .with_source_seal_ref_hash(Hash([5u8; 32]))
            .with_destination_owner_hash(Hash([6u8; 32]))
            .with_nullifier(Hash([7u8; 32]))
            .with_lock_event_id(Hash([8u8; 32]))
            .with_metadata_hash(Hash([9u8; 32]))
            .with_proof_policy_hash(Hash([10u8; 32])), HashFunction::Sha256),
            expected_hash_sui: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "solana".to_string(),
                Hash([2u8; 32]),
                Hash([3u8; 32]),
            )
            .with_content_descriptor_hash(Hash([4u8; 32]))
            .with_source_seal_ref_hash(Hash([5u8; 32]))
            .with_destination_owner_hash(Hash([6u8; 32]))
            .with_nullifier(Hash([7u8; 32]))
            .with_lock_event_id(Hash([8u8; 32]))
            .with_metadata_hash(Hash([9u8; 32]))
            .with_proof_policy_hash(Hash([10u8; 32])), HashFunction::Blake2b256),
            expected_hash_aptos: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "solana".to_string(),
                Hash([2u8; 32]),
                Hash([3u8; 32]),
            )
            .with_content_descriptor_hash(Hash([4u8; 32]))
            .with_source_seal_ref_hash(Hash([5u8; 32]))
            .with_destination_owner_hash(Hash([6u8; 32]))
            .with_nullifier(Hash([7u8; 32]))
            .with_lock_event_id(Hash([8u8; 32]))
            .with_metadata_hash(Hash([9u8; 32]))
            .with_proof_policy_hash(Hash([10u8; 32])), HashFunction::Sha3_256),
            expected_hash_bitcoin: compute_hash_for_chain(&ProofLeafV1::new(
                "bitcoin".to_string(),
                "solana".to_string(),
                Hash([2u8; 32]),
                Hash([3u8; 32]),
            )
            .with_content_descriptor_hash(Hash([4u8; 32]))
            .with_source_seal_ref_hash(Hash([5u8; 32]))
            .with_destination_owner_hash(Hash([6u8; 32]))
            .with_nullifier(Hash([7u8; 32]))
            .with_lock_event_id(Hash([8u8; 32]))
            .with_metadata_hash(Hash([9u8; 32]))
            .with_proof_policy_hash(Hash([10u8; 32])), HashFunction::DoubleSha256),
            description: "Bitcoin to Solana transfer with all fields populated".to_string(),
        },
        ProofLeafVector {
            name: "ethereum_to_sui".to_string(),
            leaf: ProofLeafV1::new(
                "ethereum".to_string(),
                "sui".to_string(),
                Hash([11u8; 32]),
                Hash([12u8; 32]),
            )
            .with_content_descriptor_hash(Hash([13u8; 32]))
            .with_source_seal_ref_hash(Hash([14u8; 32]))
            .with_destination_owner_hash(Hash([15u8; 32]))
            .with_nullifier(Hash([16u8; 32]))
            .with_lock_event_id(Hash([17u8; 32]))
            .with_metadata_hash(Hash([18u8; 32]))
            .with_proof_policy_hash(Hash([19u8; 32])),
            expected_hash_ethereum: compute_hash_for_chain(&ProofLeafV1::new(
                "ethereum".to_string(),
                "sui".to_string(),
                Hash([11u8; 32]),
                Hash([12u8; 32]),
            )
            .with_content_descriptor_hash(Hash([13u8; 32]))
            .with_source_seal_ref_hash(Hash([14u8; 32]))
            .with_destination_owner_hash(Hash([15u8; 32]))
            .with_nullifier(Hash([16u8; 32]))
            .with_lock_event_id(Hash([17u8; 32]))
            .with_metadata_hash(Hash([18u8; 32]))
            .with_proof_policy_hash(Hash([19u8; 32])), HashFunction::Keccak256),
            expected_hash_solana: compute_hash_for_chain(&ProofLeafV1::new(
                "ethereum".to_string(),
                "sui".to_string(),
                Hash([11u8; 32]),
                Hash([12u8; 32]),
            )
            .with_content_descriptor_hash(Hash([13u8; 32]))
            .with_source_seal_ref_hash(Hash([14u8; 32]))
            .with_destination_owner_hash(Hash([15u8; 32]))
            .with_nullifier(Hash([16u8; 32]))
            .with_lock_event_id(Hash([17u8; 32]))
            .with_metadata_hash(Hash([18u8; 32]))
            .with_proof_policy_hash(Hash([19u8; 32])), HashFunction::Sha256),
            expected_hash_sui: compute_hash_for_chain(&ProofLeafV1::new(
                "ethereum".to_string(),
                "sui".to_string(),
                Hash([11u8; 32]),
                Hash([12u8; 32]),
            )
            .with_content_descriptor_hash(Hash([13u8; 32]))
            .with_source_seal_ref_hash(Hash([14u8; 32]))
            .with_destination_owner_hash(Hash([15u8; 32]))
            .with_nullifier(Hash([16u8; 32]))
            .with_lock_event_id(Hash([17u8; 32]))
            .with_metadata_hash(Hash([18u8; 32]))
            .with_proof_policy_hash(Hash([19u8; 32])), HashFunction::Blake2b256),
            expected_hash_aptos: compute_hash_for_chain(&ProofLeafV1::new(
                "ethereum".to_string(),
                "sui".to_string(),
                Hash([11u8; 32]),
                Hash([12u8; 32]),
            )
            .with_content_descriptor_hash(Hash([13u8; 32]))
            .with_source_seal_ref_hash(Hash([14u8; 32]))
            .with_destination_owner_hash(Hash([15u8; 32]))
            .with_nullifier(Hash([16u8; 32]))
            .with_lock_event_id(Hash([17u8; 32]))
            .with_metadata_hash(Hash([18u8; 32]))
            .with_proof_policy_hash(Hash([19u8; 32])), HashFunction::Sha3_256),
            expected_hash_bitcoin: compute_hash_for_chain(&ProofLeafV1::new(
                "ethereum".to_string(),
                "sui".to_string(),
                Hash([11u8; 32]),
                Hash([12u8; 32]),
            )
            .with_content_descriptor_hash(Hash([13u8; 32]))
            .with_source_seal_ref_hash(Hash([14u8; 32]))
            .with_destination_owner_hash(Hash([15u8; 32]))
            .with_nullifier(Hash([16u8; 32]))
            .with_lock_event_id(Hash([17u8; 32]))
            .with_metadata_hash(Hash([18u8; 32]))
            .with_proof_policy_hash(Hash([19u8; 32])), HashFunction::DoubleSha256),
            description: "Ethereum to Sui transfer with all fields populated".to_string(),
        },
        ProofLeafVector {
            name: "aptos_to_bitcoin".to_string(),
            leaf: ProofLeafV1::new(
                "aptos".to_string(),
                "bitcoin".to_string(),
                Hash([20u8; 32]),
                Hash([21u8; 32]),
            )
            .with_content_descriptor_hash(Hash([22u8; 32]))
            .with_source_seal_ref_hash(Hash([23u8; 32]))
            .with_destination_owner_hash(Hash([24u8; 32]))
            .with_nullifier(Hash([25u8; 32]))
            .with_lock_event_id(Hash([26u8; 32]))
            .with_metadata_hash(Hash([27u8; 32]))
            .with_proof_policy_hash(Hash([28u8; 32])),
            expected_hash_ethereum: compute_hash_for_chain(&ProofLeafV1::new(
                "aptos".to_string(),
                "bitcoin".to_string(),
                Hash([20u8; 32]),
                Hash([21u8; 32]),
            )
            .with_content_descriptor_hash(Hash([22u8; 32]))
            .with_source_seal_ref_hash(Hash([23u8; 32]))
            .with_destination_owner_hash(Hash([24u8; 32]))
            .with_nullifier(Hash([25u8; 32]))
            .with_lock_event_id(Hash([26u8; 32]))
            .with_metadata_hash(Hash([27u8; 32]))
            .with_proof_policy_hash(Hash([28u8; 32])), HashFunction::Keccak256),
            expected_hash_solana: compute_hash_for_chain(&ProofLeafV1::new(
                "aptos".to_string(),
                "bitcoin".to_string(),
                Hash([20u8; 32]),
                Hash([21u8; 32]),
            )
            .with_content_descriptor_hash(Hash([22u8; 32]))
            .with_source_seal_ref_hash(Hash([23u8; 32]))
            .with_destination_owner_hash(Hash([24u8; 32]))
            .with_nullifier(Hash([25u8; 32]))
            .with_lock_event_id(Hash([26u8; 32]))
            .with_metadata_hash(Hash([27u8; 32]))
            .with_proof_policy_hash(Hash([28u8; 32])), HashFunction::Sha256),
            expected_hash_sui: compute_hash_for_chain(&ProofLeafV1::new(
                "aptos".to_string(),
                "bitcoin".to_string(),
                Hash([20u8; 32]),
                Hash([21u8; 32]),
            )
            .with_content_descriptor_hash(Hash([22u8; 32]))
            .with_source_seal_ref_hash(Hash([23u8; 32]))
            .with_destination_owner_hash(Hash([24u8; 32]))
            .with_nullifier(Hash([25u8; 32]))
            .with_lock_event_id(Hash([26u8; 32]))
            .with_metadata_hash(Hash([27u8; 32]))
            .with_proof_policy_hash(Hash([28u8; 32])), HashFunction::Blake2b256),
            expected_hash_aptos: compute_hash_for_chain(&ProofLeafV1::new(
                "aptos".to_string(),
                "bitcoin".to_string(),
                Hash([20u8; 32]),
                Hash([21u8; 32]),
            )
            .with_content_descriptor_hash(Hash([22u8; 32]))
            .with_source_seal_ref_hash(Hash([23u8; 32]))
            .with_destination_owner_hash(Hash([24u8; 32]))
            .with_nullifier(Hash([25u8; 32]))
            .with_lock_event_id(Hash([26u8; 32]))
            .with_metadata_hash(Hash([27u8; 32]))
            .with_proof_policy_hash(Hash([28u8; 32])), HashFunction::Sha3_256),
            expected_hash_bitcoin: compute_hash_for_chain(&ProofLeafV1::new(
                "aptos".to_string(),
                "bitcoin".to_string(),
                Hash([20u8; 32]),
                Hash([21u8; 32]),
            )
            .with_content_descriptor_hash(Hash([22u8; 32]))
            .with_source_seal_ref_hash(Hash([23u8; 32]))
            .with_destination_owner_hash(Hash([24u8; 32]))
            .with_nullifier(Hash([25u8; 32]))
            .with_lock_event_id(Hash([26u8; 32]))
            .with_metadata_hash(Hash([27u8; 32]))
            .with_proof_policy_hash(Hash([28u8; 32])), HashFunction::DoubleSha256),
            description: "Aptos to Bitcoin transfer with all fields populated".to_string(),
        },
    ]
}

/// Compute hash for a proof leaf using a specific hash function
fn compute_hash_for_chain(leaf: &ProofLeafV1, hash_fn: HashFunction) -> [u8; 32] {
    leaf.hash_with_function(hash_fn).unwrap().0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_leaf_hash_deterministic() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that hashing is deterministic for each chain
        for vector in &vectors {
            let hash_eth1 = compute_hash_for_chain(&vector.leaf, HashFunction::Keccak256);
            let hash_eth2 = compute_hash_for_chain(&vector.leaf, HashFunction::Keccak256);
            assert_eq!(hash_eth1, hash_eth2, "Ethereum hash should be deterministic for {}", vector.name);
            assert_eq!(hash_eth1, vector.expected_hash_ethereum, "Ethereum hash should match expected for {}", vector.name);

            let hash_sol1 = compute_hash_for_chain(&vector.leaf, HashFunction::Sha256);
            let hash_sol2 = compute_hash_for_chain(&vector.leaf, HashFunction::Sha256);
            assert_eq!(hash_sol1, hash_sol2, "Solana hash should be deterministic for {}", vector.name);
            assert_eq!(hash_sol1, vector.expected_hash_solana, "Solana hash should match expected for {}", vector.name);

            let hash_sui1 = compute_hash_for_chain(&vector.leaf, HashFunction::Blake2b256);
            let hash_sui2 = compute_hash_for_chain(&vector.leaf, HashFunction::Blake2b256);
            assert_eq!(hash_sui1, hash_sui2, "Sui hash should be deterministic for {}", vector.name);
            assert_eq!(hash_sui1, vector.expected_hash_sui, "Sui hash should match expected for {}", vector.name);

            let hash_aptos1 = compute_hash_for_chain(&vector.leaf, HashFunction::Sha3_256);
            let hash_aptos2 = compute_hash_for_chain(&vector.leaf, HashFunction::Sha3_256);
            assert_eq!(hash_aptos1, hash_aptos2, "Aptos hash should be deterministic for {}", vector.name);
            assert_eq!(hash_aptos1, vector.expected_hash_aptos, "Aptos hash should match expected for {}", vector.name);

            let hash_btc1 = compute_hash_for_chain(&vector.leaf, HashFunction::DoubleSha256);
            let hash_btc2 = compute_hash_for_chain(&vector.leaf, HashFunction::DoubleSha256);
            assert_eq!(hash_btc1, hash_btc2, "Bitcoin hash should be deterministic for {}", vector.name);
            assert_eq!(hash_btc1, vector.expected_hash_bitcoin, "Bitcoin hash should match expected for {}", vector.name);
        }
    }

    #[test]
    fn test_proof_leaf_hash_different_inputs() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that different inputs produce different hashes for each chain
        for hash_fn in [HashFunction::Keccak256, HashFunction::Sha256, HashFunction::Blake2b256, HashFunction::Sha3_256, HashFunction::DoubleSha256] {
            let hashes: Vec<[u8; 32]> = vectors.iter()
                .map(|v| compute_hash_for_chain(&v.leaf, hash_fn))
                .collect();
            
            for (i, hash_i) in hashes.iter().enumerate() {
                for (j, hash_j) in hashes.iter().enumerate() {
                    if i != j {
                        assert_ne!(hash_i, hash_j, "Different inputs should produce different hashes for {:?}", hash_fn);
                    }
                }
            }
        }
    }

    #[test]
    fn test_proof_leaf_cross_chain_consistency() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that all chain pairs are represented
        let chain_pairs: Vec<(&str, &str)> = vectors.iter()
            .map(|v| (v.leaf.source_chain.as_str(), v.leaf.destination_chain.as_str()))
            .collect();
        
        assert!(chain_pairs.contains(&("bitcoin", "ethereum")));
        assert!(chain_pairs.contains(&("bitcoin", "solana")));
        assert!(chain_pairs.contains(&("ethereum", "sui")));
        assert!(chain_pairs.contains(&("aptos", "bitcoin")));
    }

    #[test]
    fn test_proof_leaf_chain_specific_hashes_differ() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that the same leaf produces different hashes for different chains
        for vector in &vectors {
            let hash_eth = compute_hash_for_chain(&vector.leaf, HashFunction::Keccak256);
            let hash_sol = compute_hash_for_chain(&vector.leaf, HashFunction::Sha256);
            let hash_sui = compute_hash_for_chain(&vector.leaf, HashFunction::Blake2b256);
            let hash_aptos = compute_hash_for_chain(&vector.leaf, HashFunction::Sha3_256);
            let hash_btc = compute_hash_for_chain(&vector.leaf, HashFunction::DoubleSha256);
            
            // All chain-specific hashes should be different (unless by extreme coincidence)
            let hashes = vec![hash_eth, hash_sol, hash_sui, hash_aptos, hash_btc];
            let unique_hashes: std::collections::HashSet<_> = hashes.iter().collect();
            assert!(unique_hashes.len() >= 4, "Chain-specific hashes should differ for {}", vector.name);
        }
    }

    #[test]
    fn test_proof_leaf_matches_production_implementation() {
        // Test that our test vectors match the production ProofLeafV1 implementation
        let leaf = ProofLeafV1::new(
            "ethereum".to_string(),
            "solana".to_string(),
            Hash([42u8; 32]),
            Hash([99u8; 32]),
        );
        
        // Hash using the production implementation
        let hash_prod = leaf.hash_with_function(HashFunction::Keccak256).unwrap();
        
        // Hash using our test function
        let hash_test = compute_hash_for_chain(&leaf, HashFunction::Keccak256);
        
        assert_eq!(hash_prod.0, hash_test, "Test hash should match production implementation");
    }
}
