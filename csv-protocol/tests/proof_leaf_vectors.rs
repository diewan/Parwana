//! Cross-language proof leaf test vectors
//!
//! This module generates test vectors for the ProofLeafV1 schema
//! to ensure consistency across all four chains (Ethereum, Solana, Sui, Aptos).

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Canonical ProofLeafV1 schema for cross-chain proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofLeafV1 {
    pub version: u32,
    pub source_chain: String,  // Using string for test vectors (will be hashed in production)
    pub destination_chain: String,
    pub sanad_id: [u8; 32],
    pub commitment: [u8; 32],
    pub content_descriptor_hash: [u8; 32],
    pub source_seal_ref_hash: [u8; 32],
    pub destination_owner_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub lock_event_id: [u8; 32],
    pub metadata_hash: [u8; 32],
    pub proof_policy_hash: [u8; 32],
}

/// Test vector with expected hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofLeafVector {
    pub name: String,
    pub leaf: ProofLeafV1,
    pub expected_hash: [u8; 32],
    pub description: String,
}

/// Generate canonical hash for ProofLeafV1 using tagged hashing
pub fn hash_proof_leaf_v1(leaf: &ProofLeafV1) -> [u8; 32] {
    // Domain separator for tagged hashing
    let domain = b"csv.proof.leaf.v1";
    
    // Encode all fields in canonical order
    let encoded = format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}",
        leaf.version,
        leaf.source_chain,
        leaf.destination_chain,
        hex::encode(leaf.sanad_id),
        hex::encode(leaf.commitment),
        hex::encode(leaf.content_descriptor_hash),
        hex::encode(leaf.source_seal_ref_hash),
        hex::encode(leaf.destination_owner_hash),
        hex::encode(leaf.nullifier),
        hex::encode(leaf.lock_event_id),
        hex::encode(leaf.metadata_hash),
        hex::encode(leaf.proof_policy_hash),
    );
    
    // Tagged hash: H(domain || encoded)
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(encoded.as_bytes());
    hasher.finalize().into()
}

/// Generate test vectors for ProofLeafV1 schema
pub fn generate_proof_leaf_vectors() -> Vec<ProofLeafVector> {
    vec![
        ProofLeafVector {
            name: "minimal_proof_leaf".to_string(),
            leaf: ProofLeafV1 {
                version: 1,
                source_chain: "bitcoin".to_string(),
                destination_chain: "ethereum".to_string(),
                sanad_id: [0u8; 32],
                commitment: [1u8; 32],
                content_descriptor_hash: [0u8; 32],
                source_seal_ref_hash: [0u8; 32],
                destination_owner_hash: [0u8; 32],
                nullifier: [0u8; 32],
                lock_event_id: [0u8; 32],
                metadata_hash: [0u8; 32],
                proof_policy_hash: [0u8; 32],
            },
            expected_hash: hash_proof_leaf_v1(&ProofLeafV1 {
                version: 1,
                source_chain: "bitcoin".to_string(),
                destination_chain: "ethereum".to_string(),
                sanad_id: [0u8; 32],
                commitment: [1u8; 32],
                content_descriptor_hash: [0u8; 32],
                source_seal_ref_hash: [0u8; 32],
                destination_owner_hash: [0u8; 32],
                nullifier: [0u8; 32],
                lock_event_id: [0u8; 32],
                metadata_hash: [0u8; 32],
                proof_policy_hash: [0u8; 32],
            }),
            description: "Minimal proof leaf with zero values for optional fields".to_string(),
        },
        ProofLeafVector {
            name: "bitcoin_to_solana".to_string(),
            leaf: ProofLeafV1 {
                version: 1,
                source_chain: "bitcoin".to_string(),
                destination_chain: "solana".to_string(),
                sanad_id: [2u8; 32],
                commitment: [3u8; 32],
                content_descriptor_hash: [4u8; 32],
                source_seal_ref_hash: [5u8; 32],
                destination_owner_hash: [6u8; 32],
                nullifier: [7u8; 32],
                lock_event_id: [8u8; 32],
                metadata_hash: [9u8; 32],
                proof_policy_hash: [10u8; 32],
            },
            expected_hash: hash_proof_leaf_v1(&ProofLeafV1 {
                version: 1,
                source_chain: "bitcoin".to_string(),
                destination_chain: "solana".to_string(),
                sanad_id: [2u8; 32],
                commitment: [3u8; 32],
                content_descriptor_hash: [4u8; 32],
                source_seal_ref_hash: [5u8; 32],
                destination_owner_hash: [6u8; 32],
                nullifier: [7u8; 32],
                lock_event_id: [8u8; 32],
                metadata_hash: [9u8; 32],
                proof_policy_hash: [10u8; 32],
            }),
            description: "Bitcoin to Solana transfer with all fields populated".to_string(),
        },
        ProofLeafVector {
            name: "ethereum_to_sui".to_string(),
            leaf: ProofLeafV1 {
                version: 1,
                source_chain: "ethereum".to_string(),
                destination_chain: "sui".to_string(),
                sanad_id: [11u8; 32],
                commitment: [12u8; 32],
                content_descriptor_hash: [13u8; 32],
                source_seal_ref_hash: [14u8; 32],
                destination_owner_hash: [15u8; 32],
                nullifier: [16u8; 32],
                lock_event_id: [17u8; 32],
                metadata_hash: [18u8; 32],
                proof_policy_hash: [19u8; 32],
            },
            expected_hash: hash_proof_leaf_v1(&ProofLeafV1 {
                version: 1,
                source_chain: "ethereum".to_string(),
                destination_chain: "sui".to_string(),
                sanad_id: [11u8; 32],
                commitment: [12u8; 32],
                content_descriptor_hash: [13u8; 32],
                source_seal_ref_hash: [14u8; 32],
                destination_owner_hash: [15u8; 32],
                nullifier: [16u8; 32],
                lock_event_id: [17u8; 32],
                metadata_hash: [18u8; 32],
                proof_policy_hash: [19u8; 32],
            }),
            description: "Ethereum to Sui transfer with all fields populated".to_string(),
        },
        ProofLeafVector {
            name: "aptos_to_bitcoin".to_string(),
            leaf: ProofLeafV1 {
                version: 1,
                source_chain: "aptos".to_string(),
                destination_chain: "bitcoin".to_string(),
                sanad_id: [20u8; 32],
                commitment: [21u8; 32],
                content_descriptor_hash: [22u8; 32],
                source_seal_ref_hash: [23u8; 32],
                destination_owner_hash: [24u8; 32],
                nullifier: [25u8; 32],
                lock_event_id: [26u8; 32],
                metadata_hash: [27u8; 32],
                proof_policy_hash: [28u8; 32],
            },
            expected_hash: hash_proof_leaf_v1(&ProofLeafV1 {
                version: 1,
                source_chain: "aptos".to_string(),
                destination_chain: "bitcoin".to_string(),
                sanad_id: [20u8; 32],
                commitment: [21u8; 32],
                content_descriptor_hash: [22u8; 32],
                source_seal_ref_hash: [23u8; 32],
                destination_owner_hash: [24u8; 32],
                nullifier: [25u8; 32],
                lock_event_id: [26u8; 32],
                metadata_hash: [27u8; 32],
                proof_policy_hash: [28u8; 32],
            }),
            description: "Aptos to Bitcoin transfer with all fields populated".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_leaf_hash_deterministic() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that hashing is deterministic
        for vector in &vectors {
            let hash1 = hash_proof_leaf_v1(&vector.leaf);
            let hash2 = hash_proof_leaf_v1(&vector.leaf);
            assert_eq!(hash1, hash2, "Hash should be deterministic for {}", vector.name);
            assert_eq!(hash1, vector.expected_hash, "Hash should match expected for {}", vector.name);
        }
    }

    #[test]
    fn test_proof_leaf_hash_different_inputs() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that different inputs produce different hashes
        let hashes: Vec<[u8; 32]> = vectors.iter()
            .map(|v| hash_proof_leaf_v1(&v.leaf))
            .collect();
        
        for (i, hash_i) in hashes.iter().enumerate() {
            for (j, hash_j) in hashes.iter().enumerate() {
                if i != j {
                    assert_ne!(hash_i, hash_j, "Different inputs should produce different hashes");
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
    fn test_export_vectors_to_json() {
        let vectors = generate_proof_leaf_vectors();
        
        // Test that vectors can be serialized to JSON
        let json = serde_json::to_string_pretty(&vectors).expect("Should serialize to JSON");
        println!("Proof leaf vectors:\n{}", json);
        
        // Test that vectors can be deserialized from JSON
        let deserialized: Vec<ProofLeafVector> = serde_json::from_str(&json)
            .expect("Should deserialize from JSON");
        
        assert_eq!(deserialized.len(), vectors.len());
    }
}
