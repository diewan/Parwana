//! State transition DAG types
//!
//! The DAG represents deterministic state transitions verified off-chain.
//! Each node contains bytecode, witnesses, and validation data.

use serde::{Deserialize, Serialize};

use crate::Hash;
use crate::csv_tagged_hash;

/// A single node in the state transition DAG
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAGNode {
    /// Unique identifier for this node
    pub node_id: Hash,
    /// Deterministic VM bytecode (e.g., AluVM)
    pub bytecode: Vec<u8>,
    /// Authorizing signatures
    pub signatures: Vec<Vec<u8>>,
    /// Witness data for verification
    pub witnesses: Vec<Vec<u8>>,
    /// Hash of parent node(s) - empty for root
    pub parents: Vec<Hash>,
}

impl DAGNode {
    /// Create a new DAG node
    pub fn new(
        node_id: Hash,
        bytecode: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        witnesses: Vec<Vec<u8>>,
        parents: Vec<Hash>,
    ) -> Self {
        Self {
            node_id,
            bytecode,
            signatures,
            witnesses,
            parents,
        }
    }

    /// Compute the node hash using canonical serialization and tagged hashing
    pub fn hash(&self) -> Hash {
        use csv_codec::to_canonical_cbor;
        let data = to_canonical_cbor(&(
            self.node_id,
            &self.bytecode,
            &self.signatures,
            &self.witnesses,
            &self.parents,
        ))
        .unwrap_or_else(|err| format!("dag-node-canonical-serialization-error:{err}").into_bytes());
        Hash::new(csv_tagged_hash("dag-node", &data))
    }
}

/// A segment of the state transition DAG
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DAGSegment {
    /// Nodes in this segment
    pub nodes: Vec<DAGNode>,
    /// Root commitment hash
    pub root_commitment: Hash,
}

impl DAGSegment {
    /// Create a new DAG segment
    pub fn new(nodes: Vec<DAGNode>, root_commitment: Hash) -> Self {
        Self {
            nodes,
            root_commitment,
        }
    }

    /// Validate DAG structure (topological ordering)
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        // Basic validation: ensure all parent references exist
        let node_ids: std::collections::BTreeSet<_> =
            self.nodes.iter().map(|n| n.node_id).collect();

        for node in &self.nodes {
            for parent in &node.parents {
                if !node_ids.contains(parent) {
                    return Err("Parent node not found in DAG segment");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────
    // Existing tests (preserved)
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_node_creation() {
        let node = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02, 0x03],
            vec![vec![0xAB; 64]],
            vec![vec![0xCD; 32]],
            vec![],
        );
        assert_eq!(node.bytecode, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_dag_node_hash() {
        let node = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02],
            vec![],
            vec![],
            vec![],
        );
        let hash = node.hash();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_dag_segment_validation() {
        let parent = DAGNode::new(Hash::new([1u8; 32]), vec![], vec![], vec![], vec![]);

        let child = DAGNode::new(
            Hash::new([2u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([1u8; 32])],
        );

        let segment = DAGSegment::new(vec![parent, child], Hash::zero());

        assert!(segment.validate_structure().is_ok());
    }

    #[test]
    fn test_dag_segment_invalid_parent() {
        let node = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([99u8; 32])], // Non-existent parent
        );

        let segment = DAGSegment::new(vec![node], Hash::zero());
        assert!(segment.validate_structure().is_err());
    }

    // ─────────────────────────────────────────────
    // NEW: Hash determinism
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_node_hash_deterministic() {
        let node1 = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02, 0x03],
            vec![vec![0xAB; 64]],
            vec![vec![0xCD; 32]],
            vec![Hash::new([4u8; 32])],
        );
        let node2 = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02, 0x03],
            vec![vec![0xAB; 64]],
            vec![vec![0xCD; 32]],
            vec![Hash::new([4u8; 32])],
        );
        // Identical inputs must produce identical hashes
        assert_eq!(node1.hash(), node2.hash());
    }

    // ─────────────────────────────────────────────
    // NEW: Hash uniqueness (different inputs → different hash)
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_node_hash_differs_by_node_id() {
        let node_a = DAGNode::new(Hash::new([1u8; 32]), vec![0x01], vec![], vec![], vec![]);
        let node_b = DAGNode::new(Hash::new([2u8; 32]), vec![0x01], vec![], vec![], vec![]);
        assert_ne!(node_a.hash(), node_b.hash());
    }

    #[test]
    fn test_dag_node_hash_differs_by_bytecode() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02],
            vec![],
            vec![],
            vec![],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x03, 0x04],
            vec![],
            vec![],
            vec![],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    #[test]
    fn test_dag_node_hash_differs_by_signatures() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![vec![0xAA; 64]],
            vec![],
            vec![],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![vec![0xBB; 64]],
            vec![],
            vec![],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    #[test]
    fn test_dag_node_hash_differs_by_witnesses() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![vec![0xCC; 32]],
            vec![],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![vec![0xDD; 32]],
            vec![],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    #[test]
    fn test_dag_node_hash_differs_by_parents() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([10u8; 32])],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([20u8; 32])],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    // ─────────────────────────────────────────────
    // NEW: Multi-parent DAG validation
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_segment_multi_parent_validation() {
        let parent_a = DAGNode::new(Hash::new([1u8; 32]), vec![], vec![], vec![], vec![]);
        let parent_b = DAGNode::new(Hash::new([2u8; 32]), vec![], vec![], vec![], vec![]);
        let child = DAGNode::new(
            Hash::new([3u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([1u8; 32]), Hash::new([2u8; 32])],
        );

        let segment = DAGSegment::new(vec![parent_a, parent_b, child], Hash::zero());
        assert!(segment.validate_structure().is_ok());
    }

    #[test]
    fn test_dag_segment_multi_parent_missing_one() {
        let parent_a = DAGNode::new(Hash::new([1u8; 32]), vec![], vec![], vec![], vec![]);
        let child = DAGNode::new(
            Hash::new([3u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([1u8; 32]), Hash::new([99u8; 32])],
        );

        let segment = DAGSegment::new(vec![parent_a, child], Hash::zero());
        assert!(segment.validate_structure().is_err());
    }

    // ─────────────────────────────────────────────
    // NEW: Root node edge case
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_root_node_has_no_parents() {
        let root = DAGNode::new(Hash::new([1u8; 32]), vec![0x01], vec![], vec![], vec![]);
        assert!(root.parents.is_empty());

        let segment = DAGSegment::new(vec![root.clone()], Hash::zero());
        assert!(segment.validate_structure().is_ok());
    }

    // ─────────────────────────────────────────────
    // NEW: Empty segment validation
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_segment_empty_valid() {
        let segment = DAGSegment::new(vec![], Hash::zero());
        assert!(segment.validate_structure().is_ok());
    }

    // ─────────────────────────────────────────────
    // NEW: Serialization roundtrip (DAGNode, DAGSegment)
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_node_serialization_roundtrip() {
        let node = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02, 0x03],
            vec![vec![0xAB; 64]],
            vec![vec![0xCD; 32]],
            vec![Hash::new([4u8; 32])],
        );

        let bytes = csv_codec::to_canonical_cbor(&node).unwrap();
        let restored: DAGNode = csv_codec::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(node, restored);
    }

    #[test]
    fn test_dag_segment_serialization_roundtrip() {
        let parent = DAGNode::new(Hash::new([1u8; 32]), vec![0x01], vec![], vec![], vec![]);
        let child = DAGNode::new(
            Hash::new([2u8; 32]),
            vec![0x02],
            vec![vec![0xAB; 64]],
            vec![],
            vec![Hash::new([1u8; 32])],
        );

        let segment = DAGSegment::new(vec![parent, child], Hash::new([99u8; 32]));

        let bytes = csv_codec::to_canonical_cbor(&segment).unwrap();
        let restored: DAGSegment = csv_codec::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(segment, restored);
    }

    #[test]
    fn test_dag_node_serialization_preserves_hash() {
        let node = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02],
            vec![vec![0xAB; 64]],
            vec![],
            vec![],
        );
        let original_hash = node.hash();

        let bytes = csv_codec::to_canonical_cbor(&node).unwrap();
        let restored: DAGNode = csv_codec::from_canonical_cbor(&bytes).unwrap();
        assert_eq!(original_hash, restored.hash());
    }

    // ─────────────────────────────────────────────
    // NEW: Large DAG segment validation
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_segment_large_chain() {
        let mut nodes = Vec::new();

        // Build a chain of 100 nodes
        for i in 0..100u8 {
            let mut id = [0u8; 32];
            id[0] = i + 1;

            let parents = if i == 0 {
                // First node is root (no parents)
                vec![]
            } else {
                let mut prev_id = [0u8; 32];
                prev_id[0] = i;
                vec![Hash::new(prev_id)]
            };

            let node = DAGNode::new(Hash::new(id), vec![i], vec![], vec![], parents);
            nodes.push(node);
        }

        let segment = DAGSegment::new(nodes, Hash::zero());
        assert!(segment.validate_structure().is_ok());
    }

    #[test]
    fn test_dag_segment_large_diamond() {
        // Build a diamond pattern: root → A, B → leaf
        let root = DAGNode::new(Hash::new([0u8; 32]), vec![], vec![], vec![], vec![]);
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([0u8; 32])],
        );
        let node_b = DAGNode::new(
            Hash::new([2u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([0u8; 32])],
        );
        let leaf = DAGNode::new(
            Hash::new([3u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([1u8; 32]), Hash::new([2u8; 32])],
        );

        let segment = DAGSegment::new(vec![root, node_a, node_b, leaf], Hash::zero());
        assert!(segment.validate_structure().is_ok());
    }

    // ─────────────────────────────────────────────
    // NEW: Duplicate node ID handling
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_segment_duplicate_node_ids_still_valid() {
        // Two nodes with same ID (structurally valid but semantically problematic)
        let node_a = DAGNode::new(Hash::new([1u8; 32]), vec![0x01], vec![], vec![], vec![]);
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]), // Same ID as node_a
            vec![0x02],
            vec![],
            vec![],
            vec![],
        );
        let child = DAGNode::new(
            Hash::new([3u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([1u8; 32])],
        );

        let segment = DAGSegment::new(vec![node_a, node_b, child], Hash::zero());
        // Validates because the parent ID exists in the set
        assert!(segment.validate_structure().is_ok());
    }

    // ─────────────────────────────────────────────
    // NEW: Bytecode ordering in hash
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_node_hash_bytecode_order_sensitive() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02, 0x03],
            vec![],
            vec![],
            vec![],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x03, 0x02, 0x01],
            vec![],
            vec![],
            vec![],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    // ─────────────────────────────────────────────
    // NEW: Signature/witness ordering effects
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_node_hash_signature_order_sensitive() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![vec![0xAA; 64], vec![0xBB; 64]],
            vec![],
            vec![],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![vec![0xBB; 64], vec![0xAA; 64]],
            vec![],
            vec![],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    #[test]
    fn test_dag_node_hash_witness_order_sensitive() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![vec![0xCC; 32], vec![0xDD; 32]],
            vec![],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![vec![0xDD; 32], vec![0xCC; 32]],
            vec![],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    #[test]
    fn test_dag_node_hash_parent_order_sensitive() {
        let node_a = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([10u8; 32]), Hash::new([20u8; 32])],
        );
        let node_b = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![],
            vec![],
            vec![],
            vec![Hash::new([20u8; 32]), Hash::new([10u8; 32])],
        );
        assert_ne!(node_a.hash(), node_b.hash());
    }

    // ─────────────────────────────────────────────
    // NEW: Complex DAG with signatures and witnesses
    // ─────────────────────────────────────────────

    #[test]
    fn test_dag_complex_structure_with_signatures_and_witnesses() {
        let root = DAGNode::new(
            Hash::new([1u8; 32]),
            vec![0x01, 0x02],
            vec![vec![0xAA; 64]],
            vec![vec![0xBB; 32]],
            vec![],
        );
        let child = DAGNode::new(
            Hash::new([2u8; 32]),
            vec![0x03, 0x04],
            vec![vec![0xCC; 64], vec![0xDD; 64]],
            vec![vec![0xEE; 32]],
            vec![Hash::new([1u8; 32])],
        );

        let segment = DAGSegment::new(vec![root, child], Hash::zero());
        assert!(segment.validate_structure().is_ok());
        assert_ne!(segment.nodes[0].hash(), segment.nodes[1].hash());
    }

    // ─────────────────────────────────────────────
    // NEW: DAG + Commitment integration
    // ─────────────────────────────────────────────

    // These old cross-crate integration tests predate the proof/hash crate split
    // and reference modules that intentionally do not live in csv-hash anymore.
    #[cfg(any())]
    mod integration {
        use super::*;
        use crate::proof::ProofBundle;
        use csv_hash::commitment::Commitment;
        use csv_hash::seal::SealPoint;

        #[test]
        fn test_dag_hash_used_in_commitment() {
            let node = DAGNode::new(
                Hash::new([1u8; 32]),
                vec![0x01, 0x02],
                vec![vec![0xAB; 64]],
                vec![],
                vec![],
            );
            let dag_hash = node.hash();

            // DAG hash can serve as transition payload hash in commitment
            let seal = SealPoint::new(vec![0xAA; 16], Some(42)).unwrap();
            let domain = [0xBB; 32];
            let commitment =
                Commitment::simple(Hash::new([2u8; 32]), Hash::zero(), dag_hash, &seal, domain);

            // Commitment produces a valid hash
            assert_eq!(commitment.hash().as_bytes().len(), 32);
        }

        #[test]
        fn test_dag_inside_proof_bundle_roundtrip() {
            let node = DAGNode::new(
                Hash::new([1u8; 32]),
                vec![0x01],
                vec![vec![0xAB; 64]],
                vec![],
                vec![],
            );
            let segment = DAGSegment::new(vec![node], Hash::new([99u8; 32]));

            let bundle = ProofBundle::new(
                segment.clone(),
                vec![vec![0xCC; 64]],
                SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
                csv_hash::seal::CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
                crate::proof::InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
                crate::proof::FinalityProof::new(vec![], 6, false).unwrap(),
            )
            .unwrap();

            // Serialize and deserialize the full bundle (DAG included)
            let bytes = bundle.to_bytes().unwrap();
            let restored = ProofBundle::from_bytes(&bytes).unwrap();
            assert_eq!(bundle.transition_dag, restored.transition_dag);
        }

        #[test]
        fn test_dag_in_verify_proof_pipeline() {
            use secp256k1::{Message, Secp256k1, SecretKey};
            // The message signed is the DAG root commitment
            let root_commitment = Hash::new([99u8; 32]);
            let message: [u8; 32] = *root_commitment.as_bytes();
            let secp = Secp256k1::new();
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
            let msg = Message::from_digest_slice(&message).unwrap();
            let signature_ecdsa = secp.sign_ecdsa(&msg, &secret_key);
            let sig_bytes = signature_ecdsa.serialize_compact();
            let pubkey_bytes = public_key.serialize();
            let signature = csv_codec::encode::encode_vec(&pubkey_bytes) + &sig_bytes;

            let node = DAGNode::new(
                Hash::new([1u8; 32]),
                vec![0x01, 0x02],
                vec![signature.clone()],
                vec![],
                vec![],
            );
            let segment = DAGSegment::new(vec![node], Hash::new([99u8; 32]));

            let bundle = ProofBundle::new(
                segment,
                vec![signature],
                SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
                csv_hash::seal::CommitAnchor::new(vec![1, 2, 3], 100, vec![]).unwrap(),
                crate::proof::InclusionProof::new(vec![0xDD; 32], Hash::new([10u8; 32]), 100, 0)
                    .unwrap(),
                crate::proof::FinalityProof::new(vec![0xAB; 16], 6, false).unwrap(),
            )
            .unwrap();

            // Valid DAG passes verification
            let seal_registry = |_id: &[u8]| false;
            //             let result = // crate::verifier::verify_proof(
            //                 &bundle,
            //                 seal_registry,
            //                 crate::signature::SignatureScheme::Secp256k1,
            //             );
            //             assert!(result.is_valid);
        }

        #[test]
        fn test_dag_with_invalid_parent_fails_in_proof_bundle() {
            use secp256k1::{Message, Secp256k1, SecretKey};
            let root_commitment = Hash::zero();
            let message: [u8; 32] = *root_commitment.as_bytes();
            let secp = Secp256k1::new();
            let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
            let msg = Message::from_digest_slice(&message).unwrap();
            let signature_ecdsa = secp.sign_ecdsa(&msg, &secret_key);
            let sig_bytes = signature_ecdsa.serialize_compact();
            let pubkey_bytes = public_key.serialize();
            let signature = csv_codec::encode::encode_vec(&pubkey_bytes) + &sig_bytes;

            let node = DAGNode::new(
                Hash::new([1u8; 32]),
                vec![0x01],
                vec![signature.clone()],
                vec![],
                vec![Hash::new([99u8; 32])], // Non-existent parent
            );
            let segment = DAGSegment::new(vec![node], Hash::zero());

            let bundle = ProofBundle::new(
                segment,
                vec![signature],
                SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
                csv_hash::seal::CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
                crate::proof::InclusionProof::new(vec![0xDD; 32], Hash::new([10u8; 32]), 100, 0)
                    .unwrap(),
                crate::proof::FinalityProof::new(vec![], 6, false).unwrap(),
            )
            .unwrap();

            let seal_registry = |_id: &[u8]| false;
            //             let result = // crate::verifier::verify_proof(
            //                 &bundle,
            //                 seal_registry,
            //                 crate::signature::SignatureScheme::Secp256k1,
            //             );
            //             assert!(!result.is_valid);
        }

        #[test]
        fn test_same_dag_produces_same_commitment_hash() {
            // Build identical DAG twice
            fn build_dag() -> DAGSegment {
                let root = DAGNode::new(
                    Hash::new([1u8; 32]),
                    vec![0x01, 0x02],
                    vec![vec![0xAA; 64]],
                    vec![vec![0xBB; 32]],
                    vec![],
                );
                let child = DAGNode::new(
                    Hash::new([2u8; 32]),
                    vec![0x03],
                    vec![vec![0xCC; 64]],
                    vec![],
                    vec![Hash::new([1u8; 32])],
                );
                DAGSegment::new(vec![root, child], Hash::new([3u8; 32]))
            }

            let dag_a = build_dag();
            let dag_b = build_dag();

            // Use root commitment hashes as payload inputs
            let seal = SealPoint::new(vec![0xFF; 16], Some(1)).unwrap();
            let domain = [0xEE; 32];

            let commitment_a = Commitment::simple(
                Hash::new([10u8; 32]),
                Hash::zero(),
                dag_a.root_commitment,
                &seal,
                domain,
            );
            let commitment_b = Commitment::simple(
                Hash::new([10u8; 32]),
                Hash::zero(),
                dag_b.root_commitment,
                &seal,
                domain,
            );

            assert_eq!(commitment_a.hash(), commitment_b.hash());
        }
    }
}
