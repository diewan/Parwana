//! Comprehensive tests for the formal proof taxonomy

use csv_hash::Hash;
use csv_proof::{
    commitments_ext::{CommitmentScheme, EnhancedCommitment, FinalityProofType, InclusionProofType, ProofMetadata},
    CompositeProof, CompositionRule, ExecutionProof, FinalityProof, InclusionProof, OwnershipProof,
    Proof, ProofCategory, ProofDag, ProofId, ProofNode, ProofPhase, ReplayProof, TransitionProof,
    ZKProof,
};

fn test_hash() -> Hash {
    Hash::sha256(b"test hash")
}

// ==================== Proof Taxonomy Tests ====================

#[test]
fn test_proof_category_inclusion() {
    let proof = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![test_hash()],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    assert_eq!(proof.category(), ProofCategory::Inclusion);
}

#[test]
fn test_proof_category_finality() {
    let proof = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![1, 2, 3],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    assert_eq!(proof.category(), ProofCategory::Finality);
}

#[test]
fn test_proof_category_ownership() {
    let proof = Proof::Ownership(OwnershipProof {
        owner: vec![1, 2, 3],
        proof: vec![4, 5, 6],
        asset_id: test_hash(),
        scheme: "secp256k1".to_string(),
    });
    assert_eq!(proof.category(), ProofCategory::Ownership);
}

#[test]
fn test_proof_category_transition() {
    let proof = Proof::Transition(TransitionProof {
        previous_state: test_hash(),
        new_state: test_hash(),
        transition_data: vec![1, 2, 3],
        proof: vec![4, 5, 6],
    });
    assert_eq!(proof.category(), ProofCategory::Transition);
}

#[test]
fn test_proof_category_replay() {
    let proof = Proof::Replay(ReplayProof {
        nullifier: test_hash(),
        chain_id: "ethereum".to_string(),
        context: vec![1, 2, 3],
    });
    assert_eq!(proof.category(), ProofCategory::Replay);
}

#[test]
fn test_proof_category_execution() {
    let proof = Proof::Execution(ExecutionProof {
        computation_hash: test_hash(),
        proof: vec![1, 2, 3],
        context: vec![4, 5, 6],
    });
    assert_eq!(proof.category(), ProofCategory::Execution);
}

#[test]
fn test_proof_category_zk() {
    let proof = Proof::ZK(ZKProof {
        system: "groth16".to_string(),
        proof: vec![1, 2, 3],
        public_inputs: vec![test_hash()],
        verification_key_hash: test_hash(),
    });
    assert_eq!(proof.category(), ProofCategory::ZK);
}

#[test]
fn test_proof_category_composite() {
    let proof = Proof::Composite(CompositeProof {
        children: vec![],
        rule: CompositionRule::And,
        proof: vec![1, 2, 3],
    });
    assert_eq!(proof.category(), ProofCategory::Composite);
}

// ==================== Proof Hash Tests ====================

#[test]
fn test_proof_hash_is_consistent() {
    let proof = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![test_hash()],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let hash1 = proof.hash();
    let hash2 = proof.hash();
    assert_eq!(hash1, hash2);
}

#[test]
fn test_different_proofs_have_different_hashes() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![test_hash()],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let proof2 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![test_hash()],
        leaf_index: 1, // Different leaf index
        source: "ethereum".to_string(),
        ..Default::default()
    });
    assert_ne!(proof1.hash(), proof2.hash());
}

#[test]
fn test_different_categories_have_different_hashes() {
    let inclusion = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let finality = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    assert_ne!(inclusion.hash(), finality.hash());
}

// ==================== Proof Phase Tests ====================

#[test]
fn test_proof_phase_ordering() {
    assert!(ProofPhase::Constructed < ProofPhase::StructuralValidated);
    assert!(ProofPhase::StructuralValidated < ProofPhase::CryptographicallyValidated);
    assert!(ProofPhase::CryptographicallyValidated < ProofPhase::FinalityValidated);
    assert!(ProofPhase::FinalityValidated < ProofPhase::ReplayChecked);
    assert!(ProofPhase::ReplayChecked < ProofPhase::ConsensusBound);
}

#[test]
fn test_proof_phase_ord() {
    assert_eq!(ProofPhase::Constructed, ProofPhase::Constructed);
    assert!(ProofPhase::ConsensusBound > ProofPhase::Constructed);
}

// ==================== Proof DAG Tests ====================

#[test]
fn test_dag_add_root_node() {
    let proof = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node = ProofNode::root(proof);
    let mut dag = ProofDag::new();
    assert!(dag.add_node(node));
    assert_eq!(dag.proof_count(), 1);
}

#[test]
fn test_dag_add_dependent_node() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    assert!(dag.add_node(node1));
    assert!(dag.add_node(node2));
    assert_eq!(dag.proof_count(), 2);
}

#[test]
fn test_dag_reject_missing_dependency() {
    let proof = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let fake_id = ProofId::from_bytes(b"nonexistent");
    let node = ProofNode::new(proof, vec![fake_id]);

    let mut dag = ProofDag::new();
    assert!(!dag.add_node(node));
    assert_eq!(dag.proof_count(), 0);
}

#[test]
fn test_dag_verify_acyclic() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    dag.add_node(node1);
    dag.add_node(node2.clone());
    assert!(dag.verify_acyclic());
}

#[test]
fn test_dag_roots() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    dag.add_node(node1);
    dag.add_node(node2.clone());

    let roots = dag.roots();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].id, id1);
}

#[test]
fn test_dag_leaves() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    dag.add_node(node1);
    dag.add_node(node2.clone());

    let leaves = dag.leaves();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].id, node2.id);
}

#[test]
fn test_dag_topological_sort() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    dag.add_node(node1);
    dag.add_node(node2.clone());

    let order = dag.topological_sort().unwrap();
    assert_eq!(order.len(), 2);
    assert_eq!(order[0], id1);
}

#[test]
fn test_dag_depth() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    dag.add_node(node1);
    dag.add_node(node2.clone());

    assert_eq!(dag.depth(), 2);
}

#[test]
fn test_dag_verify_structure() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node1 = ProofNode::root(proof1);
    let id1 = node1.id.clone();

    let proof2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node2 = ProofNode::new(proof2, vec![id1.clone()]);

    let mut dag = ProofDag::new();
    dag.add_node(node1);
    dag.add_node(node2.clone());

    assert!(dag.verify_structure());
}

#[test]
fn test_proof_node_metadata() {
    let proof = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node = ProofNode::root(proof)
        .with_created_at(1000)
        .with_expires_at(2000)
        .with_source("ethereum");

    assert_eq!(node.metadata.created_at, 1000);
    assert_eq!(node.metadata.expires_at, 2000);
    assert_eq!(node.metadata.source, "ethereum");
}

#[test]
fn test_proof_node_is_expired() {
    let proof = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node = ProofNode::root(proof)
        .with_created_at(2000)
        .with_expires_at(1000);

    assert!(node.is_expired());
}

// ==================== Composition Rule Tests ====================

#[test]
fn test_composition_rule_and() {
    let rule = CompositionRule::And;
    assert_eq!(rule.as_bytes(), b"and");
}

#[test]
fn test_composition_rule_or() {
    let rule = CompositionRule::Or;
    assert_eq!(rule.as_bytes(), b"or");
}

#[test]
fn test_composition_rule_threshold() {
    let rule = CompositionRule::Threshold(3);
    assert_eq!(rule.as_bytes(), b"threshold");
}

// ==================== Composite Proof Tests ====================

#[test]
fn test_composite_proof_and_rule() {
    let child1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let child2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });

    let composite = CompositeProof {
        children: vec![child1, child2],
        rule: CompositionRule::And,
        proof: vec![1, 2, 3],
    };

    let proof = Proof::Composite(composite);
    assert_eq!(proof.category(), ProofCategory::Composite);
}

#[test]
fn test_composite_proof_or_rule() {
    let child = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });

    let composite = CompositeProof {
        children: vec![child],
        rule: CompositionRule::Or,
        proof: vec![],
    };

    let proof = Proof::Composite(composite);
    assert_eq!(proof.category(), ProofCategory::Composite);
}

#[test]
fn test_composite_proof_threshold_rule() {
    let child1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let child2 = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });

    let composite = CompositeProof {
        children: vec![child1, child2],
        rule: CompositionRule::Threshold(1),
        proof: vec![],
    };

    let proof = Proof::Composite(composite);
    assert_eq!(proof.category(), ProofCategory::Composite);
}

// ==================== ProofId Tests ====================

#[test]
fn test_proof_id_from_hash() {
    let hash = test_hash();
    let id = ProofId::new(hash);
    assert_eq!(id.as_hash(), &hash);
}

#[test]
fn test_proof_id_from_bytes() {
    let id = ProofId::from_bytes(b"test");
    assert!(id.as_hash().0.iter().any(|&b| b != 0));
}

#[test]
fn test_proof_id_equality() {
    let hash = test_hash();
    let id1 = ProofId::new(hash);
    let id2 = ProofId::new(hash);
    assert_eq!(id1, id2);
}

// ==================== Proof Size Constants Tests ====================

#[test]
fn test_max_proof_bytes() {
    assert_eq!(csv_proof::MAX_PROOF_BYTES, 64 * 1024);
}

#[test]
fn test_max_finality_data() {
    assert_eq!(csv_proof::MAX_FINALITY_DATA, 4 * 1024);
}

#[test]
fn test_max_signatures_total_size() {
    assert_eq!(csv_proof::MAX_SIGNATURES_TOTAL_SIZE, 1024 * 1024);
}

// ==================== Proof Category as Bytes Tests ====================

#[test]
fn test_proof_category_as_bytes() {
    assert_eq!(ProofCategory::Inclusion.as_bytes(), b"inclusion");
    assert_eq!(ProofCategory::Finality.as_bytes(), b"finality");
    assert_eq!(ProofCategory::Ownership.as_bytes(), b"ownership");
    assert_eq!(ProofCategory::Transition.as_bytes(), b"transition");
    assert_eq!(ProofCategory::Replay.as_bytes(), b"replay");
    assert_eq!(ProofCategory::Execution.as_bytes(), b"execution");
    assert_eq!(ProofCategory::ZK.as_bytes(), b"zk");
    assert_eq!(ProofCategory::Composite.as_bytes(), b"composite");
}

// ==================== Proof Node ID Tests ====================

#[test]
fn test_proof_node_id_is_unique() {
    let proof1 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let proof2 = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 1,
        source: "ethereum".to_string(),
        ..Default::default()
    });

    let node1 = ProofNode::root(proof1);
    let node2 = ProofNode::root(proof2);

    assert_ne!(node1.id, node2.id);
}

// ==================== Complex DAG Tests ====================

#[test]
fn test_complex_dag() {
    // Create a DAG with multiple branches:
    //   A -> C -> E
    //   B -> C -> E
    //   A -> D
    //   B -> D

    let proof_a = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 0,
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node_a = ProofNode::root(proof_a);
    let id_a = node_a.id.clone();

    let proof_b = Proof::Inclusion(InclusionProof {
        leaf: test_hash(),
        root: test_hash(),
        siblings: vec![],
        leaf_index: 1,
        source: "bitcoin".to_string(),
        ..Default::default()
    });
    let node_b = ProofNode::root(proof_b);
    let id_b = node_b.id.clone();

    let proof_c = Proof::Finality(FinalityProof {
        block_hash: test_hash(),
        threshold: 66,
        confirmations: 100,
        data: vec![],
        source: "ethereum".to_string(),
        ..Default::default()
    });
    let node_c = ProofNode::new(proof_c, vec![id_a.clone(), id_b.clone()]);
    let id_c = node_c.id.clone();

    let proof_d = Proof::Ownership(OwnershipProof {
        owner: vec![1, 2, 3],
        proof: vec![4, 5, 6],
        asset_id: test_hash(),
        scheme: "secp256k1".to_string(),
    });
    let node_d = ProofNode::new(proof_d, vec![id_a.clone(), id_b.clone()]);
    let id_d = node_d.id.clone();

    let proof_e = Proof::Transition(TransitionProof {
        previous_state: test_hash(),
        new_state: test_hash(),
        transition_data: vec![],
        proof: vec![],
    });
    let node_e = ProofNode::new(proof_e, vec![id_c.clone(), id_d.clone()]);

    let mut dag = ProofDag::new();
    assert!(dag.add_node(node_a));
    assert!(dag.add_node(node_b));
    assert!(dag.add_node(node_c));
    assert!(dag.add_node(node_d));
    assert!(dag.add_node(node_e.clone()));

    assert_eq!(dag.proof_count(), 5);
    assert!(dag.verify_acyclic());
    assert!(dag.verify_structure());

    let roots = dag.roots();
    assert_eq!(roots.len(), 2);

    let leaves = dag.leaves();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].id, node_e.id);

    let order = dag.topological_sort().unwrap();
    assert_eq!(order.len(), 5);

    assert!(dag.depth() >= 3);
}

// ==================== Commitment Ext Roundtrip Tests ====================

#[test]
fn test_proof_metadata_roundtrip() {
    let original = ProofMetadata {
        inclusion_proof_type: Some(InclusionProofType::Merkle),
        finality_proof_type: Some(FinalityProofType::Checkpoint),
        commitment_scheme: Some(CommitmentScheme::HashBased),
        proof_size_bytes: Some(1024),
        confirmations: Some(10),
        extra: vec![1, 2, 3, 4],
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let deserialized = ProofMetadata::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original.inclusion_proof_type, deserialized.inclusion_proof_type);
    assert_eq!(original.finality_proof_type, deserialized.finality_proof_type);
    assert_eq!(original.commitment_scheme, deserialized.commitment_scheme);
    assert_eq!(original.proof_size_bytes, deserialized.proof_size_bytes);
    assert_eq!(original.confirmations, deserialized.confirmations);
    assert_eq!(original.extra, deserialized.extra);
}

#[test]
fn test_proof_metadata_roundtrip_with_none_fields() {
    let original = ProofMetadata {
        inclusion_proof_type: None,
        finality_proof_type: None,
        commitment_scheme: None,
        proof_size_bytes: None,
        confirmations: None,
        extra: vec![],
    };

    let bytes = original.to_canonical_bytes().unwrap();
    let deserialized = ProofMetadata::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(original.inclusion_proof_type, deserialized.inclusion_proof_type);
    assert_eq!(original.finality_proof_type, deserialized.finality_proof_type);
    assert_eq!(original.commitment_scheme, deserialized.commitment_scheme);
    assert_eq!(original.proof_size_bytes, deserialized.proof_size_bytes);
    assert_eq!(original.confirmations, deserialized.confirmations);
    assert_eq!(original.extra, deserialized.extra);
}

#[test]
fn test_enhanced_commitment_roundtrip() {
    let original = EnhancedCommitment::new(
        1,
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        [7u8; 32],
        CommitmentScheme::HashBased,
        InclusionProofType::Merkle,
        FinalityProofType::Checkpoint,
    ).with_proof_metadata(1024, 10);

    let bytes = original.to_bytes().unwrap();
    let deserialized = EnhancedCommitment::from_bytes(&bytes).unwrap();

    assert_eq!(original.version, deserialized.version);
    assert_eq!(original.protocol_id, deserialized.protocol_id);
    assert_eq!(original.mpc_root, deserialized.mpc_root);
    assert_eq!(original.contract_id, deserialized.contract_id);
    assert_eq!(original.previous_commitment, deserialized.previous_commitment);
    assert_eq!(original.transition_payload_hash, deserialized.transition_payload_hash);
    assert_eq!(original.seal_id, deserialized.seal_id);
    assert_eq!(original.domain_separator, deserialized.domain_separator);
    assert_eq!(original.commitment_scheme, deserialized.commitment_scheme);
    assert_eq!(original.inclusion_proof_type, deserialized.inclusion_proof_type);
    assert_eq!(original.finality_proof_type, deserialized.finality_proof_type);
    assert_eq!(original.proof_metadata.inclusion_proof_type, deserialized.proof_metadata.inclusion_proof_type);
    assert_eq!(original.proof_metadata.finality_proof_type, deserialized.proof_metadata.finality_proof_type);
    assert_eq!(original.proof_metadata.commitment_scheme, deserialized.proof_metadata.commitment_scheme);
    assert_eq!(original.proof_metadata.proof_size_bytes, deserialized.proof_metadata.proof_size_bytes);
    assert_eq!(original.proof_metadata.confirmations, deserialized.proof_metadata.confirmations);
    assert_eq!(original.proof_metadata.extra, deserialized.proof_metadata.extra);
}

#[test]
fn test_proof_metadata_insufficient_bytes() {
    let bytes = vec![0u8; 1]; // Too short
    let result = ProofMetadata::from_canonical_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_enhanced_commitment_insufficient_bytes() {
    let bytes = vec![0u8; 10]; // Too short
    let result = EnhancedCommitment::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_proof_metadata_invalid_enum_value() {
    let mut bytes = Vec::new();
    bytes.push(1u8); // has_inclusion = true
    bytes.push(255u8); // Invalid enum value
    bytes.push(0u8); // has_finality = false
    bytes.push(0u8); // has_scheme = false
    bytes.push(0u8); // has_size = false
    bytes.push(0u8); // has_confirmations = false
    bytes.extend_from_slice(&(0u32).to_le_bytes()); // extra length

    let result = ProofMetadata::from_canonical_bytes(&bytes);
    assert!(result.is_err());
}
