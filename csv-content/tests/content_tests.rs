//! Tests for csv-content crate

use csv_content::content_tree::ContentClaim;
use csv_content::{
    AttachmentBudget, AttachmentRef, Claim, ClaimPredicate,
    ContentDisclosureProof as DisclosureProof, ContentRights, ContentTree, MediaType, Participant,
    ParticipantId, ParticipantRole, ParticipantSet, VerificationCost,
};
use csv_hash::Hash;

// ============================================================================
// ContentTree Tests
// ============================================================================

#[test]
fn test_content_tree_from_leaves() {
    let leaves = vec![
        b"leaf1".to_vec(),
        b"leaf2".to_vec(),
        b"leaf3".to_vec(),
        b"leaf4".to_vec(),
    ];

    let tree = ContentTree::from_leaves(leaves);
    assert_eq!(tree.leaf_count, 4);
    assert_eq!(tree.leaf_hashes.len(), 4);
    assert!(tree.root_hash.0 != [0u8; 32]);
}

#[test]
fn test_content_tree_empty() {
    let tree = ContentTree::empty();
    assert_eq!(tree.leaf_count, 0);
    assert_eq!(tree.root_hash.0, [0u8; 32]);
}

#[test]
fn test_content_tree_single_leaf() {
    let leaves = vec![b"single".to_vec()];
    let tree = ContentTree::from_leaves(leaves);
    assert_eq!(tree.leaf_count, 1);
    assert_eq!(tree.depth, 0);
}

#[test]
fn test_content_tree_proof() {
    let leaves: Vec<Vec<u8>> = (0..8).map(|i| format!("leaf_{}", i).into_bytes()).collect();

    let tree = ContentTree::from_leaves(leaves.clone());

    // All proofs should be valid
    for i in 0..leaves.len() {
        let proof = tree.proof(i).unwrap();
        let leaf_hash = ContentTree::hash_leaf(&leaves[i]);
        assert!(proof.verify(leaf_hash));
    }
}

#[test]
fn test_content_tree_proof_invalid_leaf() {
    let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec()];
    let tree = ContentTree::from_leaves(leaves);

    let proof = tree.proof(0).unwrap();
    let wrong_hash = Hash([99u8; 32]);
    assert!(!proof.verify(wrong_hash));
}

#[test]
fn test_content_tree_proof_invalid_root() {
    let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec()];
    let tree = ContentTree::from_leaves(leaves);

    let proof = tree.proof(0).unwrap();
    let wrong_root = Hash([99u8; 32]);
    assert_ne!(proof.root_hash, wrong_root);
}

#[test]
fn test_content_tree_inclusion() {
    let leaves = vec![
        b"content1".to_vec(),
        b"content2".to_vec(),
        b"content3".to_vec(),
    ];

    let tree = ContentTree::from_leaves(leaves.clone());

    // All leaves should be included
    for i in 0..leaves.len() {
        assert!(tree.verify_inclusion(i, &leaves[i]));
    }

    // Wrong content should not be included
    assert!(!tree.verify_inclusion(0, b"wrong content"));
}

#[test]
fn test_content_tree_deterministic() {
    let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec(), b"leaf3".to_vec()];

    let tree1 = ContentTree::from_leaves(leaves.clone());
    let tree2 = ContentTree::from_leaves(leaves);

    assert_eq!(tree1.root_hash, tree2.root_hash);
    assert_eq!(tree1.leaf_count, tree2.leaf_count);
}

#[test]
fn test_content_tree_large() {
    let leaves: Vec<Vec<u8>> = (0..100)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();

    let tree = ContentTree::from_leaves(leaves);
    assert_eq!(tree.leaf_count, 100);
    assert!(tree.root_hash.0 != [0u8; 32]);
}

// ============================================================================
// VerificationCost Tests
// ============================================================================

#[test]
fn test_verification_cost_acceptable() {
    let cost = VerificationCost {
        cpu: 100,
        memory: 1024,
        io: 10,
        recursion_depth: 5,
    };

    assert!(cost.is_acceptable(1000, 10240, 100, 10));
}

#[test]
fn test_verification_cost_cpu_exceeded() {
    let cost = VerificationCost {
        cpu: 2000,
        memory: 1024,
        io: 10,
        recursion_depth: 5,
    };

    assert!(!cost.is_acceptable(1000, 10240, 100, 10));
}

#[test]
fn test_verification_cost_memory_exceeded() {
    let cost = VerificationCost {
        cpu: 100,
        memory: 20480,
        io: 10,
        recursion_depth: 5,
    };

    assert!(!cost.is_acceptable(1000, 10240, 100, 10));
}

#[test]
fn test_verification_cost_io_exceeded() {
    let cost = VerificationCost {
        cpu: 100,
        memory: 1024,
        io: 200,
        recursion_depth: 5,
    };

    assert!(!cost.is_acceptable(1000, 10240, 100, 10));
}

#[test]
fn test_verification_cost_recursion_exceeded() {
    let cost = VerificationCost {
        cpu: 100,
        memory: 1024,
        io: 10,
        recursion_depth: 15,
    };

    assert!(!cost.is_acceptable(1000, 10240, 100, 10));
}

#[test]
fn test_verification_cost_validate() {
    let cost = VerificationCost {
        cpu: 100,
        memory: 1024,
        io: 10,
        recursion_depth: 5,
    };

    assert!(cost.validate(1000, 10240, 100, 10).is_ok());
}

#[test]
fn test_verification_cost_validate_error() {
    let cost = VerificationCost {
        cpu: 2000,
        memory: 1024,
        io: 10,
        recursion_depth: 5,
    };

    let err = cost.validate(1000, 10240, 100, 10).unwrap_err();
    assert!(matches!(
        err,
        csv_content::VerificationCostError::CpuExceeded { .. }
    ));
}

// ============================================================================
// DisclosureProof Tests
// ============================================================================

#[test]
fn test_disclosure_proof_verify() {
    let leaves: Vec<Vec<u8>> = (0..8).map(|i| format!("leaf_{}", i).into_bytes()).collect();

    let tree = ContentTree::from_leaves(leaves);
    let proof = tree.proof(3).unwrap();

    let claim = ContentClaim {
        field: "name".to_string(),
        value_hash: Hash([1u8; 32]),
        verified: true,
    };

    let disclosure = DisclosureProof {
        subtree_root: proof.leaf_hash,
        inclusion_proof: proof,
        claims: vec![claim],
    };

    assert!(disclosure.verify(tree.root_hash));
}

#[test]
fn test_disclosure_proof_verify_invalid() {
    let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec()];
    let tree = ContentTree::from_leaves(leaves);
    let proof = tree.proof(0).unwrap();

    let claim = ContentClaim {
        field: "name".to_string(),
        value_hash: Hash([1u8; 32]),
        verified: false, // Unverified claim
    };

    let disclosure = DisclosureProof {
        subtree_root: proof.leaf_hash,
        inclusion_proof: proof,
        claims: vec![claim],
    };

    // Should fail because claim is not verified
    assert!(!disclosure.verify(tree.root_hash));
}

// ============================================================================
// Attachment Tests
// ============================================================================

#[test]
fn test_attachment_ref_creation() {
    let hash = Hash([1u8; 32]);
    let ref_ = AttachmentRef::new("bafyabc123", MediaType::Pdf, 1024, hash);

    assert_eq!(ref_.cid, "bafyabc123");
    assert_eq!(ref_.size, 1024);
    assert_eq!(ref_.hash, hash);
}

#[test]
fn test_attachment_ref_with_options() {
    let hash = Hash([2u8; 32]);
    let ref_ = AttachmentRef::new("bafydef456", MediaType::Png, 2048, hash)
        .with_encryption_key_id("key-123")
        .with_created_at(1234567890);

    assert_eq!(ref_.encryption_key_id, Some("key-123".to_string()));
    assert_eq!(ref_.created_at, 1234567890);
}

#[test]
fn test_media_type_as_str() {
    assert_eq!(MediaType::Json.as_str(), "application/json");
    assert_eq!(MediaType::Pdf.as_str(), "application/pdf");
    assert_eq!(MediaType::Png.as_str(), "image/png");
}

#[test]
fn test_attachment_budget_default() {
    let budget = AttachmentBudget::default();
    assert_eq!(budget.max_count, 10);
    assert_eq!(budget.max_total_size, 100 * 1024 * 1024);
    assert_eq!(budget.max_single_size, 50 * 1024 * 1024);
}

#[test]
fn test_attachment_budget_within_limits() {
    let budget = AttachmentBudget::default();
    let attachment = AttachmentRef::new("cid1", MediaType::Pdf, 1024, Hash([1u8; 32]));

    assert!(budget.is_within_budget(&attachment));
}

#[test]
fn test_attachment_budget_exceeds_single_size() {
    let mut budget = AttachmentBudget::default();
    budget.max_single_size = 512;

    let attachment = AttachmentRef::new("cid1", MediaType::Pdf, 1024, Hash([1u8; 32]));

    assert!(!budget.is_within_budget(&attachment));
}

#[test]
fn test_attachment_budget_exceeds_total_size() {
    let budget = AttachmentBudget::default();
    let attachment = AttachmentRef::new("cid1", MediaType::Pdf, 1024, Hash([1u8; 32]));

    assert!(!budget.would_exceed_budget(9, 99 * 1024 * 1024, &attachment));
    assert!(budget.would_exceed_budget(10, 0, &attachment)); // max_count reached
}

#[test]
fn test_attachment_budget_disallowed_type() {
    let mut budget = AttachmentBudget::default();
    budget.allowed_types = vec![MediaType::Json];

    let attachment = AttachmentRef::new("cid1", MediaType::Pdf, 1024, Hash([1u8; 32]));

    assert!(!budget.is_within_budget(&attachment));
}

// ============================================================================
// Claim Tests
// ============================================================================

#[test]
fn test_claim_creation() {
    let claim = Claim::new("alice", "document-1", ClaimPredicate::Authentic);

    assert_eq!(claim.subject, "alice");
    assert_eq!(claim.object, "document-1");
    assert!(!claim.verified);
}

#[test]
fn test_claim_hash() {
    let claim1 = Claim::new("alice", "doc-1", ClaimPredicate::Authentic);
    let claim2 = Claim::new("alice", "doc-1", ClaimPredicate::Authentic);

    // Same inputs should produce same hash
    assert_eq!(claim1.hash(), claim2.hash());

    let claim3 = Claim::new("bob", "doc-1", ClaimPredicate::Authentic);
    // Different subject should produce different hash
    assert_ne!(claim1.hash(), claim3.hash());
}

#[test]
fn test_content_rights_read_access() {
    let mut rights = ContentRights::default();
    rights.owner = "alice".to_string();
    rights.readers = vec!["alice".to_string(), "bob".to_string()];

    assert!(rights.can_read("alice"));
    assert!(rights.can_read("bob"));
    assert!(!rights.can_read("charlie"));
}

#[test]
fn test_content_rights_open_access() {
    let rights = ContentRights::default();

    // Empty readers list means open access
    assert!(rights.can_read("anyone"));
}

#[test]
fn test_content_rights_write_access() {
    let mut rights = ContentRights::default();
    rights.modifiers = vec!["alice".to_string()];

    assert!(rights.can_write("alice"));
    assert!(!rights.can_write("bob"));
}

#[test]
fn test_content_rights_expiration() {
    let mut rights = ContentRights::default();
    rights.expires_at = 1000;

    assert!(rights.is_expired());

    rights.expires_at = 0;
    assert!(!rights.is_expired());
}

// ============================================================================
// Participant Tests
// ============================================================================

#[test]
fn test_participant_set_add() {
    let mut set = ParticipantSet::default();

    let creator = Participant {
        id: ParticipantId::new(b"creator-key"),
        role: ParticipantRole::Creator,
        public_key: b"creator-key".to_vec(),
        added_at: 0,
    };

    let owner = Participant {
        id: ParticipantId::new(b"owner-key"),
        role: ParticipantRole::Owner,
        public_key: b"owner-key".to_vec(),
        added_at: 0,
    };

    set.add(creator.clone());
    set.add(owner.clone());

    assert_eq!(set.participants.len(), 2);
    assert!(set.creator.is_some());
    assert!(set.owner.is_some());
}

#[test]
fn test_participant_set_get() {
    let mut set = ParticipantSet::default();

    let participant = Participant {
        id: ParticipantId::new(b"test-key"),
        role: ParticipantRole::Reader,
        public_key: b"test-key".to_vec(),
        added_at: 0,
    };

    set.add(participant.clone());

    let found = set.get(&participant.id);
    assert!(found.is_some());
    assert_eq!(found.unwrap(), &participant);
}

#[test]
fn test_participant_set_by_role() {
    let mut set = ParticipantSet::default();

    for i in 0..5 {
        set.add(Participant {
            id: ParticipantId::new(&[i as u8; 32]),
            role: ParticipantRole::Reader,
            public_key: vec![i as u8; 32],
            added_at: 0,
        });
    }

    let readers = set.by_role(&ParticipantRole::Reader);
    assert_eq!(readers.len(), 5);
}

#[test]
fn test_participant_set_has_role() {
    let mut set = ParticipantSet::default();

    let participant = Participant {
        id: ParticipantId::new(b"test-key"),
        role: ParticipantRole::Modifier,
        public_key: b"test-key".to_vec(),
        added_at: 0,
    };

    set.add(participant);

    assert!(set.has_role(&ParticipantId::new(b"test-key"), &ParticipantRole::Modifier));
    assert!(!set.has_role(&ParticipantId::new(b"test-key"), &ParticipantRole::Reader));
}
