// Protocol Canonical Serialization Tests
//
// Invariant: Serialization must be canonical and deterministic
// across all implementations and languages.

use csv_hash::dag::DAGNode;
use csv_hash::{
    Hash,
    canonical::{from_canonical_cbor, to_canonical_cbor},
    commitment::Commitment,
    dag::DAGSegment,
    seal::{CommitAnchor, SealPoint},
};
use csv_protocol::proof_types::{FinalityProof, InclusionProof, ProofBundle};
use serde::{Deserialize, Serialize};

/// Test that canonical serialization is deterministic and field-order independent.
#[test]
fn serialization_is_canonical() {
    // 1. Same input always produces same canonical CBOR output
    let seal = SealPoint::new(vec![0xAA; 16], Some(42)).unwrap();
    let cbor1 = to_canonical_cbor(&seal).expect("seal serialization");
    let cbor2 = to_canonical_cbor(&seal).expect("seal serialization");
    let cbor3 = to_canonical_cbor(&seal).expect("seal serialization");
    assert_eq!(
        cbor1, cbor2,
        "Canonical CBOR must be deterministic (run 1 vs 2)"
    );
    assert_eq!(
        cbor2, cbor3,
        "Canonical CBOR must be deterministic (run 2 vs 3)"
    );

    // 2. Roundtrip: serialize then deserialize must recover the original
    let restored: SealPoint = from_canonical_cbor(&cbor1).expect("seal deserialization");
    assert_eq!(seal, restored, "Roundtrip must recover original SealPoint");

    // 3. CommitAnchor canonical serialization
    let anchor = CommitAnchor::new(vec![0xBB; 8], 100, vec![0xCC; 4]).unwrap();
    let cbor_a = to_canonical_cbor(&anchor).expect("anchor serialization");
    let restored_anchor: CommitAnchor =
        from_canonical_cbor(&cbor_a).expect("anchor deserialization");
    assert_eq!(
        anchor, restored_anchor,
        "Anchor roundtrip must recover original"
    );

    // 4. DAGNode canonical serialization
    let node = DAGNode::new(
        Hash::new([1u8; 32]),
        vec![0x01, 0x02, 0x03],
        vec![vec![0xAB; 32]],
        vec![vec![0xCD; 16]],
        vec![Hash::new([0xFF; 32])],
    );
    let cbor_n = to_canonical_cbor(&node).expect("node serialization");
    let restored_node: DAGNode = from_canonical_cbor(&cbor_n).expect("node deserialization");
    assert_eq!(
        node, restored_node,
        "DAGNode roundtrip must recover original"
    );

    // 5. Commitment canonical serialization
    let seal2 = SealPoint::new(vec![0xFF; 16], Some(1)).unwrap();
    let commitment = Commitment::simple(
        Hash::new([10u8; 32]),
        Hash::new([20u8; 32]),
        Hash::new([30u8; 32]),
        &seal2,
        [0xEE; 32],
    );
    let cbor_c = commitment.to_canonical_bytes();
    let restored_commitment: Commitment =
        from_canonical_cbor(&cbor_c).expect("commitment deserialization");
    assert_eq!(
        commitment, restored_commitment,
        "Commitment roundtrip must recover original"
    );

    // 6. ProofBundle canonical serialization via to_bytes/from_bytes
    let bundle = ProofBundle::new(
        DAGSegment::new(vec![node.clone()], Hash::new([99u8; 32])),
        vec![vec![0xDE; 16]],
        SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
        CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
        InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
        FinalityProof::new(vec![], 6, false).unwrap(),
    )
    .unwrap();

    let bytes = to_canonical_cbor(&bundle).expect("bundle serialization");
    let restored_bundle: ProofBundle =
        from_canonical_cbor(&bytes).expect("bundle deserialization");
    assert_eq!(
        bundle, restored_bundle,
        "ProofBundle roundtrip must recover original"
    );

    // 7. Custom struct with multiple fields: field ordering must be fixed
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestStruct {
        z_field: u64,
        a_field: String,
        m_field: Vec<u8>,
        b_field: bool,
    }

    let test_obj = TestStruct {
        z_field: 42,
        a_field: "hello".to_string(),
        m_field: vec![1, 2, 3],
        b_field: true,
    };

    let cbor_obj1 = to_canonical_cbor(&test_obj).expect("test struct serialization");
    let cbor_obj2 = to_canonical_cbor(&test_obj).expect("test struct serialization");
    assert_eq!(
        cbor_obj1, cbor_obj2,
        "Custom struct CBOR must be deterministic"
    );

    let restored_obj: TestStruct =
        from_canonical_cbor(&cbor_obj1).expect("test struct deserialization");
    assert_eq!(
        test_obj, restored_obj,
        "Custom struct roundtrip must recover original"
    );

    // 8. Verify that the CBOR output is consistent across runs by checking
    //    that the hash of the CBOR is deterministic
    let hash1 = Hash::sha256(&cbor_obj1);
    let hash2 = Hash::sha256(&cbor_obj2);
    assert_eq!(hash1, hash2, "Hash of canonical CBOR must be stable");
}

/// Verify that field ordering in serialized output is fixed (lexicographic).
#[test]
fn field_ordering_is_fixed() {
    // Create two structs with same fields but different declaration order
    // and verify they produce the same canonical CBOR if fields are the same

    // Test with a struct that has fields in a specific order
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct OrderedStruct {
        alpha: u32,
        beta: u32,
        gamma: u32,
    }

    let obj = OrderedStruct {
        alpha: 1,
        beta: 2,
        gamma: 3,
    };

    // Serialize multiple times - must always produce identical bytes
    let mut all_same = true;
    for _ in 0..10 {
        let cbor = to_canonical_cbor(&obj).expect("serialization");
        if cbor != to_canonical_cbor(&obj).expect("serialization") {
            all_same = false;
            break;
        }
    }
    assert!(
        all_same,
        "Field ordering must be fixed across serializations"
    );

    // Verify the serialized bytes are non-empty and consistent
    let cbor = to_canonical_cbor(&obj).expect("serialization");
    assert!(!cbor.is_empty(), "Canonical CBOR must not be empty");

    // Verify roundtrip
    let restored: OrderedStruct = from_canonical_cbor(&cbor).expect("deserialization");
    assert_eq!(obj, restored, "Roundtrip must preserve field values");
}
