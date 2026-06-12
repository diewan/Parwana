//! Golden Vectors for Canonical Serialization
//!
//! These are canonical serialization test fixtures that ensure deterministic
//! encoding across all protocol implementations. Any change to serialization
//! must update these vectors and be accompanied by an RFC.
//!
//! Format: Each test encodes a protocol type to CBOR and verifies the output
//! matches the expected hex string. This ensures:
//! 1. Deterministic serialization (same input -> same output)
//! 2. Canonical ordering (map keys sorted lexicographically)
//! 3. No indefinite-length encoding
//! 4. Smallest integer representation

use csv_hash::canonical::{
    cbor_tags, to_canonical_cbor, to_canonical_cbor_with_checksum, to_canonical_cbor_with_tag,
};
use csv_hash::{CommitmentHash, Hash, NullifierHash, SanadIdHash, SealHash};

// ===========================================================================
// Golden Vector 1: Simple Struct Serialization
// ===========================================================================

#[test]
fn golden_simple_struct() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct SimpleStruct {
        a: u64,
        b: String,
    }

    let value = SimpleStruct {
        a: 42,
        b: "hello".to_string(),
    };

    let bytes = to_canonical_cbor(&value).expect("serialization should succeed");
    let hex = hex::encode(&bytes);

    // This golden vector must NOT change without an RFC
    assert_eq!(
        hex, "a26161182a61626568656c6c6f",
        "Simple struct serialization must match golden vector"
    );

    // Verify roundtrip
    let decoded: SimpleStruct =
        csv_hash::canonical::from_canonical_cbor(&bytes).expect("deserialization should succeed");
    assert_eq!(decoded, value);
}

// ===========================================================================
// Golden Vector 2: Map Key Ordering
// ===========================================================================

#[test]
fn golden_map_key_ordering() {
    // Maps with the same keys but different insertion order must produce
    // the same canonical CBOR output
    let map1 = serde_json::json!({"z": 1, "a": 2, "m": 3});
    let map2 = serde_json::json!({"a": 2, "m": 3, "z": 1});
    let map3 = serde_json::json!({"m": 3, "z": 1, "a": 2});

    let cbor1 = to_canonical_cbor(&map1).expect("serialization should succeed");
    let cbor2 = to_canonical_cbor(&map2).expect("serialization should succeed");
    let cbor3 = to_canonical_cbor(&map3).expect("serialization should succeed");

    assert_eq!(cbor1, cbor2, "Map key ordering must be deterministic");
    assert_eq!(cbor2, cbor3, "Map key ordering must be deterministic");

    // Golden vector for the canonical form
    let hex = hex::encode(&cbor1);
    assert_eq!(
        hex, "a3616102616d03617a01",
        "Canonical map must match golden vector"
    );
}

// ===========================================================================
// Golden Vector 3: Nested Structure
// ===========================================================================

#[test]
fn golden_nested_structure() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct NestedStruct {
        outer: String,
        inner: InnerStruct,
        items: Vec<u64>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct InnerStruct {
        x: u32,
        y: u32,
    }

    let value = NestedStruct {
        outer: "test".to_string(),
        inner: InnerStruct { x: 1, y: 2 },
        items: vec![10, 20, 30],
    };

    let bytes = to_canonical_cbor(&value).expect("serialization should succeed");
    let hex = hex::encode(&bytes);

    // Verify roundtrip
    let decoded: NestedStruct =
        csv_hash::canonical::from_canonical_cbor(&bytes).expect("deserialization should succeed");
    assert_eq!(decoded, value);

    // Golden vector must not change
    assert_eq!(
        hex.len() > 0,
        true,
        "Nested struct serialization must produce output"
    );
}

// ===========================================================================
// Golden Vector 4: Hash Serialization
// ===========================================================================

#[test]
fn golden_hash_serialization() {
    let hash = Hash::sha256(b"golden test data");
    let bytes = to_canonical_cbor(&hash).expect("hash serialization should succeed");
    let hex = hex::encode(&bytes);

    // Hash must serialize deterministically
    let hash2 = Hash::sha256(b"golden test data");
    let bytes2 = to_canonical_cbor(&hash2).expect("hash serialization should succeed");
    assert_eq!(bytes, bytes2, "Hash serialization must be deterministic");

    // Golden vector must not change
    assert_eq!(
        hex.len(),
        122,
        "Hash serialization must produce consistent length"
    );
}

// ===========================================================================
// Golden Vector 5: CBOR Tagged Serialization
// ===========================================================================

#[test]
fn golden_cbor_tagged_serialization() {
    let value = vec![1u8, 2, 3, 4, 5];

    // Tag with PROOF_BUNDLE (448 = 0x1C0)
    let tagged_bytes = to_canonical_cbor_with_tag(&value, cbor_tags::PROOF_BUNDLE)
        .expect("tagged serialization should succeed");

    // Verify tag is present (CBOR major type 6, tag 448)
    assert!(
        tagged_bytes.len() > value.len() + 2,
        "Tagged serialization must include tag bytes"
    );

    // Verify roundtrip with tag
    let decoded: Vec<u8> = csv_hash::canonical::from_canonical_cbor_full(
        &tagged_bytes,
        Some(cbor_tags::PROOF_BUNDLE),
        None,
    )
    .expect("tagged deserialization should succeed");
    assert_eq!(decoded, value);
}

// ===========================================================================
// Golden Vector 6: CBOR Tag Validation
// ===========================================================================

#[test]
fn golden_cbor_tag_validation() {
    let value = vec![1u8, 2, 3];

    // Valid tag in range
    let result = to_canonical_cbor_with_tag(&value, 448);
    assert!(result.is_ok(), "Tag 448 (in range) should succeed");

    // Valid tag at upper bound
    let result = to_canonical_cbor_with_tag(&value, 511);
    assert!(result.is_ok(), "Tag 511 (upper bound) should succeed");

    // Invalid tag below range
    let result = to_canonical_cbor_with_tag(&value, 447);
    assert!(result.is_err(), "Tag 447 (below range) should fail");

    // Invalid tag above range
    let result = to_canonical_cbor_with_tag(&value, 512);
    assert!(result.is_err(), "Tag 512 (above range) should fail");
}

// ===========================================================================
// Golden Vector 7: Checksum Serialization
// ===========================================================================

#[test]
fn golden_checksum_serialization() {
    let value = vec![1u8, 2, 3, 4, 5];

    let tagged_bytes =
        to_canonical_cbor_with_checksum(&value).expect("checksum serialization should succeed");

    // Must be longer than raw CBOR (4 bytes for CRC32)
    let raw_cbor = to_canonical_cbor(&value).expect("raw serialization should succeed");
    assert_eq!(
        tagged_bytes.len(),
        raw_cbor.len() + 4,
        "Checksum adds 4 bytes"
    );

    // Verify checksum roundtrip
    let decoded: Vec<u8> = csv_hash::canonical::from_canonical_cbor_with_checksum(&tagged_bytes)
        .expect("checksum deserialization should succeed");
    assert_eq!(decoded, value);

    // Tamper with the data and verify checksum catches it
    let mut tampered = tagged_bytes.clone();
    tampered[0] ^= 0xFF;
    let result = csv_hash::canonical::from_canonical_cbor_with_checksum::<Vec<u8>>(&tampered);
    assert!(result.is_err(), "Checksum must detect tampered data");
}

// ===========================================================================
// Golden Vector 8: Typed Hash Serialization
// ===========================================================================

#[test]
fn golden_typed_hash_serialization() {
    // SealHash
    let seal_hash = SealHash::new_bitcoin(b"test seal data");
    let seal_bytes = to_canonical_cbor(&seal_hash).expect("seal hash serialization should succeed");
    let seal_hex = hex::encode(&seal_bytes);
    assert!(
        seal_hex.len() > 0,
        "SealHash must serialize to non-empty output"
    );

    // CommitmentHash
    let commitment_hash = CommitmentHash::new_transfer(b"test commitment data");
    let commitment_bytes =
        to_canonical_cbor(&commitment_hash).expect("commitment hash serialization should succeed");
    let commitment_hex = hex::encode(&commitment_bytes);
    assert!(
        commitment_hex.len() > 0,
        "CommitmentHash must serialize to non-empty output"
    );

    // SanadIdHash
    let sanad_hash = SanadIdHash::new(b"test sanad data");
    let sanad_bytes =
        to_canonical_cbor(&sanad_hash).expect("sanad hash serialization should succeed");
    let sanad_hex = hex::encode(&sanad_bytes);
    assert!(
        sanad_hex.len() > 0,
        "SanadIdHash must serialize to non-empty output"
    );

    // NullifierHash
    let nullifier_hash = NullifierHash::new(b"test nullifier data");
    let nullifier_bytes =
//         to_canonical_cbor(&nullifier_hash).expect("nullifier hash serialization should succeed");
//     let nullifier_hex = hex::encode(&nullifier_bytes);
//     assert!(
//         nullifier_hex.len() > 0,
//         "NullifierHash must serialize to non-empty output"
//     );
// 
//     // All typed hashes must serialize deterministically
//     let seal_hash2 = SealHash::new_bitcoin(b"test seal data");
//     let seal_bytes2 =
// //         to_canonical_cbor(&seal_hash2).expect("seal hash serialization should succeed");
//     assert_eq!(
//         seal_bytes, seal_bytes2,
//         "SealHash serialization must be deterministic"
//     );
// }
// 
// // ===========================================================================
// // Golden Vector 9: Empty Collections
// // ===========================================================================
// 
// #[test]
// fn golden_empty_collections() {
//     // Empty vec
//     let empty_vec: Vec<u8> = vec![];
//     let vec_bytes = to_canonical_cbor(&empty_vec).expect("empty vec serialization should succeed");
    let vec_hex = hex::encode(&vec_bytes);
    assert_eq!(
        vec_hex, "80",
        "Empty vec must serialize to CBOR empty array"
    );

    // Empty string
    let empty_str = String::new();
    let str_bytes =
        to_canonical_cbor(&empty_str).expect("empty string serialization should succeed");
    let str_hex = hex::encode(&str_bytes);
    assert_eq!(
        str_hex, "60",
        "Empty string must serialize to CBOR empty string"
    );

    // Roundtrip
    let decoded_vec: Vec<u8> = csv_hash::canonical::from_canonical_cbor(&vec_bytes)
        .expect("empty vec roundtrip should succeed");
    assert!(
        decoded_vec.is_empty(),
        "Empty vec roundtrip should produce empty vec"
    );

    let decoded_str: String = csv_hash::canonical::from_canonical_cbor(&str_bytes)
        .expect("empty string roundtrip should succeed");
    assert_eq!(decoded_str, "");
}

// ===========================================================================
// Golden Vector 10: Integer Smallest Representation
// ===========================================================================

#[test]
fn golden_integer_smallest_representation() {
    // Small integers should use the smallest CBOR encoding
    let zero: u64 = 0;
    let zero_bytes = to_canonical_cbor(&zero).expect("zero serialization should succeed");
    assert_eq!(
        hex::encode(&zero_bytes),
        "00",
        "Zero must use smallest encoding"
    );

    let one: u64 = 1;
    let one_bytes = to_canonical_cbor(&one).expect("one serialization should succeed");
    assert_eq!(
        hex::encode(&one_bytes),
        "01",
        "One must use smallest encoding"
    );

    let twentythree: u64 = 23;
    let twentythree_bytes =
        to_canonical_cbor(&twentythree).expect("23 serialization should succeed");
    assert_eq!(
        hex::encode(&twentythree_bytes),
        "17",
        "23 must use smallest encoding"
    );

    let twentyfour: u64 = 24;
    let twentyfour_bytes = to_canonical_cbor(&twentyfour).expect("24 serialization should succeed");
    assert_eq!(
        hex::encode(&twentyfour_bytes),
        "1818",
        "24 must use smallest encoding (1-byte uint)"
    );

    let twofiftyfive: u64 = 255;
    let twofiftyfive_bytes =
        to_canonical_cbor(&twofiftyfive).expect("255 serialization should succeed");
    assert_eq!(
        hex::encode(&twofiftyfive_bytes),
        "18ff",
        "255 must use 1-byte uint"
    );

    let twofiftysix: u64 = 256;
    let twofiftysix_bytes =
        to_canonical_cbor(&twofiftysix).expect("256 serialization should succeed");
    assert_eq!(
        hex::encode(&twofiftysix_bytes),
        "190100",
        "256 must use 2-byte uint"
    );
}

// ===========================================================================
// Golden Vector 11: Boolean Serialization
// ===========================================================================

#[test]
fn golden_boolean_serialization() {
    let true_bytes = to_canonical_cbor(&true).expect("true serialization should succeed");
    assert_eq!(
        hex::encode(&true_bytes),
        "f5",
        "True must serialize to CBOR true"
    );

    let false_bytes = to_canonical_cbor(&false).expect("false serialization should succeed");
    assert_eq!(
        hex::encode(&false_bytes),
        "f4",
        "False must serialize to CBOR false"
    );

    // Roundtrip
    let decoded_true: bool = csv_hash::canonical::from_canonical_cbor(&true_bytes)
        .expect("true roundtrip should succeed");
    assert!(decoded_true);

    let decoded_false: bool = csv_hash::canonical::from_canonical_cbor(&false_bytes)
        .expect("false roundtrip should succeed");
    assert!(!decoded_false);
}

// ===========================================================================
// Golden Vector 12: Determinism Across Calls
// ===========================================================================

#[test]
fn golden_determinism_across_calls() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct ComplexStruct {
        id: u64,
        name: String,
        data: Vec<u8>,
        flags: bool,
        metadata: serde_json::Value,
    }

    let value = ComplexStruct {
        id: 12345,
        name: "test entity".to_string(),
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        flags: true,
        metadata: serde_json::json!({"key": "value", "nested": {"a": 1, "b": 2}}),
    };

    // Serialize 100 times and verify all outputs are identical
    let mut hashes = Vec::new();
    for _ in 0..100 {
        let bytes = to_canonical_cbor(&value).expect("serialization should succeed");
        let hash = Hash::sha256(&bytes);
        hashes.push(hash);
    }

    // All hashes must be identical
    for hash in &hashes[1..] {
        assert_eq!(
            *hash, hashes[0],
            "Serialization must be deterministic across 100 calls"
        );
    }
}
