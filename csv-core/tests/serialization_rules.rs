#![cfg(any())]
//! Serialization Rules — Protocol Constitution Section 2
//!
//! Tests for canonical CBOR serialization requirements.

#[cfg(test)]
mod tests {
    use csv_core::canonical::{from_canonical_cbor, to_canonical_cbor};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct TestStruct {
        a: u32,
        b: String,
        c: Vec<u8>,
    }

    /// Property: Canonical serialization is deterministic
    #[test]
    fn test_canonical_deterministic() {
        let v = TestStruct {
            a: 42,
            b: "hello".into(),
            c: vec![1, 2, 3],
        };
        let b1 = to_canonical_cbor(&v).unwrap();
        let b2 = to_canonical_cbor(&v).unwrap();
        assert_eq!(b1, b2, "Canonical serialization must be deterministic");
    }

    /// Property: Canonical serialization roundtrip is lossless
    #[test]
    fn test_canonical_roundtrip() {
        let v = TestStruct {
            a: 42,
            b: "hello".into(),
            c: vec![1, 2, 3],
        };
        let bytes = to_canonical_cbor(&v).unwrap();
        let restored: TestStruct = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(v, restored, "Roundtrip must be lossless");
    }

    /// Property: Different values produce different serialization
    #[test]
    fn test_different_values_different_serialization() {
        let v1 = TestStruct {
            a: 1,
            b: "one".into(),
            c: vec![1],
        };
        let v2 = TestStruct {
            a: 2,
            b: "two".into(),
            c: vec![2],
        };
        let b1 = to_canonical_cbor(&v1).unwrap();
        let b2 = to_canonical_cbor(&v2).unwrap();
        assert_ne!(
            b1, b2,
            "Different values must produce different serialization"
        );
    }

    /// Property: Empty structures serialize correctly
    #[test]
    fn test_empty_structures() {
        let v = TestStruct {
            a: 0,
            b: String::new(),
            c: vec![],
        };
        let bytes = to_canonical_cbor(&v).unwrap();
        let restored: TestStruct = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(v, restored);
    }

    /// Property: Large structures serialize correctly
    #[test]
    fn test_large_structures() {
        let v = TestStruct {
            a: u32::MAX,
            b: "x".repeat(1000),
            c: vec![0xABu8; 1000],
        };
        let bytes = to_canonical_cbor(&v).unwrap();
        let restored: TestStruct = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(v, restored);
    }

    /// Property: Invalid CBOR is rejected
    #[test]
    fn test_invalid_cbor_rejected() {
        let invalid = vec![0xFF, 0xFF, 0xFF];
        let result = from_canonical_cbor::<TestStruct>(&invalid);
        assert!(result.is_err(), "Invalid CBOR must be rejected");
    }

    /// Property: Truncated CBOR is rejected
    #[test]
    fn test_truncated_cbor_rejected() {
        let v = TestStruct {
            a: 42,
            b: "hello".into(),
            c: vec![1, 2, 3],
        };
        let bytes = to_canonical_cbor(&v).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        let result = from_canonical_cbor::<TestStruct>(truncated);
        assert!(result.is_err(), "Truncated CBOR must be rejected");
    }
}
