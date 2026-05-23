//! Hashing Rules — Protocol Constitution Section 3
//!
//! Tests for tagged hashing and domain separation requirements.

#[cfg(test)]
mod tests {
    use csv_core::Hash;
    use csv_core::tagged_hash::csv_tagged_hash;

    /// Property: Tagged hash is deterministic
    #[test]
    fn test_tagged_hash_deterministic() {
        let data = b"test data";
        let h1 = csv_tagged_hash("test.domain", data);
        let h2 = csv_tagged_hash("test.domain", data);
        assert_eq!(h1, h2, "Tagged hash must be deterministic");
    }

    /// Property: Different tags produce different hashes
    #[test]
    fn test_different_tags_different_hashes() {
        let data = b"test data";
        let h1 = csv_tagged_hash("tag.a", data);
        let h2 = csv_tagged_hash("tag.b", data);
        assert_ne!(h1, h2, "Different tags must produce different hashes");
    }

    /// Property: Different data produces different hashes
    #[test]
    fn test_different_data_different_hashes() {
        let h1 = csv_tagged_hash("test.domain", b"data1");
        let h2 = csv_tagged_hash("test.domain", b"data2");
        assert_ne!(h1, h2, "Different data must produce different hashes");
    }

    /// Property: Hash::combine uses tagged hashing
    #[test]
    fn test_hash_combine_uses_tagged_hashing() {
        let left = Hash::new([1u8; 32]);
        let right = Hash::new([2u8; 32]);
        let combined = Hash::combine(&left, &right);
        
        assert_ne!(combined, left);
        assert_ne!(combined, right);
    }

    /// Property: Hash::combine is commutative in terms of uniqueness
    #[test]
    fn test_hash_combine_uniqueness() {
        let a = Hash::new([1u8; 32]);
        let b = Hash::new([2u8; 32]);
        let c = Hash::new([3u8; 32]);
        
        let ab = Hash::combine(&a, &b);
        let ac = Hash::combine(&a, &c);
        let bc = Hash::combine(&b, &c);
        
        assert_ne!(ab, ac, "Different inputs must produce different combined hashes");
        assert_ne!(ab, bc, "Different inputs must produce different combined hashes");
    }

    /// Property: Hash zero is all zeros
    #[test]
    fn test_hash_zero_is_zeros() {
        let zero = Hash::zero();
        assert_eq!(zero.as_bytes(), &[0u8; 32]);
    }

    /// Property: Hash hex encoding/decoding roundtrip
    #[test]
    fn test_hash_hex_roundtrip() {
        let original = Hash::new([0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                  0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                  0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D]);
        let hex = original.to_hex();
        let restored = Hash::from_hex(&hex).unwrap();
        assert_eq!(original, restored);
    }

    /// Property: Hash hex encoding is lowercase
    #[test]
    fn test_hash_hex_lowercase() {
        let hash = Hash::new([0xABu8; 32]);
        let hex = hash.to_hex();
        assert_eq!(hex, hex.to_lowercase(), "Hex encoding must be lowercase");
    }

    /// Property: Hash from_hex rejects invalid input
    #[test]
    fn test_hash_from_hex_invalid() {
        let result = Hash::from_hex("not-a-valid-hex");
        assert!(result.is_err(), "Invalid hex must be rejected");
    }

    /// Property: Hash Display shows abbreviated form
    #[test]
    fn test_hash_display_abbreviated() {
        let hash = Hash::new([0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05,
                              0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                              0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D]);
        let display = format!("{}", hash);
        assert!(display.starts_with("0x"), "Display must start with 0x");
        assert!(display.len() < 66, "Display must be abbreviated (less than full hex)");
    }
}
