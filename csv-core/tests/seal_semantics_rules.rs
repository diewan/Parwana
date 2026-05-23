//! Seal Semantics Rules — Protocol Constitution Section 5

#[cfg(test)]
mod tests {
    use csv_core::seal::{CommitAnchor, SealPoint};

    #[test]
    fn seal_point_requires_non_empty_id() {
        assert!(SealPoint::new(vec![], None).is_err());
    }

    #[test]
    fn commit_anchor_requires_non_empty_anchor_id() {
        assert!(CommitAnchor::new(vec![], 100, vec![]).is_err());
    }

    #[test]
    fn commit_anchor_binds_block_height() {
        let anchor = CommitAnchor::new(vec![0xABu8; 32], 42, vec![]).unwrap();
        assert_eq!(anchor.block_height, 42);
    }

    #[test]
    fn distinct_seal_ids_are_not_equal() {
        let s1 = SealPoint::new(vec![1u8; 32], None).unwrap();
        let s2 = SealPoint::new(vec![2u8; 32], None).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn seal_serialization_roundtrip_preserves_id() {
        let seal = SealPoint::new(vec![0xCDu8; 32], Some(7)).unwrap();
        let bytes = seal.to_vec();
        let restored = SealPoint::from_bytes(&bytes).unwrap();
        assert_eq!(seal, restored);
        assert!(!restored.id.is_empty());
    }
}
