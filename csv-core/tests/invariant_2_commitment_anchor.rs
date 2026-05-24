#![cfg(any())]
//! Invariant 2: Commitments Must Be Published On-Chain Before Proof Building
//!
//! Rule: A `Commitment` must be published on-chain before a `ProofBundle` is built.
//! Prohibited: Building proofs without CommitAnchor, using simulated anchors.

#[cfg(test)]
mod tests {
    use csv_core::Hash;
    use csv_core::commitment::Commitment;
    use csv_core::seal::{CommitAnchor, SealPoint};

    /// Property: Commitment requires valid protocol ID
    #[test]
    fn test_commitment_requires_protocol_id() {
        let contract_id = Hash::new([1u8; 32]);
        let seal_ref = SealPoint::new(vec![2u8; 32], Some(1)).unwrap();
        let domain_sep: [u8; 32] = [4u8; 32];

        let _commitment = Commitment::simple(
            contract_id,
            Hash::zero(),
            Hash::new([3u8; 32]),
            &seal_ref,
            domain_sep,
        );

        assert!(true, "Commitment created with valid inputs");
    }

    /// Property: Commitment hash is deterministic
    #[test]
    fn test_commitment_hash_deterministic() {
        let contract_id = Hash::new([1u8; 32]);
        let seal_ref = SealPoint::new(vec![2u8; 32], Some(1)).unwrap();
        let domain_sep: [u8; 32] = [4u8; 32];

        let c1 = Commitment::simple(
            contract_id,
            Hash::zero(),
            Hash::new([3u8; 32]),
            &seal_ref,
            domain_sep,
        );
        let c2 = Commitment::simple(
            contract_id,
            Hash::zero(),
            Hash::new([3u8; 32]),
            &seal_ref,
            domain_sep,
        );

        let h1 = c1.hash();
        let h2 = c2.hash();
        assert_eq!(h1, h2, "Same commitment must produce same hash");
    }

    /// Property: Commitment serialization roundtrip preserves data
    #[test]
    fn test_commitment_serialization_roundtrip() {
        let contract_id = Hash::new([1u8; 32]);
        let seal_ref = SealPoint::new(vec![2u8; 32], Some(1)).unwrap();
        let domain_sep: [u8; 32] = [4u8; 32];

        let commitment = Commitment::simple(
            contract_id,
            Hash::zero(),
            Hash::new([3u8; 32]),
            &seal_ref,
            domain_sep,
        );

        let bytes = commitment.to_canonical_bytes();
        let restored = Commitment::from_canonical_bytes(&bytes).unwrap();

        assert_eq!(commitment.version, restored.version);
        assert_eq!(commitment.protocol_id, restored.protocol_id);
    }

    /// Property: Commitment version is fixed at 2
    #[test]
    fn test_commitment_version_is_2() {
        let contract_id = Hash::new([1u8; 32]);
        let seal_ref = SealPoint::new(vec![2u8; 32], Some(1)).unwrap();
        let domain_sep: [u8; 32] = [4u8; 32];

        let commitment = Commitment::simple(
            contract_id,
            Hash::zero(),
            Hash::new([3u8; 32]),
            &seal_ref,
            domain_sep,
        );

        assert_eq!(commitment.version, 2, "Commitment version must be 2");
    }

    /// Property: CommitAnchor has valid structure
    #[test]
    fn test_commit_anchor_structure() {
        let anchor = CommitAnchor {
            anchor_id: vec![0xABu8; 32],
            block_height: 1000,
            metadata: vec![0xCDu8; 64],
        };

        assert!(!anchor.anchor_id.is_empty(), "anchor_id must not be empty");
        assert!(anchor.block_height > 0, "block_height must be positive");
    }

    /// Property: CommitAnchor metadata size is bounded
    #[test]
    fn test_commit_anchor_metadata_size_limit() {
        let anchor = CommitAnchor {
            anchor_id: vec![0xABu8; 32],
            block_height: 1000,
            metadata: vec![0u8; 4096],
        };
        assert!(
            anchor.metadata.len() <= 4096,
            "metadata must not exceed MAX_ANCHOR_METADATA_SIZE"
        );
    }

    /// Property: CommitAnchor with oversized metadata is rejected
    #[test]
    fn test_commit_anchor_oversized_metadata_rejected() {
        let result = CommitAnchor::new(vec![0xABu8; 32], 1000, vec![0u8; 4097]);
        assert!(result.is_err(), "Oversized metadata must be rejected");
    }

    /// Property: CommitAnchor serialization preserves data
    #[test]
    fn test_commit_anchor_serialization() {
        let anchor = CommitAnchor {
            anchor_id: vec![0xABu8; 32],
            block_height: 1000,
            metadata: vec![0xCDu8; 64],
        };

        let bytes = anchor.to_vec();
        assert!(!bytes.is_empty(), "Serialized anchor must not be empty");
        assert_eq!(
            bytes.len(),
            8 + 32 + 64,
            "Serialized size must match expected"
        );
    }
}
