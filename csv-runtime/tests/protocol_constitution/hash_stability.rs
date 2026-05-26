// Protocol Hash Stability Tests
//
// Invariant: Protocol hashes must remain stable across versions
// unless explicitly changed via RFC and version bump.

use csv_hash::{
    DomainSeparatedHash, Hash, HashDomain,
    canonical::{from_canonical_cbor, to_canonical_cbor},
    commitment::Commitment,
    dag::DAGSegment,
    domains::{ProofBundleDomain, ReplayRegistryDomain, TransitionDomain},
    seal::{CommitAnchor, SealPoint},
    tagged_hash::{csv_tagged_hash, tagged_hash},
};
use csv_protocol::proof_types::{FinalityProof, InclusionProof, ProofBundle};

/// Test that canonical serialization produces stable, deterministic hashes
/// for protocol types across multiple serializations.
#[test]
fn protocol_hashes_are_stable() {
    // 1. SealPoint hash stability via canonical CBOR
    let seal = SealPoint::new(vec![0xAA; 16], Some(42)).unwrap();
    let cbor1 = to_canonical_cbor(&seal).expect("seal serialization");
    let cbor2 = to_canonical_cbor(&seal).expect("seal serialization");
    assert_eq!(cbor1, cbor2, "Canonical CBOR must be deterministic");

    let hash1 = Hash::sha256(&cbor1);
    let hash2 = Hash::sha256(&cbor2);
    assert_eq!(hash1, hash2, "Hash of canonical CBOR must be stable");

    // 2. CommitAnchor hash stability
    let anchor = CommitAnchor::new(vec![0xBB; 8], 100, vec![0xCC; 4]).unwrap();
    let cbor_a1 = to_canonical_cbor(&anchor).expect("anchor serialization");
    let cbor_a2 = to_canonical_cbor(&anchor).expect("anchor serialization");
    assert_eq!(cbor_a1, cbor_a2, "Anchor CBOR must be deterministic");

    // 3. DAGSegment hash stability
    let node = csv_hash::dag::DAGNode::new(
        Hash::new([1u8; 32]),
        vec![0x01, 0x02],
        vec![vec![0xAB; 32]],
        vec![],
        vec![],
    );
    let segment = DAGSegment::new(vec![node], Hash::new([99u8; 32]));
    let cbor_s1 = to_canonical_cbor(&segment).expect("segment serialization");
    let cbor_s2 = to_canonical_cbor(&segment).expect("segment serialization");
    assert_eq!(cbor_s1, cbor_s2, "Segment CBOR must be deterministic");

    // 4. ProofBundle roundtrip stability
    let bundle = ProofBundle::new(
        DAGSegment::new(vec![], Hash::zero()),
        vec![vec![0xDE; 16]],
        SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
        CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
        InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
        FinalityProof::new(vec![], 6, false).unwrap(),
    )
    .unwrap();

    let bytes1 = to_canonical_cbor(&bundle).expect("bundle serialization");
    let bytes2 = to_canonical_cbor(&bundle).expect("bundle serialization");
    assert_eq!(bytes1, bytes2, "ProofBundle bytes must be deterministic");

    let restored1: ProofBundle = from_canonical_cbor(&bytes1).expect("bundle deserialization");
    let restored2: ProofBundle = from_canonical_cbor(&bytes2).expect("bundle deserialization");
    assert_eq!(restored1, restored2, "Restored bundles must be equal");

    // 5. Commitment hash stability
    let seal2 = SealPoint::new(vec![0xFF; 16], Some(1)).unwrap();
    let commitment = Commitment::simple(
        Hash::new([10u8; 32]),
        Hash::new([20u8; 32]),
        Hash::new([30u8; 32]),
        &seal2,
        [0xEE; 32],
    );
    let h1 = commitment.commitment_hash();
    let h2 = commitment.commitment_hash();
    assert_eq!(h1, h2, "Commitment hash must be stable across calls");

    // 6. Verify roundtrip preserves hash
    let cbor_c = commitment.to_canonical_bytes();
    let restored_commitment: Commitment =
        from_canonical_cbor(&cbor_c).expect("commitment deserialization");
    assert_eq!(
        commitment, restored_commitment,
        "Commitment roundtrip must preserve value"
    );
    assert_eq!(
        h1,
        restored_commitment.commitment_hash(),
        "Restored commitment hash must match"
    );
}

/// Verify that all hash domain tags are unique and stable.
#[test]
fn hash_domain_separation_is_enforced() {
    // Collect all domain tags
    let domains = vec![
        HashDomain::BitcoinSealV1,
        HashDomain::EthereumSealV1,
        HashDomain::SolanaSealV1,
        HashDomain::SuiSealV1,
        HashDomain::AptosSealV1,
        HashDomain::CelestiaSealV1,
        HashDomain::StarkSealV1,
        HashDomain::TransferCommitmentV1,
        HashDomain::SanadId,
        HashDomain::Nullifier,
        HashDomain::ReplayIdV1,
        HashDomain::VerificationProofV1,
        HashDomain::StealthAddressV1,
        HashDomain::ProtocolVersion,
        HashDomain::MerkleCombine,
        HashDomain::MerkleLeaf,
    ];

    // All tags must be unique
    let tags: Vec<&[u8]> = domains.iter().map(|d| d.as_bytes()).collect();
    let unique_tags: std::collections::HashSet<&[u8]> = tags.iter().copied().collect();
    assert_eq!(
        tags.len(),
        unique_tags.len(),
        "All hash domain tags must be unique"
    );

    // Verify domain separation: same data in different domains produces different hashes
    let test_data = b"test_payload_for_domain_separation";

    let h1 = tagged_hash(HashDomain::BitcoinSealV1, test_data);
    let h2 = tagged_hash(HashDomain::EthereumSealV1, test_data);
    let h3 = tagged_hash(HashDomain::SolanaSealV1, test_data);

    assert_ne!(
        h1.hash, h2.hash,
        "Bitcoin and Ethereum seal domains must differ"
    );
    assert_ne!(
        h2.hash, h3.hash,
        "Ethereum and Solana seal domains must differ"
    );
    assert_ne!(
        h1.hash, h3.hash,
        "Bitcoin and Solana seal domains must differ"
    );

    // Verify tagged_hash_str (BIP-340 style) produces different results than raw SHA256
    let raw_hash = Hash::sha256(test_data);
    let tagged_result = csv_tagged_hash("test_domain", test_data);
    let tagged_hash_val = Hash::new(tagged_result);
    assert_ne!(
        raw_hash, tagged_hash_val,
        "Tagged hash must differ from raw SHA256"
    );

    // Verify domain-separated hashing via DomainSeparatedHash
    let dh1 = DomainSeparatedHash::<ProofBundleDomain>::hash(test_data);
    let dh2 = DomainSeparatedHash::<TransitionDomain>::hash(test_data);
    let dh3 = DomainSeparatedHash::<ReplayRegistryDomain>::hash(test_data);

    assert_ne!(dh1, dh2, "ProofBundle and Transition domains must differ");
    assert_ne!(
        dh2, dh3,
        "Transition and ReplayRegistry domains must differ"
    );
    assert_ne!(
        dh1, dh3,
        "ProofBundle and ReplayRegistry domains must differ"
    );

    // Verify domain separation prevents replay: same payload, different domains
    let payload = b"valid_proof_data";
    let hash_pb = DomainSeparatedHash::<ProofBundleDomain>::hash(payload);
    let hash_rr = DomainSeparatedHash::<ReplayRegistryDomain>::hash(payload);
    assert_ne!(
        hash_pb, hash_rr,
        "Domain separation must prevent cross-domain replay"
    );
}
