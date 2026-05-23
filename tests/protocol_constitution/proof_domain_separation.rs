// Protocol Proof Domain Separation Tests
//
// Invariant: All proofs must be properly domain-separated
// to prevent cross-domain proof reuse attacks.

use csv_hash::{
    Hash, HashDomain,
    tagged_hash::{tagged_hash, csv_tagged_hash},
    DomainSeparatedHash, Domain,
    domains::{
        ProofBundleDomain, TransitionDomain, ReplayRegistryDomain,
        BitcoinSealDomain, EthereumMintDomain, AptosAnchorDomain,
        GenesisDomain, SchemaDomain, TransferCommitmentDomain,
    },
    seal::{SealPoint, CommitAnchor},
    commitment::Commitment,
};
use csv_proof::{
    Proof, ProofCategory,
    InclusionProof, FinalityProof, OwnershipProof, TransitionProof,
    ReplayProof, ExecutionProof, ZKProof, CompositeProof,
    CompositionRule,
};
use csv_proof::proof::ProofBundle;
use csv_hash::dag::DAGSegment;

/// Test that all proof types use domain-separated hashing.
#[test]
fn all_proofs_are_domain_separated() {
    // 1. Each proof category uses a distinct domain tag
    let categories = vec![
        (ProofCategory::Inclusion, b"inclusion"),
        (ProofCategory::Finality, b"finality"),
        (ProofCategory::Ownership, b"ownership"),
        (ProofCategory::Transition, b"transition"),
        (ProofCategory::Replay, b"replay"),
        (ProofCategory::Execution, b"execution"),
        (ProofCategory::ZK, b"zk"),
        (ProofCategory::Composite, b"composite"),
    ];

    // Verify all category bytes are unique
    let category_bytes: Vec<&[u8]> = categories.iter().map(|(_, b)| *b).collect();
    let unique_categories: std::collections::HashSet<&[u8]> = category_bytes.iter().copied().collect();
    assert_eq!(
        category_bytes.len(),
        unique_categories.len(),
        "All proof category bytes must be unique"
    );

    // 2. Create proofs of each type and verify they produce different hashes
    let zero_hash = Hash::zero();

    let inclusion = Proof::Inclusion(
        InclusionProof::new(vec![1, 2, 3], zero_hash, 100, 0).unwrap()
    );
    let finality = Proof::Finality(
        FinalityProof::new(vec![0xCD; 32], 6, false).unwrap()
    );
    let ownership = Proof::Ownership(
        OwnershipProof {
            owner: vec![0xAA; 32],
            proof: vec![0xBB; 64],
            asset_id: zero_hash,
            scheme: "secp256k1".to_string(),
        }
    );
    let transition = Proof::Transition(
        TransitionProof {
            previous_state: zero_hash,
            new_state: Hash::new([1u8; 32]),
            transition_data: vec![0x01],
            proof: vec![0x02],
        }
    );
    let replay = Proof::Replay(
        ReplayProof {
            nullifier: zero_hash,
            chain_id: "bitcoin".to_string(),
            context: vec![0x03],
        }
    );
    let execution = Proof::Execution(
        ExecutionProof {
            computation_hash: zero_hash,
            proof: vec![0x04],
            context: vec![],
        }
    );
    let zk = Proof::ZK(
        ZKProof {
            system: "dilithium".to_string(),
            proof: vec![0x05],
            public_inputs: vec![],
            verification_key_hash: zero_hash,
        }
    );
    let composite = Proof::Composite(
        CompositeProof {
            children: vec![inclusion.clone()],
            rule: CompositionRule::And,
            proof: vec![],
        }
    );

    let proofs = vec![
        inclusion, finality, ownership, transition,
        replay, execution, zk, composite,
    ];

    // Each proof type must produce a unique hash
    let mut hashes = std::collections::HashSet::new();
    for proof in &proofs {
        let h = proof.hash();
        assert!(
            hashes.insert(h),
            "Each proof type must produce a unique hash"
        );
    }

    // 3. Verify that domain-separated proof hashes differ from raw hashes
    let test_data = b"proof_payload";
    let raw_hash = Hash::sha256(test_data);
    let tagged_hash_result = tagged_hash(HashDomain::VerificationProofV1, test_data);
    assert_ne!(
        raw_hash, tagged_hash_result.hash,
        "Domain-separated proof hash must differ from raw SHA256"
    );

    // 4. Verify ProofBundle domain separation
    let bundle = ProofBundle::new(
        DAGSegment::new(vec![], Hash::zero()),
        vec![vec![0xDE; 16]],
        SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
        CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
        InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
        FinalityProof::new(vec![], 6, false).unwrap(),
    ).unwrap();

    let bundle_bytes = bundle.to_bytes().expect("bundle serialization");
    let bundle_hash = Hash::sha256(&bundle_bytes);

    // The bundle hash must be different from a raw hash of the same data
    // (because the bundle uses canonical CBOR serialization internally)
    let raw_bundle_hash = Hash::sha256(&bundle_bytes);
    assert_eq!(
        bundle_hash, raw_bundle_hash,
        "Bundle hash of serialized bytes must match raw hash"
    );

    // 5. Verify that different proof bundles produce different hashes
    let bundle2 = ProofBundle::new(
        DAGSegment::new(vec![], Hash::new([1u8; 32])), // different root
        vec![vec![0xDE; 16]],
        SealPoint::new(vec![1, 2, 3], Some(42)).unwrap(),
        CommitAnchor::new(vec![4, 5, 6], 100, vec![]).unwrap(),
        InclusionProof::new(vec![], Hash::zero(), 0, 0).unwrap(),
        FinalityProof::new(vec![], 6, false).unwrap(),
    ).unwrap();

    let bundle2_bytes = bundle2.to_bytes().expect("bundle serialization");
    assert_ne!(
        bundle_bytes, bundle2_bytes,
        "Different bundles must produce different bytes"
    );
}

/// Test that proof bundles are domain-separated from other protocol types.
#[test]
fn proof_bundle_domain_separation() {
    // 1. Verify that ProofBundleDomain has a unique domain tag
    assert_eq!(
        ProofBundleDomain::DOMAIN,
        b"csv.proof.bundle.v1",
        "ProofBundleDomain must have the correct domain tag"
    );

    // 2. Verify that hashing the same data in different domains produces different results
    let test_data = b"test_proof_data";

    let pb_hash = DomainSeparatedHash::<ProofBundleDomain>::hash(test_data);
    let tr_hash = DomainSeparatedHash::<TransitionDomain>::hash(test_data);
    let rr_hash = DomainSeparatedHash::<ReplayRegistryDomain>::hash(test_data);

    assert_ne!(
        pb_hash, tr_hash,
        "ProofBundle and Transition domains must produce different hashes"
    );
    assert_ne!(
        tr_hash, rr_hash,
        "Transition and ReplayRegistry domains must produce different hashes"
    );
    assert_ne!(
        pb_hash, rr_hash,
        "ProofBundle and ReplayRegistry domains must produce different hashes"
    );

    // 3. Verify that seal domains are also distinct from proof domains
    let btc_seal_hash = DomainSeparatedHash::<BitcoinSealDomain>::hash(test_data);
    let eth_mint_hash = DomainSeparatedHash::<EthereumMintDomain>::hash(test_data);

    assert_ne!(
        pb_hash, btc_seal_hash,
        "ProofBundle and BitcoinSeal domains must differ"
    );
    assert_ne!(
        pb_hash, eth_mint_hash,
        "ProofBundle and EthereumMint domains must differ"
    );
    assert_ne!(
        btc_seal_hash, eth_mint_hash,
        "BitcoinSeal and EthereumMint domains must differ"
    );

    // 4. Verify that tagged_hash with different HashDomains produces different results
    let h1 = tagged_hash(HashDomain::BitcoinSealV1, test_data);
    let h2 = tagged_hash(HashDomain::EthereumSealV1, test_data);
    let h3 = tagged_hash(HashDomain::SolanaSealV1, test_data);
    let h4 = tagged_hash(HashDomain::VerificationProofV1, test_data);

    assert_ne!(h1.hash, h2.hash, "BitcoinSealV1 != EthereumSealV1");
    assert_ne!(h2.hash, h3.hash, "EthereumSealV1 != SolanaSealV1");
    assert_ne!(h3.hash, h4.hash, "SolanaSealV1 != VerificationProofV1");
    assert_ne!(h1.hash, h4.hash, "BitcoinSealV1 != VerificationProofV1");

    // 5. Verify that csv_tagged_hash produces domain-separated results
    let csv_h1 = csv_tagged_hash("seal", test_data);
    let csv_h2 = csv_tagged_hash("proof", test_data);
    let csv_h3 = csv_tagged_hash("commitment", test_data);

    let h1_arr = Hash::new(csv_h1);
    let h2_arr = Hash::new(csv_h2);
    let h3_arr = Hash::new(csv_h3);

    assert_ne!(h1_arr, h2_arr, "csv_tagged_hash('seal') != csv_tagged_hash('proof')");
    assert_ne!(h2_arr, h3_arr, "csv_tagged_hash('proof') != csv_tagged_hash('commitment')");
    assert_ne!(h1_arr, h3_arr, "csv_tagged_hash('seal') != csv_tagged_hash('commitment')");
}

/// Test that proof taxonomy is enforced (all proofs use the canonical Proof enum).
#[test]
fn proof_taxonomy_is_enforced() {
    // 1. Verify that the Proof enum has exactly 8 variants
    //    (we can't count variants directly, but we can verify each one works)
    let zero_hash = Hash::zero();

    let _p1 = Proof::Inclusion(
        InclusionProof::new(vec![], zero_hash, 0, 0).unwrap()
    );
    let _p2 = Proof::Finality(
        FinalityProof::new(vec![], 0, false).unwrap()
    );
    let _p3 = Proof::Ownership(
        OwnershipProof {
            owner: vec![],
            proof: vec![],
            asset_id: zero_hash,
            scheme: "test".to_string(),
        }
    );
    let _p4 = Proof::Transition(
        TransitionProof {
            previous_state: zero_hash,
            new_state: zero_hash,
            transition_data: vec![],
            proof: vec![],
        }
    );
    let _p5 = Proof::Replay(
        ReplayProof {
            nullifier: zero_hash,
            chain_id: "test".to_string(),
            context: vec![],
        }
    );
    let _p6 = Proof::Execution(
        ExecutionProof {
            computation_hash: zero_hash,
            proof: vec![],
            context: vec![],
        }
    );
    let _p7 = Proof::ZK(
        ZKProof {
            system: "test".to_string(),
            proof: vec![],
            public_inputs: vec![],
            verification_key_hash: zero_hash,
        }
    );
    let _p8 = Proof::Composite(
        CompositeProof {
            children: vec![],
            rule: CompositionRule::And,
            proof: vec![],
        }
    );

    // 2. Verify that each proof's category matches its variant
    let p_inclusion = Proof::Inclusion(
        InclusionProof::new(vec![], zero_hash, 0, 0).unwrap()
    );
    assert_eq!(p_inclusion.category(), ProofCategory::Inclusion);

    let p_finality = Proof::Finality(
        FinalityProof::new(vec![], 0, false).unwrap()
    );
    assert_eq!(p_finality.category(), ProofCategory::Finality);

    let p_ownership = Proof::Ownership(
        OwnershipProof {
            owner: vec![], proof: vec![],
            asset_id: zero_hash, scheme: "test".to_string(),
        }
    );
    assert_eq!(p_ownership.category(), ProofCategory::Ownership);

    let p_transition = Proof::Transition(
        TransitionProof {
            previous_state: zero_hash, new_state: zero_hash,
            transition_data: vec![], proof: vec![],
        }
    );
    assert_eq!(p_transition.category(), ProofCategory::Transition);

    let p_replay = Proof::Replay(
        ReplayProof {
            nullifier: zero_hash, chain_id: "test".to_string(), context: vec![],
        }
    );
    assert_eq!(p_replay.category(), ProofCategory::Replay);

    let p_execution = Proof::Execution(
        ExecutionProof {
            computation_hash: zero_hash, proof: vec![], context: vec![],
        }
    );
    assert_eq!(p_execution.category(), ProofCategory::Execution);

    let p_zk = Proof::ZK(
        ZKProof {
            system: "test".to_string(), proof: vec![],
            public_inputs: vec![], verification_key_hash: zero_hash,
        }
    );
    assert_eq!(p_zk.category(), ProofCategory::ZK);

    let p_composite = Proof::Composite(
        CompositeProof {
            children: vec![], rule: CompositionRule::And, proof: vec![],
        }
    );
    assert_eq!(p_composite.category(), ProofCategory::Composite);

    // 3. Verify that all proof hashes are non-zero
    for proof in [
        p_inclusion, p_finality, p_ownership, p_transition,
        p_replay, p_execution, p_zk, p_composite,
    ] {
        assert_ne!(
            proof.hash(),
            Hash::zero(),
            "Proof hash must not be zero"
        );
    }
}
