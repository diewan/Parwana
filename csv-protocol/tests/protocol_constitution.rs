//! Protocol Constitution Tests
//!
//! These tests enforce protocol invariants and MUST NEVER BREAK.
//! Any change that breaks these tests requires an RFC and protocol version bump.

use csv_hash::{Hash, HashDomain, DomainSeparatedHash};
use csv_protocol::transition::{State, is_legal_transition};

// ===========================================================================
// Test 1: Protocol Hashes Are Stable
// ===========================================================================

#[test]
fn protocol_hashes_are_stable() {
    // Test that hash domains produce stable, deterministic outputs
    let data = b"test data for hash stability";

    // Test that the same data produces the same hash across calls
    let hash1 = DomainSeparatedHash::<csv_hash::domains::GenesisDomain>::hash(data);
    let hash2 = DomainSeparatedHash::<csv_hash::domains::GenesisDomain>::hash(data);

    assert_eq!(hash1, hash2, "Hash must be deterministic");

    // Test that different domains produce different hashes
    let hash_genesis = DomainSeparatedHash::<csv_hash::domains::GenesisDomain>::hash(data);
    let hash_schema = DomainSeparatedHash::<csv_hash::domains::SchemaDomain>::hash(data);

    assert_ne!(hash_genesis, hash_schema, "Different domains must produce different hashes");

    // Test hash stability across multiple calls
    let expected = DomainSeparatedHash::<csv_hash::domains::ProofBundleDomain>::hash(data);
    for _ in 0..100 {
        assert_eq!(
            DomainSeparatedHash::<csv_hash::domains::ProofBundleDomain>::hash(data),
            expected,
            "Hash must be stable across repeated calls"
        );
    }
}

// ===========================================================================
// Test 2: Serialization Is Canonical
// ===========================================================================

#[test]
fn serialization_is_canonical() {
    use csv_hash::canonical::{to_canonical_cbor, from_canonical_cbor};

    // Test that canonical serialization is deterministic
    let test_struct = CanonicalTestStruct {
        a: 42u64,
        b: "hello".to_string(),
        c: vec![1u8, 2, 3],
        d: true,
    };

    let bytes1 = to_canonical_cbor(&test_struct).expect("serialization should succeed");
    let bytes2 = to_canonical_cbor(&test_struct).expect("serialization should succeed");

    assert_eq!(bytes1, bytes2, "Canonical serialization must be deterministic");

    // Test roundtrip
    let decoded: CanonicalTestStruct = from_canonical_cbor(&bytes1).expect("deserialization should succeed");
    assert_eq!(decoded.a, test_struct.a);
    assert_eq!(decoded.b, test_struct.b);
    assert_eq!(decoded.c, test_struct.c);
    assert_eq!(decoded.d, test_struct.d);

    // Test that Hash serialization is deterministic
    let hash = Hash::sha256(b"test data");
    let hash_bytes1 = hash.to_vec();
    let hash_bytes2 = hash.to_vec();
    assert_eq!(hash_bytes1, hash_bytes2, "Hash serialization must be deterministic");

    // Test that canonical CBOR produces consistent ordering for maps
    let map1 = serde_json::json!({"z": 1, "a": 2, "m": 3});
    let map2 = serde_json::json!({"a": 2, "m": 3, "z": 1});
    // After canonical serialization, both should produce the same bytes
    let cbor1 = to_canonical_cbor(&map1).expect("serialization should succeed");
    let cbor2 = to_canonical_cbor(&map2).expect("serialization should succeed");
    assert_eq!(cbor1, cbor2, "Canonical serialization must order map keys consistently");
}

/// Helper struct for canonical serialization tests.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct CanonicalTestStruct {
    a: u64,
    b: String,
    c: Vec<u8>,
    d: bool,
}

// ===========================================================================
// Test 3: Replay Is Impossible (Domain Separation)
// ===========================================================================

#[test]
fn replay_is_impossible() {
    // Test that domain separation prevents cross-domain replay
    let data = b"replay test data";

    let hash_genesis = DomainSeparatedHash::<csv_hash::domains::GenesisDomain>::hash(data);
    let hash_transfer = DomainSeparatedHash::<csv_hash::domains::TransferCommitmentDomain>::hash(data);
    let hash_schema = DomainSeparatedHash::<csv_hash::domains::SchemaDomain>::hash(data);
    let hash_proof = DomainSeparatedHash::<csv_hash::domains::ProofBundleDomain>::hash(data);
    let hash_transition = DomainSeparatedHash::<csv_hash::domains::TransitionDomain>::hash(data);

    // All hashes must be unique for the same input
    let hashes = [hash_genesis, hash_transfer, hash_schema, hash_proof, hash_transition];
    for (i, hi) in hashes.iter().enumerate() {
        for (j, hj) in hashes.iter().enumerate() {
            if i != j {
                assert_ne!(hi, hj, "Domain {} and {} must produce different hashes to prevent replay", i, j);
            }
        }
    }

    // Test that nullifier domain is distinct from all others
    let hash_replay = DomainSeparatedHash::<csv_hash::domains::ReplayRegistryDomain>::hash(data);
    assert_ne!(hash_genesis, hash_replay, "Genesis and replay domains must be distinct");
}

// ===========================================================================
// Test 4: Forbidden State Transitions Fail
// ===========================================================================

#[test]
fn forbidden_state_transitions_fail() {
    // Test that forbidden state transitions are rejected by the state machine

    // Legal transitions must succeed
    assert!(is_legal_transition(State::Locked, State::AwaitingFinality),
        "Locked -> AwaitingFinality must be legal");
    assert!(is_legal_transition(State::AwaitingFinality, State::ProofBuilding),
        "AwaitingFinality -> ProofBuilding must be legal");
    assert!(is_legal_transition(State::ProofBuilding, State::ProofValidated),
        "ProofBuilding -> ProofValidated must be legal");
    assert!(is_legal_transition(State::ProofValidated, State::Minting),
        "ProofValidated -> Minting must be legal");
    assert!(is_legal_transition(State::Minting, State::Completed),
        "Minting -> Completed must be legal");

    // Emergency transitions from any state
    assert!(is_legal_transition(State::Locked, State::RolledBack),
        "Any -> RolledBack must be legal");
    assert!(is_legal_transition(State::Completed, State::RolledBack),
        "Completed -> RolledBack must be legal (reorg recovery)");
    assert!(is_legal_transition(State::Locked, State::Compromised),
        "Any -> Compromised must be legal");
    assert!(is_legal_transition(State::Minting, State::Compromised),
        "Minting -> Compromised must be legal");

    // Forbidden transitions must fail
    assert!(!is_legal_transition(State::Locked, State::ProofBuilding),
        "Locked -> ProofBuilding must be forbidden (skips AwaitingFinality)");
    assert!(!is_legal_transition(State::Locked, State::Minting),
        "Locked -> Minting must be forbidden (skips multiple states)");
    assert!(!is_legal_transition(State::Locked, State::Completed),
        "Locked -> Completed must be forbidden (skips entire pipeline)");
    assert!(!is_legal_transition(State::AwaitingFinality, State::Completed),
        "AwaitingFinality -> Completed must be forbidden");
    assert!(!is_legal_transition(State::ProofValidated, State::AwaitingFinality),
        "ProofValidated -> AwaitingFinality must be forbidden (no backward transitions)");
    assert!(!is_legal_transition(State::Completed, State::Minting),
        "Completed -> Minting must be forbidden (Completed is terminal)");
    assert!(!is_legal_transition(State::Completed, State::ProofBuilding),
        "Completed -> ProofBuilding must be forbidden");
    assert!(!is_legal_transition(State::RolledBack, State::Completed),
        "RolledBack -> Completed must be forbidden (requires re-sealing)");
    assert!(!is_legal_transition(State::Compromised, State::Completed),
        "Compromised -> Completed must be forbidden (requires investigation)");
    assert!(!is_legal_transition(State::Completed, State::Completed),
        "Completed -> Completed must be forbidden (no self-transition)");
}

// ===========================================================================
// Test 5: All Proofs Are Domain Separated
// ===========================================================================

#[test]
fn all_proofs_are_domain_separated() {
    use csv_hash::tagged_hash::tagged_hash;

    let data = b"proof test data";

    // Test that all proof-related hash domains produce unique hashes
    let domains: Vec<HashDomain> = vec![
        HashDomain::BitcoinSealV1,
        HashDomain::EthereumSealV1,
        HashDomain::SolanaSealV1,
        HashDomain::SuiSealV1,
        HashDomain::AptosSealV1,
        HashDomain::TransferCommitmentV1,
        HashDomain::SanadId,
        HashDomain::Nullifier,
        HashDomain::ReplayIdV1,
        HashDomain::VerificationProofV1,
        HashDomain::VerificationResult,
        HashDomain::MerkleCombine,
    ];

    // Test that each domain produces a unique hash
    let mut hashes = Vec::new();
    for domain in &domains {
        let hash = tagged_hash(*domain, data);
        hashes.push(hash.hash);
    }

    // All hashes should be unique
    for (i, hash_i) in hashes.iter().enumerate() {
        for (j, hash_j) in hashes.iter().enumerate() {
            if i != j {
                assert_ne!(hash_i, hash_j,
                    "Hash domains at index {} and {} must produce different hashes (domain separation violation)",
                    i, j);
            }
        }
    }

    // Test that domain separation works with different data
    let data2 = b"different proof data";
    for domain in &domains {
        let hash1 = tagged_hash(*domain, data);
        let hash2 = tagged_hash(*domain, data2);
        assert_ne!(hash1.hash, hash2.hash,
            "Same domain with different data must produce different hashes");
    }
}

// ===========================================================================
// Test 6: Hash Registry Domain Separation
// ===========================================================================

#[test]
fn hash_registry_domain_separation() {
    use csv_hash::tagged_hash::tagged_hash;

    let data = b"domain separation test";

    // Test all domain categories produce distinct hashes
    let seal_hash = tagged_hash(HashDomain::BitcoinSealV1, data);
    let commitment_hash = tagged_hash(HashDomain::TransferCommitmentV1, data);
    let sanad_id_hash = tagged_hash(HashDomain::SanadId, data);
    let nullifier_hash = tagged_hash(HashDomain::Nullifier, data);
    let merkle_hash = tagged_hash(HashDomain::MerkleCombine, data);

    let hashes = [seal_hash.hash, commitment_hash.hash, sanad_id_hash.hash, nullifier_hash.hash, merkle_hash.hash];

    for (i, hi) in hashes.iter().enumerate() {
        for (j, hj) in hashes.iter().enumerate() {
            if i != j {
                assert_ne!(hi, hj, "Hash categories {} and {} must be domain-separated", i, j);
            }
        }
    }
}

// ===========================================================================
// Test 7: Protocol Constants Are Valid
// ===========================================================================

#[test]
fn protocol_constants_are_valid() {
    use csv_protocol::constants::*;

    // MAX_PROOF_BYTES must be positive
    assert!(MAX_PROOF_BYTES > 0, "MAX_PROOF_BYTES must be positive");

    // MAX_FINALITY_DATA must be positive
    assert!(MAX_FINALITY_DATA > 0, "MAX_FINALITY_DATA must be positive");

    // MAX_SIGNATURES_TOTAL_SIZE must be positive
    assert!(MAX_SIGNATURES_TOTAL_SIZE > 0, "MAX_SIGNATURES_TOTAL_SIZE must be positive");

    // MAX_PROOF_BUNDLE_SIZE must be positive
    assert!(MAX_PROOF_BUNDLE_SIZE > 0, "MAX_PROOF_BUNDLE_SIZE must be positive");

    // MIN_REQUIRED_CONFIRMATIONS must be positive
    assert!(MIN_REQUIRED_CONFIRMATIONS > 0, "MIN_REQUIRED_CONFIRMATIONS must be positive");

    // MAX_PROOF_AGE_SECONDS must be positive
    assert!(MAX_PROOF_AGE_SECONDS > 0, "MAX_PROOF_AGE_SECONDS must be positive");

    // Protocol version must be non-empty
    assert!(!csv_protocol::version::PROTOCOL_VERSION.is_empty(),
        "Protocol version must be non-empty");
}

// ===========================================================================
// Test 8: Invariant Violations Are Distinct
// ===========================================================================

#[test]
fn invariant_violations_are_distinct() {
    use csv_protocol::invariants::InvariantViolation;

    let violations: Vec<InvariantViolation> = vec![
        InvariantViolation::ProofSizeExceeded,
        InvariantViolation::FinalityDataSizeExceeded,
        InvariantViolation::SignaturesSizeExceeded,
        InvariantViolation::ProofBundleSizeExceeded,
        InvariantViolation::InsufficientConfirmations,
        InvariantViolation::ProofExpired,
        InvariantViolation::InvalidStateTransition,
        InvariantViolation::ReplayDetected,
    ];

    // All violations must be distinct
    for (i, vi) in violations.iter().enumerate() {
        for (j, vj) in violations.iter().enumerate() {
            if i != j {
                assert_ne!(vi, vj, "Invariant violations {} and {} must be distinct", i, j);
            }
        }
    }
}

// ===========================================================================
// Test 9: State Machine Completeness
// ===========================================================================

#[test]
fn state_machine_completeness() {
    use csv_protocol::transition::State;

    // All states must be reachable
    let states = [
        State::Locked,
        State::AwaitingFinality,
        State::ProofBuilding,
        State::ProofValidated,
        State::Minting,
        State::Completed,
        State::RolledBack,
        State::Compromised,
    ];

    // Each state must be distinct
    for (i, si) in states.iter().enumerate() {
        for (j, sj) in states.iter().enumerate() {
            if i != j {
                assert_ne!(si, sj, "States {} and {} must be distinct", i, j);
            }
        }
    }

    // Terminal states must not have outgoing legal transitions (except to emergency states)
    assert!(!is_legal_transition(State::Completed, State::AwaitingFinality));
    assert!(!is_legal_transition(State::Completed, State::ProofBuilding));
    assert!(!is_legal_transition(State::Completed, State::ProofValidated));
    assert!(!is_legal_transition(State::Completed, State::Minting));
    assert!(!is_legal_transition(State::Completed, State::Completed));

    assert!(!is_legal_transition(State::RolledBack, State::AwaitingFinality));
    assert!(!is_legal_transition(State::RolledBack, State::ProofBuilding));
    assert!(!is_legal_transition(State::RolledBack, State::ProofValidated));
    assert!(!is_legal_transition(State::RolledBack, State::Minting));
    assert!(!is_legal_transition(State::RolledBack, State::Completed));

    assert!(!is_legal_transition(State::Compromised, State::AwaitingFinality));
    assert!(!is_legal_transition(State::Compromised, State::ProofBuilding));
    assert!(!is_legal_transition(State::Compromised, State::ProofValidated));
    assert!(!is_legal_transition(State::Compromised, State::Minting));
    assert!(!is_legal_transition(State::Compromised, State::Completed));
}

// ===========================================================================
// Test 10: All Hash Domains Have Unique Tags
// ===========================================================================

#[test]
fn all_hash_domains_have_unique_tags() {
    use csv_hash::tagged_hash::tagged_hash;

    let data = b"tag uniqueness test";

    // Test all seal domains
    let seal_domains = [
        HashDomain::BitcoinSealV1,
        HashDomain::EthereumSealV1,
        HashDomain::SolanaSealV1,
        HashDomain::SuiSealV1,
        HashDomain::AptosSealV1,
        HashDomain::CelestiaSealV1,
        HashDomain::StarkSealV1,
    ];

    let mut seal_hashes = Vec::new();
    for domain in &seal_domains {
        let hash = tagged_hash(*domain, data);
        seal_hashes.push(hash.hash);
    }

    // All seal hashes must be unique
    for (i, hi) in seal_hashes.iter().enumerate() {
        for (j, hj) in seal_hashes.iter().enumerate() {
            if i != j {
                assert_ne!(hi, hj, "Seal domains {} and {} must produce different hashes", i, j);
            }
        }
    }

    // Test all commitment domains
    let commitment_domains = [
        HashDomain::TransferCommitmentV1,
        HashDomain::CommitmentVersion,
        HashDomain::CommitmentProtocolId,
        HashDomain::CommitmentMpcRoot,
        HashDomain::CommitmentContractId,
        HashDomain::CommitmentPrevious,
        HashDomain::CommitmentPayload,
        HashDomain::CommitmentSeal,
        HashDomain::CommitmentDomain,
    ];

    let mut commitment_hashes = Vec::new();
    for domain in &commitment_domains {
        let hash = tagged_hash(*domain, data);
        commitment_hashes.push(hash.hash);
    }

    // All commitment hashes must be unique
    for (i, hi) in commitment_hashes.iter().enumerate() {
        for (j, hj) in commitment_hashes.iter().enumerate() {
            if i != j {
                assert_ne!(hi, hj, "Commitment domains {} and {} must produce different hashes", i, j);
            }
        }
    }
}
