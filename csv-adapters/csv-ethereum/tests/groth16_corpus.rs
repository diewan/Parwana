//! Negative proof corpus tests for Groth16 verification.
//!
//! These tests verify that the real Groth16 pairing implementation correctly
//! rejects malformed/invalid proofs. They only run when the `real-groth16`
//! feature is enabled.

#[cfg(feature = "real-groth16")]
use csv_hash::Hash;
#[cfg(feature = "real-groth16")]
use csv_core::protocol_version::builtin;
#[cfg(feature = "real-groth16")]
use csv_core::seal::SealPoint;
#[cfg(feature = "real-groth16")]
use csv_core::zk_proof::{ProofSystem, VerifierKey, ZkError, ZkPublicInputs, ZkSealProof, ZkVerifier};
#[cfg(feature = "real-groth16")]
use csv_ethereum::zk_verifier::EthereumGroth16Verifier;

/// Helper: create a verifier key for testing
#[cfg(feature = "real-groth16")]
fn test_verifier_key() -> Vec<u8> {
    // A minimal 64-byte compressed BN254 verifying key for testing
    // This is a placeholder — real tests need an actual generated VK
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&[0x01u8; 32]); // alpha_g1
    key.extend_from_slice(&[0x02u8; 32]); // beta_g2 (partial)
    key
}

/// Helper: create default proof inputs
#[cfg(feature = "real-groth16")]
fn default_proof() -> (ZkSealProof, VerifierKey) {
    let seal = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
    let public_inputs = ZkPublicInputs {
        seal_ref: seal,
        block_hash: Hash::new([1u8; 32]),
        commitment: Hash::new([2u8; 32]),
        source_chain: builtin::ETHEREUM.clone(),
        block_height: 19_000_000,
        timestamp: 1_000_000,
    };

    let vk = VerifierKey::new(
        builtin::ETHEREUM.clone(),
        test_verifier_key(),
        ProofSystem::Groth16,
        1,
    );

    let proof = ZkSealProof::new(
        vec![0xABu8; 200],
        vk.clone(),
        public_inputs,
    ).unwrap();

    (proof, vk)
}

#[cfg(feature = "real-groth16")]
#[test]
fn rejects_zero_proof() {
    let verifier = EthereumGroth16Verifier::new_with_key(test_verifier_key());

    let seal = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
    let public_inputs = ZkPublicInputs {
        seal_ref: seal,
        block_hash: Hash::new([1u8; 32]),
        commitment: Hash::new([2u8; 32]),
        source_chain: builtin::ETHEREUM.clone(),
        block_height: 19_000_000,
        timestamp: 1_000_000,
    };

    let proof = ZkSealProof::new(
        vec![0u8; 192], // All-zero proof
        VerifierKey::new(
            builtin::ETHEREUM.clone(),
            test_verifier_key(),
            ProofSystem::Groth16,
            1,
        ),
        public_inputs,
    ).unwrap();

    let result = verifier.verify(&proof);
    assert!(result.is_err(), "Zero proof should be rejected");
}

#[cfg(feature = "real-groth16")]
#[test]
fn rejects_truncated_proof() {
    let verifier = EthereumGroth16Verifier::new_with_key(test_verifier_key());

    let seal = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
    let public_inputs = ZkPublicInputs {
        seal_ref: seal,
        block_hash: Hash::new([1u8; 32]),
        commitment: Hash::new([2u8; 32]),
        source_chain: builtin::ETHEREUM.clone(),
        block_height: 19_000_000,
        timestamp: 1_000_000,
    };

    let proof = ZkSealProof::new(
        vec![0xABu8; 64], // Too short — need at least 192 bytes
        VerifierKey::new(
            builtin::ETHEREUM.clone(),
            test_verifier_key(),
            ProofSystem::Groth16,
            1,
        ),
        public_inputs,
    ).unwrap();

    let result = verifier.verify(&proof);
    assert!(
        matches!(result, Err(ZkError::InvalidProof(_))),
        "Truncated proof should give InvalidProof error, got: {:?}",
        result
    );
}

#[cfg(feature = "real-groth16")]
#[test]
fn rejects_wrong_proof_system() {
    let verifier = EthereumGroth16Verifier::new_with_key(test_verifier_key());

    let (proof, _) = default_proof();
    // Create an SP1-marked proof
    let sp1_proof = ZkSealProof {
        verifier_key: VerifierKey::new(
            builtin::ETHEREUM.clone(),
            test_verifier_key(),
            ProofSystem::SP1,
            1,
        ),
        ..proof
    };

    let result = verifier.verify(&sp1_proof);
    assert!(matches!(result, Err(ZkError::UnsupportedSystem(_))));
}

#[cfg(feature = "real-groth16")]
#[test]
fn rejects_uninitialized_verifier() {
    let verifier = EthereumGroth16Verifier::new(); // No key loaded
    let (proof, _) = default_proof();

    let result = verifier.verify(&proof);
    assert!(
        matches!(result, Err(ZkError::VerifierNotFound(_))),
        "Uninitialized verifier should give VerifierNotFound error, got: {:?}",
        result
    );
}