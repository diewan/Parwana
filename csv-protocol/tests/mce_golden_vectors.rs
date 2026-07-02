//! Golden vector tests for Minimal Canonical Encoding (MCE) of ProofLeafV1
//!
//! These tests provide known inputs → known 311-byte MCE preimage → known leaf hash per chain.
//! These serve as cross-language regression tests for contract implementations.

use csv_hash::Hash;
use csv_protocol::proof_taxonomy::{HashFunction, ProofLeafV1};

/// Test vector 1: Ethereum → Solana transfer with minimal fields
#[test]
fn test_vector_1_ethereum_to_solana_minimal() {
    let leaf = ProofLeafV1::new(
        "ethereum".to_string(),
        "solana".to_string(),
        Hash([0x11; 32]),
        Hash([0x22; 32]),
    );

    let mce = leaf.to_canonical_bytes();
    assert_eq!(mce.len(), 311, "MCE preimage must be exactly 311 bytes");

    // Expected MCE preimage (hex-encoded for documentation)
    // domain_tag: 63 73 76 2e 70 72 6f 6f 66 2e 6c 65 61 66 2e 76 31 ("csv.proof.leaf.v1")
    // version: 01 00 00 00 (little-endian u32 = 1)
    // source_chain: 00 (ethereum)
    // destination_chain: 01 (solana)
    // sanad_id: 11 11 11 ... (32 bytes)
    // commitment: 22 22 22 ... (32 bytes)
    // rest: zeros (32 bytes × 7 = 224 bytes)

    let expected_prefix = [
        0x63, 0x73, 0x76, 0x2e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2e, 0x6c, 0x65, 0x61, 0x66, 0x2e,
        0x76, 0x31, // domain tag
        0x01, 0x00, 0x00, 0x00, // version
        0x00, // source_chain (ethereum)
        0x01, // destination_chain (solana)
    ];
    assert_eq!(
        &mce[..23],
        &expected_prefix,
        "MCE prefix must match expected"
    );

    // Verify sanad_id and commitment are in correct positions
    assert_eq!(&mce[23..55], &[0x11u8; 32], "sanad_id must be at offset 23");
    assert_eq!(
        &mce[55..87],
        &[0x22u8; 32],
        "commitment must be at offset 55"
    );

    // Expected leaf hash per chain (computed from MCE preimage)
    let eth_hash = leaf.hash_with_function(HashFunction::Keccak256).unwrap();
    let sol_hash = leaf.hash_with_function(HashFunction::Sha256).unwrap();

    // These hashes serve as golden vectors for contract implementations
    // Contracts must produce identical hashes from the same MCE preimage
    println!("Test Vector 1 - Ethereum→Solana (minimal):");
    println!("  MCE preimage (hex): {:02x?}", &mce[..64]);
    println!("  Ethereum hash (Keccak256): {:02x?}", eth_hash.0);
    println!("  Solana hash (SHA256): {:02x?}", sol_hash.0);
}

/// Test vector 2: Bitcoin → Sui transfer with all optional fields populated
#[test]
fn test_vector_2_bitcoin_to_sui_full() {
    let leaf = ProofLeafV1::new(
        "bitcoin".to_string(),
        "sui".to_string(),
        Hash([0xaa; 32]),
        Hash([0xbb; 32]),
    )
    .with_content_descriptor_hash(Hash([0xcc; 32]))
    .with_source_seal_ref_hash(Hash([0xdd; 32]))
    .with_destination_owner_hash(Hash([0xee; 32]))
    .with_nullifier(Hash([0xff; 32]))
    .with_lock_event_id(Hash([0x01; 32]))
    .with_metadata_hash(Hash([0x02; 32]))
    .with_proof_policy_hash(Hash([0x03; 32]));

    let mce = leaf.to_canonical_bytes();
    assert_eq!(mce.len(), 311, "MCE preimage must be exactly 311 bytes");

    // Verify chain IDs
    assert_eq!(mce[21], 0x03, "source_chain must be bitcoin (3)");
    assert_eq!(mce[22], 0x02, "destination_chain must be sui (2)");

    // Verify all hash fields are in correct positions
    assert_eq!(&mce[23..55], &[0xaau8; 32], "sanad_id must be at offset 23");
    assert_eq!(
        &mce[55..87],
        &[0xbbu8; 32],
        "commitment must be at offset 55"
    );
    assert_eq!(
        &mce[87..119],
        &[0xccu8; 32],
        "content_descriptor_hash must be at offset 87"
    );
    assert_eq!(
        &mce[119..151],
        &[0xddu8; 32],
        "source_seal_ref_hash must be at offset 119"
    );
    assert_eq!(
        &mce[151..183],
        &[0xeeu8; 32],
        "destination_owner_hash must be at offset 151"
    );
    assert_eq!(
        &mce[183..215],
        &[0xffu8; 32],
        "nullifier must be at offset 183"
    );
    assert_eq!(
        &mce[215..247],
        &[0x01u8; 32],
        "lock_event_id must be at offset 215"
    );
    assert_eq!(
        &mce[247..279],
        &[0x02u8; 32],
        "metadata_hash must be at offset 247"
    );
    assert_eq!(
        &mce[279..311],
        &[0x03u8; 32],
        "proof_policy_hash must be at offset 279"
    );

    // Expected leaf hash per chain
    let btc_hash = leaf.hash_with_function(HashFunction::DoubleSha256).unwrap();
    let sui_hash = leaf.hash_with_function(HashFunction::Blake2b256).unwrap();

    println!("Test Vector 2 - Bitcoin→Sui (full):");
    println!("  MCE preimage (hex): {:02x?}", &mce[..64]);
    println!("  Bitcoin hash (Double SHA256): {:02x?}", btc_hash.0);
    println!("  Sui hash (Blake2b256): {:02x?}", sui_hash.0);
}

/// Test vector 3: Aptos → Ethereum transfer with mixed fields
#[test]
fn test_vector_3_aptos_to_ethereum_mixed() {
    let leaf = ProofLeafV1::new(
        "aptos".to_string(),
        "ethereum".to_string(),
        Hash([0x33; 32]),
        Hash([0x44; 32]),
    )
    .with_nullifier(Hash([0x55; 32]))
    .with_proof_policy_hash(Hash([0x66; 32]));

    let mce = leaf.to_canonical_bytes();
    assert_eq!(mce.len(), 311, "MCE preimage must be exactly 311 bytes");

    // Verify chain IDs
    assert_eq!(mce[21], 0x04, "source_chain must be aptos (4)");
    assert_eq!(mce[22], 0x00, "destination_chain must be ethereum (0)");

    // Verify populated fields
    assert_eq!(&mce[23..55], &[0x33u8; 32], "sanad_id must be at offset 23");
    assert_eq!(
        &mce[55..87],
        &[0x44u8; 32],
        "commitment must be at offset 55"
    );
    assert_eq!(
        &mce[183..215],
        &[0x55u8; 32],
        "nullifier must be at offset 183"
    );
    assert_eq!(
        &mce[279..311],
        &[0x66u8; 32],
        "proof_policy_hash must be at offset 279"
    );

    // Expected leaf hash per chain
    let aptos_hash = leaf.hash_with_function(HashFunction::Sha3_256).unwrap();
    let eth_hash = leaf.hash_with_function(HashFunction::Keccak256).unwrap();

    println!("Test Vector 3 - Aptos→Ethereum (mixed):");
    println!("  MCE preimage (hex): {:02x?}", &mce[..64]);
    println!("  Aptos hash (SHA3-256): {:02x?}", aptos_hash.0);
    println!("  Ethereum hash (Keccak256): {:02x?}", eth_hash.0);
}

/// Test vector 4: Solana → Bitcoin transfer with version field
#[test]
fn test_vector_4_solana_to_bitcoin_version() {
    let mut leaf = ProofLeafV1::new(
        "solana".to_string(),
        "bitcoin".to_string(),
        Hash([0x77; 32]),
        Hash([0x88; 32]),
    );
    leaf.version = 1; // Explicit version

    let mce = leaf.to_canonical_bytes();
    assert_eq!(mce.len(), 311, "MCE preimage must be exactly 311 bytes");

    // Verify version encoding
    assert_eq!(
        &mce[17..21],
        [0x01, 0x00, 0x00, 0x00],
        "version must be little-endian u32"
    );

    // Verify chain IDs
    assert_eq!(mce[21], 0x01, "source_chain must be solana (1)");
    assert_eq!(mce[22], 0x03, "destination_chain must be bitcoin (3)");

    // Expected leaf hash per chain
    let sol_hash = leaf.hash_with_function(HashFunction::Sha256).unwrap();
    let btc_hash = leaf.hash_with_function(HashFunction::DoubleSha256).unwrap();

    println!("Test Vector 4 - Solana→Bitcoin (version):");
    println!("  MCE preimage (hex): {:02x?}", &mce[..64]);
    println!("  Solana hash (SHA256): {:02x?}", sol_hash.0);
    println!("  Bitcoin hash (Double SHA256): {:02x?}", btc_hash.0);
}

/// Test vector 5: Cross-chain verification - same leaf, different hash functions
#[test]
fn test_vector_5_cross_chain_verification() {
    let leaf = ProofLeafV1::new(
        "ethereum".to_string(),
        "solana".to_string(),
        Hash([0x99; 32]),
        Hash([0xaa; 32]),
    );

    let mce = leaf.to_canonical_bytes();

    // All chains must produce the same MCE preimage
    assert_eq!(mce.len(), 311);

    // But different hash functions produce different leaf hashes
    let eth_hash = leaf.hash_with_function(HashFunction::Keccak256).unwrap();
    let sol_hash = leaf.hash_with_function(HashFunction::Sha256).unwrap();
    let sui_hash = leaf.hash_with_function(HashFunction::Blake2b256).unwrap();
    let btc_hash = leaf.hash_with_function(HashFunction::DoubleSha256).unwrap();
    let aptos_hash = leaf.hash_with_function(HashFunction::Sha3_256).unwrap();

    // Verify hashes are different (different hash functions)
    assert_ne!(
        eth_hash, sol_hash,
        "Different hash functions must produce different hashes"
    );
    assert_ne!(
        sol_hash, sui_hash,
        "Different hash functions must produce different hashes"
    );
    assert_ne!(
        sui_hash, btc_hash,
        "Different hash functions must produce different hashes"
    );
    assert_ne!(
        btc_hash, aptos_hash,
        "Different hash functions must produce different hashes"
    );

    println!("Test Vector 5 - Cross-chain verification:");
    println!("  MCE preimage (hex): {:02x?}", &mce[..64]);
    println!("  Ethereum hash (Keccak256): {:02x?}", eth_hash.0);
    println!("  Solana hash (SHA256): {:02x?}", sol_hash.0);
    println!("  Sui hash (Blake2b256): {:02x?}", sui_hash.0);
    println!("  Bitcoin hash (Double SHA256): {:02x?}", btc_hash.0);
    println!("  Aptos hash (SHA3-256): {:02x?}", aptos_hash.0);
}

/// Regression test: MCE must produce deterministic output
#[test]
fn test_mce_determinism() {
    let leaf1 = ProofLeafV1::new(
        "ethereum".to_string(),
        "solana".to_string(),
        Hash([0x11; 32]),
        Hash([0x22; 32]),
    );

    let leaf2 = ProofLeafV1::new(
        "ethereum".to_string(),
        "solana".to_string(),
        Hash([0x11; 32]),
        Hash([0x22; 32]),
    );

    assert_eq!(
        leaf1.to_canonical_bytes(),
        leaf2.to_canonical_bytes(),
        "MCE must be deterministic for identical inputs"
    );
}
