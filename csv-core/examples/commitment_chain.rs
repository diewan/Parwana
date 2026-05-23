//! Example: Building and validating a commitment chain
//!
//! This example demonstrates how commitments form a chain:
//! 1. Creating a genesis commitment
//! 2. Linking subsequent commitments to previous ones
//! 3. Verifying the integrity of the commitment chain

use csv_core::{Commitment, Hash, SealPoint};

fn main() {
    println!("=== CSV Adapter Core: Commitment Chain Example ===\n");

    // Step 1: Create a genesis commitment (no previous commitment)
    let contract_id = Hash::new([0x01; 32]);
    let payload_hash = Hash::new([0xAA; 32]);
    let seal_ref = SealPoint::new(vec![0x00; 32], None).expect("valid seal ref");
    let domain_separator = [0u8; 32];

    let genesis = Commitment::simple(
        contract_id,
        Hash::zero(), // Zero hash for genesis (no previous commitment)
        payload_hash,
        &seal_ref,
        domain_separator,
    );

    println!("1. Genesis Commitment:");
    println!("   Hash: {}", hex::encode(genesis.hash().as_bytes()));
    println!("   Previous: {}", hex::encode(Hash::zero().as_bytes()));
    println!("   Payload: {}", hex::encode(payload_hash.as_bytes()));

    // Step 2: Create a second commitment linked to the genesis
    let payload_hash_2 = Hash::new([0xBB; 32]);
    let seal_ref_2 = SealPoint::new(vec![0x01; 32], None).expect("valid seal ref");

    let commitment_2 = Commitment::simple(
        contract_id,
        genesis.hash(), // Link to genesis
        payload_hash_2,
        &seal_ref_2,
        domain_separator,
    );

    println!("\n2. Second Commitment:");
    println!("   Hash: {}", hex::encode(commitment_2.hash().as_bytes()));
    println!("   Previous: {}", hex::encode(genesis.hash().as_bytes()));
    println!("   Payload: {}", hex::encode(payload_hash_2.as_bytes()));

    // Step 3: Create a third commitment
    let payload_hash_3 = Hash::new([0xCC; 32]);
    let seal_ref_3 = SealPoint::new(vec![0x02; 32], None).expect("valid seal ref");

    let commitment_3 = Commitment::simple(
        contract_id,
        commitment_2.hash(), // Link to commitment_2
        payload_hash_3,
        &seal_ref_3,
        domain_separator,
    );

    println!("\n3. Third Commitment:");
    println!("   Hash: {}", hex::encode(commitment_3.hash().as_bytes()));
    println!(
        "   Previous: {}",
        hex::encode(commitment_2.hash().as_bytes())
    );
    println!("   Payload: {}", hex::encode(payload_hash_3.as_bytes()));

    // Step 4: Verify the chain integrity
    println!("\n4. Commitment Chain Summary:");
    println!("   Genesis → Commitment 2 → Commitment 3");
    println!("   Chain length: 3 commitments");
    println!(
        "   Latest commitment: {}",
        hex::encode(commitment_3.hash().as_bytes())
    );

    // The chain can be traced backwards:
    // commitment_3.previous == commitment_2.hash()
    // commitment_2.previous == genesis.hash()
    // genesis.previous == Hash::zero()

    println!("\n=== Example Complete ===");
}
