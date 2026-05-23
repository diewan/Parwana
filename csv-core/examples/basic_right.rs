//! Example: Creating and transferring a Sanad
//!
//! This example demonstrates the basic lifecycle of a Sanad:
//! 1. Creating a Sanad with an initial owner
//! 2. Transferring it to a new owner
//! 3. Verifying the Sanad's integrity

use csv_core::{Hash, OwnershipProof, Sanad, SignatureScheme};

fn main() {
    println!("=== CSV Adapter Core: Basic Sanad Example ===\n");

    // Step 1: Create a commitment (represents the Sanad's content/state)
    let commitment = Hash::new([0xAB; 32]);
    println!(
        "1. Created commitment: {}",
        hex::encode(commitment.as_bytes())
    );

    // Step 2: Create an initial ownership proof
    // In a real scenario, this would contain a cryptographic signature
    let initial_owner = OwnershipProof {
        proof: vec![0x01; 64], // Simulated signature (64 bytes)
        owner: vec![0x02; 33], // Simulated public key (33 bytes, compressed)
        scheme: Some(SignatureScheme::Secp256k1),
    };

    // Step 3: Create a Sanad with unique salt
    let salt = b"genesis-salt-2026";
    let sanad = Sanad::new(commitment, initial_owner, salt);

    println!(
        "2. Created Sanad with ID: {}",
        hex::encode(sanad.id.0.as_bytes())
    );
    println!(
        "   Commitment: {}",
        hex::encode(sanad.commitment.as_bytes())
    );
    println!("   Owner: {}", hex::encode(&sanad.owner.owner));
    println!("   Salt: {}", String::from_utf8_lossy(&sanad.salt));

    // Step 4: Transfer to a new owner
    let new_owner = OwnershipProof {
        proof: vec![0x03; 64], // New simulated signature
        owner: vec![0x04; 33], // New simulated public key
        scheme: Some(SignatureScheme::Secp256k1),
    };

    let transfer_salt = b"transfer-salt-2026";
    let transferred_sanad = sanad.transfer(new_owner.clone(), transfer_salt);

    println!("\n3. Transferred Sanad:");
    println!(
        "   New Sanad ID: {}",
        hex::encode(transferred_sanad.id.0.as_bytes())
    );
    println!(
        "   New Owner: {}",
        hex::encode(&transferred_sanad.owner.owner)
    );
    println!(
        "   New Salt: {}",
        String::from_utf8_lossy(&transferred_sanad.salt)
    );

    println!("\n=== Example Complete ===");
}
