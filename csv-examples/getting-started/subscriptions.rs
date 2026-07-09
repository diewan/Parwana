use csv_hash::Hash;
// Cross-Chain Subscriptions Example
//
// This example demonstrates how to create and manage subscription sanads
// that can be transferred across chains.
//
// Run with: `cargo run --example subscriptions --features "all-chains,tokio"`

use csv_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CSV Adapter: Cross-Chain Subscriptions Demo ===\n");

    // Initialize client with all chains
    let client = CsvClient::builder()
        .with_all_chains()
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await?;

    println!("✓ Client initialized with all chains\n");

    // Create a subscription sanad on Bitcoin
    println!("Creating subscription sanad on Bitcoin...");
    let commitment = Hash::from([1u8; 32]);

    let sanad = client.sanads().create(
        &csv_protocol::SanadPayloadDescriptor::new(
            csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            commitment,
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        ),
        commitment,
        csv_protocol::OwnershipProof {
            owner: vec![],
            proof: vec![],
            scheme: None,
            // Unsigned draft: an empty public_key fails closed before this proof
            // could ever be treated as authoritative (SANAD-OWNERSHIP-PROOF-VERIFY-001).
            public_key: vec![],
        },
        &[],
        ChainId::new("bitcoin"),
    )?;

    println!("✓ Created sanad: {:?}\n", sanad.id);

    // Query the sanad
    println!("Querying sanad status...");
    let sanad_id: csv_hash::SanadId =
        csv_protocol::wire::SanadIdWire::try_into(sanad.id.clone()).unwrap();
    let found_sanad = client.sanads().get(&sanad_id)?;
    if let Some(found_sanad) = found_sanad {
        println!("✓ Found sanad: {:?}\n", found_sanad.id);
    }

    // Simulate cross-chain transfer to Ethereum
    println!("Initiating cross-chain transfer to Ethereum...");
    println!("  1. Locking sanad on Bitcoin...");
    println!("  2. Generating proof bundle...");
    println!("  3. Verifying on Ethereum...");
    println!("  4. Minting destination sanad...");

    let transfer_receipt = client
        .transfers()
        .cross_chain(
            csv_protocol::wire::SanadIdWire::try_into(sanad.id.clone()).unwrap(),
            ChainId::new("ethereum"),
        )
        .to_address("0x1234567890abcdef".to_string())
        .execute()
        .await?;

    println!("\n✓ Transfer initiated: {}\n", transfer_receipt);

    // Check status
    let status = client.transfers().status(&transfer_receipt.transfer_id)?;
    println!("Transfer status: {:?}", status);

    println!("\n=== Demo Complete ===");
    println!("In production, this would:");
    println!("  - Broadcast lock transaction on Bitcoin");
    println!("  - Wait for finality (6 confirmations)");
    println!("  - Generate inclusion proof");
    println!("  - Submit proof to Ethereum contract");
    println!("  - Mint equivalent sanad on Ethereum");

    Ok(())
}
