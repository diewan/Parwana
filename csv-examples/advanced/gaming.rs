use csv_hash::Hash;
// Gaming Assets Cross-Chain Example
//
// This example demonstrates how gaming assets can be represented as sanads
// and transferred between chains for different game ecosystems.
//
// Run with: `cargo run --example gaming --features "all-chains,tokio"`

use csv_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CSV Adapter: Gaming Assets Demo ===\n");

    let client = CsvClient::builder()
        .with_all_chains()
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await?;

    // Scenario: Player has a rare sword on Bitcoin-anchored game
    // wants to use it in an Ethereum-based game

    println!("Creating gaming asset (Legendary Sword)...");
    let sword_commitment = Hash::from([1u8; 32]);

    let sword = client.sanads().create(
        &csv_protocol::SanadPayloadDescriptor::new(
            csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            sword_commitment,
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        ),
        sword_commitment,
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

    println!("✓ Created sword asset: {:?}", sword.id);
    println!("  Owner: {:?}", sword.owner);
    println!("  Chain: Bitcoin (Bitcoin Quest game)\n");

    // Create a shield on Sui
    println!("Creating shield asset (Aegis of Protection)...");
    let shield_commitment = Hash::from([2u8; 32]);

    let shield = client.sanads().create(
        &csv_protocol::SanadPayloadDescriptor::new(
            csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            shield_commitment,
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        ),
        shield_commitment,
        csv_protocol::OwnershipProof {
            owner: vec![],
            proof: vec![],
            scheme: None,
            // Unsigned draft: an empty public_key fails closed before this proof
            // could ever be treated as authoritative (SANAD-OWNERSHIP-PROOF-VERIFY-001).
            public_key: vec![],
        },
        &[],
        ChainId::new("sui"),
    )?;

    println!("✓ Created shield asset: {:?}", shield.id);
    println!("  Chain: Sui (Sui Defenders game)\n");

    // Transfer sword from Bitcoin to Ethereum
    println!("Transferring sword to Ethereum (Ethereum Warriors game)...");
    let transfer_receipt = client
        .transfers()
        .cross_chain(
            csv_protocol::wire::SanadIdWire::try_into(sword.id.clone()).unwrap(),
            ChainId::new("ethereum"),
        )
        .to_address("0xwarrior123".to_string())
        .execute()
        .await?;

    println!("✓ Transfer initiated: {}", transfer_receipt);

    // Check transfer status
    let status = client.transfers().status(&transfer_receipt.transfer_id)?;
    println!("  Status: {:?}\n", status);

    // List all player assets
    println!("Player Asset Inventory:");
    println!("------------------------");

    let sanads = client.sanads().list(SanadFilters::default())?;
    for sanad in sanads {
        println!("  - {:?} (active)", sanad.id);
    }

    println!("\n=== Gaming Integration Points ===");
    println!("1. Game clients verify asset ownership via proofs");
    println!("2. Assets can move between game ecosystems");
    println!("3. Each game defines asset interpretation");
    println!("4. Proof verification ensures no duplication");
    println!("5. Explorer provides asset history/timeline");

    Ok(())
}
