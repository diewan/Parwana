//! Gaming Assets Cross-Chain Example
//!
//! This example demonstrates how gaming assets can be represented as sanads
//! and transferred between chains for different game ecosystems.
//!
//! Run with: `cargo run --example gaming --features "all-chains,tokio"`

use csv_sdk::prelude::*;

fn main() -> Result<()> {
    println!("=== CSV Adapter: Gaming Assets Demo ===\n");

    let rt = tokio::runtime::Runtime::new()?;
    let client = rt.block_on(async {
        CsvClient::builder()
            .with_all_chains()
            .with_store_backend(StoreBackend::InMemory)
            .build()
    })?;

    // Scenario: Player has a rare sword on Bitcoin-anchored game
    // wants to use it in an Ethereum-based game

    println!("Creating gaming asset (Legendary Sword)...");
    let sword_commitment = Hash::from([1u8; 32]);

    let sword = rt.block_on(async {
        client
            .sanads()
            .create(sword_commitment, ChainId::new("bitcoin"))
    })?;

    println!("✓ Created sword asset: {:?}", sword.id);
    println!("  Owner: {:?}", sword.owner);
    println!("  Chain: Bitcoin (Bitcoin Quest game)\n");

    // Create a shield on Sui
    println!("Creating shield asset (Aegis of Protection)...");
    let shield_commitment = Hash::from([2u8; 32]);

    let shield = rt.block_on(async {
        client
            .sanads()
            .create(shield_commitment, ChainId::new("sui"))
    })?;

    println!("✓ Created shield asset: {:?}", shield.id);
    println!("  Chain: Sui (Sui Defenders game)\n");

    // Transfer sword from Bitcoin to Ethereum
    println!("Transferring sword to Ethereum (Ethereum Warriors game)...");
    let transfer_id = rt.block_on(async {
        client
            .transfers()
            .cross_chain(sword.id.clone(), ChainId::new("ethereum"))
            .to_address("0xwarrior123".to_string())
            .execute()
            .await
    })?;

    println!("✓ Transfer initiated: {}", transfer_id);

    // Check transfer status
    let status = rt.block_on(async { client.transfers().status(&transfer_id) })?;
    println!("  Status: {:?}\n", status);

    // List all player assets
    println!("Player Asset Inventory:");
    println!("------------------------");

    let sanads = rt.block_on(async { client.sanads().list(SanadFilters::default()) })?;
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
