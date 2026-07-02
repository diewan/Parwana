use csv_hash::Hash;
// Performance Benchmarking Example
//
// This example demonstrates performance characteristics of the CSV Adapter,
// including Sanad creation and transfer throughput.
//
// Run with: `cargo run --example performance --features "all-chains,tokio" --release`

use csv_sdk::prelude::*;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CSV Adapter: Performance Benchmarks ===\n");

    let client = CsvClient::builder()
        .with_all_chains()
        .with_store_backend(StoreBackend::InMemory)
        .build()
        .await?;

    // Benchmark 1: Sanad creation throughput
    println!("Benchmark 1: Sanad Creation Throughput");
    println!("-------------------------------------");

    let iterations = 1000;
    let start = Instant::now();

    for i in 0..iterations {
        let commitment = Hash::from([i as u8; 32]);
        let _ = client.sanads().create(
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
            },
            &[],
            ChainId::new("bitcoin"),
        );
    }

    let duration = start.elapsed();
    let throughput = iterations as f64 / duration.as_secs_f64();

    println!("  Iterations: {}", iterations);
    println!("  Total time: {:.2?}", duration);
    println!("  Throughput: {:.0} sanads/second\n", throughput);

    // Benchmark 2: Query latency
    println!("Benchmark 2: Sanad Query Latency");
    println!("---------------------------------");

    // Create a sanad to query
    let test_commitment = Hash::from([255u8; 32]);
    let test_sanad = client.sanads().create(
        &csv_protocol::SanadPayloadDescriptor::new(
            csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            test_commitment,
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        ),
        test_commitment,
        csv_protocol::OwnershipProof {
            owner: vec![],
            proof: vec![],
            scheme: None,
        },
        &[],
        ChainId::new("bitcoin"),
    )?;

    let iterations = 1000;
    let start = Instant::now();

    for _ in 0..iterations {
        let sanad_id: csv_hash::SanadId =
            csv_protocol::wire::SanadIdWire::try_into(test_sanad.id.clone()).unwrap();
        let _ = client.sanads().get(&sanad_id);
    }

    let duration = start.elapsed();
    let avg_latency = duration / iterations as u32;

    println!("  Iterations: {}", iterations);
    println!("  Average latency: {:.2?} per query\n", avg_latency);

    // Benchmark 3: Cross-chain transfer flow
    println!("Benchmark 3: Cross-Chain Transfer Flow");
    println!("---------------------------------------");

    let start = Instant::now();

    // Create and transfer a sanad
    let sanad = client.sanads().create(
        &csv_protocol::SanadPayloadDescriptor::new(
            csv_protocol::SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            Hash::from([42u8; 32]),
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        ),
        Hash::from([42u8; 32]),
        csv_protocol::OwnershipProof {
            owner: vec![],
            proof: vec![],
            scheme: None,
        },
        &[],
        ChainId::new("bitcoin"),
    )?;

    let transfer_id = client
        .transfers()
        .cross_chain(
            csv_protocol::wire::SanadIdWire::try_into(sanad.id.clone()).unwrap(),
            ChainId::new("ethereum"),
        )
        .to_address("0x1234567890abcdef".to_string())
        .execute()
        .await?;

    let duration = start.elapsed();

    println!("  Sanad creation + transfer initiation: {:.2?}", duration);
    println!("  Transfer ID: {}\n", transfer_id);

    // List all sanads
    println!("Benchmark 4: Sanads Listing");
    println!("--------------------------");

    let start = Instant::now();
    let sanads = client.sanads().list(SanadFilters::default())?;
    let list_duration = start.elapsed();

    println!(
        "  Listed {} sanads in {:.2?}\n",
        sanads.len(),
        list_duration
    );

    // Summary
    println!("=== Performance Summary ===");
    println!("Sanad creation: {:.0} ops/sec", throughput);
    println!("Query latency: {:?}", avg_latency);
    println!("Cross-chain flow: {:?} end-to-end", duration);
    println!("List operation: {:?}", list_duration);

    Ok(())
}
