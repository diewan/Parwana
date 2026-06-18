use csv_hash::Hash;
// Parallel Operations Example
// 
// This example demonstrates concurrent Sanad creation and queries,
// useful for high-throughput scenarios like batch processing or gaming.
// 
// Run with: `cargo run --example parallel_verification --features "all-chains,tokio" --release`

use csv_sdk::prelude::*;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== CSV Adapter: Parallel Operations Demo ===\n");

    let client = CsvClient::builder()
        .with_all_chains()
        .with_store_backend(StoreBackend::InMemory)
        .build().await?;

    // Sequential creation benchmark
    println!("Sequential Sanad Creation:");
    println!("-------------------------");

    let num_sanads = 100;
    let start = Instant::now();

    for i in 0..num_sanads {
        let commitment = Hash::from([i as u8; 32]);
        let _ = client.sanads().create(&csv_protocol::SanadPayloadDescriptor::new(csv_protocol::SanadPayloadDescriptor::SCHEMA_ID, Hash::new([0u8; 32]), 1, commitment, None, Hash::new([0u8; 32]), Hash::new([0u8; 32])), commitment, csv_protocol::OwnershipProof { owner: vec![], proof: vec![], scheme: None }, &[], ChainId::new("bitcoin"));
    }

    let seq_duration = start.elapsed();
    println!("  Created {} sanads in {:.2?}", num_sanads, seq_duration);
    println!(
        "  Throughput: {:.0} sanads/sec\n",
        num_sanads as f64 / seq_duration.as_secs_f64()
    );

    // Parallel creation using threads
    println!("Parallel Sanad Creation (using threads):");
    println!("----------------------------------------");

    let client_arc = Arc::new(client);
    let num_threads = 4;
    let sanads_per_thread = 25;

    let start = Instant::now();

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let client_ref = Arc::clone(&client_arc);
            thread::spawn(move || {
                for i in 0..sanads_per_thread {
                    let commitment = Hash::from([(thread_id * sanads_per_thread + i) as u8; 32]);
                    let _ = client_ref
                        .sanads()
                        .create(&csv_protocol::SanadPayloadDescriptor::new(csv_protocol::SanadPayloadDescriptor::SCHEMA_ID, Hash::new([0u8; 32]), 1, commitment, None, Hash::new([0u8; 32]), Hash::new([0u8; 32])), commitment, csv_protocol::OwnershipProof { owner: vec![], proof: vec![], scheme: None }, &[], ChainId::new("ethereum"));
                }
                sanads_per_thread
            })
        })
        .collect();

    let total_created: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();

    let par_duration = start.elapsed();
    println!(
        "  Created {} sanads across {} threads in {:.2?}",
        total_created, num_threads, par_duration
    );
    println!(
        "  Throughput: {:.0} sanads/sec\n",
        total_created as f64 / par_duration.as_secs_f64()
    );

    // Query benchmark
    println!("Parallel Query Benchmark:");
    println!("-------------------------");

    // First create a sanad to query repeatedly
    let test_sanad = client_arc
        .sanads()
        .create(&csv_protocol::SanadPayloadDescriptor::new(csv_protocol::SanadPayloadDescriptor::SCHEMA_ID, Hash::new([0u8; 32]), 1, Hash::from([255u8; 32]), None, Hash::new([0u8; 32]), Hash::new([0u8; 32])), Hash::from([255u8; 32]), csv_protocol::OwnershipProof { owner: vec![], proof: vec![], scheme: None }, &[], ChainId::new("bitcoin"))?;

    let num_queries = 1000;
    let start = Instant::now();

    for _ in 0..num_queries {
        let sanad_id: csv_hash::SanadId = csv_protocol::wire::SanadIdWire::try_into(test_sanad.id.clone()).unwrap();
        let _ = client_arc.sanads().get(&sanad_id);
    }

    let query_duration = start.elapsed();
    let avg_query_time = query_duration / num_queries as u32;

    println!(
        "  Performed {} queries in {:.2?}",
        num_queries, query_duration
    );
    println!("  Average latency: {:?}\n", avg_query_time);

    // Speedup calculation
    let speedup = seq_duration.as_secs_f64() / par_duration.as_secs_f64();
    println!("=== Results ===");
    println!("Parallel speedup: {:.2}x", speedup);
    println!(
        "Sequential throughput: {:.0} sanads/sec",
        num_sanads as f64 / seq_duration.as_secs_f64()
    );
    println!(
        "Parallel throughput: {:.0} sanads/sec",
        total_created as f64 / par_duration.as_secs_f64()
    );
    println!("Query latency: {:?}", avg_query_time);

    println!("\n=== Use Cases ===");
    println!("- Batch creation of gaming assets");
    println!("- High-throughput credential issuance");
    println!("- Parallel proof verification (when available)");
    println!("- Multi-threaded indexing operations");

    Ok(())
}
