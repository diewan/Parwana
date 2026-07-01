//! Bitcoin Signet Real Transaction Demo
//!
//! Uses the funded wallet from bitcoin-test.txt seed to perform
//! a real on-chain Signet commitment transaction.
//!
//! Run with:
//! ```bash
//! cargo run -p csv-adapter-bitcoin --example signet_real_tx_demo --features signet-rest -- --nocapture
//! ```

use bitcoin::Network as BtcNetwork;
use csv_bitcoin::mempool_rpc::MempoolSignetRpc;
use csv_bitcoin::wallet::{Bip86Path, SealWallet};
use csv_bitcoin::{BitcoinConfig, BitcoinSealProtocol, Network};
use csv_hash::Hash;
use csv_protocol::seal_protocol::SealProtocol;

#[tokio::main]
async fn main() {
    println!("=== Bitcoin Signet Real Transaction Demo ===\n");

    let seed_hex = std::env::var("BTC_SEED_HEX")
        .expect("⚠️  BTC_SEED_HEX is not set. Copy .env.example to .env and fill in your key.");
    let seed_bytes = hex::decode(&seed_hex).expect("Invalid seed hex");
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&seed_bytes);

    // Create wallet
    let wallet = SealWallet::from_seed(&seed, BtcNetwork::Signet).expect("Failed to create wallet");

    // Show wallet info
    let (key, _path) = wallet.next_address(0).expect("Failed to derive address");
    println!("📬 Wallet address: {}", key.address);

    // Create RPC client
    let rpc = MempoolSignetRpc::new();

    // Get UTXOs from mempool.space
    println!("\n--- Scanning for UTXOs ---");
    let utxos = csv_bitcoin::mempool_rpc::get_address_utxos(&rpc, &key.address)
        .await
        .expect("Failed to get UTXOs");

    if utxos.is_empty() {
        println!("❌ No UTXOs found! Fund this address first.");
        return;
    }

    println!("✅ Found {} UTXO(s):", utxos.len());
    let mut total = 0u64;
    for (outpoint, value) in &utxos {
        println!("   {}:{} → {} sat", outpoint.txid, outpoint.vout, value);
        total += value;
    }
    println!("   Total: {} sat", total);

    // Add UTXOs to wallet
    for (outpoint, value) in &utxos {
        // We need to find the derivation path for each UTXO
        // For this demo, we know all UTXOs are at m/86'/1'/0'/0/0
        wallet.add_utxo(*outpoint, *value, Bip86Path::external(0, 0));
    }

    // Create Bitcoin adapter with real RPC
    let config = BitcoinConfig {
        network: Network::Signet,
        finality_depth: 1, // Signet blocks come fast, 1 conf is enough for demo
        publication_timeout_seconds: 300,
        rpc_url: "https://mempool.space/signet".to_string(),
        rpc_backend: csv_bitcoin::BitcoinRpcBackend::MempoolRest,
        indexer_url: None,
        api_key: None,
        xpub: None,
        private_key: None,
        seed: None,
        account: 0,
        index: 0,
        utxos: Vec::new(),
        sanad_seals: Vec::new(),
    };

    let required_depth = config.finality_depth;

    let adapter = BitcoinSealProtocol::with_wallet(config, wallet)
        .expect("Failed to create adapter")
        .with_rpc(Box::new(rpc));

    // Step 1: Create seal from first UTXO
    println!("\n--- Creating seal from real UTXO ---");
    let utxos = adapter.wallet.list_utxos();
    let first_utxo = &utxos[0];
    let (seal, path) = adapter
        .fund_seal(first_utxo.outpoint)
        .expect("Failed to create seal from UTXO");

    println!("✅ Created seal:");
    println!("   TXID: {}", seal.txid_hex());
    println!("   VOUT: {}", seal.vout);
    println!("   Value: {} sat", seal.nonce.unwrap_or(0));
    println!("   Path: m/86'/1'/0'/0/{}", path.index);

    // Step 2: Publish commitment (real transaction broadcast!)
    println!("\n--- Publishing commitment to Signet ---");
    let commitment = Hash::new([0xAB; 32]);

    // Demo uses the commitment as the sanad_id (Bitcoin ignores it here).
    let anchor = adapter
        .publish(commitment, seal.clone(), commitment)
        .await
        .expect("Failed to publish commitment");

    let txid_hex = hex::encode(anchor.txid);
    println!("✅ Commitment published!");
    println!("   TXID: {}", txid_hex);
    println!("   Block height: {}", anchor.block_height);
    println!("   🔍 View: https://mempool.space/signet/tx/{}", txid_hex);

    // Wait for confirmation
    println!(
        "\n--- Waiting for confirmation ({} required) ---",
        required_depth
    );
    let txid_bytes = hex::decode(&txid_hex).unwrap();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);

    // Poll for confirmation
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(600); // 10 minutes
    let poll_interval = std::time::Duration::from_secs(10);

    loop {
        if start.elapsed() > timeout {
            println!("❌ Timeout waiting for confirmation");
            return;
        }

        // Check if tx is confirmed
        let current_height = adapter.get_current_height_for_test().await;
        if current_height > anchor.block_height + required_depth as u64 {
            println!("✅ Transaction confirmed at block {}", current_height);
            break;
        }

        println!(
            "   Waiting... (current block: {}, needed: {})",
            current_height,
            anchor.block_height + required_depth as u64
        );
        std::thread::sleep(poll_interval);
    }

    // Step 3: Verify inclusion
    println!("\n--- Verifying inclusion ---");
    let inclusion = adapter
        .verify_inclusion(anchor.clone())
        .await
        .expect("Failed to verify inclusion");

    println!("✅ Inclusion proof:");
    println!("   Block height: {}", inclusion.block_height);
    println!("   Merkle branch length: {}", inclusion.merkle_branch.len());

    // Step 4: Verify finality
    println!("\n--- Verifying finality ---");
    let finality = adapter
        .verify_finality(anchor.clone())
        .await
        .expect("Failed to verify finality");

    println!("✅ Finality proof:");
    println!("   Confirmations: {}", finality.confirmations);
    println!("   Required depth: {}", finality.required_depth);
    println!("   Meets requirement: {}", finality.meets_required_depth);

    // Step 5: Test replay prevention
    println!("\n--- Testing replay prevention ---");
    adapter
        .enforce_seal(seal.clone())
        .await
        .expect("First enforcement should succeed");
    println!("✅ First enforcement succeeded");

    let replay_result = adapter.enforce_seal(seal).await;
    assert!(replay_result.is_err(), "Replay should be prevented");
    println!("✅ Replay prevention works correctly");

    println!("\n=== Bitcoin Signet Real Transaction Demo PASSED ===");
}
