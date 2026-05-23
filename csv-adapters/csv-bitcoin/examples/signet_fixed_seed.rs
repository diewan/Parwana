//! Generate a Bitcoin Signet wallet from a fixed seed for testing
//!
//! Run with:
//! ```bash
//! cargo run -p csv-adapter-bitcoin --example signet_fixed_seed --features signet-rest
//! ```

use bitcoin::Network as BtcNetwork;
use csv_bitcoin::wallet::SealWallet;
use sha2::{Digest, Sha256};

fn main() {
    // Deterministic seed derived from a known phrase for reproducibility
    let seed_phrase = "csv-adapter-signet-test-wallet-2024";
    let mut seed = [0u8; 64];
    let hash = Sha256::digest(seed_phrase.as_bytes());
    // Expand to 64 bytes
    for i in 0..32 {
        seed[i] = hash[i];
        seed[i + 32] = hash[i] ^ 0xAA;
    }

    let wallet = SealWallet::from_seed(&seed, BtcNetwork::Signet).unwrap();
    let (key, _path) = wallet.next_address(0).unwrap();

    println!("=== Bitcoin Signet Wallet (Fixed Seed) ===\n");
    println!("  Address:  {}", key.address);
    println!("  Seed hex: {}", hex::encode(seed));
    println!("  Path:     m/86'/1'/0'/0/0");
    println!("\n→ Fund this address from a Signet faucet:");
    println!("    https://mempool.space/signet/faucet");
    println!("\n→ After funding, verify at:");
    println!("    https://mempool.space/signet/address/{}", key.address);
    println!("\n→ Then export and run the test:");
    println!("    export CSV_SIGNET_SEED=\"{}\"", hex::encode(seed));
    println!(
        "    cargo test -p csv-adapter-bitcoin --test signet_real_tx --features signet-rest -- --ignored --nocapture"
    );
}
