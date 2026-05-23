//! Generate a Bitcoin Signet funding address
//!
//! Run with:
//! ```bash
//! cargo run -p csv-adapter-bitcoin --example signet_funding_addr --features signet-rest
//! ```

use bitcoin::Network as BtcNetwork;
use csv_bitcoin::wallet::SealWallet;

fn main() {
    let wallet = SealWallet::generate_random(BtcNetwork::Signet);
    let (key, _path) = wallet.next_address(0).expect("Failed to derive address");

    println!("=== Bitcoin Signet Funding Address ===\n");
    println!("  Address:  {}", key.address);
    println!("  Path:     m/86'/1'/0'/0/0");
    println!("\n→ Fund this address from a Signet faucet:");
    println!("    https://mempool.space/signet/faucet");
    println!("    https://signet.bc-2.jp");
    println!("\n→ After funding, check the funding transaction:");
    println!("    https://mempool.space/signet/address/{}", key.address);
    println!("\n→ Then run the real tx test:");
    println!("    export CSV_SIGNET_FUNDING_TXID=\"<txid>\"");
    println!("    export CSV_SIGNET_FUNDING_VOUT=0");
    println!("    export CSV_SIGNET_FUNDING_AMOUNT=<satoshis>");
    println!(
        "    cargo test -p csv-adapter-bitcoin --test signet_real_tx --features signet-rest -- --ignored --nocapture"
    );
}
