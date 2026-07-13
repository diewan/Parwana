//! One-time operator action: initialize the CSV-Seal `LockRegistry` PDA on
//! devnet (`initialize_registry`). The lock path (`lock_sanad`) requires this
//! PDA; without it every source-side lock fails with
//! AccountOwnedByWrongProgram on the `registry` account.
//!
//! Usage: cargo run -p csv-solana --features rpc --example init_lock_registry
//! Signer: ~/.config/solana/id.json (the deploy/upgrade authority).

use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use std::str::FromStr;

const RPC: &str = "https://api.devnet.solana.com";
const PROGRAM_ID: &str = "9ekKQYpaLkTrycYmRNRDHohYZwXycHAyfLNirUDRnRVh";

fn rpc_call(method: &str, params: serde_json::Value) -> serde_json::Value {
    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    client
        .post(RPC)
        .json(&body)
        .send()
        .expect("rpc send")
        .json::<serde_json::Value>()
        .expect("rpc json")
}

fn main() {
    let home = std::env::var("HOME").expect("HOME");
    let key_json =
        std::fs::read_to_string(format!("{home}/.config/solana/id.json")).expect("id.json");
    let key_bytes: Vec<u8> = serde_json::from_str(&key_json).expect("keypair json");
    let payer = Keypair::try_from(key_bytes.as_slice()).expect("keypair");
    let program_id = Pubkey::from_str(PROGRAM_ID).unwrap();

    let (registry, _bump) = Pubkey::find_program_address(&[b"lock_registry"], &program_id);
    println!("authority: {}", payer.pubkey());
    println!("registry PDA: {}", registry);

    // Anchor discriminator for `initialize_registry`.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"global:initialize_registry");
    let disc: [u8; 8] = hasher.finalize()[..8].try_into().unwrap();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(registry, false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(
                Pubkey::from_str("11111111111111111111111111111111").unwrap(),
                false,
            ),
        ],
        data: disc.to_vec(),
    };

    let blockhash_resp = rpc_call("getLatestBlockhash", serde_json::json!([]));
    let blockhash_str = blockhash_resp["result"]["value"]["blockhash"]
        .as_str()
        .expect("blockhash");
    let blockhash = solana_sdk::hash::Hash::from_str(blockhash_str).unwrap();

    let message = Message::new(&[ix], Some(&payer.pubkey()));
    let mut tx = Transaction::new_unsigned(message);
    tx.sign(&[&payer], blockhash);

    let tx_bytes = bincode::serialize(&tx).expect("serialize tx");
    use base64::Engine;
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

    let resp = rpc_call(
        "sendTransaction",
        serde_json::json!([tx_b64, {"encoding": "base64"}]),
    );
    println!("send response: {}", resp);
}
