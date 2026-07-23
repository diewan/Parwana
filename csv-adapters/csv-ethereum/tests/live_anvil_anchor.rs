//! Live local-dev RPC acceptance for accountability commitment anchoring.
//!
//! Run with an Anvil node and `PARWANA_ANVIL_RPC_URL`, for example:
//! `PARWANA_ANVIL_RPC_URL=http://127.0.0.1:8547 cargo test -p csv-ethereum
//! --all-features --test live_anvil_anchor -- --ignored --exact`.

#![cfg(feature = "rpc")]

use csv_accountability::{
    AnchorFinality, CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE, ChainAnchor, ChainAnchorAssessment,
};
use serde_json::{Value, json};
use std::time::Duration;

async fn rpc(client: &reqwest::Client, endpoint: &str, method: &str, params: Value) -> Value {
    let response: Value = client
        .post(endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .expect("local Anvil RPC request succeeds")
        .error_for_status()
        .expect("local Anvil RPC returns success status")
        .json()
        .await
        .expect("local Anvil RPC returns JSON");
    assert!(response.get("error").is_none(), "RPC error: {response}");
    response["result"].clone()
}

fn hex_u64(value: &Value) -> u64 {
    u64::from_str_radix(
        value
            .as_str()
            .expect("hex quantity")
            .trim_start_matches("0x"),
        16,
    )
    .expect("valid hex quantity")
}

fn digest(value: &Value) -> [u8; 32] {
    let bytes = hex::decode(value.as_str().expect("hex digest").trim_start_matches("0x"))
        .expect("valid hex digest");
    bytes.try_into().expect("32-byte digest")
}

async fn wait_for_receipt(client: &reqwest::Client, endpoint: &str, tx_hash: &Value) -> Value {
    for _ in 0..50 {
        let receipt = rpc(
            client,
            endpoint,
            "eth_getTransactionReceipt",
            json!([tx_hash]),
        )
        .await;
        if !receipt.is_null() {
            return receipt;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("anchor transaction was not mined by the local dev node");
}

#[tokio::test]
#[ignore = "requires a live local Anvil RPC selected by PARWANA_ANVIL_RPC_URL"]
async fn commitment_anchor_progresses_from_pending_to_final_on_live_dev_rpc() {
    let endpoint = std::env::var("PARWANA_ANVIL_RPC_URL")
        .expect("PARWANA_ANVIL_RPC_URL must identify the approved local dev node");
    assert!(
        endpoint.starts_with("http://127.0.0.1:") || endpoint.starts_with("http://localhost:"),
        "this acceptance test is deliberately restricted to a local dev RPC"
    );
    let client = reqwest::Client::new();
    let accounts = rpc(&client, &endpoint, "eth_accounts", json!([])).await;
    let sender = accounts[0]
        .as_str()
        .expect("Anvil exposes a funded account");
    let commitment = [0x5au8; 32];
    let commitment_hex = format!("0x{}", hex::encode(commitment));

    // A zero-value self-transfer is a real mined transaction whose exact input
    // commits the accountability digest without requiring a deployed contract.
    let tx_hash = rpc(
        &client,
        &endpoint,
        "eth_sendTransaction",
        json!([{
            "from": sender,
            "to": sender,
            "value": "0x0",
            "data": commitment_hex,
        }]),
    )
    .await;
    let receipt = wait_for_receipt(&client, &endpoint, &tx_hash).await;
    assert_eq!(receipt["status"], "0x1", "anchor transaction succeeded");
    let transaction = rpc(
        &client,
        &endpoint,
        "eth_getTransactionByHash",
        json!([tx_hash]),
    )
    .await;
    assert_eq!(transaction["input"], commitment_hex);

    let anchor_block = hex_u64(&receipt["blockNumber"]);
    let block_hash = digest(&receipt["blockHash"]);
    let anchor_ref = tx_hash
        .as_str()
        .expect("transaction hash")
        .trim_start_matches("0x")
        .to_owned();
    let pending = ChainAnchor {
        commitment,
        chain_id: "ethereum-anvil-31337".into(),
        anchor_ref: anchor_ref.as_bytes().to_vec(),
        block_height: anchor_block,
        block_hash,
        finality: AnchorFinality::from_confirmations(1, 2),
        anchor_backend: "chain.ethereum-anvil.v1".into(),
    };
    pending.validate().expect("pending anchor is canonical");
    assert_eq!(
        pending.assess(commitment),
        ChainAnchorAssessment::AnchoredPending
    );

    rpc(&client, &endpoint, "evm_mine", json!([])).await;
    let latest = hex_u64(&rpc(&client, &endpoint, "eth_blockNumber", json!([])).await);
    let confirmations = latest.saturating_sub(anchor_block) + 1;
    let final_anchor = ChainAnchor {
        finality: AnchorFinality::from_confirmations(confirmations, 2),
        ..pending
    };
    final_anchor.validate().expect("final anchor is canonical");
    assert_eq!(
        final_anchor.assess(commitment),
        ChainAnchorAssessment::AnchoredFinal
    );
    println!(
        "anchor_evidence commitment={} tx_hash={} block_height={} block_hash={} pending_confirmations=1 final_confirmations={confirmations} required_confirmations=2",
        hex::encode(commitment),
        anchor_ref,
        anchor_block,
        hex::encode(block_hash),
    );
    assert_eq!(
        CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE,
        "application/vnd.diewan.chain-commitment-anchor-v1+csv-binary"
    );
}
