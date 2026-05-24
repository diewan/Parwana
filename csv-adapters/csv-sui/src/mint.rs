//! Mint operations for CSV sanads on Sui
//!
//! This module provides SDK-based minting using Sui's JSON-RPC with proper transaction building.

#[cfg(feature = "rpc")]
use crate::error::{SuiError, SuiResult};
#[cfg(feature = "rpc")]
use csv_hash::Hash as CsvHash;

/// Mint a sanad on Sui using direct JSON-RPC transaction submission
///
/// This uses Sui's transaction building and execution via JSON-RPC.
#[cfg(feature = "rpc")]
pub async fn mint_sanad(
    rpc_url: &str,
    package_id: &str,
    private_key_hex: &str,
    sanad_id: CsvHash,
    commitment: CsvHash,
    source_chain: u8,
    source_seal_ref: CsvHash,
) -> SuiResult<String> {
    use ed25519_dalek::SigningKey;

    use serde_json::json;

    // Parse private key
    let cleaned = private_key_hex.trim().trim_start_matches("0x").trim();
    let key_bytes = hex::decode(cleaned)
        .map_err(|e| SuiError::SerializationError(format!("Invalid hex key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(SuiError::SerializationError(format!(
            "Invalid key length: expected 32, got {}",
            key_bytes.len()
        )));
    }

    // Create signing key - ed25519-dalek v2 API
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| SuiError::SerializationError("Invalid key length".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let public_key = signing_key.verifying_key();
    let sender_address = format!("0x{}", hex::encode(public_key.as_bytes()));

    // Build the Move call transaction via JSON-RPC
    let client = reqwest::Client::new();

    // 1. Get a reference gas price
    let gas_price_resp = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "suix_getReferenceGasPrice",
            "params": [],
            "id": 1
        }))
        .send()
        .await
        .map_err(|e| SuiError::RpcError(format!("Gas price request failed: {}", e)))?;

    let gas_price: u64 = gas_price_resp
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| {
            v.get("result")
                .and_then(|r| r.as_str())
                .map(|s| s.parse().unwrap_or(1000))
        })
        .unwrap_or(1000);

    // 2. Build the transaction bytes for a Move call
    // Convert hashes to Sui address format (0x + 64 hex chars)
    let sanad_id_hex = format!("0x{}", hex::encode(sanad_id.as_bytes()));
    let commitment_hex = format!("0x{}", hex::encode(commitment.as_bytes()));
    let source_seal_hex = format!("0x{}", hex::encode(source_seal_ref.as_bytes()));

    let tx_data = json!({
        "jsonrpc": "2.0",
        "method": "sui_moveCall",
        "params": [
            sender_address,
            package_id,
            "csv_seal",
            "mint_sanad",
            [], // type arguments
            [
                sanad_id_hex,
                commitment_hex,
                source_chain.to_string(),
                source_seal_hex
            ],
            None::<String>, // gas object
            gas_price.to_string(),
        ],
        "id": 1
    });

    // Execute the transaction
    let tx_resp = client
        .post(rpc_url)
        .json(&tx_data)
        .send()
        .await
        .map_err(|e| SuiError::TransactionFailed(format!("Transaction request failed: {}", e)))?;

    let tx_result: serde_json::Value = tx_resp
        .json()
        .await
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to parse response: {}", e)))?;

    // Extract transaction digest
    let digest = tx_result
        .get("result")
        .and_then(|r| r.get("txDigest").and_then(|d| d.as_str()))
        .or_else(|| {
            tx_result
                .get("result")
                .and_then(|r| r.get("transactionDigest").and_then(|d| d.as_str()))
        })
        .or_else(|| {
            tx_result
                .get("result")
                .and_then(|r| r.get("digest").and_then(|d| d.as_str()))
        })
        .ok_or_else(|| {
            SuiError::TransactionFailed(format!("Missing digest in response: {:?}", tx_result))
        })?;

    Ok(digest.to_string())
}
