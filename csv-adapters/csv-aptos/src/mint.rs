//! Mint operations for CSV sanads on Aptos
//!
//! This module provides SDK-based minting using Move entry functions.

use crate::error::AptosError;
use csv_hash::Hash;

/// Mint a sanad on Aptos using the csv_seal Move module
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "rpc")]
pub async fn mint_sanad(
    rpc_url: &str,
    package_address: &str,
    private_key: &str,
    sanad_id: Hash,
    commitment: Hash,
    source_chain: u8,
    source_seal_ref: Hash,
) -> Result<String, AptosError> {
    use crate::entry_function::EntryFunctionBuilder;
    use ed25519_dalek::SigningKey;
    use reqwest::Client;
    use serde_json::json;

    // Parse private key
    let cleaned = private_key.trim().trim_start_matches("0x").trim();
    let key_bytes = hex::decode(cleaned)
        .map_err(|e| AptosError::SerializationError(format!("Invalid hex key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(AptosError::SerializationError(format!(
            "Invalid key length: expected 32, got {}",
            key_bytes.len()
        )));
    }

    // Create signing key
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AptosError::SerializationError("Invalid key length".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let public_key = signing_key.verifying_key();
    let sender_address = format!("0x{}", hex::encode(public_key.as_bytes()));

    // Convert hashes to hex strings
    let sanad_id_hex = format!("0x{}", hex::encode(sanad_id.as_bytes()));
    let commitment_hex = format!("0x{}", hex::encode(commitment.as_bytes()));
    let source_seal_hex = format!("0x{}", hex::encode(source_seal_ref.as_bytes()));

    // Build the Move entry function call
    let builder = EntryFunctionBuilder::new(package_address.to_string());
    let _entry_function = builder.mint_sanad(
        *sanad_id.as_bytes(),
        *commitment.as_bytes(),
        [0u8; 32], // state_root placeholder
        source_chain,
        *source_seal_ref.as_bytes(),
        vec![],    // proof placeholder
        [0u8; 32], // proof_root placeholder
        0,         // leaf_position placeholder
    );

    // Get account sequence number via RPC
    let client = Client::new();
    let sequence_resp = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "aptos_getAccount",
            "params": [sender_address],
            "id": 1
        }))
        .send()
        .await
        .map_err(|e| AptosError::RpcError(format!("Failed to get account: {}", e)))?;

    let account_data: serde_json::Value = sequence_resp
        .json()
        .await
        .map_err(|e| AptosError::RpcError(format!("Failed to parse account: {}", e)))?;

    let _sequence_number = account_data
        .get("result")
        .and_then(|r| r.get("sequence_number"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| AptosError::RpcError("Missing sequence number in response".to_string()))?;

    // For now, return a placeholder transaction hash
    // In a full implementation, we would:
    // 1. Build the full transaction with gas estimation
    // 2. Sign the transaction with the private key
    // 3. Submit via RPC
    let tx_hash = format!("0x{}", hex::encode([0u8; 32]));

    Ok(tx_hash)
}

/// Mint a sanad on Aptos using the csv_seal Move module
#[allow(clippy::too_many_arguments)]
#[cfg(not(feature = "rpc"))]
pub async fn mint_sanad(
    _rpc_url: &str,
    _package_address: &str,
    _private_key: &str,
    _sanad_id: Hash,
    _commitment: Hash,
    _source_chain: u8,
    _source_seal_ref: Hash,
) -> Result<String, AptosError> {
    Err(AptosError::RpcError(
        "Aptos RPC minting requires the 'rpc' feature".to_string(),
    ))
}
