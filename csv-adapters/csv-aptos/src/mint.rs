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
    use aptos_sdk::{
        Aptos, AptosConfig, account::Ed25519Account, transaction::EntryFunction,
        types::MoveModuleId,
    };

    // Create Aptos client with custom RPC URL
    let config = AptosConfig::custom(rpc_url)
        .map_err(|e| AptosError::RpcError(format!("Failed to create Aptos config: {}", e)))?;
    let aptos = Aptos::new(config)
        .map_err(|e| AptosError::RpcError(format!("Failed to create Aptos client: {}", e)))?;

    // Parse the private key
    let cleaned = private_key.trim().trim_start_matches("0x").trim();
    let key_bytes = hex::decode(cleaned)
        .map_err(|e| AptosError::SerializationError(format!("Invalid hex key: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(AptosError::SerializationError(format!(
            "Invalid key length: expected 32, got {}",
            key_bytes.len()
        )));
    }

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AptosError::SerializationError("Invalid key length".to_string()))?;

    // Create account from private key
    let account = Ed25519Account::from_private_key_hex(&hex::encode(key_array))
        .map_err(|e| AptosError::SerializationError(format!("Failed to create account: {}", e)))?;

    // Create entry function for mint_sanad
    // Function signature: mint_sanad(sanad_id: vector<u8>, commitment: vector<u8>, source_chain: u8, source_seal_ref: vector<u8>)
    let module_id = MoveModuleId::from_str_strict(&format!("{}::csv_seal", package_address))
        .map_err(|e| AptosError::RpcError(format!("Invalid module ID: {}", e)))?;

    let payload = EntryFunction::new(
        module_id,
        "mint_sanad",
        vec![],
        vec![
            sanad_id.as_bytes().to_vec(),
            commitment.as_bytes().to_vec(),
            vec![source_chain],
            source_seal_ref.as_bytes().to_vec(),
        ],
    );

    // Submit transaction and wait for confirmation
    let result = aptos
        .sign_submit_and_wait(&account, payload.into(), None)
        .await
        .map_err(|e| AptosError::RpcError(format!("Failed to submit transaction: {}", e)))?;

    // Extract transaction hash from result
    let txn_hash = result
        .data
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AptosError::RpcError("Missing transaction hash in response".to_string()))?;

    Ok(txn_hash.to_string())
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
        "Aptos RPC minting requires the 'rpc' feature to be enabled".to_string(),
    ))
}
