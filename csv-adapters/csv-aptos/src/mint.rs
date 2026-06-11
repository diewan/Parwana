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

    // Parse the sequence number
    let sequence_number: u64 = _sequence_number
        .parse()
        .map_err(|e| AptosError::RpcError(format!("Failed to parse sequence number: {}", e)))?;

    // Build the full transaction with gas estimation
    // For Aptos, we need to:
    // 1. Create the transaction payload (entry function call to csv_seal::mint_sanad)
    // 2. Estimate gas
    // 3. Sign the transaction with the private key
    // 4. Submit via RPC
    // 5. Return the actual transaction hash

    #[cfg(feature = "rpc")]
    {
        use aptos_sdk::types::transaction::{EntryFunction, ModuleId, TransactionPayload};
        use aptos_sdk::types::account_address::AccountAddress;
        use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
        use aptos_sdk::crypto::SigningKey;
        use aptos_sdk::transaction_builder::TransactionFactory;
        use aptos_sdk::bcs::to_bytes;

        // Parse the package address
        let package_addr = AccountAddress::from_hex_literal(package_address)
            .map_err(|e| AptosError::RpcError(format!("Invalid package address: {}", e)))?;

        // Create the entry function for mint_sanad
        // Function signature: mint_sanad(sanad_id: vector<u8>, commitment: vector<u8>, source_chain: u8, source_seal_ref: vector<u8>)
        let module_id = ModuleId::new(package_addr, ident_str!("csv_seal"));
        let entry_function = EntryFunction::new(
            module_id,
            ident_str!("mint_sanad"),
            vec![],
            vec![
                bcs::to_bytes(&sanad_id.as_bytes().to_vec()).unwrap(),
                bcs::to_bytes(&commitment.as_bytes().to_vec()).unwrap(),
                bcs::to_bytes(&source_chain).unwrap(),
                bcs::to_bytes(&source_seal_ref.as_bytes().to_vec()).unwrap(),
            ],
        );

        let payload = TransactionPayload::EntryFunction(entry_function);

        // Create transaction factory
        let factory = TransactionFactory::new(aptos_sdk::chain_id::ChainId::testnet());

        // Parse the private key
        let private_key_bytes = hex::decode(private_key)
            .map_err(|e| AptosError::RpcError(format!("Failed to decode private key: {}", e)))?;

        if private_key_bytes.len() != 32 {
            return Err(AptosError::RpcError(
                "Private key must be 32 bytes".to_string()
            ));
        }

        let private_key_array: [u8; 32] = private_key_bytes.try_into()
            .map_err(|_| AptosError::RpcError("Failed to convert private key to array".to_string()))?;

        let private_key = Ed25519PrivateKey::from_bytes(private_key_array)
            .map_err(|e| AptosError::RpcError(format!("Failed to create private key: {}", e)))?;

        let public_key = private_key.public_key();

        // Build the transaction
        let raw_transaction = factory.build(
            payload,
            public_key,
            sequence_number,
            100_000, // max_gas_amount
            1, // gas_unit_price
            0, // expiration_timestamp_secs
        );

        // Sign the transaction
        let signed_transaction = raw_transaction.sign(&private_key, public_key).map_err(|e| {
            AptosError::RpcError(format!("Failed to sign transaction: {}", e))
        })?;

        // Submit the transaction via RPC
        let client = aptos_sdk::rest_client::Client::new(reqwest::Url::parse(rpc_url)
            .map_err(|e| AptosError::RpcError(format!("Invalid RPC URL: {}", e)))?);

        let txn_hash = client.submit_bcs_transaction(&signed_transaction).await
            .map_err(|e| AptosError::RpcError(format!("Failed to submit transaction: {}", e)))?
            .into_inner();

        Ok(hex::encode(txn_hash))
    }

    #[cfg(not(feature = "rpc"))]
    {
        Err(AptosError::RpcError(
            "Aptos RPC minting requires the 'rpc' feature to be enabled".to_string()
        ))
    }
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
