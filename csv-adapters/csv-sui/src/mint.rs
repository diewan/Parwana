//! Mint operations for CSV sanads on Sui
//!
//! This module provides SDK-based minting using Sui's gRPC via sui-rust-sdk.

#[cfg(feature = "rpc")]
use crate::error::{SuiError, SuiResult};
#[cfg(feature = "rpc")]
use crate::node::SuiNode;
#[cfg(feature = "rpc")]
use csv_hash::Hash as CsvHash;
#[cfg(feature = "rpc")]
use std::sync::Arc;

/// Mint a sanad on Sui using sui-rust-sdk gRPC client
///
/// This uses Sui's transaction building and execution via gRPC.
#[cfg(feature = "rpc")]
pub async fn mint_sanad(
    node: &Arc<SuiNode>,
    package_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
    sanad_id: CsvHash,
    commitment: CsvHash,
    source_chain: u8,
    source_seal_ref: CsvHash,
) -> SuiResult<String> {
    use ed25519_dalek::Signer;
    use sui_rpc::api::ReadApi;
    use sui_sdk_types::base_types::{ObjectID, SuiAddress};
    use sui_transaction_builder::TransactionBuilder;

    // Parse the package ID
    let package_id = ObjectID::from_hex_literal(package_id)
        .map_err(|e| SuiError::TransactionFailed(format!("Invalid package ID: {}", e)))?;

    // Derive the sender address from the signing key
    let public_key = signing_key.verifying_key();
    let pubkey_bytes = public_key.as_bytes();
    
    // Sui address is derived from public key using SHA3-256
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(pubkey_bytes);
    let mut addr_bytes = [0u8; 32];
    addr_bytes.copy_from_slice(&hash[..32]);
    let sender_address = SuiAddress::from_bytes(addr_bytes)
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to derive address: {}", e)))?;

    let client = node.client();
    let mut client_guard = client.lock().map_err(|e| {
        SuiError::TransactionFailed(format!("Failed to lock client: {}", e))
    })?;

    // Build the transaction using sui-transaction-builder
    let mut tx_builder = TransactionBuilder::new(
        sender_address,
        10000000, // gas budget
    );

    // Add the MoveCall to mint the sanad
    tx_builder.move_call(
        package_id,
        "csv_sanad".to_string(),
        "mint".to_string(),
        vec![], // type arguments
        vec![
            sui_transaction_builder::CallArg::Pure(sanad_id.as_bytes().to_vec()),
            sui_transaction_builder::CallArg::Pure(commitment.as_bytes().to_vec()),
            sui_transaction_builder::CallArg::Pure(vec![source_chain]),
            sui_transaction_builder::CallArg::Pure(source_seal_ref.as_bytes().to_vec()),
        ],
    ).map_err(|e| SuiError::TransactionFailed(format!("Failed to build MoveCall: {}", e)))?;

    // Build the transaction data
    let tx_data = tx_builder.build()
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to build transaction: {}", e)))?;

    // Sign the transaction using Ed25519
    let signature = signing_key.sign(&tx_data);

    // Execute the transaction via sui-rust-sdk
    // Note: The exact execution method depends on the sui-rust-sdk version
    // This is a simplified version - in production you'd use the proper SDK execution method
    let tx_digest = client_guard
        .execute_transaction(&tx_data, &signature.to_bytes())
        .await
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to execute transaction: {}", e)))?;

    Ok(tx_digest)
}
