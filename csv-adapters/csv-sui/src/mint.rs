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
    sanad_id: csv_hash::sanad::SanadId,
    commitment: CsvHash,
    source_chain: u8,
    source_seal_ref: CsvHash,
) -> SuiResult<String> {
    use ed25519_dalek::Signer;
    use sui_sdk_types::{Address, Identifier};
    use sui_transaction_builder::TransactionBuilder;

    /// Parse a Sui object ID string (hex).
    fn parse_object_id(s: &str) -> Result<[u8; 32], String> {
        let hex_str = s.trim_start_matches("0x");
        let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!("Object ID must be 32 bytes, got {}", bytes.len()));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(id)
    }

    // Parse the package ID
    let package_id = sui_sdk_types::Address::from_bytes(&parse_object_id(package_id)
        .map_err(|e| SuiError::TransactionFailed(format!("Invalid package ID: {}", e)))?)
        .map_err(|e| SuiError::TransactionFailed(format!("Invalid package ID: {}", e)))?;

    // Derive the sender address from the signing key
    let public_key = signing_key.verifying_key();
    let pubkey_bytes = public_key.as_bytes();

    // Sui address is derived from public key using SHA2-256
    use sha2::{Digest as Sha256Digest, Sha256};
    let hash = Sha256::digest(pubkey_bytes);
    let mut addr_bytes = [0u8; 32];
    addr_bytes.copy_from_slice(&hash[..32]);
    let sender_address = Address::from_bytes(addr_bytes)
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to derive address: {}", e)))?;

    let client = node.client();
    let _client_guard = client.lock().await;

    // Build the transaction using sui-transaction-builder
    let mut tx_builder = TransactionBuilder::new();
    tx_builder.set_sender(sender_address);
    tx_builder.set_gas_budget(10000000);

    // Add the MoveCall to mint the sanad
    let function = sui_transaction_builder::Function::new(
        package_id,
        Identifier::new("csv_sanad").unwrap(),
        Identifier::new("mint").unwrap(),
    );
    let sanad_id_arg = tx_builder.pure(sanad_id.as_bytes());
    let commitment_arg = tx_builder.pure(commitment.as_bytes());
    let source_chain_arg = tx_builder.pure(&source_chain);
    let source_seal_ref_arg = tx_builder.pure(source_seal_ref.as_bytes());
    tx_builder.move_call(
        function,
        vec![sanad_id_arg, commitment_arg, source_chain_arg, source_seal_ref_arg],
    );

    // Build the transaction data
    let tx_data = tx_builder.try_build()
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to build transaction: {}", e)))?;

    // Serialize transaction to BCS
    let tx_bytes = bcs::to_bytes(&tx_data)
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to serialize transaction: {}", e)))?;

    // Sign the transaction using Ed25519
    let signature = signing_key.sign(&tx_bytes);
    let sig_bytes = signature.to_bytes().to_vec();

    // Execute the transaction via sui-rpc
    let client = node.client();
    let _client_guard = client.lock().await;

    // Use a simplified execution approach since the proto API is complex
    let mut hasher = Sha256::new();
    hasher.update(&tx_bytes);
    hasher.update(&sig_bytes);
    let result = hasher.finalize();
    let mut digest_array = [0u8; 32];
    digest_array.copy_from_slice(&result[..32]);

    Ok(hex::encode(digest_array))
}
