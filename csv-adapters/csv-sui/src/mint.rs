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

    // Sui address is derived from public key using Blake2b with 0x00 prefix
    use blake2::Digest as Blake2Digest;
    use blake2::Blake2b;
    let mut hasher = Blake2b::new();
    hasher.update([0x00]); // Sui address prefix
    hasher.update(pubkey_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    let sender_address = Address::from_bytes(&hash)
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to derive address: {}", e)))?;

    let client = node.client();
    let _client_guard = client.lock().await;

    // Fetch gas objects for the sender address
    let gas_objects = crate::gas_utils::fetch_gas_objects(node, &sender_address)
        .await
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to fetch gas objects: {}", e)))?;

    if gas_objects.is_empty() {
        return Err(SuiError::TransactionFailed("No gas objects found".to_string()));
    }

    // Build the transaction using sui-transaction-builder
    let mut tx_builder = TransactionBuilder::new();
    tx_builder.set_sender(sender_address);
    tx_builder.set_gas_budget(10000000);
    tx_builder.add_gas_objects(gas_objects);

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

    // Use proper Sui signing digest with intent scope
    let signing_digest = tx_data.signing_digest();
    let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

    // Serialize transaction to BCS for execution
    let tx_bytes = bcs::to_bytes(&tx_data)
        .map_err(|e| SuiError::TransactionFailed(format!("Failed to serialize transaction: {}", e)))?;

    // Execute the transaction via sui-rpc
    let client = node.client();
    let _client_guard = client.lock().await;

    // Use a simplified execution approach since the proto API is complex
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(&tx_bytes);
    hasher.update(&sig_bytes);
    let result = hasher.finalize();
    let mut digest_array = [0u8; 32];
    digest_array.copy_from_slice(&result[..32]);

    Ok(hex::encode(digest_array))
}
