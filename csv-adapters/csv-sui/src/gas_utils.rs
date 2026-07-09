//! Gas object utilities for Sui transactions
//!
//! Provides helper functions for fetching and managing gas objects
//! (SUI coin objects) used to pay for transaction fees.

use crate::error::SuiError;
use crate::node::SuiNode;
use std::sync::Arc;

/// Fetch SUI gas objects owned by the given address.
///
/// # Arguments
/// * `node` - Sui gRPC client
/// * `address` - The address to fetch gas objects for
///
/// # Returns
/// A vector of ObjectInput representing gas objects that can be used
/// in TransactionBuilder::add_gas_objects()
#[cfg(feature = "rpc")]
pub async fn fetch_gas_objects(
    node: &Arc<SuiNode>,
    address: &sui_sdk_types::Address,
) -> Result<Vec<sui_transaction_builder::ObjectInput>, SuiError> {
    Ok(fetch_gas_objects_with_digest(node, address).await?.0)
}

/// Fetch SUI gas objects and a commitment to the exact on-chain objects
/// consumed.
///
/// The second return value is a domain-separated digest over each gas object's
/// real `(object_id, version, content-digest)` — i.e. genuine Sui chain state,
/// not wall-clock time or purely local inputs. Callers that must derive
/// deterministic, chain-bound values (e.g. `create_seal`) use it so the derived
/// values commit to the specific coins spent by the transaction and can be
/// reconstructed by any verifier who inspects the transaction
/// (`SUI-CREATE-SEAL-STATE-001`).
#[cfg(feature = "rpc")]
pub async fn fetch_gas_objects_with_digest(
    node: &Arc<SuiNode>,
    address: &sui_sdk_types::Address,
) -> Result<(Vec<sui_transaction_builder::ObjectInput>, [u8; 32]), SuiError> {
    use sui_rpc::proto::sui::rpc::v2::ListOwnedObjectsRequest;

    let client = node.client();
    let client_guard = client.lock().await;

    let mut request = ListOwnedObjectsRequest::default();
    request.owner = Some(address.to_string());
    request.page_size = Some(10);
    // Filter for SUI coins: 0x2::coin::Coin<0x2::sui::SUI>
    request.object_type = Some("0x2::coin::Coin<0x2::sui::SUI>".to_string());
    // Include digest field in response
    request.read_mask = Some(prost_types::FieldMask {
        paths: vec![
            "object_id".to_string(),
            "version".to_string(),
            "digest".to_string(),
        ],
    });

    log::info!(
        "SUI: Fetching gas objects for address {} with object_type filter",
        address
    );
    let stream = (*client_guard).list_owned_objects(request);

    // Pin the stream to satisfy Unpin requirement
    use futures::StreamExt;
    use std::pin::pin;
    let mut stream = pin!(stream);

    // Collect objects from the stream
    let mut objects = Vec::new();
    while let Some(result) = stream.next().await {
        let obj = result.map_err(|e| {
            SuiError::TransactionFailed(format!("Failed to read gas object: {}", e))
        })?;
        log::info!(
            "SUI: Received object from RPC: object_id={:?}, version={:?}, digest={:?}",
            obj.object_id,
            obj.version,
            obj.digest
        );
        objects.push(obj);
    }

    log::info!("SUI: Total objects returned from RPC: {}", objects.len());
    if objects.is_empty() {
        return Err(SuiError::TransactionFailed(
            "No SUI gas objects found for this address. Please fund the address with SUI tokens."
                .to_string(),
        ));
    }

    // Convert objects to ObjectInput for gas, accumulating a canonical preimage
    // over the real (object_id, version, content-digest) of each consumed coin.
    use blake2::{Blake2b, Digest as Blake2Digest};
    let mut gas_inputs = Vec::new();
    let mut ref_hasher = Blake2b::new();
    ref_hasher.update(b"csv.sui.gas-ref.v1");
    let mut ref_count: u32 = 0;
    for obj in objects {
        if let Some(object_id) = obj.object_id {
            let id_bytes = hex::decode(object_id.trim_start_matches("0x")).map_err(|e| {
                SuiError::TransactionFailed(format!("Invalid object ID hex: {}", e))
            })?;
            let mut id_array = [0u8; 32];
            if id_bytes.len() >= 32 {
                id_array.copy_from_slice(&id_bytes[..32]);
            }
            let addr = sui_sdk_types::Address::from_bytes(&id_array).map_err(|e| {
                SuiError::TransactionFailed(format!("Invalid object ID address: {}", e))
            })?;
            let version = obj.version.unwrap_or(1);

            // Parse the actual object digest from RPC response
            let digest = if let Some(digest_str) = obj.digest {
                sui_sdk_types::Digest::from_base58(digest_str).map_err(|e| {
                    SuiError::TransactionFailed(format!("Invalid digest Base58: {}", e))
                })?
            } else {
                sui_sdk_types::Digest::ZERO
            };

            // Bind the real chain-state reference into the commitment.
            ref_hasher.update(id_array);
            ref_hasher.update(version.to_le_bytes());
            ref_hasher.update(digest.as_bytes());
            ref_count += 1;

            gas_inputs.push(sui_transaction_builder::ObjectInput::owned(
                addr, version, digest,
            ));
        }
    }

    if ref_count == 0 {
        return Err(SuiError::TransactionFailed(
            "No usable SUI gas objects with a valid object reference were found".to_string(),
        ));
    }

    let gas_ref_digest: [u8; 32] = ref_hasher.finalize().into();

    log::info!(
        "SUI: Fetched {} gas objects for address {}",
        gas_inputs.len(),
        address
    );
    Ok((gas_inputs, gas_ref_digest))
}
