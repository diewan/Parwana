//! Proof verification for the Sui adapter
//!
//! This module provides proof verification for Sui's object model,
//! including object existence proofs, transaction proofs, and event verification.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{SuiError, SuiResult};
use crate::node::SuiNode;

/// State proof for object existence/ownership verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateProof {
    /// The object ID being proven
    pub object_id: [u8; 32],
    /// Object version
    pub version: u64,
    /// Merkle proof of object existence in state
    pub merkle_proof: Vec<u8>,
    /// State root hash at the time of proof
    pub state_root: [u8; 32],
}

impl StateProof {
    /// Create a new state proof.
    pub fn new(
        object_id: [u8; 32],
        version: u64,
        merkle_proof: Vec<u8>,
        state_root: [u8; 32],
    ) -> Self {
        Self {
            object_id,
            version,
            merkle_proof,
            state_root,
        }
    }

    /// Compute the leaf hash for this state proof.
    pub fn leaf_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.object_id);
        hasher.update(self.version.to_le_bytes());
        hasher.finalize().into()
    }
}

/// Transaction proof for verifying a transaction was included in a checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Transaction digest
    pub tx_digest: [u8; 32],
    /// Checkpoint sequence number
    pub checkpoint: u64,
    /// Effects signature proving inclusion
    pub effects_signature: Vec<u8>,
}

impl TransactionProof {
    /// Create a new transaction proof.
    pub fn new(tx_digest: [u8; 32], checkpoint: u64, effects_signature: Vec<u8>) -> Self {
        Self {
            tx_digest,
            checkpoint,
            effects_signature,
        }
    }
}

/// Event proof for verifying commitment events in transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventProof {
    /// Transaction digest containing the event
    pub tx_digest: [u8; 32],
    /// Event index within the transaction
    pub event_index: u64,
    /// Expected event data hash
    pub expected_hash: [u8; 32],
}

impl EventProof {
    /// Create a new event proof.
    pub fn new(tx_digest: [u8; 32], event_index: u64, expected_hash: [u8; 32]) -> Self {
        Self {
            tx_digest,
            event_index,
            expected_hash,
        }
    }

    /// Compute the hash of event data.
    pub fn compute_event_hash(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Trait for state proof verification operations
#[async_trait]
pub trait StateProofVerifierTrait: Send + Sync {
    /// Verify that an object exists on-chain.
    async fn verify_object_exists(node: &Arc<SuiNode>, object_id: [u8; 32]) -> SuiResult<bool>;

    /// Verify that an object has been consumed (deleted).
    async fn verify_object_consumed(node: &Arc<SuiNode>, object_id: [u8; 32]) -> SuiResult<bool>;

    /// Verify that a transaction consumed a specific object.
    async fn verify_object_consumed_in_tx(
        node: &Arc<SuiNode>,
        tx_digest: [u8; 32],
        object_id: [u8; 32],
    ) -> SuiResult<bool>;
}

/// Verifier for state proofs (object existence/ownership).
pub struct StateProofVerifier;

#[async_trait]
impl StateProofVerifierTrait for StateProofVerifier {
    /// Verify that an object exists on-chain.
    async fn verify_object_exists(node: &Arc<SuiNode>, object_id: [u8; 32]) -> SuiResult<bool> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::ObjectID;
        
        let client = node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::StateProofFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let object_id = ObjectID::from_bytes(object_id)
            .map_err(|e| SuiError::StateProofFailed(format!("Invalid object ID: {}", e)))?;
        
        let object = client_guard
            .get_object(object_id)
            .await
            .map_err(|e| SuiError::StateProofFailed(format!("Failed to get object: {}", e)))?;
        
        Ok(object.is_some())
    }

    /// Verify that an object has been consumed (deleted).
    async fn verify_object_consumed(node: &Arc<SuiNode>, object_id: [u8; 32]) -> SuiResult<bool> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::ObjectID;
        
        let client = node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::StateProofFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let object_id = ObjectID::from_bytes(object_id)
            .map_err(|e| SuiError::StateProofFailed(format!("Invalid object ID: {}", e)))?;
        
        let object = client_guard
            .get_object(object_id)
            .await
            .map_err(|e| SuiError::StateProofFailed(format!("Failed to get object: {}", e)))?;
        
        // Object is consumed if it doesn't exist or is wrapped/deleted
        Ok(object.is_none())
    }

    /// Verify that a transaction consumed a specific object.
    async fn verify_object_consumed_in_tx(
        node: &Arc<SuiNode>,
        tx_digest: [u8; 32],
        object_id: [u8; 32],
    ) -> SuiResult<bool> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::{ObjectID, TransactionDigest};
        
        let client = node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::StateProofFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_digest = TransactionDigest::from_bytes(tx_digest)
            .map_err(|e| SuiError::StateProofFailed(format!("Invalid tx digest: {}", e)))?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| SuiError::StateProofFailed(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Ok(false);
        }
        
        let tx = tx_response.unwrap();
        
        // Check if the object ID appears in the transaction's input objects
        let object_id_bytes = object_id.to_vec();
        let consumed = tx.transaction.input_objects.iter().any(|input| {
            input.object_ref().map_or(false, |obj_ref| {
                obj_ref.0.to_vec() == object_id_bytes
            })
        });
        
        Ok(consumed)
    }
}

/// Trait for event proof verification operations
#[async_trait]
pub trait EventProofVerifierTrait: Send + Sync {
    /// Verify that an event was emitted in a transaction.
    async fn verify_event_in_tx(
        node: &Arc<SuiNode>,
        tx_digest: [u8; 32],
        expected_event_data: &[u8],
    ) -> SuiResult<bool>;
}

/// Verifier for event proofs.
pub struct EventProofVerifier;

#[async_trait]
impl EventProofVerifierTrait for EventProofVerifier {
    /// Verify that an event was emitted in a transaction.
    async fn verify_event_in_tx(
        node: &Arc<SuiNode>,
        tx_digest: [u8; 32],
        expected_event_data: &[u8],
    ) -> SuiResult<bool> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let client = node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::EventProofFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_digest = TransactionDigest::from_bytes(tx_digest)
            .map_err(|e| SuiError::EventProofFailed(format!("Invalid tx digest: {}", e)))?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| SuiError::EventProofFailed(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Ok(false);
        }
        
        let tx = tx_response.unwrap();
        
        // Check if any event matches the expected event data
        let event_found = tx.events.iter().any(|event| {
            event.parsed_json == expected_event_data
        });
        
        Ok(event_found)
    }
}

/// Convert hex string to bytes (local helper for proof verification)
fn hex_to_bytes_for_proof(hex: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))
}

/// Builder for commitment events emitted when seals are consumed.
pub struct CommitmentEventBuilder {
    /// Package ID of the CSV seal module
    pub(crate) module_address: [u8; 32],
    /// Event type tag
    pub(crate) event_type: String,
}

impl CommitmentEventBuilder {
    /// Create a new event builder.
    ///
    /// # Arguments
    /// * `package_id` - The package ID where CSVSeal is deployed
    /// * `event_type` - The event type (e.g., "csv_seal::AnchorEvent")
    pub fn new(package_id: [u8; 32], event_type: String) -> Self {
        Self {
            module_address: package_id,
            event_type,
        }
    }

    /// Build the expected event data for a commitment.
    ///
    /// # Arguments
    /// * `commitment_hash` - The 32-byte commitment hash
    /// * `seal_object_id` - The object ID of the consumed seal
    pub fn build(&self, commitment_hash: [u8; 32], seal_object_id: [u8; 32]) -> Vec<u8> {
        // Event format: module_address (32) + commitment (32) + seal_object_id (32)
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&self.module_address);
        data.extend_from_slice(&commitment_hash);
        data.extend_from_slice(&seal_object_id);
        data
    }

    /// Parse event data back into commitment and seal components.
    pub fn parse(&self, event_data: &[u8]) -> Result<([u8; 32], [u8; 32]), SuiError> {
        if event_data.len() < 96 {
            return Err(SuiError::EventProofFailed(format!(
                "Event data too short: expected 96 bytes, got {}",
                event_data.len()
            )));
        }

        let mut commitment = [0u8; 32];
        let mut seal_id = [0u8; 32];

        commitment.copy_from_slice(&event_data[32..64]);
        seal_id.copy_from_slice(&event_data[64..96]);

        Ok((commitment, seal_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_proof_hash() {
        let data = vec![0xAB, 0xCD, 0xEF];
        let hash1 = EventProof::compute_event_hash(&data);
        let hash2 = EventProof::compute_event_hash(&data);
        assert_eq!(hash1, hash2);

        let different_data = vec![0xFF];
        let hash3 = EventProof::compute_event_hash(&different_data);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_commitment_event_builder() {
        let builder = CommitmentEventBuilder::new([1u8; 32], "csv_seal::AnchorEvent".to_string());
        let event_data = builder.build([2u8; 32], [3u8; 32]);
        assert_eq!(event_data.len(), 96);

        let (commitment, seal_id) = builder.parse(&event_data).unwrap();
        assert_eq!(commitment, [2u8; 32]);
        assert_eq!(seal_id, [3u8; 32]);
    }

    #[test]
    fn test_commitment_event_builder_parse_error() {
        let builder = CommitmentEventBuilder::new([1u8; 32], "csv_seal::AnchorEvent".to_string());
        let short_data = vec![0u8; 50];
        assert!(builder.parse(&short_data).is_err());
    }

    #[test]
    fn test_state_proof_leaf_hash() {
        let proof = StateProof::new([1u8; 32], 1, vec![], [0u8; 32]);
        let hash = proof.leaf_hash();
        // Hash should be deterministic
        let hash2 = proof.leaf_hash();
        assert_eq!(hash, hash2);
    }
}
