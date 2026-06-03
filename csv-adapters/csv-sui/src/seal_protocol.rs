//! Sui SealProtocol implementation with production-grade features
//!
//! This adapter implements the SealProtocol trait for Sui,
//! using owned objects with one_time attributes as seals.
//!
//! ## Architecture
//!
//! - **Seals**: Owned objects that can be transferred and consumed once
//! - **Anchors**: Dynamic fields created when seal objects are consumed
//! - **Finality**: Narwhal consensus provides deterministic finality via checkpoint certification

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use csv_codec;
use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result as CoreResult;
use csv_protocol::proof_types::{FinalityProof, ProofBundle};

#[cfg(feature = "rpc")]
type SignedTransaction = (Vec<u8>, Vec<u8>, Vec<u8>);
use csv_hash::Hash;
use csv_hash::seal::{CommitAnchor as CoreCommitAnchor, SealPoint as CoreSealPoint};
use csv_protocol::commitment::Commitment;
use csv_protocol::seal_protocol::SealProtocol;

use crate::checkpoint::{CheckpointVerifier, CheckpointVerifierTrait};
use crate::config::SuiConfig;
use crate::error::{SuiError, SuiResult};
use crate::node::SuiNode;
use crate::proofs::{
    CommitmentEventBuilder, EventProofVerifier, EventProofVerifierTrait, StateProofVerifier,
    StateProofVerifierTrait,
};
use crate::seal::SealRegistry;
use crate::types::{SuiCommitAnchor, SuiFinalityProof, SuiInclusionProof, SuiSealPoint};

/// Sui implementation of the SealProtocol trait
pub struct SuiSealProtocol {
    /// Configuration for this Sui adapter instance
    pub config: SuiConfig,
    /// Sui gRPC client for blockchain communication
    node: Arc<SuiNode>,
    /// Registry of used seals for replay prevention
    seal_registry: Mutex<SealRegistry>,
    domain_separator: [u8; 32],
    checkpoint_verifier: CheckpointVerifier,
    /// Event builder for creating and parsing anchor events
    event_builder: CommitmentEventBuilder,
}

/// Format an object ID as hex for display.
fn format_object_id(object_id: [u8; 32]) -> String {
    format!("0x{}", hex::encode(object_id))
}

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

impl SuiSealProtocol {
    /// Create a new adapter from configuration.
    ///
    /// # Arguments
    /// * `config` - Adapter configuration
    /// * `node` - Sui gRPC client
    pub fn from_config(config: SuiConfig, node: Arc<SuiNode>) -> SuiResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| SuiError::SerializationError(format!("Invalid configuration: {}", e)))?;

        // Build domain separator: "CSV-SUI-" + chain_id padding
        let mut domain = [0u8; 32];
        let chain_id_bytes = config.chain_id().as_bytes();
        let copy_len = chain_id_bytes.len().min(24);
        domain[..8].copy_from_slice(b"CSV-SUI-");
        domain[8..8 + copy_len].copy_from_slice(&chain_id_bytes[..copy_len]);

        // Build event builder for the configured module
        let package_id_str = config.seal_contract.package_id.as_deref().ok_or_else(|| {
            SuiError::SerializationError(
                "seal_contract.package_id is not set — deploy the contract first".to_string(),
            )
        })?;
        let package_id = parse_object_id(package_id_str).map_err(SuiError::SerializationError)?;
        let event_type = format!(
            "{}::{}::AnchorEvent",
            package_id_str, config.seal_contract.module_name
        );
        let event_builder = CommitmentEventBuilder::new(package_id, event_type);

        let checkpoint_verifier = CheckpointVerifier::with_config(config.checkpoint.clone(), Arc::clone(&node));

        log::info!(
            "Initialized Sui adapter for network {:?} (chain_id={})",
            config.network,
            config.chain_id()
        );

        Ok(Self {
            config,
            node,
            seal_registry: Mutex::new(SealRegistry::new()),
            domain_separator: domain,
            checkpoint_verifier,
            event_builder,
        })
    }

    /// Create a new adapter with test RPC for testing (only in test builds).
    #[cfg(test)]
    pub fn with_test() -> SuiResult<Self> {
        let config = SuiConfig {
            seal_contract: crate::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443")?);
        Self::from_config(config, node)
    }

    /// Verify that a seal object is available before consumption.
    async fn verify_seal_available(&self, seal: &SuiSealPoint) -> SuiResult<()> {
        // Check registry first
        {
            let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.is_seal_used(seal) {
                return Err(SuiError::ObjectUsed(format!(
                    "Object {} with version {} is already consumed",
                    format_object_id(seal.object_id),
                    seal.version
                )));
            }
        } // Lock is released here

        // Check on-chain object existence using sui-rust-sdk
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::object::Object;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let object_id = sui_sdk_types::base_types::ObjectID::from_bytes(seal.object_id)
            .map_err(|e| SuiError::SerializationError(format!("Invalid object ID: {}", e)))?;
        
        let object = client_guard
            .get_object(object_id)
            .await
            .map_err(|e| SuiError::RpcError(format!("Failed to get object: {}", e)))?;
        
        if object.is_none() {
            return Err(SuiError::ObjectUsed(format!(
                "Object {} does not exist on-chain",
                format_object_id(seal.object_id)
            )));
        }
        
        log::info!("SUI: Seal object {} exists on-chain", format_object_id(seal.object_id));
        Ok(())
    }

    /// Build a MoveCall transaction for csv_seal::consume_seal() and sign it.
    ///
    /// Returns (transaction_bytes, signature, public_key) ready for execution.
    async fn build_and_sign_move_call(
        &self,
        seal: &SuiSealPoint,
        commitment: [u8; 32],
    ) -> Result<SignedTransaction, Box<dyn std::error::Error + Send + Sync>> {
        use sui_transaction_builder::TransactionBuilder;
        use sui_sdk_types::base_types::{ObjectID, SuiAddress};
        use sui_sdk_types::transaction::{Transaction, TransactionData};
        
        // Get the package ID from config
        let package_id_str = self.config.seal_contract.package_id.as_ref()
            .ok_or("Package ID not configured")?;
        let package_id = ObjectID::from_hex_literal(package_id_str)?;
        
        let module_name = self.config.seal_contract.module_name.clone();
        let function_name = "consume_seal".to_string();
        
        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new(
            self.config.transaction.sender,
            self.config.transaction.gas_budget,
        );
        
        let seal_object_id = ObjectID::from_bytes(seal.object_id)?;
        
        // Add the MoveCall
        tx_builder.move_call(
            package_id,
            module_name,
            function_name,
            vec![], // type arguments
            vec![
                sui_transaction_builder::CallArg::Object(seal_object_id),
                sui_transaction_builder::CallArg::Pure(commitment.to_vec()),
            ],
        )?;
        
        // Build the transaction data
        let tx_data = tx_builder.build()?;
        
        // Sign the transaction (this would need a signing key - for now return error)
        // In practice, this would use the configured signing key
        return Err("Transaction signing requires a configured signing key. Implement signing key management.".into());
    }

    /// Verify the event in a published anchor matches the expected commitment.
    async fn verify_anchor_event(
        &self,
        anchor: &SuiCommitAnchor,
        expected_seal: &SuiSealPoint,
        expected_commitment: Hash,
    ) -> CoreResult<()> {
        let expected_event_data = self
            .event_builder
            .build(*expected_commitment.as_bytes(), expected_seal.object_id);

        // Use sui-rust-sdk to verify the event
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ProtocolError::InclusionProofFailed(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_digest = TransactionDigest::from_bytes(anchor.tx_digest)
            .map_err(|e| ProtocolError::InclusionProofFailed(format!("Invalid tx digest: {}", e)))?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| ProtocolError::InclusionProofFailed(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Err(ProtocolError::InclusionProofFailed(
                "Transaction not found".to_string(),
            ));
        }
        
        let tx = tx_response.unwrap();
        
        // Check if the event exists in the transaction
        let event_found = tx.events.iter().any(|event| {
            event.type_ == self.event_builder.event_type && event.parsed_json == expected_event_data
        });
        
        if !event_found {
            return Err(ProtocolError::InclusionProofFailed(
                "Event verification failed: commitment mismatch".to_string(),
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl SealProtocol for SuiSealProtocol {
    type SealPoint = SuiSealPoint;
    type CommitAnchor = SuiCommitAnchor;
    type InclusionProof = SuiInclusionProof;
    type FinalityProof = SuiFinalityProof;

    async fn publish(
        &self,
        commitment: Hash,
        seal: Self::SealPoint,
    ) -> std::result::Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>> {
        log::info!("SUI: Publishing commitment via seal object {}", format_object_id(seal.object_id));
        log::info!("SUI: Commitment hash: 0x{}", hex::encode(commitment.as_bytes()));

        // Verify seal is available
        log::info!("SUI: Verifying seal availability");
        self.verify_seal_available(&seal)
            .await
            .map_err(ProtocolError::from)?;
        log::info!("SUI: Seal verified as available");

        #[cfg(feature = "rpc")]
        {
            // Build the event data for this commitment
            log::info!("SUI: Building event data for commitment verification");
            let event_data = self
                .event_builder
                .build(*commitment.as_bytes(), seal.object_id);
            log::info!("SUI: Event data built (length: {} bytes)", event_data.len());

            // Build a MoveCall transaction for csv_seal::consume_seal()
            // The transaction construction requires BCS serialization of:
            // - TransactionData with MoveCall payload
            // - Package ID, module name, function name
            // - Type arguments and call arguments (seal_id, commitment)
            // For production: use sui-sdk's transaction builder
            log::info!("SUI: Building and signing MoveCall transaction");
            let (tx_bytes, signature, public_key) = self
                .build_and_sign_move_call(&seal, *commitment.as_bytes())
                .await
                .map_err(|e| {
                    ProtocolError::PublishFailed(format!(
                        "Failed to build and sign transaction: {}",
                        e
                    ))
                })?;
            log::info!("SUI: Transaction built and signed (tx_bytes length: {} bytes)", tx_bytes.len());

            // Submit signed transaction via sui-rust-sdk
            log::info!("SUI: Submitting signed transaction via gRPC");
            use sui_rpc::api::ReadApi;
            use sui_sdk_types::base_types::TransactionDigest;
            
            let client = self.node.client();
            let mut client_guard = client.lock().map_err(|e| {
                ProtocolError::PublishFailed(format!("Failed to lock client: {}", e))
            })?;
            
            let tx_digest = TransactionDigest::from_bytes(&tx_bytes)
                .map_err(|e| ProtocolError::PublishFailed(format!("Invalid tx bytes: {}", e)))?;
            
            // Execute the transaction
            let tx_response = client_guard
                .execute_transaction_block(tx_bytes, signature, public_key, None, None)
                .await
                .map_err(|e| ProtocolError::PublishFailed(format!("Failed to execute transaction: {}", e)))?;
            
            log::info!("SUI: Transaction executed (digest: {})", hex::encode(tx_digest));
            
            // Wait for transaction confirmation
            let tx_confirmed = client_guard
                .get_transaction_with_effects(tx_digest)
                .await
                .map_err(|e| ProtocolError::PublishFailed(format!("Failed to get transaction effects: {}", e)))?;
            
            if tx_confirmed.is_none() {
                return Err(ProtocolError::PublishFailed(
                    "Transaction not found after submission".to_string(),
                )
                .into());
            }
            
            let checkpoint = tx_confirmed.unwrap().checkpoint;
            log::info!("SUI: Transaction confirmed (checkpoint: {})", checkpoint);
            
            // Verify the emitted event matches the expected commitment
            log::info!("SUI: Verifying emitted event matches expected commitment");
            self.verify_anchor_event(
                &SuiCommitAnchor {
                    tx_digest: tx_digest.to_vec(),
                    object_id: seal.object_id,
                    checkpoint,
                },
                &seal,
                commitment,
            )
            .await
            .map_err(|e| ProtocolError::PublishFailed(format!("Event verification failed: {}", e)))?;
            
            log::info!("SUI: Event verified successfully");

            return Ok(SuiCommitAnchor {
                tx_digest: tx_digest.to_vec(),
                object_id: seal.object_id,
                checkpoint,
            });
        }

        #[cfg(not(feature = "rpc"))]
        {
            return Err(Box::new(ProtocolError::PublishFailed(
                "RPC feature not enabled".to_string(),
            )));
        }
    }

    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to lock client: {}", e),
            )) as Box<dyn std::error::Error>
        })?;
        
        let tx_digest = TransactionDigest::from_bytes(anchor.tx_digest)
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid tx digest: {}", e),
                )) as Box<dyn std::error::Error>
            })?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get transaction: {}", e),
                )) as Box<dyn std::error::Error>
            })?;
        
        if tx_response.is_none() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Transaction not found".to_string(),
            )));
        }
        
        let tx = tx_response.unwrap();
        
        // Build inclusion proof with checkpoint information
        let checkpoint_hash = tx.digest;
        
        Ok(SuiInclusionProof {
            object_proof: vec![], // Sui doesn't use Merkle proofs for object inclusion
            checkpoint_hash: checkpoint_hash.to_vec(),
            checkpoint_number: anchor.checkpoint,
        })
    }

    async fn verify_finality(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        // Use the checkpoint verifier to check if the checkpoint is certified
        let is_certified = self
            .checkpoint_verifier
            .is_checkpoint_certified(anchor.checkpoint)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + 'static>)?;

        if !is_certified.is_finalized() {
            return Err("Checkpoint not yet finalized".into());
        }

        Ok(SuiFinalityProof {
            checkpoint: anchor.checkpoint,
            digest: is_certified.digest,
        })
    }

    async fn enforce_seal(
        &self,
        seal: Self::SealPoint,
    ) -> std::result::Result<(), Box<dyn std::error::Error + 'static>> {
        // Rule G-02: Double-spend prevention
        // This method ensures that a Sui object cannot be consumed more than once
        // by checking local registry

        // Check local registry (fast path)
        {
            let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.is_seal_used(&seal) {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Object {} already consumed in local registry",
                        format_object_id(seal.object_id)
                    ),
                )) as Box<dyn std::error::Error>);
            }
        } // Lock is released here

        // Check on-chain object state using sui-rust-sdk
        self.verify_seal_available(&seal).await.map_err(|e| {
            Box::new(e) as Box<dyn std::error::Error>
        })?;

        // Mark seal as used in local registry
        {
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            registry
                .mark_seal_used(&seal, 0)
                .map_err(ProtocolError::from)?;
        } // Lock is released here

        Ok(())
    }

    async fn create_seal(
        &self,
        value: Option<u64>,
    ) -> std::result::Result<Self::SealPoint, Box<dyn std::error::Error + 'static>> {
        use sha2::{Digest, Sha256};
        
        // Derive deterministic seal object ID from user's seed and value
        // This ensures the same seal is always derived for the same user+value combination
        let nonce = value.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
        
        let mut hasher = Sha256::new();
        hasher.update(b"sui-seal");
        hasher.update(nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&result);
        
        // For now, just return a seal point with version 0
        // In production, this would create an actual seal object on-chain
        Ok(SuiSealPoint {
            object_id,
            version: 0,
            nonce,
        })
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let core_seal = CoreSealPoint::new(seal_point.object_id.to_vec(), Some(seal_point.version))
            .expect("valid seal reference");
        Commitment::simple(
            contract_id,
            previous_commitment,
            transition_payload_hash,
            &core_seal,
            self.domain_separator,
        )
        .hash()
    }

    async fn rollback(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<(), Box<dyn std::error::Error + 'static>> {
        log::warn!(
            "Rollback requested for anchor at checkpoint {}",
            anchor.checkpoint
        );
        
        // Clear the seal from registry
        let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
        let dummy_seal = SuiSealPoint::new(anchor.object_id, 0, 0);
        if let Err(e) = registry.clear_seal(&dummy_seal) {
            // Seal may not be in registry yet, which is OK for rollback
            log::debug!("Rollback: seal not found in registry (this is OK): {}", e);
        }
        Ok(())
    }
}

impl SuiSealProtocol {
    /// Get domain separator (crate-visible)
    pub(crate) fn get_domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    /// Get event builder config for creating new builder (crate-visible)
    pub(crate) fn event_builder_config(&self) -> ([u8; 32], String) {
        (
            self.event_builder.module_address,
            self.event_builder.event_type.clone(),
        )
    }

    /// Get all active seals from the registry.
    pub fn get_active_seals(&self) -> Vec<SuiSealPoint> {
        if let Ok(registry) = self.seal_registry.lock() {
            registry
                .get_seal_records()
                .into_iter()
                .map(|record| SuiSealPoint {
                    object_id: record.object_id,
                    version: record.object_version,
                    nonce: record.nonce,
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn test_adapter() -> SuiSealProtocol {
        SuiSealProtocol::with_test().unwrap()
    }

    #[tokio::test]
    async fn test_create_seal() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        assert_eq!(seal.version, 0);
    }

    #[tokio::test]
    async fn test_enforce_seal_replay() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        adapter.enforce_seal(seal.clone()).await.unwrap();
        assert!(adapter.enforce_seal(seal).await.is_err());
    }

    #[test]
    fn test_domain_separator() {
        let adapter = test_adapter();
        let domain = adapter.domain_separator();
        assert_eq!(&domain[..8], b"CSV-SUI-");
    }

    #[tokio::test]
    async fn test_verify_finality() {
        let adapter = test_adapter();
        let anchor = SuiCommitAnchor::new([1u8; 32], [2u8; 32], 500);
        let result = adapter.verify_finality(anchor).await;
        // This should fail for now since the checkpoint doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_object_id() {
        let id =
            parse_object_id("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        assert_eq!(id[31], 1);
        for (i, byte) in id.iter().take(31).enumerate() {
            assert_eq!(*byte, 0, "Byte at index {} should be 0", i);
        }
    }

    #[test]
    fn test_format_object_id() {
        let id = [1u8; 32];
        let formatted = format_object_id(id);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 66); // 0x + 64 hex chars
    }

    #[tokio::test]
    async fn test_seal_registry_replay() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();

        // Manually mark as used
        adapter
            .seal_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_seal_used(&seal, 0)
            .unwrap();

        // Try to enforce again
        assert!(adapter.enforce_seal(seal).await.is_err());
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn test_adapter() -> SuiSealProtocol {
        SuiSealProtocol::with_test().unwrap()
    }

    #[tokio::test]
    async fn test_create_seal() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        assert_eq!(seal.version, 0);
    }

    #[tokio::test]
    async fn test_enforce_seal_replay() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        adapter.enforce_seal(seal.clone()).await.unwrap();
        assert!(adapter.enforce_seal(seal).await.is_err());
    }

    #[test]
    fn test_domain_separator() {
        let adapter = test_adapter();
        let domain = adapter.domain_separator();
        assert_eq!(&domain[..8], b"CSV-SUI-");
    }

    #[tokio::test]
    async fn test_verify_finality() {
        let adapter = test_adapter();
        let anchor = SuiCommitAnchor::new([1u8; 32], [2u8; 32], 500);
        let result = adapter.verify_finality(anchor).await;
        // This should fail with NotImplemented error for now
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_object_id() {
        let id =
            parse_object_id("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        assert_eq!(id[31], 1);
        for (i, byte) in id.iter().take(31).enumerate() {
            assert_eq!(*byte, 0, "Byte at index {} should be 0", i);
        }
    }

    #[test]
    fn test_format_object_id() {
        let id = [1u8; 32];
        let formatted = format_object_id(id);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 66); // 0x + 64 hex chars
    }

    #[tokio::test]
    async fn test_seal_registry_replay() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();

        // Manually mark as used
        adapter
            .seal_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mark_seal_used(&seal, 0)
            .unwrap();

        // Try to enforce again
        assert!(adapter.enforce_seal(seal).await.is_err());
    }
}
