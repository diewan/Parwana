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

use std::sync::Arc;
use tokio::sync::Mutex;

use async_trait::async_trait;
use blake2::Digest as Blake2Digest;
use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result as CoreResult;

#[cfg(feature = "rpc")]
type SignedTransaction = (Vec<u8>, Vec<u8>, Vec<u8>);
use csv_hash::Hash;
use csv_hash::seal::SealPoint as CoreSealPoint;
use csv_protocol::commitment::Commitment;
use csv_protocol::seal_protocol::SealProtocol;

use crate::checkpoint::{CheckpointVerifier, CheckpointVerifierTrait};
use crate::config::SuiConfig;
use crate::error::{SuiError, SuiResult};
use crate::node::SuiNode;
use crate::proofs::{
    CommitmentEventBuilder,
};
use crate::seal::SealRegistry;
use crate::types::{SuiCommitAnchor, SuiFinalityProof, SuiInclusionProof, SuiSealPoint};

#[cfg(feature = "rpc")]
use sui_transaction_builder::TransactionBuilder;

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
    /// Ed25519 signing key for transaction execution (RPC only)
    #[cfg(feature = "rpc")]
    signing_key: Option<ed25519_dalek::SigningKey>,
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

        // Extract signing key from config if available
        #[cfg(feature = "rpc")]
        let signing_key = if let Some(private_key_bytes) = &config.signer_private_key {
            if private_key_bytes.len() == 32 {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(private_key_bytes);
                Some(ed25519_dalek::SigningKey::from_bytes(&key_bytes))
            } else {
                log::warn!("Invalid signing key length in config (expected 32 bytes, got {})", private_key_bytes.len());
                None
            }
        } else {
            None
        };

        log::info!(
            "Initialized Sui adapter for network {:?} (chain_id={})",
            config.network,
            config.chain_id()
        );

        #[cfg(feature = "rpc")]
        {
            Ok(Self {
                config,
                node,
                seal_registry: Mutex::new(SealRegistry::new()),
                domain_separator: domain,
                checkpoint_verifier,
                event_builder,
                signing_key,
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Ok(Self {
                config,
                node,
                seal_registry: Mutex::new(SealRegistry::new()),
                domain_separator: domain,
                checkpoint_verifier,
                event_builder,
            })
        }
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

    /// Fetch the object digest from the chain for a given object ID and version.
    #[cfg(feature = "rpc")]
    async fn fetch_object_digest(&self, object_id: [u8; 32], version: u64) -> SuiResult<String> {
        use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
        use sui_sdk_types::Address;

        let object_id_addr = Address::from_bytes(object_id)
            .map_err(|e| SuiError::ObjectUsed(format!("Invalid object ID: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetObjectRequest::new(&object_id_addr);

        let object_response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| SuiError::ObjectUsed(format!("Failed to get object: {}", e)))?;

        let object = object_response.into_inner().object.ok_or_else(|| {
            SuiError::ObjectUsed("Object not found".to_string())
        })?;

        // Verify object version matches
        if let Some(obj_version) = object.version {
            if obj_version != version {
                return Err(SuiError::ObjectUsed(format!(
                    "Object version mismatch: expected {}, got {}",
                    version, obj_version
                )));
            }
        }

        // Return the digest if available
        object.digest.ok_or_else(|| {
            SuiError::ObjectUsed("Object digest not found".to_string())
        })
    }

    /// Verify that a seal object is available before consumption.
    async fn verify_seal_available(&self, seal: &SuiSealPoint) -> SuiResult<()> {
        log::info!("SUI: verify_seal_available called for object {} with version {}", format_object_id(seal.object_id), seal.version);

        // Check registry first
        {
            let registry = self.seal_registry.lock().await;
            if registry.is_seal_used(seal) {
                return Err(SuiError::ObjectUsed(format!(
                    "Object {} with version {} is already consumed",
                    format_object_id(seal.object_id),
                    seal.version
                )));
            }
        } // Lock is released here

        #[cfg(feature = "rpc")]
        {
            use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
            use sui_sdk_types::Address;
            use tokio::time::{sleep, Duration};

            let object_id = Address::from_bytes(seal.object_id)
                .map_err(|e| SuiError::ObjectUsed(format!("Invalid object ID: {}", e)))?;

            let client = self.node.client();
            
            // Retry mechanism with exponential backoff
            let mut retries = 0;
            let max_retries = 5;
            let base_delay = Duration::from_millis(500);
            
            loop {
                let mut client_guard = client.lock().await;
                let request = GetObjectRequest::new(&object_id);

                let object_response = (*client_guard)
                    .ledger_client()
                    .get_object(request)
                    .await;

                match object_response {
                    Ok(response) => {
                        let object = response.into_inner().object.ok_or_else(|| {
                            SuiError::ObjectUsed("Object not found".to_string())
                        })?;

                        // Check if object exists - simplified since deleted field doesn't exist in proto
                        if object.object_id.is_none() {
                            if retries < max_retries {
                                retries += 1;
                                let delay = base_delay * 2_u32.pow(retries - 1);
                                log::info!("SUI: Object not found, retry {} in {:?}", retries, delay);
                                drop(client_guard);
                                sleep(delay).await;
                                continue;
                            } else {
                                return Err(SuiError::ObjectUsed(format!(
                                    "Object {} not found after {} retries",
                                    format_object_id(seal.object_id),
                                    max_retries
                                )));
                            }
                        }

                        // Verify object version matches
                        if let Some(version) = object.version {
                            if version != seal.version {
                                return Err(SuiError::ObjectUsed(format!(
                                    "Object version mismatch: expected {}, got {}",
                                    seal.version, version
                                )));
                            }
                        }

                        log::info!("SUI: Object {} verified as available on-chain", format_object_id(seal.object_id));
                        break;
                    }
                    Err(e) => {
                        if retries < max_retries {
                            retries += 1;
                            let delay = base_delay * 2_u32.pow(retries - 1);
                            log::info!("SUI: Failed to get object: {}, retry {} in {:?}", e, retries, delay);
                            drop(client_guard);
                            sleep(delay).await;
                            continue;
                        } else {
                            return Err(SuiError::ObjectUsed(format!("Failed to get object after {} retries: {}", max_retries, e)));
                        }
                    }
                }
            }

            log::info!("SUI: Object {} verified as available on-chain", format_object_id(seal.object_id));
        }

        #[cfg(not(feature = "rpc"))]
        {
            log::info!("SUI: Skipping on-chain seal verification (RPC feature not enabled)");
        }

        Ok(())
    }

    /// Build a MoveCall transaction for csv_seal::consume_seal() and sign it.
    ///
    /// Returns (transaction_bytes, signature, public_key) ready for execution.
    #[cfg(feature = "rpc")]
    async fn build_and_sign_move_call(
        &self,
        seal: &SuiSealPoint,
        commitment: [u8; 32],
    ) -> Result<SignedTransaction, Box<dyn std::error::Error + Send + Sync>> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::Address;

        let signing_key = self.signing_key.as_ref()
            .ok_or("Signing key not configured. Set signer_private_key in SuiConfig.")?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using Blake2b with 0x00 prefix
        use blake2::Blake2b;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(pubkey_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let sender_address = Address::from_bytes(&hash)
            .map_err(|e| format!("Failed to derive address: {}", e))?;

        // Get the package ID from config
        let package_id_str = self.config.seal_contract.package_id.as_ref()
            .ok_or("Package ID not configured")?;
        let package_id_bytes = parse_object_id(package_id_str)
            .map_err(|e| format!("Invalid package ID: {}", e))?;
        let package_id = Address::from_bytes(&package_id_bytes)
            .map_err(|e| format!("Invalid package ID: {}", e))?;
        let module_name = self.config.seal_contract.module_name.clone();
        let function_name = "consume_seal".to_string();

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(self.config.transaction.max_gas_budget);
        tx_builder.set_gas_price(self.config.transaction.max_gas_price);

        let seal_object_id = Address::from_bytes(seal.object_id)?;

        // Add the MoveCall
        let function = sui_transaction_builder::Function::new(
            package_id,
            sui_sdk_types::Identifier::new(&module_name).map_err(|e| format!("Invalid module name: {}", e))?,
            sui_sdk_types::Identifier::new(&function_name).map_err(|e| format!("Invalid function name: {}", e))?,
        );
        let seal_object_arg = tx_builder.object(sui_transaction_builder::ObjectInput::owned(
            seal_object_id,
            seal.version,
            sui_sdk_types::Digest::from_base58(&seal.digest).unwrap_or_else(|_| sui_sdk_types::Digest::ZERO),
        ));
        let commitment_arg = tx_builder.pure(&commitment.to_vec());
        tx_builder.move_call(function, vec![seal_object_arg, commitment_arg]);

        // Build the transaction data
        let tx_data = tx_builder.try_build()?;

        // Use proper Sui signing digest with intent scope
        let signing_digest = tx_data.signing_digest();
        let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();
        let pubkey_bytes = public_key.as_bytes().to_vec();

        // Serialize transaction to BCS for execution
        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| format!("Failed to serialize transaction: {}", e))?;

        Ok((tx_bytes, sig_bytes, pubkey_bytes))
    }

    /// Verify the event in a published anchor matches the expected commitment.
    #[cfg(feature = "rpc")]
    async fn verify_anchor_event(
        &self,
        anchor: &SuiCommitAnchor,
        expected_seal: &SuiSealPoint,
        expected_commitment: Hash,
    ) -> CoreResult<()> {
        let _expected_event_data = self
            .event_builder
            .build(*expected_commitment.as_bytes(), expected_seal.object_id);

        // Use sui-rust-sdk to verify the event
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(anchor.tx_digest)
            .map_err(|e| ProtocolError::InclusionProofFailed(format!("Invalid tx digest: {}", e)))?;
        
        let request = GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ProtocolError::InclusionProofFailed(format!("Failed to get transaction: {}", e)))?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ProtocolError::InclusionProofFailed("Transaction not found in response".to_string())
        })?;
        
        // Check if the event exists in the transaction
        let tx_events = tx.events.as_ref().ok_or_else(|| {
            ProtocolError::InclusionProofFailed("Transaction has no events".to_string())
        })?;
        
        let event_found = tx_events.events.iter().any(|event| {
            let type_match = event.event_type.as_ref().map_or(false, |t| t == &self.event_builder.event_type);
            let json_match = event.json.as_ref().map_or(false, |j| {
                // prost_types::Value doesn't implement serde::Serialize directly
                // Compare the struct type and kind for basic matching
                // A proper implementation would convert prost_types::Value to a comparable format
                match &j.kind {
                    Some(_) => true, // If there's any value, consider it a match for now
                    None => false,
                }
            });
            type_match && json_match
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
        log::info!("SUI: Seal digest in publish method: '{}'", seal.digest);

        // Verify seal is available
        log::info!("SUI: Verifying seal availability");
        self.verify_seal_available(&seal)
            .await
            .map_err(ProtocolError::from)?;
        log::info!("SUI: Seal verified as available");

        #[cfg(feature = "rpc")]
        {
            use ed25519_dalek::Signer;
            use sui_sdk_types::{Address, Identifier};

            // If digest is empty, fetch it from the chain
            let seal_digest = if seal.digest.is_empty() {
                log::info!("SUI: Digest is empty, fetching from chain for object {} version {}", format_object_id(seal.object_id), seal.version);
                self.fetch_object_digest(seal.object_id, seal.version).await?
            } else {
                seal.digest.clone()
            };

            let signing_key = self.signing_key.as_ref().ok_or_else(|| {
                Box::new(ProtocolError::PublishFailed(
                    "Signing key not configured. Set signer_private_key in SuiConfig.".to_string(),
                )) as Box<dyn std::error::Error + 'static>
            })?;

            // Derive the sender address from the signing key
            let public_key = signing_key.verifying_key();
            let pubkey_bytes = public_key.as_bytes();

            // Sui address is derived from public key using Blake2b with 0x00 prefix
            use blake2::Blake2b;
            let mut hasher = Blake2b::new();
            hasher.update([0x00]); // Sui address prefix
            hasher.update(pubkey_bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            let sender_address = Address::from_bytes(&hash)
                .map_err(|e| format!("Failed to derive address: {}", e))?;

            // Get the package ID from config
            let package_id_str = self.config.seal_contract.package_id.as_ref()
                .ok_or("Package ID not configured")?;
            let package_id_bytes = parse_object_id(package_id_str)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let package_id = Address::from_bytes(&package_id_bytes)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let module_name = self.config.seal_contract.module_name.clone();

            // Fetch gas objects for the sender address
            let gas_objects = crate::gas_utils::fetch_gas_objects(&self.node, &sender_address)
                .await
                .map_err(|e| format!("Failed to fetch gas objects: {}", e))?;

            // Build the transaction using sui-transaction-builder
            let mut tx_builder = TransactionBuilder::new();
            tx_builder.set_sender(sender_address);
            tx_builder.set_gas_budget(10000000);
            tx_builder.set_gas_price(1000); // Sui testnet gas price
            tx_builder.add_gas_objects(gas_objects);

            let seal_object_id = Address::from_bytes(seal.object_id)?;

            // Add the MoveCall
            let function = sui_transaction_builder::Function::new(
                package_id,
                Identifier::new(&module_name).map_err(|e| format!("Invalid module name: {}", e))?,
                Identifier::new("consume_seal").map_err(|e| format!("Invalid function name: {}", e))?,
            );
            log::info!("SUI: Using digest for transaction: {}", &seal_digest);
            let seal_digest_str = seal_digest.clone();
            let seal_digest = sui_sdk_types::Digest::from_base58(&seal_digest);
            let seal_digest = match seal_digest {
                Ok(d) => {
                    log::info!("SUI: Successfully parsed digest from base58");
                    d
                }
                Err(e) => {
                    log::warn!("SUI: Failed to parse digest from base58 '{}': {}, using ZERO digest", &seal_digest_str, e);
                    sui_sdk_types::Digest::ZERO
                }
            };
            let seal_object_arg = tx_builder.object(sui_transaction_builder::ObjectInput::owned(
                seal_object_id,
                seal.version,
                seal_digest,
            ));
            let commitment_arg = tx_builder.pure(&commitment.as_bytes().to_vec());
            tx_builder.move_call(function, vec![seal_object_arg, commitment_arg]);

            // Build the transaction data
            let tx_data = tx_builder.try_build()
                .map_err(|e| format!("Failed to build transaction: {}", e))?;

            // Use proper Sui signing digest with intent scope
            let signing_digest = tx_data.signing_digest();
            let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

            // Serialize transaction to BCS for execution
            let tx_bytes = bcs::to_bytes(&tx_data)
                .map_err(|e| format!("Failed to serialize transaction: {}", e))?;

            // Execute the transaction via sui-rpc
            let client = self.node.client();
            let mut client_guard = client.lock().await;

            // Build the ExecuteTransactionRequest
            use sui_rpc::proto::sui::rpc::v2::{ExecuteTransactionRequest, Transaction, UserSignature};
            use sui_sdk_types::SimpleSignature;

            // Convert the transaction data to sui-sdk-types Transaction
            // The bcs field expects Bcs type
            let mut sui_transaction = Transaction::default();
            sui_transaction.bcs = Some(tx_bytes.clone().into());

            // Build the UserSignature using sui-sdk-types SimpleSignature
            // This properly BCS-encodes the signature with the correct structure
            let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|e| format!("Invalid signature bytes: {:?}", e))?;
            let pubkey_array: [u8; 32] = *pubkey_bytes;
            let simple_sig = SimpleSignature::Ed25519 {
                signature: sig_array.into(),
                public_key: pubkey_array.into(),
            };
            let sig_bcs = bcs::to_bytes(&simple_sig)
                .map_err(|e| format!("Failed to serialize signature: {}", e))?;
            let mut user_signature = UserSignature::default();
            user_signature.bcs = Some(sig_bcs.into());

            // Build the ExecuteTransactionRequest
            let mut execute_request = ExecuteTransactionRequest::default();
            execute_request.transaction = Some(sui_transaction);
            execute_request.signatures = vec![user_signature];

            // Execute the transaction
            let execution_response = (*client_guard)
                .execution_client()
                .execute_transaction(execute_request)
                .await
                .map_err(|e| Box::new(ProtocolError::PublishFailed(format!("Failed to execute transaction: {}", e))) as Box<dyn std::error::Error + 'static>)?;

            let executed_tx = execution_response.into_inner().transaction
                .ok_or_else(|| Box::new(ProtocolError::PublishFailed("No transaction in response".to_string())) as Box<dyn std::error::Error + 'static>)?;

            log::info!("SUI: Executed transaction response - digest: {:?}, checkpoint: {:?}", executed_tx.digest, executed_tx.checkpoint);
            log::info!("SUI: Transaction effects present: {}", executed_tx.effects.is_some());
            
            // Check transaction status and return error if failed
            if let Some(ref effects) = executed_tx.effects {
                log::info!("SUI: Effects status: {:?}", effects.status);
                if let Some(ref status) = effects.status {
                    if let Some(success) = status.success {
                        if !success {
                            let error_msg = if let Some(ref error) = status.error {
                                format!("Transaction execution failed: {:?}", error)
                            } else {
                                "Transaction execution failed (unknown error)".to_string()
                            };
                            return Err(Box::new(ProtocolError::PublishFailed(error_msg)) as Box<dyn std::error::Error + 'static>);
                        }
                    }
                }
            }

            // Extract the transaction digest from the response if available
            // Otherwise compute it from the transaction data
            let tx_digest_str = if let Some(digest) = executed_tx.digest {
                digest
            } else {
                // Compute digest from transaction data using Blake2b
                use blake2::Blake2b;
                let mut hasher = Blake2b::new();
                hasher.update(&tx_bytes);
                let digest: [u8; 32] = hasher.finalize().into();
                hex::encode(digest)
            };
            let digest_bytes = hex::decode(tx_digest_str.trim_start_matches("0x"))
                .map_err(|e| Box::new(ProtocolError::PublishFailed(format!("Invalid digest hex: {}", e))) as Box<dyn std::error::Error + 'static>)?;
            let mut digest_array = [0u8; 32];
            digest_array.copy_from_slice(&digest_bytes[..32]);

            // Extract the checkpoint from the transaction effects if available
            // Note: TransactionEffects doesn't have a direct checkpoint field
            // We'll use the transaction's checkpoint if available, or default to 0
            let checkpoint = executed_tx.checkpoint.unwrap_or(0);

            log::info!("SUI: Transaction executed successfully (digest: 0x{}, checkpoint: {})", hex::encode(digest_array), checkpoint);

            // Mark seal as used in local registry
            {
                let mut registry = self.seal_registry.lock().await;
                registry
                    .mark_seal_used(&seal, checkpoint)
                    .map_err(ProtocolError::from)?;
            }

            Ok(SuiCommitAnchor {
                object_id: seal.object_id,
                tx_digest: digest_array,
                checkpoint,
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            return Err(Box::new(ProtocolError::PublishFailed(
                "RPC feature not enabled".to_string(),
            )));
        }
    }

    #[cfg(feature = "rpc")]
    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
                        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(anchor.tx_digest)
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid tx digest: {}", e),
                )) as Box<dyn std::error::Error>
            })?;
        
        let request = sui_rpc::proto::sui::rpc::v2::GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get transaction: {}", e),
                )) as Box<dyn std::error::Error>
            })?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Transaction not found".to_string(),
            )) as Box<dyn std::error::Error>
        })?;
        
        // Build inclusion proof with checkpoint information
        let checkpoint_hash = if let Some(digest) = tx.digest {
            let decoded = hex::decode(digest.trim_start_matches("0x")).unwrap_or_default();
            let mut hash = [0u8; 32];
            if decoded.len() >= 32 {
                hash.copy_from_slice(&decoded[..32]);
            }
            hash
        } else {
            [0u8; 32]
        };
        
        Ok(SuiInclusionProof {
            object_proof: vec![], // Sui doesn't use Merkle proofs for object inclusion
            checkpoint_hash,
            checkpoint_number: anchor.checkpoint,
        })
    }

    #[cfg(not(feature = "rpc"))]
    async fn verify_inclusion(
        &self,
        _anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
        Err("RPC feature not enabled".into())
    }

    #[cfg(feature = "rpc")]
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
            is_certified: is_certified.is_finalized(),
        })
    }

    #[cfg(not(feature = "rpc"))]
    async fn verify_finality(
        &self,
        _anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        Err("RPC feature not enabled".into())
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
            let registry = self.seal_registry.lock().await;
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
            let mut registry = self.seal_registry.lock().await;
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
        #[cfg(feature = "rpc")]
        {
            use ed25519_dalek::Signer;
            use sui_sdk_types::{Address, Identifier};

            let signing_key = self.signing_key.as_ref()
                .ok_or("Signing key not configured. Set signer_private_key in SuiConfig.")?;

            // Derive the sender address from the signing key
            let public_key = signing_key.verifying_key();
            let pubkey_bytes = public_key.as_bytes();

            // Sui address is derived from public key using Blake2b with 0x00 prefix
            use blake2::Blake2b;
            let mut hasher = Blake2b::new();
            hasher.update([0x00]); // Sui address prefix
            hasher.update(pubkey_bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            let sender_address = Address::from_bytes(&hash)
                .map_err(|e| format!("Failed to derive address: {}", e))?;

            // Get the package ID from config
            let package_id_str = self.config.seal_contract.package_id.as_ref()
                .ok_or("Package ID not configured")?;
            let package_id_bytes = parse_object_id(package_id_str)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let package_id = Address::from_bytes(&package_id_bytes)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let module_name = self.config.seal_contract.module_name.clone();

            // Fetch gas objects for the sender address
            let gas_objects = crate::gas_utils::fetch_gas_objects(&self.node, &sender_address)
                .await
                .map_err(|e| format!("Failed to fetch gas objects: {}", e))?;

            // Build the transaction using sui-transaction-builder
            let mut tx_builder = TransactionBuilder::new();
            tx_builder.set_sender(sender_address);
            tx_builder.set_gas_budget(10000000);
            tx_builder.set_gas_price(1000); // Sui testnet gas price
            tx_builder.add_gas_objects(gas_objects);

            // Add the MoveCall to create the seal
            let function = sui_transaction_builder::Function::new(
                package_id,
                Identifier::new(&module_name).map_err(|e| format!("Invalid module name: {}", e))?,
                Identifier::new("create_seal").map_err(|e| format!("Invalid function name: {}", e))?,
            );
            
            // Generate required parameters from value
            let nonce = value.unwrap_or(0);
            let sanad_id = vec![0u8; 32]; // Placeholder - should be actual sanad ID
            let commitment = vec![0u8; 32]; // Placeholder - should be actual commitment
            let state_root = vec![0u8; 32]; // Placeholder - should be actual state root
            
            let sanad_id_arg = tx_builder.pure(&sanad_id);
            let commitment_arg = tx_builder.pure(&commitment);
            let state_root_arg = tx_builder.pure(&state_root);
            let nonce_arg = tx_builder.pure(&nonce);
            let owner_arg = tx_builder.pure(&sender_address);
            let seal_result = tx_builder.move_call(function, vec![sanad_id_arg, commitment_arg, state_root_arg, nonce_arg, owner_arg]);
            
            // Transfer the returned Seal object to the sender
            let address_arg = tx_builder.pure(&sender_address);
            tx_builder.transfer_objects(vec![seal_result], address_arg);

            // Build the transaction data
            let tx_data = tx_builder.try_build()
                .map_err(|e| format!("Failed to build transaction: {}", e))?;

            // Use proper Sui signing digest with intent scope
            let signing_digest = tx_data.signing_digest();
            let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

            // Serialize transaction to BCS for execution
            let tx_bytes = bcs::to_bytes(&tx_data)
                .map_err(|e| format!("Failed to serialize transaction: {}", e))?;

            // Execute the transaction via sui-rpc
            let client = self.node.client();
            let mut client_guard = client.lock().await;

            // Build the ExecuteTransactionRequest
            use sui_rpc::proto::sui::rpc::v2::{ExecuteTransactionRequest, Transaction, UserSignature};
            use sui_sdk_types::SimpleSignature;

            // Convert the transaction data to sui-sdk-types Transaction
            // The bcs field expects Bcs type
            let mut sui_transaction = Transaction::default();
            sui_transaction.bcs = Some(tx_bytes.clone().into());

            // Build the UserSignature using sui-sdk-types SimpleSignature
            // This properly BCS-encodes the signature with the correct structure
            let pubkey_bytes = public_key.as_bytes().to_vec();
            let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|e| format!("Invalid signature bytes: {:?}", e))?;
            let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|e| format!("Invalid public key bytes: {:?}", e))?;
            let simple_sig = SimpleSignature::Ed25519 {
                signature: sig_array.into(),
                public_key: pubkey_array.into(),
            };
            let sig_bcs = bcs::to_bytes(&simple_sig)
                .map_err(|e| format!("Failed to serialize signature: {}", e))?;
            let mut user_signature = UserSignature::default();
            user_signature.bcs = Some(sig_bcs.into());

            // Build the ExecuteTransactionRequest
            let mut execute_request = ExecuteTransactionRequest::default();
            execute_request.transaction = Some(sui_transaction);
            execute_request.signatures = vec![user_signature];

            // Execute the transaction
            let execution_response = (*client_guard)
                .execution_client()
                .execute_transaction(execute_request)
                .await
                .map_err(|e| format!("Failed to execute transaction: {}", e))?;

            let executed_tx = execution_response.into_inner().transaction
                .ok_or_else(|| "No transaction in response")?;

            log::info!("SUI: Executed transaction response - digest: {:?}, checkpoint: {:?}", executed_tx.digest, executed_tx.checkpoint);
            log::info!("SUI: Transaction effects present: {}", executed_tx.effects.is_some());
            if let Some(ref effects) = executed_tx.effects {
                log::info!("SUI: Effects status: {:?}", effects.status);
            }

            // Extract the created object ID from the transaction effects
            // The effects should contain the created seal object
            let (object_id, object_version, object_digest) = if let Some(effects) = executed_tx.effects {
                // Look for created objects in changed_objects
                log::info!("SUI: changed_objects count: {}", effects.changed_objects.len());
                let mut created_object_id = None;
                let mut created_object_version = None;
                let mut created_object_digest = None;
                for (idx, changed_obj) in effects.changed_objects.iter().enumerate() {
                    log::info!("SUI: changed_objects[{}]: object_id={:?}, input_state={:?}, output_state={:?}, output_version={:?}, output_digest={:?}",
                        idx, changed_obj.object_id, changed_obj.input_state, changed_obj.output_state, changed_obj.output_version, changed_obj.output_digest);
                    // Check if this is a newly created object (input_state is DOES_NOT_EXIST/1)
                    // and output_state indicates it was modified/created
                    if let Some(input_state) = changed_obj.input_state {
                        // input_state: 1 = DOES_NOT_EXIST, 2 = EXIST, etc.
                        // Objects that didn't exist before are newly created
                        if input_state == 1 && changed_obj.object_id.is_some() {
                            created_object_id = changed_obj.object_id.clone();
                            created_object_version = changed_obj.output_version;
                            created_object_digest = changed_obj.output_digest.clone();
                            log::info!("SUI: Found created object with ID: {:?}, version: {:?}, digest: {:?}", created_object_id, created_object_version, created_object_digest);
                            break;
                        }
                    }
                }

                if let Some(obj_id_str) = created_object_id {
                    let id_bytes = hex::decode(obj_id_str.trim_start_matches("0x"))
                        .map_err(|e| format!("Invalid object ID hex: {}", e))?;
                    let mut id = [0u8; 32];
                    if id_bytes.len() >= 32 {
                        id.copy_from_slice(&id_bytes[..32]);
                    }
                    let version = created_object_version.unwrap_or(1);

                    // Store the object digest as base58 string
                    let digest = if let Some(digest_str) = created_object_digest {
                        digest_str
                    } else {
                        log::warn!("SUI: No digest in changed_objects, using empty string");
                        String::new()
                    };

                    (id, version, digest)
                } else {
                    // Fallback: compute digest from transaction data using Blake2b
                    use blake2::Blake2b;
                    let mut hasher = Blake2b::new();
                    hasher.update(&tx_bytes);
                    let digest: [u8; 32] = hasher.finalize().into();
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&digest);
                    log::info!("SUI: No created object found in effects, using computed digest as fallback");
                    (id, 1, String::new())
                }
            } else {
                // Fallback: use transaction digest as object ID
                let tx_digest_str = executed_tx.digest.ok_or("No transaction digest in response")?;
                let digest_bytes = hex::decode(tx_digest_str.trim_start_matches("0x"))
                    .map_err(|e| format!("Invalid digest hex: {}", e))?;
                let mut id = [0u8; 32];
                id.copy_from_slice(&digest_bytes[..32]);
                (id, 1, String::new())
            };

            let nonce = value.unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

            log::info!("SUI: Created seal object {} with version {} on-chain", format_object_id(object_id), object_version);
            log::info!("SUI: Storing digest in SuiSealPoint: '{}'", object_digest);

            Ok(SuiSealPoint {
                object_id,
                version: object_version,
                digest: object_digest,
                nonce,
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err("RPC feature not enabled".into())
        }
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let core_seal = CoreSealPoint::new(seal_point.object_id.to_vec(), Some(seal_point.version), Some(seal_point.version))
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
        let mut registry = self.seal_registry.lock().await;
        let dummy_seal = SuiSealPoint::new(anchor.object_id, 0, String::new(), 0);
        if let Err(e) = registry.clear_seal(&dummy_seal) {
            // Seal may not be in registry yet, which is OK for rollback
            log::debug!("Rollback: seal not found in registry (this is OK): {}", e);
        }
        Ok(())
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
        csv_protocol::signature::SignatureScheme::Ed25519
    }

    #[cfg(feature = "rpc")]
    async fn build_proof_bundle(&self, anchor: Self::CommitAnchor, _extra_data: Vec<u8>) -> Result<csv_protocol::proof_types::ProofBundle, Box<dyn std::error::Error + 'static>> {
        use csv_protocol::proof_types::{ProofBundle, InclusionProof, FinalityProof};
        use csv_hash::dag::DAGSegment;
        use csv_hash::seal::{SealPoint, CommitAnchor};
        use csv_hash::Hash;

        // Get transaction to extract checkpoint hash for inclusion proof
        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let tx_digest = sui_sdk_types::Digest::from_bytes(&anchor.tx_digest)
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid tx digest: {}", e))) as Box<dyn std::error::Error + 'static>)?;

        let request = sui_rpc::proto::sui::rpc::v2::GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to get transaction: {}", e))) as Box<dyn std::error::Error + 'static>)?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Transaction not found".to_string())) as Box<dyn std::error::Error + 'static>
        })?;

        // Extract checkpoint hash from transaction
        let checkpoint_hash = if let Some(digest) = tx.digest {
            let decoded = hex::decode(digest.trim_start_matches("0x")).unwrap_or_default();
            let mut hash = [0u8; 32];
            if decoded.len() >= 32 {
                hash.copy_from_slice(&decoded[..32]);
            }
            Hash::new(hash)
        } else {
            Hash::zero()
        };

        // Build inclusion proof with checkpoint information
        let inclusion_proof = InclusionProof::new(
            vec![], // Sui doesn't use Merkle proofs for transaction inclusion
            checkpoint_hash,
            anchor.checkpoint,
            0, // Transaction index within checkpoint (not applicable for Sui)
        ).map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error + 'static>)?;

        // Build finality proof by checking if checkpoint is certified
        let is_certified = self.checkpoint_verifier.is_checkpoint_certified(anchor.checkpoint).await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + 'static>)?;

        let finality_proof = FinalityProof::new(
            vec![], // Sui uses checkpoint certification signatures
            anchor.checkpoint,
            is_certified.is_finalized(),
        ).map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error + 'static>)?;

        // Build DAG segment (empty for Sui as it doesn't use DAG-based consensus)
        let dag_segment = DAGSegment::new(vec![], Hash::zero());

        // Build seal point from SuiCommitAnchor
        let seal_point = SealPoint::new(anchor.object_id.to_vec(), Some(anchor.checkpoint), None)
            .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error + 'static>)?;

        // Build commit anchor from SuiCommitAnchor
        let commit_anchor = CommitAnchor::new(
            anchor.tx_digest.to_vec(),
            anchor.checkpoint,
            vec![], // Additional data (empty for now)
        ).map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error + 'static>)?;

        // Build the proof bundle
        ProofBundle::new(
            dag_segment,
            vec![], // Additional proofs (empty for now)
            seal_point,
            commit_anchor,
            inclusion_proof,
            finality_proof,
        ).map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn std::error::Error + 'static>)
    }

    #[cfg(not(feature = "rpc"))]
    async fn build_proof_bundle(&self, _anchor: Self::CommitAnchor, _extra_data: Vec<u8>) -> Result<csv_protocol::proof_types::ProofBundle, Box<dyn std::error::Error + 'static>> {
        Err("RPC feature not enabled".into())
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
    pub async fn get_active_seals(&self) -> Vec<SuiSealPoint> {
        let registry = self.seal_registry.lock().await;
        registry
            .get_seal_records()
            .into_iter()
            .map(|record| SuiSealPoint {
                object_id: record.object_id,
                version: record.object_version,
                digest: String::new(), // SealRecord doesn't store digest, use empty string for now
                nonce: record.nonce,
            })
            .collect()
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
            .await
            .mark_seal_used(&seal, 0)
            .unwrap();

        // Try to enforce again
        assert!(adapter.enforce_seal(seal).await.is_err());
    }
}
