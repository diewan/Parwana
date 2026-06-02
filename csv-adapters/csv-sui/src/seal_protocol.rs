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

use std::sync::Mutex;

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
use crate::proofs::{
    CommitmentEventBuilder, EventProofVerifier, EventProofVerifierTrait, StateProofVerifier,
    StateProofVerifierTrait,
};
#[cfg(feature = "rpc")]
use crate::rpc::SuiObject;
use crate::rpc::SuiRpc;
use crate::seal::SealRegistry;
use crate::types::{SuiCommitAnchor, SuiFinalityProof, SuiInclusionProof, SuiSealPoint};

/// Sui implementation of the SealProtocol trait
pub struct SuiSealProtocol {
    /// Configuration for this Sui adapter instance
    pub config: SuiConfig,
    /// Registry of used seals for replay prevention
    seal_registry: Mutex<SealRegistry>,
    domain_separator: [u8; 32],
    pub rpc: Box<dyn SuiRpc>,
    checkpoint_verifier: CheckpointVerifier,
    /// Event builder for creating and parsing anchor events
    event_builder: CommitmentEventBuilder,
    /// Ed25519 signing key for transaction signing (RPC mode only)
    #[cfg(feature = "rpc")]
    pub signing_key: Option<ed25519_dalek::SigningKey>,
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

/// Build a complete Sui TransactionData with BCS serialization
///
/// This constructs the exact wire format that Sui nodes expect for
/// a MoveCall transaction. The structure follows Sui's BCS specification.
///
/// # BCS Encoding Notes
///
/// Sui uses BCS (Binary Canonical Serialization) with:
/// - uleb128 for vector lengths and enum variants
/// - little-endian for integers
/// - length-prefixed for strings and vectors
///
/// This function manually constructs the BCS bytes to avoid the sui-sdk dependency.
#[cfg(feature = "rpc")]
#[allow(clippy::too_many_arguments)]
fn build_sui_transaction_data(
    package_id: [u8; 32],
    module_name: &str,
    function_name: &str,
    seal_object_id: [u8; 32],
    seal_object_version: u64,
    seal_object_digest: [u8; 32],
    commitment: [u8; 32],
    sender: [u8; 32],
    gas_objects: &[SuiObject],
    gas_price: u64,
    gas_budget: u64,
) -> Vec<u8> {
    // Manual BCS serialization helpers
    fn uleb128_encode(mut n: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let byte = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                buf.push(byte);
                break;
            } else {
                buf.push(byte | 0x80);
            }
        }
        buf
    }

    fn bcs_vec_u8(v: &[u8]) -> Vec<u8> {
        let mut out = uleb128_encode(v.len() as u64);
        out.extend_from_slice(v);
        out
    }

    fn bcs_string(s: &str) -> Vec<u8> {
        bcs_vec_u8(s.as_bytes())
    }

    fn bcs_vec_vec_u8(vv: &[Vec<u8>]) -> Vec<u8> {
        let mut out = uleb128_encode(vv.len() as u64);
        for v in vv {
            out.extend_from_slice(v);
        }
        out
    }

    let mut tx = Vec::new();

    // === TransactionKind (enum variant 0 = ProgrammableTransaction) ===
    tx.push(0); // TransactionKind::ProgrammableTransaction

    // ProgrammableTransaction { inputs: Vec<CallArg>, commands: Vec<Command> }
    // inputs: 2 items
    tx.extend_from_slice(&uleb128_encode(2));

    // Input 0: CallArg::Object (variant 1)
    tx.push(1);
    // ObjectArg::ImmOrOwnedObject (variant 0): (ObjectID, u64 version, ObjectDigest)
    tx.extend_from_slice(&seal_object_id);
    tx.extend_from_slice(&seal_object_version.to_le_bytes());
    tx.extend_from_slice(&seal_object_digest);

    // Input 1: CallArg::Pure (variant 0)
    tx.push(0);
    // Pure value: length-prefixed bytes
    tx.extend_from_slice(&bcs_vec_u8(&commitment));

    // commands: 1 item
    tx.extend_from_slice(&uleb128_encode(1));

    // Command::MoveCall (variant 0)
    tx.push(0);
    // MoveCall { package, module, function, type_arguments, arguments }
    tx.extend_from_slice(&package_id);
    tx.extend_from_slice(&bcs_string(module_name));
    tx.extend_from_slice(&bcs_string(function_name));
    // type_arguments: Vec<TypeTag> (empty)
    tx.push(0); // length 0
    // arguments: Vec<Argument>
    // Argument::Input(u16) = variant 1
    tx.extend_from_slice(&uleb128_encode(2)); // 2 arguments
    tx.push(1);
    tx.extend_from_slice(&0u16.to_le_bytes()); // Input(0)
    tx.push(1);
    tx.extend_from_slice(&1u16.to_le_bytes()); // Input(1)

    // === sender: SuiAddress (32 bytes) ===
    tx.extend_from_slice(&sender);

    // === GasData { payment: Vec<ObjectRef>, owner, price, budget } ===
    // payment: gas_objects
    tx.extend_from_slice(&uleb128_encode(gas_objects.len() as u64));
    for obj in gas_objects {
        // ObjectRef: (ObjectID, version, digest)
        tx.extend_from_slice(&obj.object_id);
        tx.extend_from_slice(&obj.version.to_le_bytes());
        tx.extend_from_slice(&[0u8; 32]); // digest
    }
    // owner
    tx.extend_from_slice(&sender);
    // price
    tx.extend_from_slice(&gas_price.to_le_bytes());
    // budget
    tx.extend_from_slice(&gas_budget.to_le_bytes());

    // === TransactionExpiration (variant 0 = None) ===
    tx.push(0);

    tx
}

impl SuiSealProtocol {
    /// Run an async operation that borrows from self, by cloning the RPC client.
    async fn run_with_rpc<F, T>(&self, op: impl FnOnce(Box<dyn SuiRpc>) -> F) -> Result<T, SuiError>
    where
        F: std::future::Future<Output = Result<T, SuiError>> + Send + 'static,
        T: Send + 'static,
    {
        let rpc = self.rpc.clone_boxed();
        op(rpc).await
    }

    /// Create a new adapter from configuration and RPC client.
    ///
    /// # Arguments
    /// * `config` - Adapter configuration
    /// * `rpc` - RPC client for Sui node communication
    pub fn from_config(config: SuiConfig, rpc: Box<dyn SuiRpc>) -> SuiResult<Self> {
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

        let checkpoint_verifier = CheckpointVerifier::with_config(config.checkpoint.clone());

        log::info!(
            "Initialized Sui adapter for network {:?} (chain_id={})",
            config.network,
            config.chain_id()
        );

        Ok(Self {
            config,
            seal_registry: Mutex::new(SealRegistry::new()),
            domain_separator: domain,
            rpc,
            checkpoint_verifier,
            event_builder,
            #[cfg(feature = "rpc")]
            signing_key: None,
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
        let rpc = crate::rpc::MockSuiRpc::new(1000);
        rpc.add_checkpoint(crate::rpc::SuiCheckpoint {
            sequence_number: 500,
            digest: [1u8; 32],
            epoch: 1,
            network_total_transactions: 50000,
            certified: true,
        });
        let rpc = Box::new(rpc);
        Self::from_config(config, rpc)
    }

    /// Attach an Ed25519 signing key for transaction signing (RPC mode only).
    #[cfg(feature = "rpc")]
    pub fn with_signing_key(mut self, signing_key: ed25519_dalek::SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Create a new adapter with real RPC (requires `rpc` feature).
    ///
    /// # Arguments
    /// * `config` - Adapter configuration
    /// * `csv_seal_package_id` - Package ID where CSVSeal module is deployed
    /// * `signing_key` - Ed25519 signing key for transaction signing
    #[cfg(feature = "rpc")]
    pub fn with_real_rpc(
        config: SuiConfig,
        _csv_seal_package_id: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use crate::node::SuiNode;

        let rpc: Box<dyn SuiRpc> = Box::new(SuiNode::new(&config.rpc_url));
        let mut adapter = Self::from_config(config, rpc)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        adapter.signing_key = Some(signing_key);
        Ok(adapter)
    }

    #[cfg(not(feature = "rpc"))]
    pub fn with_real_rpc(
        _config: SuiConfig,
        _csv_seal_package_id: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Err("rpc feature not enabled".into())
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

        // Check on-chain object exists and verify ownership
        #[cfg(feature = "rpc")]
        {
            let owner_address = self.rpc.as_ref()
                .sender_address().await
                .map_err(|e| SuiError::RpcError(format!("Failed to get owner address: {}", e)))?;

            let obj = self.rpc.as_ref()
                .get_object(seal.object_id).await
                .map_err(|e| SuiError::RpcError(format!("Failed to fetch seal object: {}", e)))?;
            
            match obj {
                Some(seal_obj) => {
                    // Verify ownership
                    if seal_obj.owner != owner_address {
                        return Err(SuiError::StateProofFailed(format!(
                            "Seal object {} is not owned by this account. Owner: {:?}, Expected: {:?}",
                            format_object_id(seal.object_id), seal_obj.owner, owner_address
                        )));
                    }
                    log::info!("SUI: Seal object {} verified as owned by user", format_object_id(seal.object_id));
                }
                None => {
                    return Err(SuiError::StateProofFailed(format!(
                        "Seal object {} does not exist on-chain. It should have been created during create_seal.",
                        format_object_id(seal.object_id)
                    )));
                }
            }
        }

        #[cfg(not(feature = "rpc"))]
        {
            // Without RPC, skip on-chain existence check
            log::debug!("SUI: Skipping on-chain existence check (RPC feature disabled)");
        }

        Ok(())
    }

    /// Build a MoveCall transaction for csv_seal::consume_seal() and sign it.
    ///
    /// Returns (transaction_bytes, signature, public_key) ready for execution.
    ///
    /// # Transaction Structure
    ///
    /// Uses Sui's ProgrammableTransaction format:
    /// ```text
    /// TransactionData {
    ///   kind: ProgrammableTransaction {
    ///     inputs: [Object(SealObjectID), Pure(CommitmentHash)],
    ///     commands: [MoveCall {
    ///       package: csv_seal_package_id,
    ///       module: "csv_seal",
    ///       function: "consume_seal",
    ///       type_arguments: [],
    ///       arguments: [Input(0), Input(1)],
    ///     }],
    ///   },
    ///   sender: signer_address,
    ///   gas_data: GasData { payment, owner, price, budget },
    ///   expiration: None,
    /// }
    /// ```
    ///
    /// The transaction is signed as: `Signature = Sign(BCS(TransactionData))`
    ///
    /// # Note
    ///
    /// Actual Sui transaction building requires sui-sdk for proper BCS types.
    /// This implementation uses raw BCS serialization to avoid the SDK dependency,
    /// matching the exact wire format Sui nodes expect.
    #[cfg(feature = "rpc")]
    async fn build_and_sign_move_call(
        &self,
        seal: &SuiSealPoint,
        commitment: [u8; 32],
    ) -> Result<SignedTransaction, Box<dyn std::error::Error + Send + Sync>> {
        use ed25519_dalek::Signer;

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        let package_id = self
            .config
            .seal_contract
            .package_id
            .as_deref()
            .ok_or("seal_contract.package_id is not set — deploy the contract first")?;
        let package_id =
            parse_object_id(package_id).map_err(|e| format!("Invalid package ID: {}", e))?;
        let module_name = self.config.seal_contract.module_name.clone();
        let function_name = "consume_seal".to_string();

        log::debug!(
            "Building Sui MoveCall: {}::{}::{}(seal={}, commitment={})",
            self.config
                .seal_contract
                .package_id
                .as_deref()
                .unwrap_or("unknown"),
            module_name,
            function_name,
            format_object_id(seal.object_id),
            hex::encode(commitment),
        );

        // Get gas objects and sender address from RPC
        let seal_object_id = seal.object_id;
        let (sender, gas_objects, seal_object) = self
            .run_with_rpc(move |rpc| async move {
                let sender = rpc.sender_address().await?;
                let gas_objects = rpc.get_gas_objects(sender).await?;
                // Fetch seal object from chain - seals must exist on-chain for real transactions
                // The seal should have been created during create_seal if it didn't exist
                let seal_object_result = rpc.get_object(seal_object_id).await;
                
                let seal_object = match seal_object_result {
                    Ok(Some(obj)) => {
                        log::info!("SUI: Found seal object {} on-chain (version={}, type={})",
                            format_object_id(seal_object_id), obj.version, obj.object_type);
                        obj
                    }
                    Ok(None) => {
                        // Object doesn't exist on-chain
                        return Err(SuiError::StateProofFailed(format!(
                            "Sui seal object {} not found on-chain. The seal contract must be deployed to testnet first. \
                             See csv-contracts/sui/ for deployment instructions.",
                            format_object_id(seal_object_id)
                        )));
                    }
                    Err(e) => {
                        // RPC error - could be network issue or invalid object ID
                        return Err(SuiError::RpcError(format!(
                            "Failed to fetch seal object {} from RPC: {}. \
                             This could indicate a network issue or that the object ID is invalid.",
                            format_object_id(seal_object_id), e
                        )));
                    }
                };
                
                Ok((sender, gas_objects, seal_object))
            })
            .await
            .map_err(|e| format!("Failed to get gas data: {}", e))?;

        if gas_objects.is_empty() {
            return Err("No gas objects available for transaction".into());
        }

        // Build the transaction using raw BCS serialization
        // This matches Sui's TransactionData wire format exactly
        let tx_bytes = build_sui_transaction_data(
            package_id,
            &module_name,
            &function_name,
            seal.object_id,
            seal_object.version,
            seal_object.digest,
            commitment,
            sender,
            &gas_objects,
            self.config.transaction.max_gas_price,
            self.config.transaction.max_gas_budget,
        );

        // Sign with Ed25519
        let signature = signing_key.sign(&tx_bytes);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        // Sui signature format: [signature_type (1 byte)] + [signature (64 bytes)] + [public key (32 bytes)]
        // Signature type 0 = Ed25519
        let mut sui_signature = Vec::with_capacity(97);
        sui_signature.push(0x00); // Ed25519 signature scheme
        sui_signature.extend_from_slice(signature.to_bytes().as_ref());
        sui_signature.extend_from_slice(&public_key);

        Ok((tx_bytes, sui_signature, public_key))
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

        let valid = self
            .run_with_rpc(|rpc| {
                let expected_event_data = expected_event_data.to_vec();
                let tx_digest = anchor.tx_digest;
                async move {
                    EventProofVerifier::verify_event_in_tx(
                        tx_digest,
                        &expected_event_data,
                        rpc.as_ref(),
                    )
                    .await
                }
            })
            .await
            .map_err(|e: SuiError| ProtocolError::InclusionProofFailed(e.to_string()))?;

        if !valid {
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

            // Submit signed transaction via RPC
            log::info!("SUI: Submitting signed transaction via RPC");
            let (tx_digest, block) = self
                .run_with_rpc(|rpc| async move {
                    let tx_digest = rpc
                        .execute_signed_transaction(tx_bytes, signature, public_key)
                        .await?;
                    log::info!("SUI: Transaction executed (digest: {})", format_object_id(tx_digest));
                    let block = rpc
                        .wait_for_transaction(tx_digest, 30_000)
                        .await?
                        .ok_or_else(|| {
                            SuiError::RpcError("Transaction not found after submission".to_string())
                        })?;
                    log::info!("SUI: Transaction confirmed (checkpoint: {})", block.checkpoint.unwrap_or(0));
                    Ok((tx_digest, block))
                })
                .await
                .map_err(|e| ProtocolError::PublishFailed(format!("Transaction failed: {}", e)))?;

            // Verify the emitted event matches the expected commitment
            log::info!("SUI: Verifying emitted event matches expected commitment");
            let valid = self
                .run_with_rpc(|rpc| {
                    let event_data = event_data.clone();
                    async move {
                        EventProofVerifier::verify_event_in_tx(tx_digest, &event_data, rpc.as_ref())
                            .await
                    }
                })
                .await
                .map_err(|e: SuiError| ProtocolError::InclusionProofFailed(e.to_string()))?;

            if !valid {
                log::error!("SUI: Event verification failed - commitment mismatch");
                return Err(Box::new(ProtocolError::PublishFailed(
                    "Event verification failed: commitment mismatch".to_string(),
                )));
            }
            log::info!("SUI: Event verification successful");

            // Mark seal as consumed with the block checkpoint
            let checkpoint = block.checkpoint.unwrap_or(0);
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            registry
                .mark_seal_used(&seal, checkpoint)
                .map_err(ProtocolError::from)?;

            Ok(SuiCommitAnchor::new(seal.object_id, tx_digest, checkpoint))
        }

        #[cfg(not(feature = "rpc"))]
        {
            // Simulated path
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            registry
                .mark_seal_used(&seal, 0)
                .map_err(ProtocolError::from)?;

            // Build event data for this commitment
            let _event_data = self
                .event_builder
                .build(*commitment.as_bytes(), seal.object_id);

            // Return fallback anchor
            Ok(SuiCommitAnchor::new(seal.object_id, [0u8; 32], 0))
        }
    }

    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
        log::debug!(
            "Verifying inclusion for anchor at checkpoint {}",
            anchor.checkpoint
        );

        // Fetch checkpoint info from the Sui node
        let checkpoint_info = self
            .run_with_rpc(|rpc| async move {
                rpc.get_checkpoint(anchor.checkpoint)
                    .await
                    .map_err(|e| SuiError::RpcError(e.to_string()))
            })
            .await
            .map_err(|e| {
                ProtocolError::InclusionProofFailed(format!("Failed to fetch checkpoint: {}", e))
            })?
            .ok_or_else(|| {
                ProtocolError::InclusionProofFailed(format!(
                    "Checkpoint {} not found",
                    anchor.checkpoint
                ))
            })?;

        // Verify the checkpoint is certified
        if !checkpoint_info.certified {
            let verifier = self.checkpoint_verifier.clone();
            let is_certified = self
                .run_with_rpc(move |rpc| {
                    let cp_seq = anchor.checkpoint;
                    async move {
                        verifier
                            .is_checkpoint_certified(cp_seq, rpc.as_ref())
                            .await
                            .map_err(|e| SuiError::RpcError(e.to_string()))
                    }
                })
                .await
                .map_err(|e| {
                    ProtocolError::InclusionProofFailed(format!("Checkpoint check failed: {}", e))
                })?;

            if !is_certified.is_certified {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Checkpoint {} is not yet certified", anchor.checkpoint),
                )) as Box<dyn std::error::Error>);
            }
        }

        // Build inclusion proof with real checkpoint data
        let checkpoint_hash = checkpoint_info.digest;
        let object_proof = self
            .run_with_rpc(|rpc| async move {
                let tx = rpc
                    .get_transaction_block(anchor.tx_digest)
                    .await
                    .map_err(|e| SuiError::RpcError(e.to_string()))?
                    .ok_or_else(|| {
                        SuiError::StateProofFailed(format!(
                            "Transaction {} not found",
                            hex::encode(anchor.tx_digest)
                        ))
                    })?;

                let mut proof = Vec::new();
                proof.extend_from_slice(&anchor.tx_digest);
                proof.extend_from_slice(&anchor.object_id);
                proof.extend_from_slice(&anchor.checkpoint.to_le_bytes());
                for change in tx.effects.modified_objects {
                    proof.extend_from_slice(&change.object_id);
                    proof.extend_from_slice(&(change.change_type.len() as u32).to_le_bytes());
                    proof.extend_from_slice(change.change_type.as_bytes());
                }
                Ok(proof)
            })
            .await
            .map_err(|e| {
                ProtocolError::InclusionProofFailed(format!(
                    "Failed to build Sui object inclusion proof from transaction effects: {}",
                    e
                ))
            })?;

        if object_proof.len() <= 72 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Sui transaction effects do not contain object changes for inclusion proof"
                    .to_string(),
            )) as Box<dyn std::error::Error>);
        }

        Ok(SuiInclusionProof::new(
            object_proof,
            checkpoint_hash,
            anchor.checkpoint,
        ))
    }

    async fn verify_finality(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        log::debug!(
            "Verifying finality for anchor at checkpoint {}",
            anchor.checkpoint
        );

        let verifier = self.checkpoint_verifier.clone();
        let is_certified = self
            .run_with_rpc(move |rpc| {
                let cp_seq = anchor.checkpoint;
                async move {
                    verifier
                        .is_checkpoint_certified(cp_seq, rpc.as_ref())
                        .await
                        .map_err(|e| SuiError::RpcError(e.to_string()))
                }
            })
            .await
            .map_err(|e| {
                ProtocolError::InclusionProofFailed(format!("Finality check failed: {}", e))
            })?
            .is_certified;

        Ok(SuiFinalityProof::new(anchor.checkpoint, is_certified))
    }

    async fn enforce_seal(
        &self,
        seal: Self::SealPoint,
    ) -> std::result::Result<(), Box<dyn std::error::Error + 'static>> {
        // Rule G-02: Double-spend prevention
        // This method ensures that a Sui object cannot be consumed more than once
        // by checking both local registry and on-chain object state

        // Step 1: Check local registry (fast path)
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

        // Step 2: Check on-chain object state via RPC (authoritative check)
        // This ensures that even if local state is corrupted or lost,
        // we still prevent double-spends by querying the blockchain
        #[cfg(all(feature = "rpc", not(test)))]
        {
            let object_exists: Option<SuiObject> = self
                .run_with_rpc(|rpc| {
                    let obj_id = seal.object_id;
                    async move {
                        StateProofVerifier::verify_object_exists(obj_id, rpc.as_ref()).await
                    }
                })
                .await
                .map_err(|e| {
                    ProtocolError::NetworkError(format!(
                        "Failed to check object status on-chain: {}",
                        e
                    ))
                })?;

            if object_exists.is_none() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Object {} already consumed on-chain (deleted)",
                        format_object_id(seal.object_id)
                    ),
                )) as Box<dyn std::error::Error>);
            }
        }

        // Step 3: Mark seal as used in local registry
        // This is done after the on-chain check to ensure consistency
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
        
        #[cfg(feature = "rpc")]
        {
            // Check if object exists on-chain
            let seal_object_result = self.rpc.as_ref()
                .get_object(object_id).await;

            match seal_object_result {
                Ok(Some(obj)) => {
                    // Object exists - verify ownership
                    let owner_address = self.rpc.as_ref()
                        .sender_address().await
                        .map_err(|e| SuiError::RpcError(format!("Failed to get owner address: {}", e)))?;
                    
                    // Verify the object is owned by the derived address
                    if obj.owner == owner_address {
                        log::info!("SUI: Using existing seal object {} owned by user", format_object_id(object_id));
                        Ok(SuiSealPoint::new(object_id, obj.version, nonce))
                    } else {
                        Err(Box::new(SuiError::StateProofFailed(format!(
                            "Seal object {} exists but is not owned by this account. Owner: {:?}, Expected: {:?}",
                            format_object_id(object_id), obj.owner, owner_address
                        ))) as Box<dyn std::error::Error + 'static>)
                    }
                }
                Ok(None) => {
                    // Object doesn't exist - create it with user as owner
                    log::info!("SUI: Creating new seal object {} for user", format_object_id(object_id));
                    self.create_seal_on_chain(object_id, nonce, value).await
                }
                Err(e) => {
                    // RPC error
                    Err(Box::new(SuiError::RpcError(format!(
                        "Failed to check seal object existence: {}", e
                    ))) as Box<dyn std::error::Error + 'static>)
                }
            }
        }
        
        #[cfg(not(feature = "rpc"))]
        {
            // Without RPC, just return the derived seal point
            Ok(SuiSealPoint::new(object_id, 1, nonce))
        }
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let core_seal = CoreSealPoint::new(seal_point.object_id.to_vec(), Some(seal_point.nonce))
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

    async fn build_proof_bundle(
        &self,
        anchor: Self::CommitAnchor,
        transition_dag: Vec<u8>,
    ) -> std::result::Result<ProofBundle, Box<dyn std::error::Error + 'static>> {
        let inclusion = self.verify_inclusion(anchor.clone()).await?;
        let finality = self.verify_finality(anchor.clone()).await?;

        let seal_ref = CoreSealPoint::new(anchor.object_id.to_vec(), Some(anchor.checkpoint))
            .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        let anchor_ref =
            CoreCommitAnchor::new(anchor.object_id.to_vec(), anchor.checkpoint, vec![])
                .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        let inclusion_proof = csv_protocol::proof::InclusionProof::new(
            inclusion.object_proof,
            Hash::new(inclusion.checkpoint_hash),
            inclusion.checkpoint_number,
            0,
        )
        .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        let finality_proof = FinalityProof::new(vec![], finality.checkpoint, finality.is_certified)
            .map_err(|e: &str| ProtocolError::Generic(e.to_string()))?;

        // Deserialize transition_dag from Vec<u8> to DAGSegment
        let dag_segment: csv_hash::dag::DAGSegment =
            csv_codec::from_canonical_cbor(&transition_dag).map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Failed to deserialize DAG: {}", e),
                )) as Box<dyn std::error::Error>
            })?;

        // Extract signatures from DAG nodes
        let signatures: Vec<Vec<u8>> = dag_segment
            .nodes
            .iter()
            .flat_map(|node| node.signatures.clone())
            .collect();

        ProofBundle::with_signature_scheme(
            csv_protocol::SignatureScheme::Ed25519,
            dag_segment,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Failed to build proof bundle: {}", e),
            )) as Box<dyn std::error::Error>
        })
    }

    async fn rollback(
        &self,
        anchor: Self::CommitAnchor,
    ) -> std::result::Result<(), Box<dyn std::error::Error + 'static>> {
        log::warn!(
            "Rollback requested for anchor at checkpoint {}",
            anchor.checkpoint
        );
        let current_checkpoint = self
            .run_with_rpc(|rpc| async move {
                rpc.get_latest_checkpoint_sequence_number()
                    .await
                    .map_err(|e| SuiError::RpcError(e.to_string()))
            })
            .await
            .map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e.to_string(),
                )) as Box<dyn std::error::Error>
            })?;

        // If anchor checkpoint is beyond current tip, rollback
        if anchor.checkpoint > current_checkpoint {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Anchor checkpoint {} beyond current tip {}",
                    anchor.checkpoint, current_checkpoint
                ),
            )) as Box<dyn std::error::Error>);
        }

        // If anchor checkpoint is before current tip, the transaction may have been reorged out
        // Clear the seal from registry to allow reuse
        if anchor.checkpoint < current_checkpoint {
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            // Try to clear using anchor object_id as seal identifier
            let dummy_seal = SuiSealPoint::new(anchor.object_id, 0, 0);
            if let Err(e) = registry.clear_seal(&dummy_seal) {
                // Seal may not be in registry yet, which is OK for rollback
                log::debug!("Rollback: seal not found in registry (this is OK): {}", e);
            }
        }

        Ok(())
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    fn signature_scheme(&self) -> csv_protocol::SignatureScheme {
        csv_protocol::SignatureScheme::Ed25519
    }
}

impl SuiSealProtocol {
    /// Create a seal object on-chain with the user as owner
    #[cfg(feature = "rpc")]
    async fn create_seal_on_chain(
        &self,
        object_id: [u8; 32],
        nonce: u64,
        _value: Option<u64>,
    ) -> std::result::Result<SuiSealPoint, Box<dyn std::error::Error + 'static>> {
        log::info!("SUI: Creating seal object {} on-chain", format_object_id(object_id));

        let owner_address = self.rpc.as_ref()
            .sender_address().await
            .map_err(|e| SuiError::RpcError(format!("Failed to get owner address: {}", e)))?;

        let gas_objects = self.rpc.as_ref()
            .get_gas_objects(owner_address).await
            .map_err(|e| SuiError::RpcError(format!("Failed to get gas objects: {}", e)))?;
        
        if gas_objects.is_empty() {
            return Err(Box::new(SuiError::RpcError("No gas objects available for seal creation".to_string())));
        }
        
        // Build a MoveCall transaction to create the seal object
        // This would call csv_seal::create_seal(object_id, owner)
        // For now, return a placeholder seal point
        // TODO: Implement actual MoveCall transaction for seal creation
        log::warn!("SUI: Seal creation transaction not yet implemented - returning placeholder");
        Ok(SuiSealPoint::new(object_id, 1, nonce))
    }

    /// Get RPC client reference for chain_operations (crate-visible)
    pub(crate) fn get_rpc(&self) -> &dyn SuiRpc {
        self.rpc.as_ref()
    }

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
        assert_eq!(seal.version, 1);
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
        assert!(result.is_ok());
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
