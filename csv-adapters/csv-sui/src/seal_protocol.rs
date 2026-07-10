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

use std::sync::Arc;
use tokio::sync::Mutex;

use async_trait::async_trait;
use blake2::Digest as Blake2Digest;
use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result as CoreResult;

#[cfg(feature = "rpc")]
// Return shape of `build_and_sign_move_call`, which is itself a retained seam.
#[allow(dead_code)]
type SignedTransaction = (Vec<u8>, Vec<u8>, Vec<u8>);
use csv_hash::Hash;
use csv_hash::seal::SealPoint as CoreSealPoint;
use csv_protocol::commitment::Commitment;
use csv_protocol::seal_protocol::SealProtocol;

use crate::checkpoint::{CheckpointVerifier, CheckpointVerifierTrait};
use crate::config::SuiConfig;
use crate::error::{SuiError, SuiResult};
use crate::node::SuiNode;
use crate::proofs::CommitmentEventBuilder;
use crate::seal::SealRegistry;
use crate::types::{SuiCommitAnchor, SuiFinalityProof, SuiInclusionProof, SuiSealPoint};

#[cfg(feature = "rpc")]
use sui_transaction_builder::TransactionBuilder;

#[cfg(feature = "rpc")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct CreatedSealObject {
    object_id: [u8; 32],
    version: u64,
    digest: String,
}

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

/// Preserve the SDK's canonical fields at the Sui transaction boundary.
fn canonical_creation_fields(sanad_id: Hash, commitment: Hash) -> ([u8; 32], [u8; 32]) {
    (*sanad_id.as_bytes(), *commitment.as_bytes())
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

        let checkpoint_verifier =
            CheckpointVerifier::with_config(config.checkpoint.clone(), Arc::clone(&node));

        // Extract signing key from config if available
        #[cfg(feature = "rpc")]
        let signing_key = if let Some(private_key) = &config.signer_private_key {
            let private_key_bytes = private_key.expose_secret();
            Some(ed25519_dalek::SigningKey::from_bytes(private_key_bytes))
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
        // Generate a test signing key
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let key_bytes = signing_key.to_bytes();

        let secret_key = csv_keys::memory::SecretKey::new(key_bytes);

        // Derive signer address from private key
        let key_bytes = secret_key.expose_secret();
        use blake2::Blake2b;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(key_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let signer_address = Some(format!("0x{}", hex::encode(hash)));

        let config = SuiConfig {
            seal_contract: crate::config::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            signer_private_key: Some(secret_key),
            signer_address,
            ..Default::default()
        };

        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443")?);
        Self::from_config(config, node)
    }

    /// Check if the adapter is ready for write operations.
    ///
    /// Returns true if signer_private_key is configured, false otherwise.
    /// Read operations (verification, queries) work without a signer,
    /// but write operations (create_seal, publish) require a signer.
    pub fn is_write_ready(&self) -> bool {
        #[cfg(feature = "rpc")]
        {
            self.signing_key.is_some()
        }
        #[cfg(not(feature = "rpc"))]
        {
            false
        }
    }

    /// Get the signer address if configured.
    ///
    /// Returns None if no signer is configured.
    pub fn signer_address(&self) -> Option<String> {
        self.config.signer_address.clone()
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

        let object = object_response
            .into_inner()
            .object
            .ok_or_else(|| SuiError::ObjectUsed("Object not found".to_string()))?;

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
        object
            .digest
            .ok_or_else(|| SuiError::ObjectUsed("Object digest not found".to_string()))
    }

    /// Compare a Move struct tag against the expected one, normalizing the
    /// leading package address so that `0xabc::m::T` and its zero-padded
    /// 32-byte form compare equal.
    #[cfg(feature = "rpc")]
    fn move_type_matches(actual: &str, expected: &str) -> bool {
        /// Sui may abbreviate a leading package address (`0x2::coin::Coin`), so
        /// widen to the canonical 32 bytes before comparing.
        fn normalize_address(address: &str) -> Option<[u8; 32]> {
            let hex_str = address.trim().trim_start_matches("0x");
            if hex_str.is_empty() || hex_str.len() > 64 {
                return None;
            }
            let padded = format!("{:0>64}", hex_str);
            let bytes = hex::decode(padded).ok()?;
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Some(out)
        }

        fn normalize(tag: &str) -> Option<([u8; 32], String)> {
            let (address, rest) = tag.split_once("::")?;
            if rest.is_empty() {
                return None;
            }
            Some((normalize_address(address)?, rest.to_ascii_lowercase()))
        }

        match (normalize(actual), normalize(expected)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Extract the seal object created by a `create_seal` transaction.
    ///
    /// Only a real created object write is accepted: a fabricated identifier
    /// derived from the transaction would name an object that does not exist,
    /// and `publish` would later fail trying to consume it. `expected_type` is
    /// the fully qualified `<package>::<module>::<type>` tag.
    ///
    /// `object_type` is supplied by the node's indexing layer rather than by the
    /// effects structure itself, so it may be absent. When it is present it must
    /// match exactly; when it is absent the created object must be unambiguous.
    #[cfg(feature = "rpc")]
    fn extract_created_seal_object(
        changed_objects: &[sui_rpc::proto::sui::rpc::v2::ChangedObject],
        expected_type: &str,
    ) -> Result<CreatedSealObject, String> {
        use sui_rpc::proto::sui::rpc::v2::changed_object::{
            IdOperation, InputObjectState, OutputObjectState,
        };

        let created: Vec<_> = changed_objects
            .iter()
            .filter(|changed_obj| {
                changed_obj.input_state == Some(InputObjectState::DoesNotExist as i32)
                    && changed_obj.output_state == Some(OutputObjectState::ObjectWrite as i32)
                    && changed_obj.id_operation == Some(IdOperation::Created as i32)
                    && changed_obj.object_id.is_some()
            })
            .collect();

        // Prefer the typed match when the node reports object types at all.
        // Falling back to the untyped set only when *no* candidate is typed
        // keeps a type-reporting node from silently accepting a wrong object.
        let any_typed = created.iter().any(|obj| obj.object_type.is_some());
        let candidates: Vec<_> = if any_typed {
            created
                .iter()
                .filter(|obj| {
                    obj.object_type
                        .as_ref()
                        .is_some_and(|actual| Self::move_type_matches(actual, expected_type))
                })
                .collect()
        } else {
            created.iter().collect()
        };

        let selected = match candidates.as_slice() {
            [only] => *only,
            [] => {
                return Err(format!(
                    "Sui create_seal transaction did not report a created {} object",
                    expected_type
                ));
            }
            many => {
                return Err(format!(
                    "Sui create_seal transaction reported {} created objects; \
                     cannot identify the {} seal unambiguously",
                    many.len(),
                    expected_type
                ));
            }
        };

        let obj_id_str = selected
            .object_id
            .as_ref()
            .expect("candidate filter requires object_id");
        let object_id = parse_object_id(obj_id_str)
            .map_err(|e| format!("Invalid created seal object ID: {}", e))?;

        let version = selected.output_version.ok_or_else(|| {
            format!(
                "Created seal object {} has no output version in effects",
                obj_id_str
            )
        })?;
        let digest = selected.output_digest.clone().ok_or_else(|| {
            format!(
                "Created seal object {} has no output digest in effects",
                obj_id_str
            )
        })?;
        if digest.trim().is_empty() {
            return Err(format!(
                "Created seal object {} has an empty output digest",
                obj_id_str
            ));
        }

        Ok(CreatedSealObject {
            object_id,
            version,
            digest,
        })
    }

    /// Verify that a seal object is available before consumption.
    async fn verify_seal_available(&self, seal: &SuiSealPoint) -> SuiResult<()> {
        log::info!(
            "SUI: verify_seal_available called for object {} with version {}",
            format_object_id(seal.object_id),
            seal.version
        );

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
            use tokio::time::{Duration, sleep};

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

                let object_response = (*client_guard).ledger_client().get_object(request).await;

                match object_response {
                    Ok(response) => {
                        let object = response
                            .into_inner()
                            .object
                            .ok_or_else(|| SuiError::ObjectUsed("Object not found".to_string()))?;

                        // Check if object exists - simplified since deleted field doesn't exist in proto
                        if object.object_id.is_none() {
                            if retries < max_retries {
                                retries += 1;
                                let delay = base_delay * 2_u32.pow(retries - 1);
                                log::info!(
                                    "SUI: Object not found, retry {} in {:?}",
                                    retries,
                                    delay
                                );
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

                        log::info!(
                            "SUI: Object {} verified as available on-chain",
                            format_object_id(seal.object_id)
                        );
                        break;
                    }
                    Err(e) => {
                        if retries < max_retries {
                            retries += 1;
                            let delay = base_delay * 2_u32.pow(retries - 1);
                            log::info!(
                                "SUI: Failed to get object: {}, retry {} in {:?}",
                                e,
                                retries,
                                delay
                            );
                            drop(client_guard);
                            sleep(delay).await;
                            continue;
                        } else {
                            return Err(SuiError::ObjectUsed(format!(
                                "Failed to get object after {} retries: {}",
                                max_retries, e
                            )));
                        }
                    }
                }
            }

            log::info!(
                "SUI: Object {} verified as available on-chain",
                format_object_id(seal.object_id)
            );
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
    /// Retained as the generic Move-call builder; `create_seal` and `publish` build
    /// their transactions inline against their own gas-object selection.
    #[allow(dead_code)]
    #[cfg(feature = "rpc")]
    async fn build_and_sign_move_call(
        &self,
        seal: &SuiSealPoint,
        commitment: [u8; 32],
    ) -> Result<SignedTransaction, Box<dyn std::error::Error + Send + Sync>> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::Address;

        let signing_key = self
            .signing_key
            .as_ref()
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
        let sender_address =
            Address::from_bytes(hash).map_err(|e| format!("Failed to derive address: {}", e))?;

        // Get the package ID from config
        let package_id_str = self
            .config
            .seal_contract
            .package_id
            .as_ref()
            .ok_or("Package ID not configured")?;
        let package_id_bytes =
            parse_object_id(package_id_str).map_err(|e| format!("Invalid package ID: {}", e))?;
        let package_id = Address::from_bytes(package_id_bytes)
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
            sui_sdk_types::Identifier::new(&module_name)
                .map_err(|e| format!("Invalid module name: {}", e))?,
            sui_sdk_types::Identifier::new(&function_name)
                .map_err(|e| format!("Invalid function name: {}", e))?,
        );
        let seal_digest = sui_sdk_types::Digest::from_base58(&seal.digest)
            .map_err(|e| format!("Invalid seal object digest: {}", e))?;
        let seal_object_arg = tx_builder.object(sui_transaction_builder::ObjectInput::owned(
            seal_object_id,
            seal.version,
            seal_digest,
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
    ///
    /// Kept as the anchor-event check; publish verifies via the runtime proof path.
    #[allow(dead_code)]
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

        let tx_digest = sui_sdk_types::Digest::from_bytes(anchor.tx_digest).map_err(|e| {
            ProtocolError::InclusionProofFailed(format!("Invalid tx digest: {}", e))
        })?;

        let request = GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| {
                ProtocolError::InclusionProofFailed(format!("Failed to get transaction: {}", e))
            })?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ProtocolError::InclusionProofFailed("Transaction not found in response".to_string())
        })?;

        // Check if the event exists in the transaction
        let tx_events = tx.events.as_ref().ok_or_else(|| {
            ProtocolError::InclusionProofFailed("Transaction has no events".to_string())
        })?;

        let event_found = tx_events.events.iter().any(|event| {
            let type_match = event
                .event_type
                .as_ref()
                .is_some_and(|t| t == &self.event_builder.event_type);
            let json_match = event.json.as_ref().is_some_and(|j| {
                // prost_types::Value doesn't implement serde::Serialize directly
                // Compare the struct type and kind for basic matching
                // A proper implementation would convert prost_types::Value to a comparable format
                j.kind.is_some()
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
        sanad_id: Hash,
    ) -> std::result::Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>> {
        log::info!(
            "SUI: Publishing commitment via seal object {}",
            format_object_id(seal.object_id)
        );
        log::info!(
            "SUI: Commitment hash: 0x{}",
            hex::encode(commitment.as_bytes())
        );

        // Verify seal is available
        log::info!("SUI: Verifying seal availability");
        self.verify_seal_available(&seal)
            .await
            .map_err(ProtocolError::from)?;
        log::info!("SUI: Seal verified as available");

        #[cfg(feature = "rpc")]
        {
            use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
            use sui_sdk_types::Address;

            // On Sui the commitment is anchored at seal creation:
            // `csv_seal::create_seal(sanad_id, commitment, owner)` writes both
            // fields into the Seal object and emits `SanadCreated`. Publishing
            // therefore VERIFIES that binding on-chain and anchors to the
            // creation transaction. It must NOT consume the seal — a consumed
            // seal can never be locked for a cross-chain transfer
            // (`lock_sanad` aborts with ESEAL_ALREADY_CONSUMED), which is the
            // Single-Use-Seal equivalent of burning a Bitcoin sanad's UTXO at
            // creation time.
            let object_id = Address::from_bytes(seal.object_id)
                .map_err(|e| format!("Invalid seal object ID: {}", e))?;

            let client = self.node.client();
            let mut client_guard = client.lock().await;

            let mut request = GetObjectRequest::new(&object_id);
            request.read_mask = Some(prost_types::FieldMask {
                paths: vec![
                    "object_id".to_string(),
                    "version".to_string(),
                    "contents".to_string(),
                    "previous_transaction".to_string(),
                ],
            });

            let object = (*client_guard)
                .ledger_client()
                .get_object(request)
                .await
                .map_err(|e| {
                    Box::new(ProtocolError::PublishFailed(format!(
                        "Failed to fetch seal object: {}",
                        e
                    ))) as Box<dyn std::error::Error + 'static>
                })?
                .into_inner()
                .object
                .ok_or_else(|| {
                    Box::new(ProtocolError::PublishFailed(
                        "Seal object not found on-chain".to_string(),
                    )) as Box<dyn std::error::Error + 'static>
                })?;

            let contents = object.contents.and_then(|bcs| bcs.value).ok_or_else(|| {
                Box::new(ProtocolError::PublishFailed(
                    "Sui RPC did not return Seal object contents".to_string(),
                )) as Box<dyn std::error::Error + 'static>
            })?;
            let view = crate::ops::SuiSealStateView::from_move_contents(contents.as_ref())
                .map_err(|e| {
                    Box::new(ProtocolError::PublishFailed(format!(
                        "Failed to decode Seal object: {}",
                        e
                    ))) as Box<dyn std::error::Error + 'static>
                })?;

            // Fail closed unless the on-chain object binds exactly this
            // (sanad_id, commitment) pair and is still in Created state.
            if view.sanad_id != sanad_id.as_bytes().to_vec() {
                return Err(Box::new(ProtocolError::PublishFailed(format!(
                    "Seal object binds sanad 0x{}, expected 0x{}",
                    hex::encode(&view.sanad_id),
                    hex::encode(sanad_id.as_bytes())
                ))));
            }
            if view.commitment != commitment {
                return Err(Box::new(ProtocolError::PublishFailed(format!(
                    "Seal object binds commitment 0x{}, expected 0x{}",
                    hex::encode(view.commitment.as_bytes()),
                    hex::encode(commitment.as_bytes())
                ))));
            }
            const SANAD_STATE_CREATED: u8 = 1;
            if view.state != SANAD_STATE_CREATED {
                return Err(Box::new(ProtocolError::PublishFailed(format!(
                    "Seal object is in state {}, expected Created ({})",
                    view.state, SANAD_STATE_CREATED
                ))));
            }

            // Anchor to the real creation transaction recorded on the object.
            let prev_tx = object.previous_transaction.ok_or_else(|| {
                Box::new(ProtocolError::PublishFailed(
                    "Sui RPC did not return the seal object's previous transaction".to_string(),
                )) as Box<dyn std::error::Error + 'static>
            })?;
            let digest_array = crate::rpc_utils::tx_digest_to_bytes(&prev_tx).map_err(|e| {
                Box::new(ProtocolError::PublishFailed(format!(
                    "Invalid creation transaction digest: {}",
                    e
                ))) as Box<dyn std::error::Error + 'static>
            })?;

            log::info!(
                "SUI: Seal object verified on-chain; anchored to creation tx 0x{}",
                hex::encode(digest_array)
            );

            Ok(SuiCommitAnchor {
                object_id: seal.object_id,
                tx_digest: digest_array,
                checkpoint: object.version.unwrap_or(0),
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

        let tx_digest = sui_sdk_types::Digest::from_bytes(anchor.tx_digest).map_err(|e| {
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
                Box::new(std::io::Error::other(format!(
                    "Failed to get transaction: {}",
                    e
                ))) as Box<dyn std::error::Error>
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
        self.verify_seal_available(&seal)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

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
        canonical_sanad_id: Hash,
        canonical_commitment: Hash,
    ) -> std::result::Result<Self::SealPoint, Box<dyn std::error::Error + 'static>> {
        #[cfg(feature = "rpc")]
        {
            use ed25519_dalek::Signer;
            use sui_sdk_types::{Address, Identifier};

            let signing_key = self
                .signing_key
                .as_ref()
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
            let sender_address = Address::from_bytes(hash)
                .map_err(|e| format!("Failed to derive address: {}", e))?;

            // Get the package ID from config
            let package_id_str = self
                .config
                .seal_contract
                .package_id
                .as_ref()
                .ok_or("Package ID not configured")?;
            let package_id_bytes = parse_object_id(package_id_str)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let package_id = Address::from_bytes(package_id_bytes)
                .map_err(|e| format!("Invalid package ID: {}", e))?;
            let module_name = self.config.seal_contract.module_name.clone();

            // Fetch gas objects for the sender address, together with a
            // commitment to the exact on-chain coins being consumed.
            let (gas_objects, gas_ref_digest) =
                crate::gas_utils::fetch_gas_objects_with_digest(&self.node, &sender_address)
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
                Identifier::new("create_seal")
                    .map_err(|e| format!("Invalid function name: {}", e))?,
            );

            // The SDK derives the owner-bound identity before any chain write.
            // The on-chain SanadCreated footprint must use exactly those values;
            // an adapter-local gas/time derivation creates a different Sanad.
            let (sanad_id, commitment) =
                canonical_creation_fields(canonical_sanad_id, canonical_commitment);

            log::info!("SUI: Canonical sanad_id 0x{}", hex::encode(sanad_id));
            log::info!("SUI: Canonical commitment 0x{}", hex::encode(commitment));
            log::debug!(
                "SUI: creation gas-reference binding: 0x{}",
                hex::encode(gas_ref_digest)
            );

            let sanad_id_vec = sanad_id.to_vec();
            let commitment_vec = commitment.to_vec();

            // Argument list must match `csv_seal::create_seal(sanad_id,
            // commitment, owner, &mut TxContext)`. `state_root` and `nonce` are
            // derived inputs the Move entry point does not take: `state_root`
            // already commits into `sanad_id`/`commitment` via
            // `derive_seal_inputs`, and `nonce` is carried on the local
            // `SuiSealPoint`.
            let sanad_id_arg = tx_builder.pure(&sanad_id_vec);
            let commitment_arg = tx_builder.pure(&commitment_vec);
            let owner_arg = tx_builder.pure(&sender_address);
            let seal_result =
                tx_builder.move_call(function, vec![sanad_id_arg, commitment_arg, owner_arg]);

            // Transfer the returned Seal object to the sender
            let address_arg = tx_builder.pure(&sender_address);
            tx_builder.transfer_objects(vec![seal_result], address_arg);

            // Build the transaction data
            let tx_data = tx_builder
                .try_build()
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
            use sui_rpc::proto::sui::rpc::v2::{
                ExecuteTransactionRequest, Transaction, UserSignature,
            };
            use sui_sdk_types::SimpleSignature;

            // Convert the transaction data to sui-sdk-types Transaction
            // The bcs field expects Bcs type
            let mut sui_transaction = Transaction::default();
            sui_transaction.bcs = Some(tx_bytes.clone().into());

            // Build the UserSignature using sui-sdk-types SimpleSignature
            // This properly BCS-encodes the signature with the correct structure
            let pubkey_bytes = public_key.as_bytes().to_vec();
            let sig_array: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|e| format!("Invalid signature bytes: {:?}", e))?;
            let pubkey_array: [u8; 32] = pubkey_bytes
                .try_into()
                .map_err(|e| format!("Invalid public key bytes: {:?}", e))?;
            let simple_sig = SimpleSignature::Ed25519 {
                signature: sig_array.into(),
                public_key: pubkey_array.into(),
            };
            let sig_bcs = bcs::to_bytes(&simple_sig)
                .map_err(|e| format!("Failed to serialize signature: {}", e))?;
            let mut user_signature = UserSignature::default();
            user_signature.bcs = Some(sig_bcs.into());

            // Build the ExecuteTransactionRequest. The read mask is required:
            // without it the service returns only `effects.status,checkpoint`,
            // so `changed_objects` would come back empty and the created seal
            // object could not be identified.
            let mut execute_request = ExecuteTransactionRequest::default();
            execute_request.transaction = Some(sui_transaction);
            execute_request.signatures = vec![user_signature];
            execute_request.read_mask = Some(crate::rpc_utils::execution_read_mask());

            // Execute the transaction
            let execution_response = (*client_guard)
                .execution_client()
                .execute_transaction(execute_request)
                .await
                .map_err(|e| format!("Failed to execute transaction: {}", e))?;

            let executed_tx = execution_response
                .into_inner()
                .transaction
                .ok_or("No transaction in response")?;
            drop(client_guard);

            log::info!(
                "SUI: Executed transaction response - digest: {:?}, checkpoint: {:?}",
                executed_tx.digest,
                executed_tx.checkpoint
            );
            log::info!(
                "SUI: Transaction effects present: {}",
                executed_tx.effects.is_some()
            );
            let created_seal = if let Some(effects) = executed_tx.effects {
                log::info!("SUI: Effects status: {:?}", effects.status);
                // A reverted create_seal must never yield a seal point.
                crate::rpc_utils::ensure_execution_succeeded(&effects)?;

                log::info!(
                    "SUI: changed_objects count: {}",
                    effects.changed_objects.len()
                );
                for (idx, changed_obj) in effects.changed_objects.iter().enumerate() {
                    log::info!(
                        "SUI: changed_objects[{}]: object_id={:?}, input_state={:?}, output_state={:?}, id_operation={:?}, object_type={:?}, output_version={:?}, output_digest={:?}",
                        idx,
                        changed_obj.object_id,
                        changed_obj.input_state,
                        changed_obj.output_state,
                        changed_obj.id_operation,
                        changed_obj.object_type,
                        changed_obj.output_version,
                        changed_obj.output_digest
                    );
                }

                // Bind the expected type to the configured package: a suffix
                // match would also accept `<other-package>::csv_seal::Seal`.
                let expected_type = format!(
                    "0x{}::{}::{}",
                    hex::encode(package_id_bytes),
                    self.config.seal_contract.module_name,
                    self.config.seal_contract.seal_type
                );
                Self::extract_created_seal_object(&effects.changed_objects, &expected_type)?
            } else {
                return Err("No transaction effects in create_seal response".into());
            };

            // Deterministic nonce: reuse the value-derived nonce computed above.
            // Never introduce wall-clock entropy here (SUI-CREATE-SEAL-STATE-001).
            let nonce = value.unwrap_or(0);

            log::info!(
                "SUI: Created seal object {} with version {} on-chain",
                format_object_id(created_seal.object_id),
                created_seal.version
            );
            log::info!(
                "SUI: Storing digest in SuiSealPoint: '{}'",
                created_seal.digest
            );

            Ok(SuiSealPoint {
                object_id: created_seal.object_id,
                version: created_seal.version,
                digest: created_seal.digest,
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
        let core_seal = CoreSealPoint::new(
            seal_point.object_id.to_vec(),
            Some(seal_point.version),
            Some(seal_point.version),
        )
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
    async fn build_proof_bundle(
        &self,
        anchor: Self::CommitAnchor,
        _extra_data: csv_protocol::seal_protocol::DagSegment,
    ) -> Result<csv_protocol::proof_taxonomy::ProofBundle, Box<dyn std::error::Error + 'static>>
    {
        use csv_hash::Hash;
        use csv_hash::dag::DAGSegment;
        use csv_hash::seal::{CommitAnchor, SealPoint};
        use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof, ProofBundle};

        // Get transaction to extract checkpoint hash for inclusion proof
        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let tx_digest = sui_sdk_types::Digest::from_bytes(anchor.tx_digest).map_err(|e| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid tx digest: {}", e),
            )) as Box<dyn std::error::Error + 'static>
        })?;

        let request = sui_rpc::proto::sui::rpc::v2::GetTransactionRequest::new(&tx_digest);

        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| {
                Box::new(std::io::Error::other(format!(
                    "Failed to get transaction: {}",
                    e
                ))) as Box<dyn std::error::Error + 'static>
            })?;

        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Transaction not found".to_string(),
            )) as Box<dyn std::error::Error + 'static>
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
        )
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + 'static>)?;

        // Build finality proof by checking if checkpoint is certified
        let is_certified = self
            .checkpoint_verifier
            .is_checkpoint_certified(anchor.checkpoint)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + 'static>)?;

        let finality_proof = FinalityProof::new(
            vec![], // Sui uses checkpoint certification signatures
            anchor.checkpoint,
            is_certified.is_finalized(),
        )
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + 'static>)?;

        // Build DAG segment (empty for Sui as it doesn't use DAG-based consensus)
        let dag_segment = DAGSegment::new(vec![], Hash::zero());

        // Build seal point from SuiCommitAnchor
        let seal_point = SealPoint::new(anchor.object_id.to_vec(), Some(anchor.checkpoint), None)
            .map_err(|e| {
            Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + 'static>
        })?;

        // Build commit anchor from SuiCommitAnchor
        let commit_anchor = CommitAnchor::new(
            anchor.tx_digest.to_vec(),
            anchor.checkpoint,
            vec![], // Additional data (empty for now)
        )
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + 'static>)?;

        // Build the proof bundle
        ProofBundle::new(
            dag_segment,
            vec![], // Additional proofs (empty for now)
            seal_point,
            commit_anchor,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + 'static>)
    }

    #[cfg(not(feature = "rpc"))]
    async fn build_proof_bundle(
        &self,
        _anchor: Self::CommitAnchor,
        _extra_data: csv_protocol::seal_protocol::DagSegment,
    ) -> Result<csv_protocol::proof_taxonomy::ProofBundle, Box<dyn std::error::Error + 'static>>
    {
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

    #[test]
    fn creation_fields_are_the_sdk_canonical_values() {
        let sanad_id = Hash::new([0x11; 32]);
        let commitment = Hash::new([0x22; 32]);
        let (encoded_id, encoded_commitment) = canonical_creation_fields(sanad_id, commitment);

        assert_eq!(encoded_id, [0x11; 32]);
        assert_eq!(encoded_commitment, [0x22; 32]);
        assert_ne!(encoded_id, encoded_commitment);
    }

    #[tokio::test]
    #[ignore = "Requires funded SUI address for gas objects"]
    async fn test_create_seal() {
        let adapter = test_adapter();
        let seal = adapter
            .create_seal(
                None,
                csv_hash::Hash::new([0x11; 32]),
                csv_hash::Hash::new([0x22; 32]),
            )
            .await
            .unwrap();
        assert_eq!(seal.version, 0);
    }

    #[tokio::test]
    #[ignore = "Requires funded SUI address for gas objects"]
    async fn test_enforce_seal_replay() {
        let adapter = test_adapter();
        let seal = adapter
            .create_seal(
                None,
                csv_hash::Hash::new([0x11; 32]),
                csv_hash::Hash::new([0x22; 32]),
            )
            .await
            .unwrap();
        adapter.enforce_seal(seal.clone()).await.unwrap();
        assert!(adapter.enforce_seal(seal).await.is_err());
    }

    #[tokio::test]
    async fn test_domain_separator() {
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

    #[tokio::test]
    async fn test_write_readiness_with_signer() {
        let adapter = test_adapter();
        // Adapter created with signer should be write-ready
        assert!(adapter.is_write_ready());
        // Signer address should be present
        assert!(adapter.signer_address().is_some());
    }

    #[tokio::test]
    async fn test_write_readiness_without_signer() {
        // Create adapter without signer
        let config = SuiConfig {
            seal_contract: crate::config::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            signer_private_key: None, // No signer
            signer_address: None,
            ..Default::default()
        };

        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let adapter = SuiSealProtocol::from_config(config, node).unwrap();

        // Adapter without signer should not be write-ready
        assert!(!adapter.is_write_ready());
        // Signer address should be None
        assert!(adapter.signer_address().is_none());
    }

    #[tokio::test]
    async fn test_create_seal_fails_without_signer() {
        // Create adapter without signer
        let config = SuiConfig {
            seal_contract: crate::config::SealContractConfig {
                package_id: Some(
                    "0x0000000000000000000000000000000000000000000000000000000000000002"
                        .to_string(),
                ),
                ..Default::default()
            },
            signer_private_key: None, // No signer
            signer_address: None,
            ..Default::default()
        };

        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let adapter = SuiSealProtocol::from_config(config, node).unwrap();

        // create_seal should fail with SigningKeyNotConfigured error
        let result = adapter
            .create_seal(
                None,
                csv_hash::Hash::new([0x11; 32]),
                csv_hash::Hash::new([0x22; 32]),
            )
            .await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Signing key not configured") || error_msg.contains("signer"));
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

    #[cfg(feature = "rpc")]
    fn changed_object(
        object_id: Option<String>,
        input_state: sui_rpc::proto::sui::rpc::v2::changed_object::InputObjectState,
        output_state: sui_rpc::proto::sui::rpc::v2::changed_object::OutputObjectState,
        id_operation: sui_rpc::proto::sui::rpc::v2::changed_object::IdOperation,
        object_type: Option<String>,
        output_digest: Option<String>,
    ) -> sui_rpc::proto::sui::rpc::v2::ChangedObject {
        let mut changed = sui_rpc::proto::sui::rpc::v2::ChangedObject::default();
        changed.object_id = object_id;
        changed.input_state = Some(input_state as i32);
        changed.output_state = Some(output_state as i32);
        changed.output_version = Some(7);
        changed.output_digest = output_digest;
        changed.id_operation = Some(id_operation as i32);
        changed.object_type = object_type;
        changed
    }

    /// Fully qualified tag of the seal type under package `0xab..ab`.
    #[cfg(feature = "rpc")]
    fn expected_seal_type() -> String {
        format!("0x{}::csv_seal::Seal", hex::encode([0xabu8; 32]))
    }

    #[cfg(feature = "rpc")]
    fn seal_write(object_type: Option<String>, digest: Option<String>) -> ChangedObject {
        use sui_rpc::proto::sui::rpc::v2::changed_object::{
            IdOperation, InputObjectState, OutputObjectState,
        };
        changed_object(
            Some(format!("0x{}", hex::encode([9u8; 32]))),
            InputObjectState::DoesNotExist,
            OutputObjectState::ObjectWrite,
            IdOperation::Created,
            object_type,
            digest,
        )
    }

    #[cfg(feature = "rpc")]
    use sui_rpc::proto::sui::rpc::v2::ChangedObject;

    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_selects_created_object_write() {
        use sui_rpc::proto::sui::rpc::v2::changed_object::{
            IdOperation, InputObjectState, OutputObjectState,
        };

        let changed_objects = vec![
            changed_object(
                Some(format!("0x{}", hex::encode([1u8; 32]))),
                InputObjectState::DoesNotExist,
                OutputObjectState::PackageWrite,
                IdOperation::Created,
                Some("csv_seal::Package".to_string()),
                Some("package-digest".to_string()),
            ),
            seal_write(Some(expected_seal_type()), Some("seal-digest".to_string())),
        ];

        let created =
            SuiSealProtocol::extract_created_seal_object(&changed_objects, &expected_seal_type())
                .unwrap();

        assert_eq!(created.object_id, [9u8; 32]);
        assert_eq!(created.version, 7);
        assert_eq!(created.digest, "seal-digest");
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_rejects_missing_digest() {
        let changed_objects = vec![seal_write(Some(expected_seal_type()), None)];

        let err =
            SuiSealProtocol::extract_created_seal_object(&changed_objects, &expected_seal_type())
                .expect_err("missing digest must not produce a seal point");

        assert!(err.contains("has no output digest"), "unexpected: {}", err);
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_rejects_empty_digest() {
        let changed_objects = vec![seal_write(
            Some(expected_seal_type()),
            Some("  ".to_string()),
        )];

        let err =
            SuiSealProtocol::extract_created_seal_object(&changed_objects, &expected_seal_type())
                .expect_err("empty digest must not produce a seal point");

        assert!(err.contains("empty output digest"), "unexpected: {}", err);
    }

    /// The seal type must be bound to the configured package: a suffix match
    /// would also accept an identically named type from a foreign package.
    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_rejects_foreign_package_type() {
        let foreign = format!("0x{}::csv_seal::Seal", hex::encode([0xcdu8; 32]));
        let changed_objects = vec![seal_write(Some(foreign), Some("seal-digest".to_string()))];

        let err =
            SuiSealProtocol::extract_created_seal_object(&changed_objects, &expected_seal_type())
                .expect_err("foreign package type must be rejected");

        assert!(
            err.contains("did not report a created"),
            "unexpected: {}",
            err
        );
    }

    /// A node that reports no object types at all must still yield the seal,
    /// but only when the created object is unambiguous.
    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_allows_untyped_single_created_object() {
        let changed_objects = vec![seal_write(None, Some("seal-digest".to_string()))];

        let created =
            SuiSealProtocol::extract_created_seal_object(&changed_objects, &expected_seal_type())
                .unwrap();

        assert_eq!(created.object_id, [9u8; 32]);
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_rejects_ambiguous_untyped_creates() {
        use sui_rpc::proto::sui::rpc::v2::changed_object::{
            IdOperation, InputObjectState, OutputObjectState,
        };

        let changed_objects = vec![
            seal_write(None, Some("seal-digest".to_string())),
            changed_object(
                Some(format!("0x{}", hex::encode([8u8; 32]))),
                InputObjectState::DoesNotExist,
                OutputObjectState::ObjectWrite,
                IdOperation::Created,
                None,
                Some("other-digest".to_string()),
            ),
        ];

        let err =
            SuiSealProtocol::extract_created_seal_object(&changed_objects, &expected_seal_type())
                .expect_err("ambiguous creates must not produce a seal point");

        assert!(err.contains("unambiguously"), "unexpected: {}", err);
    }

    /// Empty effects (what the node returns when no read mask requests
    /// `changed_objects`) must fail rather than fabricate an object id.
    #[cfg(feature = "rpc")]
    #[test]
    fn created_seal_extraction_rejects_empty_changed_objects() {
        let err = SuiSealProtocol::extract_created_seal_object(&[], &expected_seal_type())
            .expect_err("empty effects must not produce a seal point");

        assert!(
            err.contains("did not report a created"),
            "unexpected: {}",
            err
        );
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn move_type_matches_normalizes_abbreviated_addresses() {
        assert!(SuiSealProtocol::move_type_matches(
            "0x2::coin::Coin",
            "0x0000000000000000000000000000000000000000000000000000000000000002::coin::Coin",
        ));
        assert!(!SuiSealProtocol::move_type_matches(
            "0x3::coin::Coin",
            "0x2::coin::Coin",
        ));
        // A suffix match must not be mistaken for a package-bound match.
        assert!(!SuiSealProtocol::move_type_matches(
            "0x2::evil_csv_seal::Seal",
            "0x2::csv_seal::Seal",
        ));
        assert!(!SuiSealProtocol::move_type_matches(
            "not-a-tag",
            "0x2::a::B"
        ));
    }

    #[tokio::test]
    #[ignore = "Requires funded SUI address for gas objects"]
    async fn test_seal_registry_replay() {
        let adapter = test_adapter();
        let seal = adapter
            .create_seal(
                None,
                csv_hash::Hash::new([0x11; 32]),
                csv_hash::Hash::new([0x22; 32]),
            )
            .await
            .unwrap();

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
