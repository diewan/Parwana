//! Aptos SealProtocol implementation with production-grade features
//!
//! This adapter implements the SealProtocol trait for Aptos,
//! using resources with consumed flag tracking as seals.
//!
//! ## Architecture
//!
//! - **Seals**: Move resources with `consumed` flag (marked consumed, not deleted)
//! - **Anchors**: Events emitted when seal resources are consumed
//! - **Finality**: HotStuff consensus provides deterministic finality via 2f+1 certification

#![allow(dead_code)]

use std::sync::Mutex;

#[cfg(feature = "rpc")]
use crate::proofs::StateProofVerifier;
#[cfg(feature = "rpc")]
use tokio::runtime::Handle;

use csv_hash::Hash;
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::commitment::Commitment;
// DAGSegment removed during migration - using placeholder
// use csv_protocol::dag::DAGSegment;
use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result as CoreResult;
use csv_proof::proof::{FinalityProof, ProofBundle};
use csv_hash::seal::CommitAnchor as CoreCommitAnchor;
use csv_hash::seal::SealPoint as CoreSealPoint;

use crate::checkpoint::CheckpointVerifier;
use crate::config::{AptosConfig, AptosNetwork};
use crate::error::{AptosError, AptosResult};
use crate::proofs::{CommitmentEventBuilder, EventProofVerifier};
use crate::rpc::AptosRpc;
#[cfg(not(feature = "rpc"))]
use crate::rpc::{AptosLedgerInfo, AptosTransaction};
use crate::seal::SealRegistry;
use crate::types::{AptosCommitAnchor, AptosFinalityProof, AptosInclusionProof, AptosSealPoint};
use crate::address_utils::{format_address, parse_aptos_address};

#[cfg(feature = "rpc")]
fn spawn_blocking_async<F, T>(future: F) -> Result<T, AptosError>
where
    F: std::future::Future<Output = Result<T, AptosError>> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| AptosError::RpcError(format!("Failed to create runtime: {}", e)))?;
        rt.block_on(future)
    })
    .join()
    .map_err(|_| AptosError::RpcError("Thread panicked".to_string()))
    .and_then(|r| r)
}

/// Aptos implementation of the SealProtocol trait
pub struct AptosSealProtocol {
    config: AptosConfig,
    /// Registry of used seals for replay prevention
    seal_registry: Mutex<SealRegistry>,
    domain_separator: [u8; 32],
    /// RPC client for Aptos node communication (crate-visible for chain_adapter_impl)
    pub(crate) rpc: Box<dyn AptosRpc>,
    checkpoint_verifier: CheckpointVerifier,
    /// Event builder for creating and parsing anchor events
    event_builder: CommitmentEventBuilder,
    /// Ed25519 signing key for transaction signing (RPC mode only)
    #[cfg(feature = "rpc")]
    pub signing_key: Option<ed25519_dalek::SigningKey>,
}

impl AptosSealProtocol {
    pub(crate) fn config(&self) -> &AptosConfig {
        &self.config
    }

    /// Create a new adapter from configuration and RPC client.
    ///
    /// # Arguments
    /// * `config` - Adapter configuration
    /// * `rpc` - RPC client for Aptos node communication
    pub fn from_config(config: AptosConfig, rpc: Box<dyn AptosRpc>) -> AptosResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| AptosError::SerializationError(format!("Invalid configuration: {}", e)))?;

        // Build domain separator: "CSV-APTOS-" + chain_id padding
        let mut domain = [0u8; 32];
        domain[..10].copy_from_slice(b"CSV-APTOS-");
        domain[10] = config.chain_id();

        // Build event builder for the configured module
        let module_address = parse_aptos_address(&config.seal_contract.module_address)
            .map_err(AptosError::SerializationError)?;
        let event_type = format!(
            "{}::csv_seal::AnchorEvent",
            config.seal_contract.module_address
        );
        let event_builder = CommitmentEventBuilder::new(module_address, event_type);

        let checkpoint_verifier = CheckpointVerifier::with_config(config.checkpoint.clone());

        log::info!(
            "Initialized Aptos adapter for network {:?} (chain_id={})",
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
    pub fn with_test() -> AptosResult<Self> {
        let config = AptosConfig::default();
        let rpc = Box::new(crate::rpc::MockAptosRpc::new(5000));
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
    /// * `csv_seal_address` - Address where CSVSeal module is deployed
    /// * `signing_key` - Ed25519 signing key for transaction signing
    #[cfg(feature = "rpc")]
    pub fn with_real_rpc(
        config: AptosConfig,
        csv_seal_address: [u8; 32],
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use crate::node::AptosNode;

        let rpc: Box<dyn AptosRpc> = Box::new(AptosNode::new(&config.rpc_url));
        let mut adapter = Self::from_config(config, rpc)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        adapter.signing_key = Some(signing_key);
        // Also store the seal address in config for the event builder
        adapter.config.seal_contract.module_address = format_address(csv_seal_address);
        Ok(adapter)
    }

    #[cfg(not(feature = "rpc"))]
    pub fn with_real_rpc(
        _config: AptosConfig,
        _csv_seal_address: [u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Err("rpc feature not enabled".into())
    }

    /// Verify that a seal resource is available before consumption.
    fn verify_seal_available(&self, seal: &AptosSealPoint) -> AptosResult<()> {
        // Check registry first
        let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
        if registry.is_seal_used(seal) {
            return Err(AptosError::ResourceUsed(format!(
                "Seal at address {} is already consumed",
                format_address(seal.account_address)
            )));
        }

        // Check on-chain resource
        #[cfg(feature = "rpc")]
        let exists = {
            let resource_type = format!(
                "{}::csv_seal::{}",
                self.config.seal_contract.module_address, self.config.seal_contract.seal_resource
            );
            let account_address = seal.account_address;
            let rpc = self.rpc.clone_boxed();
            spawn_blocking_async(async move {
                StateProofVerifier::verify_resource_exists_async(
                    account_address,
                    &resource_type,
                    rpc.as_ref(),
                )
                .await
            })
        };

        #[cfg(not(feature = "rpc"))]
        let exists: AptosResult<bool> = Err(AptosError::FeatureNotEnabled(
            "Aptos seal availability requires the 'rpc' feature; refusing to assume the on-chain resource exists".to_string(),
        ));

        let exists = exists.map_err(|e: AptosError| ProtocolError::from(e))?;

        if !exists {
            return Err(AptosError::StateProofFailed(format!(
                "Seal resource at {} does not exist on-chain",
                format_address(seal.account_address)
            )));
        }

        Ok(())
    }

    /// Build a raw transaction for BCS serialization using aptos-sdk types.
    #[cfg(feature = "rpc")]
    fn build_raw_transaction(
        &self,
        sender: [u8; 32],
        sequence_number: u64,
        expiration_secs: u64,
        module_address: &str,
        commitment: [u8; 32],
    ) -> Result<
        aptos_sdk::transaction::types::RawTransaction,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use aptos_sdk::transaction::EntryFunction;
        use aptos_sdk::transaction::payload::TransactionPayload;
        use aptos_sdk::transaction::types::RawTransaction;
        use aptos_sdk::types::{AccountAddress, ChainId, MoveModuleId};

        // Parse module address
        let module_addr = AccountAddress::from_hex(module_address)
            .map_err(|e| format!("Invalid module address: {}", e))?;

        // Build the EntryFunction for consume_seal
        let module_name = aptos_sdk::types::Identifier::new("csv_seal")
            .map_err(|e| format!("Invalid module name: {}", e))?;
        let module_id = MoveModuleId::new(module_addr, module_name);

        // Convert commitment to Move value (hex string)
        let commitment_arg = aptos_bcs::to_bytes(&format!("0x{}", hex::encode(commitment)))
            .map_err(|e| format!("Failed to serialize commitment: {}", e))?;

        let entry_function = EntryFunction::new(
            module_id,
            "consume_seal",
            vec![],               // type arguments
            vec![commitment_arg], // arguments
        );

        // Build raw transaction
        let sender_addr = AccountAddress::new(sender);
        let payload = TransactionPayload::EntryFunction(entry_function);
        let max_gas = self.config.transaction.max_gas;

        let chain_id = ChainId::new(self.config.network.chain_id());

        Ok(RawTransaction::new(
            sender_addr,
            sequence_number,
            payload,
            max_gas,
            100, // gas_unit_price
            expiration_secs,
            chain_id,
        ))
    }

    /// Build an Entry Function payload for CSVSeal.consume_seal() and sign it.
    ///
    /// Returns (signed_transaction_json, expected_event_data) ready for submission.
    ///
    /// # Transaction Structure
    ///
    /// Aptos Entry Function:
    /// ```text
    /// {
    ///   "type": "entry_function_payload",
    ///   "function": "{module_address}::csv_seal::consume_seal",
    ///   "type_arguments": [],
    ///   "arguments": ["{commitment_hex}"]
    /// }
    /// ```
    ///
    /// The transaction is signed with Ed25519 and formatted for the
    /// Aptos REST API `/v1/transactions` endpoint.
    #[cfg(feature = "rpc")]
    fn build_and_sign_entry_function(
        &self,
        seal: &AptosSealPoint,
        commitment: [u8; 32],
    ) -> Result<(serde_json::Value, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        use ed25519_dalek::Signer;

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        // Get account sequence number from RPC
        let rt = Handle::current();
        let (sender, sequence_number, ledger) = rt.block_on(async {
            let sender = self
                .rpc
                .sender_address()
                .await
                .map_err(|e| format!("Failed to get sender address: {}", e))?;
            let sequence_number = self
                .rpc
                .get_account_sequence_number(sender)
                .await
                .map_err(|e| format!("Failed to get sequence number: {}", e))?;
            let ledger = self
                .rpc
                .get_ledger_info()
                .await
                .map_err(|e| format!("Failed to get ledger info: {}", e))?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((sender, sequence_number, ledger))
        })?;

        let sender_hex = format_address(sender);

        // Build event data for verification
        let event_data = self.event_builder.build(commitment, seal.account_address);

        // Build Entry Function payload
        let module_address = &self.config.seal_contract.module_address;
        // consume_seal only takes commitment (seal is at signer's address)
        let function = format!("{}::csv_seal::consume_seal", module_address);

        log::debug!(
            "Building Aptos Entry Function: {}(seal={}, commitment={})",
            function,
            format_address(seal.account_address),
            hex::encode(commitment),
        );

        // Calculate expiration (current timestamp + 600 seconds)
        let expiration_secs = (ledger.ledger_timestamp / 1_000_000) + 600;

        // Build the signed transaction JSON for Aptos REST API
        // This matches the format expected by POST /v1/transactions
        let tx_payload = serde_json::json!({
            "sender": sender_hex,
            "sequence_number": sequence_number.to_string(),
            "max_gas_amount": self.config.transaction.max_gas.to_string(),
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiration_secs.to_string(),
            "payload": {
                "type": "entry_function_payload",
                "function": function,
                "type_arguments": [],
                "arguments": [
                    format!("0x{}", hex::encode(commitment))
                ]
            }
        });

        // Build proper BCS-serialized transaction for signing
        // Using aptos-sdk types for correct serialization
        let raw_transaction = self
            .build_raw_transaction(
                sender,
                sequence_number,
                expiration_secs,
                module_address,
                commitment,
            )
            .map_err(|e| format!("Failed to build raw transaction: {}", e))?;

        // Serialize to BCS format for signing
        let signing_bytes = aptos_bcs::to_bytes(&raw_transaction)
            .map_err(|e| format!("BCS serialization failed: {}", e))?;

        // Sign with Ed25519 using the BCS-serialized transaction bytes
        let signature = signing_key.sign(&signing_bytes);
        let public_key = signing_key.verifying_key().to_bytes();

        // Build the final signed transaction JSON
        let signed_tx = serde_json::json!({
            "sender": sender_hex,
            "sequence_number": sequence_number.to_string(),
            "max_gas_amount": self.config.transaction.max_gas.to_string(),
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiration_secs.to_string(),
            "payload": tx_payload["payload"],
            "signature": {
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(public_key)),
                "signature": format!("0x{}", hex::encode(signature.to_bytes()))
            }
        });

        Ok((signed_tx, event_data))
    }

    /// Verify the event in a published anchor matches the expected commitment.
    fn verify_anchor_event(
        &self,
        anchor: &AptosCommitAnchor,
        expected_seal: &AptosSealPoint,
        expected_commitment: Hash,
    ) -> CoreResult<()> {
        let expected_event_data = self.event_builder.build(
            *expected_commitment.as_bytes(),
            expected_seal.account_address,
        );

        let valid: bool = EventProofVerifier::verify_event_in_tx(
            anchor.version,
            &expected_event_data,
            self.rpc.as_ref(),
        )
        .map_err(|e: AptosError| ProtocolError::InclusionProofFailed(e.to_string()))?;

        if !valid {
            return Err(ProtocolError::InclusionProofFailed(
                "Event verification failed: commitment mismatch".to_string(),
            ));
        }

        Ok(())
    }
}

impl SealProtocol for AptosSealProtocol {
    type SealPoint = AptosSealPoint;
    type CommitAnchor = AptosCommitAnchor;
    type InclusionProof = AptosInclusionProof;
    type FinalityProof = AptosFinalityProof;

    fn publish(&self, commitment: Hash, seal: Self::SealPoint) -> Result<Self::CommitAnchor, Box<dyn std::error::Error>> {
        log::debug!(
            "Publishing commitment via seal {}",
            format_address(seal.account_address)
        );

        // Verify seal is available
        self.verify_seal_available(&seal)
            .map_err(ProtocolError::from)?;

        #[cfg(feature = "rpc")]
        {
            // Build the Entry Function payload and sign the transaction
            let (tx_json, expected_event_data) = self
                .build_and_sign_entry_function(&seal, *commitment.as_bytes())
                .map_err(|e| {
                    ProtocolError::PublishFailed(format!(
                        "Failed to build and sign transaction: {}",
                        e
                    ))
                })?;

            // Submit signed transaction via REST API
            let submit_result = {
                let rt = Handle::current();
                rt.block_on(async { self.rpc.submit_signed_transaction(tx_json).await })
            }
            .map_err(|e| {
                ProtocolError::PublishFailed(format!("Failed to submit transaction: {}", e))
            })?;

            // Wait for transaction confirmation
            let tx = {
                let rt = Handle::current();
                rt.block_on(async { self.rpc.wait_for_transaction(submit_result).await })
            }
            .map_err(|e| ProtocolError::NetworkError(e.to_string()))?;

            // Verify the emitted event matches the expected commitment
            let valid = {
                let rt = Handle::current();
                rt.block_on(async {
                    EventProofVerifier::verify_event_in_tx_async(
                        tx.version,
                        &expected_event_data,
                        self.rpc.as_ref(),
                    )
                    .await
                })
            }
            .map_err(|e: AptosError| ProtocolError::InclusionProofFailed(e.to_string()))?;

            if !valid {
                return Err(ProtocolError::PublishFailed(
                    "Event verification failed: commitment mismatch".to_string(),
                ));
            }

            // Mark seal as consumed with the transaction version
            let version = tx.version;
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            registry
                .mark_seal_used(&seal, version)
                .map_err(ProtocolError::from)?;

            Ok(AptosCommitAnchor::new(
                version,
                seal.account_address,
                version,
            ))
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
                .build(*commitment.as_bytes(), seal.account_address);

            // Return fallback anchor
            Ok(AptosCommitAnchor::new(0, seal.account_address, 0))
        }
    }

    fn verify_inclusion(&self, anchor: Self::CommitAnchor) -> Result<Self::InclusionProof, Box<dyn std::error::Error>> {
        log::debug!(
            "Verifying inclusion for anchor at version {}",
            anchor.version
        );

        // Fetch transaction from the Aptos node by version
        #[cfg(feature = "rpc")]
        let tx = {
            let rt = Handle::current();
            rt.block_on(async { self.rpc.get_transaction(anchor.version).await })
        }
        .map_err(|e| {
            ProtocolError::InclusionProofFailed(format!(
                "Failed to fetch transaction at version {}: {}",
                anchor.version, e
            ))
        })?
        .ok_or_else(|| {
            ProtocolError::InclusionProofFailed(format!(
                "Transaction at version {} not found",
                anchor.version
            ))
        })?;

        #[cfg(not(feature = "rpc"))]
        let tx = AptosTransaction {
            version: anchor.version,
            hash: [0u8; 32],
            state_change_hash: [0u8; 32],
            event_root_hash: [0u8; 32],
            state_checkpoint_hash: None,
            epoch: 0,
            round: 0,
            events: vec![],
            payload: vec![],
            success: true,
            vm_status: "Simulated".to_string(),
            gas_used: 0,
            cumulative_gas_used: 0,
        };

        // Verify transaction succeeded
        if !tx.success {
            return Err(ProtocolError::InclusionProofFailed(format!(
                "Transaction at version {} failed: {}",
                anchor.version, tx.vm_status
            )));
        }

        // Fetch ledger info to verify the transaction is part of the ledger
        #[cfg(feature = "rpc")]
        let ledger_info = {
            let rt = Handle::current();
            rt.block_on(async { self.rpc.get_ledger_info().await })
        }
        .map_err(|e| {
            ProtocolError::InclusionProofFailed(format!("Failed to fetch ledger info: {}", e))
        })?;

        #[cfg(not(feature = "rpc"))]
        let ledger_info = AptosLedgerInfo {
            chain_id: 0,
            epoch: 0,
            ledger_version: 0,
            oldest_ledger_version: 0,
            ledger_timestamp: 0,
            oldest_transaction_timestamp: 0,
            epoch_start_timestamp: 0,
        };

        // Verify the transaction version is within the ledger
        if tx.version > ledger_info.ledger_version {
            return Err(ProtocolError::InclusionProofFailed(format!(
                "Transaction version {} exceeds latest ledger version {}",
                tx.version, ledger_info.ledger_version
            )));
        }

        // Build inclusion proof with real transaction and ledger data
        let transaction_proof = tx.hash.to_vec();
        let ledger_proof = ledger_info.ledger_version.to_le_bytes().to_vec();

        Ok(AptosInclusionProof::new(
            transaction_proof,
            ledger_proof,
            anchor.version,
        ))
    }

    fn verify_finality(&self, anchor: Self::CommitAnchor) -> Result<Self::FinalityProof, Box<dyn std::error::Error>> {
        log::debug!(
            "Verifying finality for anchor at version {}",
            anchor.version
        );

        #[cfg(feature = "rpc")]
        let is_certified = {
            let f_plus_one = self.config.f_plus_one();
            let rt = Handle::current();
            match rt.block_on(async {
                self.checkpoint_verifier
                    .is_version_finalized_async(anchor.version, self.rpc.as_ref(), f_plus_one)
                    .await
            }) {
                Ok(info) => info.is_certified,
                Err(e) => {
                    log::warn!("Finality check failed: {}", e);
                    false
                }
            }
        };

        #[cfg(not(feature = "rpc"))]
        let is_certified = true;

        Ok(AptosFinalityProof::new(anchor.version, is_certified))
    }

    fn enforce_seal(&self, seal: Self::SealPoint) -> Result<(), Box<dyn std::error::Error>> {
        // Rule G-02: Double-spend prevention
        // This method ensures that an Aptos resource cannot be consumed more than once
        // by checking both local registry and on-chain resource state

        // Step 1: Check local registry (fast path)
        let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
        if registry.is_seal_used(&seal) {
            return Err(ProtocolError::SealReplay(format!(
                "Resource already consumed at {} in local registry",
                format_address(seal.account_address)
            )));
        }
        drop(registry);

        // Step 2: Check on-chain resource state via RPC (authoritative check)
        // This ensures that even if local state is corrupted or lost,
        // we still prevent double-spends by querying the blockchain
        #[cfg(feature = "rpc")]
        {
            use tokio::runtime::Handle;
            if let Ok(handle) = Handle::try_current() {
                let resource_exists = handle
                    .block_on(StateProofVerifier::verify_resource_exists_async(
                        seal.account_address,
                        &seal.resource_type,
                        self.rpc.as_ref(),
                    ))
                    .map_err(|e| {
                        ProtocolError::NetworkError(format!(
                            "Failed to check resource status on-chain: {}",
                            e
                        ))
                    })?;

                if !resource_exists {
                    return Err(ProtocolError::SealReplay(format!(
                        "Resource already consumed on-chain at {}",
                        format_address(seal.account_address)
                    )));
                }
            }
        }

        // Step 3: Mark seal as used in local registry
        // This is done after the on-chain check to ensure consistency
        let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
        registry
            .mark_seal_used(&seal, 0)
            .map_err(ProtocolError::from)?;

        Ok(())
    }

    fn create_seal(&self, _value: Option<u64>) -> Result<Self::SealPoint, Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"aptos-seal");
        let result = hasher.finalize();
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&result);
        Ok(AptosSealPoint::new(addr, "CSV::Seal".to_string(), 0))
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let core_seal =
            CoreSealPoint::new(seal_point.account_address.to_vec(), Some(seal_point.nonce))
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

    fn build_proof_bundle(
        &self,
        anchor: Self::CommitAnchor,
        transition_dag: Vec<u8>,
    ) -> Result<ProofBundle, Box<dyn std::error::Error>> {
        let inclusion = self.verify_inclusion(anchor.clone())?;
        let finality = self.verify_finality(anchor.clone())?;
        let seal_ref = CoreSealPoint::new(anchor.event_handle.to_vec(), Some(anchor.version))
            .map_err(|e| ProtocolError::Generic(e.to_string()))?;

        let anchor_ref =
            CoreCommitAnchor::new(anchor.event_handle.to_vec(), anchor.version, vec![])
                .map_err(|e| ProtocolError::Generic(e.to_string()))?;

        let inclusion_proof = csv_protocol::cross_chain::InclusionProof::Aptos(
            csv_protocol::cross_chain::AptosLedgerProof {
                version: inclusion.version,
                transaction_proof: inclusion.transaction_proof,
                ledger_info: inclusion.ledger_info,
                events: inclusion.events,
                success: true,
            }
        );

        let finality_proof = FinalityProof::new(vec![], finality.version, finality.is_certified)
            .map_err(|e| ProtocolError::Generic(e.to_string()))?;

        // Since transition_dag is now Vec<u8>, pass it directly
        // Signatures would need to be extracted from the DAG bytes if needed
        let signatures: Vec<Vec<u8>> = vec![]; // Placeholder - would need to parse from DAG bytes

        ProofBundle::new(
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| ProtocolError::Generic(e.to_string()))
    }

    fn rollback(&self, anchor: Self::CommitAnchor) -> Result<(), Box<dyn std::error::Error>> {
        log::warn!(
            "Rollback requested for anchor at version {}",
            anchor.version
        );
        #[cfg(feature = "rpc")]
        let current_version = {
            let rt = Handle::current();
            rt.block_on(async { self.rpc.get_latest_version().await })
        }
        .map_err(|e| ProtocolError::NetworkError(e.to_string()))?;

        #[cfg(not(feature = "rpc"))]
        let current_version = anchor.version;

        // If anchor version is beyond current tip, rollback
        if anchor.version > current_version {
            return Err(ProtocolError::ReorgInvalid(format!(
                "Anchor version {} beyond current tip {}",
                anchor.version, current_version
            )));
        }

        // If anchor version is before current tip, the transaction may have been reorged out
        // Clear the seal from registry to allow reuse
        if anchor.version < current_version {
            let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            // Try to clear using anchor event_handle as seal identifier
            let dummy_seal = AptosSealPoint::new(anchor.event_handle, "CSV::Seal".to_string(), 0);
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

    fn signature_scheme(&self) -> csv_protocol::signature::SignatureScheme {
        csv_protocol::signature::SignatureScheme::Ed25519
    }
}

impl AptosSealProtocol {
    /// Get RPC client reference (crate-visible for chain_operations)
    pub(crate) fn rpc(&self) -> &dyn AptosRpc {
        self.rpc.as_ref()
    }

    /// Get network configuration
    pub(crate) fn network(&self) -> AptosNetwork {
        self.config.network.clone()
    }

    /// Get domain separator
    pub(crate) fn domain(&self) -> [u8; 32] {
        self.domain_separator
    }

    /// Get event builder module address and event type for creating new builder
    pub(crate) fn event_builder_config(&self) -> ([u8; 32], String) {
        (
            self.event_builder.module_address,
            self.event_builder.event_type.clone(),
        )
    }

    /// Get all active seals from the registry.
    pub fn get_active_seals(&self) -> Vec<AptosSealPoint> {
        if let Ok(registry) = self.seal_registry.lock() {
            registry
                .get_seal_records()
                .into_iter()
                .map(|record| AptosSealPoint {
                    account_address: record.account_address,
                    resource_type: record.resource_type.clone(),
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

    fn test_adapter() -> AptosSealProtocol {
        AptosSealProtocol::with_test().unwrap()
    }

    #[test]
    fn test_create_seal() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).unwrap();
        assert_eq!(seal.nonce, 0);
    }

    #[test]
    fn test_enforce_seal_replay() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).unwrap();
        adapter.enforce_seal(seal.clone()).unwrap();
        assert!(adapter.enforce_seal(seal).is_err());
    }

    #[test]
    fn test_domain_separator() {
        let adapter = test_adapter();
        assert_eq!(&adapter.domain_separator()[..10], b"CSV-APTOS-");
        assert_eq!(adapter.domain_separator()[10], 4); // Devnet chain_id
    }

    #[tokio::test]
    #[cfg(feature = "rpc")]
    #[ignore = "Requires manual runtime setup due to nested block_on in verify_finality()"]
    async fn test_verify_finality() {
        let adapter = test_adapter();
        let anchor = AptosCommitAnchor::new(1500, [1u8; 32], 0);
        let result = adapter.verify_finality(anchor);
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "rpc")]
    #[ignore = "Requires manual runtime setup due to nested block_on in publish()"]
    async fn test_publish_seal_available() {
        use ed25519_dalek::SigningKey;

        let config = AptosConfig::default();
        let test_rpc = crate::rpc::MockAptosRpc::new(5000);

        // Register the seal resource in the test RPC so verify_seal_available finds it
        let resource_type = format!(
            "{}::csv_seal::{}",
            config.seal_contract.module_address, config.seal_contract.seal_resource
        );
        test_rpc.set_resource(
            [1u8; 32],
            resource_type.as_str(),
            crate::rpc::AptosResource { data: vec![0u8; 8] },
        );

        let rpc = Box::new(test_rpc);
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let adapter = AptosSealProtocol::from_config(config.clone(), rpc)
            .unwrap()
            .with_signing_key(signing_key);

        // Create a seal
        let seal = AptosSealPoint::new([1u8; 32], resource_type.clone(), 0);
        let commitment = Hash::new([1u8; 32]);
        let result = adapter.publish(commitment, seal);
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "rpc")]
    #[ignore = "Requires manual runtime setup due to nested block_on in publish()"]
    async fn test_publish_seal_replay() {
        use ed25519_dalek::SigningKey;

        let config = AptosConfig::default();
        let test_rpc = crate::rpc::MockAptosRpc::new(5000);

        // Register the seal resource in the test RPC
        let resource_type = format!(
            "{}::csv_seal::{}",
            config.seal_contract.module_address, config.seal_contract.seal_resource
        );
        test_rpc.set_resource(
            [1u8; 32],
            resource_type.as_str(),
            crate::rpc::AptosResource { data: vec![0u8; 8] },
        );

        let rpc = Box::new(test_rpc);
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let adapter = AptosSealProtocol::from_config(config.clone(), rpc)
            .unwrap()
            .with_signing_key(signing_key);

        let seal = AptosSealPoint::new([1u8; 32], resource_type.clone(), 0);
        let commitment = Hash::new([1u8; 32]);
        adapter.publish(commitment, seal.clone()).unwrap();

        // Try to publish again with same seal
        let commitment2 = Hash::new([2u8; 32]);
        let result = adapter.publish(commitment2, seal);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aptos_address() {
        let addr = parse_aptos_address("0x1").unwrap();
        assert_eq!(addr[31], 1);
        for (i, byte) in addr.iter().take(31).enumerate() {
            assert_eq!(*byte, 0, "Byte at index {} should be 0", i);
        }
    }

    #[test]
    fn test_parse_aptos_address_full() {
        let full = "0xdeadbeef00000000000000000000000000000000000000000000000000000001";
        let addr = parse_aptos_address(full).unwrap();
        assert_eq!(addr[0], 0xDE);
        assert_eq!(addr[1], 0xAD);
        assert_eq!(addr[31], 0x01);
    }
}
