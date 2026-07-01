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

use async_trait::async_trait;
use std::sync::Mutex;
use tokio::runtime::Handle;

#[cfg(feature = "rpc")]
use crate::proofs::StateProofVerifier;

use csv_hash::Hash;
use csv_protocol::commitment::Commitment;
use csv_protocol::seal_protocol::SealProtocol;
// DAGSegment removed during migration - using placeholder
// use csv_protocol::dag::DAGSegment;
use csv_hash::seal::CommitAnchor as CoreCommitAnchor;
use csv_hash::seal::SealPoint as CoreSealPoint;
use csv_protocol::error::ProtocolError;
use csv_protocol::error::Result as CoreResult;
use csv_protocol::proof_taxonomy::{FinalityProof, ProofBundle};

use crate::address_utils::{format_address, parse_aptos_address};
use crate::checkpoint::CheckpointVerifier;
use crate::config::{AptosConfig, AptosNetwork};
use crate::error::{AptosError, AptosResult};
use crate::proofs::{CommitmentEventBuilder, EventProofVerifier};
use crate::rpc::AptosRpc;
#[cfg(not(feature = "rpc"))]
use crate::rpc::{AptosLedgerInfo, AptosTransaction};
use crate::rpc::{AptosLedgerReader, AptosTransactionReader, AptosTransactionSubmitter};
use crate::seal::SealRegistry;
use crate::types::{AptosCommitAnchor, AptosFinalityProof, AptosInclusionProof, AptosSealPoint};

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
            "{}::CSVSeal::AnchorEvent",
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

    /// Create a new adapter with real RPC and signing key from hex (requires `rpc` feature).
    ///
    /// # Arguments
    /// * `config` - Adapter configuration
    /// * `rpc_url` - RPC endpoint URL
    /// * `private_key_hex` - Hex-encoded Ed25519 private key (with or without 0x prefix)
    #[cfg(feature = "rpc")]
    pub fn with_rpc_and_signing_key(
        config: AptosConfig,
        rpc_url: &str,
        private_key_hex: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use crate::node::AptosNode;
        use sha3::{Digest, Sha3_256};

        // Parse private key
        let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        if private_key_bytes.len() != 32 {
            return Err("Private key must be 32 bytes".into());
        }
        let key_array: [u8; 32] = private_key_bytes.clone().try_into().map_err(|_| "Failed to parse private key")?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);

        // Derive Aptos account address from signing key
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00); // Ed25519 single key scheme
        let hash = Sha3_256::digest(&data);
        let mut sender_address = [0u8; 32];
        sender_address.copy_from_slice(&hash[..32]);

        // Create RPC client with signer address
        let rpc: Box<dyn AptosRpc> = Box::new(AptosNode::with_signer_address(rpc_url, sender_address));

        // Create seal protocol and attach signing key
        let mut seal = Self::from_config(config, rpc)?;
        seal.signing_key = Some(signing_key);
        // Also store private key in config for readiness check
        let key_array: [u8; 32] = private_key_bytes.try_into().unwrap();
        seal.config.private_key = Some(csv_keys::memory::SecretKey::new(key_array));
        Ok(seal)
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
        use sha3::{Digest, Sha3_256};

        // Derive Aptos account address from signing key
        // Aptos authentication key = SHA3-256(public_key || 0x00)
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00); // Ed25519 single key scheme
        let hash = Sha3_256::digest(&data);
        let mut sender_address = [0u8; 32];
        sender_address.copy_from_slice(&hash[..32]);

        let rpc: Box<dyn AptosRpc> = Box::new(AptosNode::with_signer_address(
            &config.rpc_url,
            sender_address,
        ));
        let mut adapter = Self::from_config(config, rpc)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        // Also store private key in config for readiness check
        let key_array = signing_key.to_bytes();
        adapter.config.private_key = Some(csv_keys::memory::SecretKey::new(key_array));
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
    pub async fn verify_seal_available(&self, seal: &AptosSealPoint) -> AptosResult<()> {
        // Check registry first
        {
            let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.is_seal_used(seal) {
                return Err(AptosError::ResourceUsed(format!(
                    "Seal at address {} is already consumed",
                    format_address(seal.account_address)
                )));
            }
        }

        // Check on-chain resource existence via RPC
        #[cfg(feature = "rpc")]
        let exists = {
            // Verify seal resource exists on-chain before consumption
            // This ensures the seal was properly created and deployed
            let seal_resource_type = format!("{}::CSVSeal::Seal", self.config.seal_contract.module_address);
            StateProofVerifier::verify_resource_exists_async(
                seal.account_address,
                &seal_resource_type,
                self.rpc.as_ref() as &(dyn crate::rpc::AptosAccountReader + Send + Sync),
            )
            .await
            .map_err(|e| {
                AptosError::StateProofFailed(format!(
                    "Failed to verify seal resource on-chain: {}",
                    e
                ))
            })?
        };

        #[cfg(not(feature = "rpc"))]
        let exists: AptosResult<bool> = Err(AptosError::FeatureNotEnabled(
            "Aptos seal availability requires the 'rpc' feature; refusing to assume the on-chain resource exists".to_string(),
        ));

        #[cfg(not(feature = "rpc"))]
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
        nonce: u64,
        commitment_arg: Vec<u8>,
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
        let module_name = aptos_sdk::types::Identifier::new("CSVSeal")
            .map_err(|e| format!("Invalid module name: {}", e))?;
        let module_id = MoveModuleId::new(module_addr, module_name);

        // BCS-encode nonce as u64
        let nonce_arg = aptos_bcs::to_bytes(&nonce)
            .map_err(|e| format!("Failed to serialize nonce: {}", e))?;

        let entry_function = EntryFunction::new(
            module_id,
            "consume_seal",
            vec![],                      // type arguments
            vec![nonce_arg, commitment_arg], // arguments: nonce (u64) and commitment (vector<u8>)
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

    /// Build a raw transaction from JSON payload format.
    /// This takes raw commitment bytes and BCS-encodes them as vector<u8>,
    /// matching what the Aptos node will do when reconstructing from JSON.
    #[cfg(feature = "rpc")]
    fn build_raw_transaction_from_json(
        &self,
        sender: [u8; 32],
        sequence_number: u64,
        expiration_secs: u64,
        module_address: &str,
        nonce: u64,
        commitment: [u8; 32],
    ) -> Result<
        aptos_sdk::transaction::types::RawTransaction,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // BCS-encode the commitment as vector<u8> (this is what the Aptos node will do)
        let commitment_vec: Vec<u8> = commitment.to_vec();
        let commitment_arg = aptos_bcs::to_bytes(&commitment_vec)
            .map_err(|e| format!("Failed to serialize commitment: {}", e))?;

        self.build_raw_transaction(
            sender,
            sequence_number,
            expiration_secs,
            module_address,
            nonce,
            commitment_arg,
        )
    }

    /// Build a raw transaction from an EntryFunctionPayload.
    #[cfg(feature = "rpc")]
    fn build_raw_transaction_from_entry_function(
        &self,
        sender: [u8; 32],
        sequence_number: u64,
        expiration_secs: u64,
        payload: &crate::entry_function::EntryFunctionPayload,
    ) -> Result<
        aptos_sdk::transaction::types::RawTransaction,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use aptos_sdk::transaction::EntryFunction;
        use aptos_sdk::transaction::payload::TransactionPayload;
        use aptos_sdk::transaction::types::RawTransaction;
        use aptos_sdk::types::{AccountAddress, ChainId, MoveModuleId};

        // Parse the function name to extract module address and function name
        // Format: "0x1234...::CSVSeal::lock_sanad"
        let parts: Vec<&str> = payload.function.split("::").collect();
        if parts.len() != 3 {
            return Err(format!("Invalid function format: {}", payload.function).into());
        }

        let module_address = parts[0];
        let module_name_str = parts[1];
        let function_name = parts[2];

        // Parse module address
        let module_addr = AccountAddress::from_hex(module_address)
            .map_err(|e| format!("Invalid module address: {}", e))?;

        // Build the EntryFunction
        let module_name = aptos_sdk::types::Identifier::new(module_name_str)
            .map_err(|e| format!("Invalid module name: {}", e))?;
        let module_id = MoveModuleId::new(module_addr, module_name);

        // Serialize arguments to BCS bytes using explicit types.
        // The encoding MUST match what the Aptos REST API produces from JSON arguments.
        let args_bcs: Vec<Vec<u8>> = payload
            .arguments
            .iter()
            .map(|arg| arg.to_bcs_bytes())
            .collect();

        let entry_function = EntryFunction::new(
            module_id,
            function_name,
            vec![], // type arguments
            args_bcs,
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

    #[cfg(feature = "rpc")]
    fn sign_raw_transaction(
        raw_transaction: &aptos_sdk::transaction::types::RawTransaction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            aptos_sdk::crypto::Ed25519PublicKey,
            aptos_sdk::crypto::Ed25519Signature,
            Vec<u8>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use aptos_sdk::crypto::Ed25519PrivateKey;

        let aptos_private_key = Ed25519PrivateKey::from_bytes(&signing_key.to_bytes())
            .map_err(|e| format!("Failed to convert private key: {}", e))?;
        let signing_message = raw_transaction
            .signing_message()
            .map_err(|e| format!("Failed to build Aptos signing message: {}", e))?;
        let signature = aptos_private_key.sign(&signing_message);
        let public_key = aptos_private_key.public_key();

        Ok((public_key, signature, signing_message))
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
    ///   "function": "{module_address}::CSVSeal::consume_seal",
    ///   "type_arguments": [],
    ///   "arguments": ["{commitment_hex}"]
    /// }
    /// ```
    ///
    /// The transaction is signed with Ed25519 and formatted for the
    /// Aptos REST API `/v1/transactions` endpoint.
    #[cfg(feature = "rpc")]
    pub async fn build_and_sign_entry_function(
        &self,
        seal: &AptosSealPoint,
        commitment: [u8; 32],
    ) -> Result<(serde_json::Value, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        use sha3::{Digest, Sha3_256};

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        // Derive sender address from signing key (Aptos address derivation)
        // Aptos authentication key = SHA3-256(public_key || 0x00)
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00); // Ed25519 single key scheme
        let hash = Sha3_256::digest(&data);
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&hash[..32]);
        let sender_hex = format_address(sender);
        log::info!(
            "APTOS ADAPTER LAYER: Derived sender address from signing key: {}",
            sender_hex
        );
        log::info!(
            "APTOS ADAPTER LAYER: Seal owner address: {}",
            format_address(seal.account_address)
        );
        log::info!(
            "APTOS ADAPTER LAYER: Seal resource type: {}",
            seal.resource_type
        );
        log::debug!("APTOS ADAPTER LAYER: Seal nonce: {}", seal.nonce);

        // Get account sequence number from RPC
        // Fetch fresh sequence number to avoid SEQUENCE_NUMBER_TOO_OLD errors
        // Retry a few times if we get a stale sequence number
        let (sequence_number, ledger) = {
            let max_retries = 3;
            let mut retry_count = 0;
            let sequence_number;
            
            loop {
                log::debug!("APTOS: Fetching account sequence number (attempt {}/{})", retry_count + 1, max_retries);
                match self.rpc.get_account_sequence_number(sender).await {
                    Ok(seq) => {
                        sequence_number = seq;
                        log::debug!("APTOS: Account sequence number: {}", sequence_number);
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= max_retries {
                            return Err(format!("Failed to get sequence number after {} attempts: {}", max_retries, e).into());
                        }
                        log::warn!("APTOS: Failed to get sequence number, retrying in 1 second...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
            
            log::debug!("APTOS: Fetching ledger info");
            let ledger = self
                .rpc
                .get_ledger_info()
                .await
                .map_err(|e| format!("Failed to get ledger info: {}", e))?;
            log::info!(
                "APTOS: Ledger info - chain_id={}, epoch={}, ledger_version={}, ledger_timestamp={}",
                ledger.chain_id,
                ledger.epoch,
                ledger.ledger_version,
                ledger.ledger_timestamp
            );

            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((sequence_number, ledger))
        }?;

        // Build event data for verification
        log::debug!("APTOS: Building event data for commitment verification");
        let event_data = self.event_builder.build(commitment, seal.account_address);
        log::info!(
            "APTOS: Event data built (length: {} bytes)",
            event_data.len()
        );

        // Build Entry Function payload
        let module_address = &self.config.seal_contract.module_address;
        // consume_seal takes nonce and commitment (seal is at signer's address)
        let function = format!("{}::CSVSeal::consume_seal", module_address);

        log::info!(
            "APTOS: Building Entry Function: {}(nonce={}, commitment={})",
            function,
            seal.nonce,
            hex::encode(commitment),
        );

        // Calculate expiration (current timestamp + 600 seconds)
        let expiration_secs = (ledger.ledger_timestamp / 1_000_000) + 600;
        log::info!(
            "APTOS: Transaction expiration timestamp: {} seconds",
            expiration_secs
        );

        // Build the raw transaction using the existing method
        log::debug!("APTOS: Building raw transaction");
        let raw_transaction = self
            .build_raw_transaction_from_json(
                sender,
                sequence_number,
                expiration_secs,
                module_address,
                seal.nonce,
                commitment,
            )
            .map_err(|e| format!("Failed to build raw transaction: {}", e))?;
        log::debug!("APTOS: Raw transaction built successfully");

        // Sign using aptos-sdk's Ed25519PrivateKey and create SignedTransaction
        log::debug!("APTOS: Signing transaction");
        let (public_key, signature, signing_message) =
            Self::sign_raw_transaction(&raw_transaction, signing_key)?;
        log::info!(
            "APTOS: Aptos signing message built (length: {} bytes)",
            signing_message.len()
        );
        log::info!(
            "APTOS: Transaction signed successfully (public_key: 0x{})",
            hex::encode(&public_key.to_bytes()[..8])
        );
        log::info!(
            "APTOS: Signature (first 8 bytes): 0x{}",
            hex::encode(&signature.to_bytes()[..8])
        );

        // Serialize the SignedTransaction to JSON using the SDK's format
        // The aptos-sdk doesn't provide a direct JSON serializer, so we construct it manually
        // but using the same format as the SDK would
        // The REST API receives Move values as JSON and reconstructs the same
        // BCS argument bytes that were placed into the signed RawTransaction.
        let signed_tx = serde_json::json!({
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
                    seal.nonce.to_string(),
                    format!("0x{}", hex::encode(commitment))
                ]
            },
            "signature": {
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(public_key.to_bytes())),
                "signature": format!("0x{}", hex::encode(signature.to_bytes()))
            }
        });
        log::debug!("APTOS: Signed transaction JSON built successfully");
        log::info!(
            "APTOS: Full transaction payload: {}",
            serde_json::to_string_pretty(&signed_tx)
                .unwrap_or_else(|_| "Failed to serialize".to_string())
        );

        Ok((signed_tx, event_data))
    }

    /// Sign an EntryFunctionPayload and return the signed transaction JSON.
    #[cfg(feature = "rpc")]
    pub async fn sign_entry_function_payload(
        &self,
        payload: crate::entry_function::EntryFunctionPayload,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        use sha3::{Digest, Sha3_256};

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        // Derive sender address from signing key (Aptos address derivation)
        // Aptos authentication key = SHA3-256(public_key || 0x00)
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00); // Ed25519 single key scheme
        let hash = Sha3_256::digest(&data);
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&hash[..32]);
        let sender_hex = format_address(sender);
        log::info!(
            "APTOS: Derived sender address from signing key: {}",
            sender_hex
        );

        // Get account sequence number from RPC
        let (sequence_number, ledger) = {
            let max_retries = 3;
            let mut retry_count = 0;
            let sequence_number;
            
            loop {
                log::debug!("APTOS: Fetching account sequence number (attempt {}/{})", retry_count + 1, max_retries);
                match self.rpc.get_account_sequence_number(sender).await {
                    Ok(seq) => {
                        sequence_number = seq;
                        log::debug!("APTOS: Account sequence number: {}", sequence_number);
                        break;
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count >= max_retries {
                            return Err(format!("Failed to get sequence number after {} attempts: {}", max_retries, e).into());
                        }
                        log::warn!("APTOS: Failed to get sequence number, retrying in 1 second...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
            
            log::debug!("APTOS: Fetching ledger info");
            let ledger = self
                .rpc
                .get_ledger_info()
                .await
                .map_err(|e| format!("Failed to get ledger info: {}", e))?;
            log::info!(
                "APTOS: Ledger info - chain_id={}, epoch={}, ledger_version={}, ledger_timestamp={}",
                ledger.chain_id,
                ledger.epoch,
                ledger.ledger_version,
                ledger.ledger_timestamp
            );

            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((sequence_number, ledger))
        }?;

        // Calculate expiration (current timestamp + 600 seconds)
        let expiration_secs = (ledger.ledger_timestamp / 1_000_000) + 600;
        log::info!(
            "APTOS: Transaction expiration timestamp: {} seconds",
            expiration_secs
        );

        // Build the raw transaction from the entry function payload
        log::info!("APTOS: Building raw transaction from entry function payload");
        let raw_transaction = self
            .build_raw_transaction_from_entry_function(
                sender,
                sequence_number,
                expiration_secs,
                &payload,
            )
            .map_err(|e| format!("Failed to build raw transaction: {}", e))?;
        log::debug!("APTOS: Raw transaction built successfully");

        // Sign using aptos-sdk's Ed25519PrivateKey and create SignedTransaction
        log::debug!("APTOS: Signing transaction");
        let (public_key, signature, signing_message) =
            Self::sign_raw_transaction(&raw_transaction, signing_key)?;
        log::info!(
            "APTOS: Aptos signing message built (length: {} bytes)",
            signing_message.len()
        );
        log::info!(
            "APTOS: Transaction signed successfully (public_key: 0x{})",
            hex::encode(&public_key.to_bytes()[..8])
        );
        log::info!(
            "APTOS: Signature (first 8 bytes): 0x{}",
            hex::encode(&signature.to_bytes()[..8])
        );

        // Serialize the SignedTransaction to JSON using the SDK's format
        // Arguments are converted to JSON using their explicit type mappings.
        let json_args: Vec<serde_json::Value> = payload.arguments.iter().map(|a| a.to_json_value()).collect();
        let signed_tx = serde_json::json!({
            "sender": sender_hex,
            "sequence_number": sequence_number.to_string(),
            "max_gas_amount": self.config.transaction.max_gas.to_string(),
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiration_secs.to_string(),
            "payload": {
                "type": "entry_function_payload",
                "function": payload.function,
                "type_arguments": payload.type_arguments,
                "arguments": json_args
            },
            "signature": {
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(public_key.to_bytes())),
                "signature": format!("0x{}", hex::encode(signature.to_bytes()))
            }
        });
        log::debug!("APTOS: Signed transaction JSON built successfully");
        log::info!(
            "APTOS: Full transaction payload: {}",
            serde_json::to_string_pretty(&signed_tx)
                .unwrap_or_else(|_| "Failed to serialize".to_string())
        );

        Ok(signed_tx)
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

        let valid: bool = Handle::current()
            .block_on(async {
                EventProofVerifier::verify_event_in_tx(
                    anchor.version,
                    &expected_event_data,
                    self.rpc_as_transaction_reader(),
                )
                .await
            })
            .map_err(|e: AptosError| ProtocolError::InclusionProofFailed(e.to_string()))?;

        if !valid {
            return Err(ProtocolError::InclusionProofFailed(
                "Event verification failed: commitment mismatch".to_string(),
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl SealProtocol for AptosSealProtocol {
    type SealPoint = AptosSealPoint;
    type CommitAnchor = AptosCommitAnchor;
    type InclusionProof = AptosInclusionProof;
    type FinalityProof = AptosFinalityProof;

    async fn publish(
        &self,
        commitment: Hash,
        seal: Self::SealPoint,
        _sanad_id: Hash,
    ) -> Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>> {
        log::debug!(
            "Publishing commitment via seal {}",
            format_address(seal.account_address)
        );

        // Verify seal is available
        self.verify_seal_available(&seal)
            .await
            .map_err(ProtocolError::from)?;

        #[cfg(feature = "rpc")]
        {
            // For Aptos CSVSealV2, do NOT call consume_seal here.
            // The deployed contract's lock_sanad function handles commitment publishing
            // (creates AnchorData, emits SanadConsumed event) when the sanad is locked
            // for cross-chain transfer. Calling consume_seal here would mark the seal
            // as consumed before lock_sanad, causing ESealAlreadyConsumed errors.
            log::debug!("APTOS: Skipping consume_seal during publish - lock_sanad will handle commitment publishing");

            // SECURITY CRITICAL: Fetch actual ledger version from chain instead of using placeholder
            // The anchor version must reflect the actual blockchain state at the time of commitment
            let ledger_info = self.rpc.get_ledger_info().await
                .map_err(|e| ProtocolError::NetworkError(format!("Failed to fetch ledger info: {}", e)))?;
            let ledger_version = ledger_info.ledger_version;

            // Return anchor with actual ledger version
            Ok(AptosCommitAnchor::new(
                ledger_version,
                seal.account_address,
                ledger_version,
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

    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>> {
        log::debug!(
            "Verifying inclusion for anchor at version {}",
            anchor.version
        );

        // Fetch transaction from the Aptos node by version
        #[cfg(feature = "rpc")]
        let tx = self
            .rpc_as_transaction_reader()
            .get_transaction(anchor.version)
            .await
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
            return Err(Box::new(ProtocolError::InclusionProofFailed(format!(
                "Transaction at version {} failed: {}",
                anchor.version, tx.vm_status
            ))) as Box<dyn std::error::Error>);
        }

        // Fetch ledger info to verify the transaction is part of the ledger
        #[cfg(feature = "rpc")]
        let ledger_info = self
            .rpc_as_ledger_reader()
            .get_ledger_info()
            .await
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
            return Err(Box::new(ProtocolError::InclusionProofFailed(format!(
                "Transaction version {} exceeds latest ledger version {}",
                tx.version, ledger_info.ledger_version
            ))) as Box<dyn std::error::Error>);
        }

        // Build inclusion proof with real transaction and ledger data
        let transaction_proof = tx.hash.to_vec();
        let ledger_proof = ledger_info.ledger_version.to_le_bytes().to_vec();

        Ok(AptosInclusionProof::new(
            transaction_proof,
            ledger_proof.clone(),
            anchor.version,
            ledger_proof, // ledger_info
            vec![],       // events
        ))
    }

    async fn verify_finality(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>> {
        log::debug!(
            "Verifying finality for anchor at version {}",
            anchor.version
        );

        #[cfg(feature = "rpc")]
        let is_certified = {
            let f_plus_one = self.config.f_plus_one();
            match self
                .checkpoint_verifier
                .is_version_finalized_async(anchor.version, self.rpc.as_ref(), f_plus_one)
                .await
            {
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

    async fn enforce_seal(
        &self,
        seal: Self::SealPoint,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        // Rule G-02: Double-spend prevention
        // This method ensures that an Aptos resource cannot be consumed more than once
        // by checking both local registry and on-chain resource state

        // Step 1: Check local registry (fast path)
        {
            let registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
            if registry.is_seal_used(&seal) {
                return Err(Box::new(ProtocolError::SealReplay(format!(
                    "Resource already consumed at {} in local registry",
                    format_address(seal.account_address)
                ))) as Box<dyn std::error::Error>);
            }
        } // Lock is dropped here

        // Step 2: Check on-chain resource state via RPC (authoritative check)
        // This ensures that even if local state is corrupted or lost,
        // we still prevent double-spends by querying the blockchain
        #[cfg(all(feature = "rpc", not(test)))]
        {
            // With collection-based seals, check if SealCollection exists
            let seal_collection_type = format!("{}::CSVSeal::SealCollection", self.config.seal_contract.module_address);
            let collection_exists = StateProofVerifier::verify_resource_exists_async(
                seal.account_address,
                &seal_collection_type,
                self.rpc.as_ref() as &(dyn crate::rpc::AptosAccountReader + Send + Sync),
            )
            .await
            .map_err(|e| {
                ProtocolError::NetworkError(format!(
                    "Failed to check seal collection on-chain: {}",
                    e
                ))
            })?;

            if !collection_exists {
                return Err(Box::new(ProtocolError::SealReplay(format!(
                    "Seal collection does not exist at {}",
                    format_address(seal.account_address)
                ))) as Box<dyn std::error::Error>);
            }

            // Verify the specific seal nonce is available (not yet consumed)
            // Query the SealCollection to check if the requested nonce exists and is unconsumed
            let seal_collection_data = self
                .rpc
                .get_resource(
                    seal.account_address,
                    &seal_collection_type,
                    None,
                )
                .await
                .map_err(|e| {
                    ProtocolError::NetworkError(format!(
                        "Failed to query seal collection data: {}",
                        e
                    ))
                })?
                .ok_or_else(|| ProtocolError::SealReplay(
                    "Seal collection resource not found".to_string()
                ))?;

            // Parse the next_nonce from the collection data
            // If the seal's nonce is >= next_nonce, it has been consumed
            let next_nonce = seal_collection_data
                .parse_u64_field("next_nonce")
                .map_err(|e| ProtocolError::SerializationError(format!(
                    "Failed to parse next_nonce from seal collection: {}",
                    e
                )))?;

            if seal.nonce >= next_nonce {
                return Err(Box::new(ProtocolError::SealReplay(format!(
                    "Seal with nonce {} has already been consumed (next_nonce: {})",
                    seal.nonce, next_nonce
                ))) as Box<dyn std::error::Error>);
            }

            log::debug!(
                "APTOS: Verified seal nonce {} is available (next_nonce: {})",
                seal.nonce, next_nonce
            );
        }

        #[cfg(not(feature = "rpc"))]
        {
            // In test mode without RPC, skip on-chain verification
            // This is acceptable for unit tests but not for production
            log::warn!("Skipping on-chain seal registry verification (RPC feature disabled)");
        }

        // Step 3: Mark seal as used in local registry
        // This is done after the on-chain check to ensure consistency
        let mut registry = self.seal_registry.lock().unwrap_or_else(|e| e.into_inner());
        registry
            .mark_seal_used(&seal, 0)
            .map_err(ProtocolError::from)?;

        Ok(())
    }

   async fn create_seal(
        &self,
        value: Option<u64>,
    ) -> Result<Self::SealPoint, Box<dyn std::error::Error + 'static>> {
        // In Aptos, seals are resources owned by the signer's account
        // The seal address should be the signer's address, not a hash-derived address
        #[cfg(feature = "rpc")]
        let addr = if let Some(ref signing_key) = self.signing_key {
            // Derive the signer's address from the signing key
            use sha3::{Digest, Sha3_256};
            let public_key = signing_key.verifying_key().to_bytes();
            let mut data = public_key.to_vec();
            data.push(0x00); // Ed25519 single key scheme
            let hash = Sha3_256::digest(&data);
            let mut sender_address = [0u8; 32];
            sender_address.copy_from_slice(&hash[..32]);
            sender_address
        } else {
            // Fallback to hash-derived address if no signing key (for testing)
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"aptos-seal");
            if let Some(v) = value {
                hasher.update(v.to_le_bytes());
            }
            let result = hasher.finalize();
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&result);
            addr
        };

        #[cfg(not(feature = "rpc"))]
        let addr = {
            // Fallback to hash-derived address if no signing key (for testing)
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"aptos-seal");
            if let Some(v) = value {
                hasher.update(v.to_le_bytes());
            }
            let result = hasher.finalize();
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&result);
            addr
        };

        // Generate a nonce for Aptos using timestamp (not using value parameter)
        // The value parameter is for Sanad content, not for the nonce
        let nonce = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0));
            duration.as_secs()
        };
        log::info!(
            "APTOS ADAPTER LAYER: Checking for existing seal at address: {}",
            format_address(addr)
        );

        // Check if seal already exists on-chain and reuse it if unconsumed
        #[cfg(feature = "rpc")]
        let nonce = if self.signing_key.is_some() {
            // Initialize seal collection if needed
            // The resource type format is: 0xADDRESS::MODULE::STRUCT
            let seal_collection_type = format!("0x{}::CSVSeal::SealCollection", 
                self.config.seal_contract.module_address.strip_prefix("0x").unwrap_or(&self.config.seal_contract.module_address));
            log::debug!("APTOS: Checking for seal collection resource type: {}", seal_collection_type);
            match self.rpc.get_resource(addr, &seal_collection_type, None).await {
                Ok(None) => {
                    log::debug!("APTOS: Initializing seal collection (REQUIRED)");
                    self.init_seal_collection(addr).await.map_err(|e| {
                        AptosError::InitializationFailed {
                            operation: "init_seal_collection".to_string(),
                            reason: e.to_string(),
                        }
                    })?;
                }
                Ok(Some(_)) => {
                    log::debug!("APTOS: Seal collection already exists");
                }
                Err(e) => {
                    log::warn!("APTOS: Failed to check seal collection: {}, assuming it exists", e);
                }
            }

            let mut effective_nonce = nonce;
            
            // With collection-based seals, check if AnchorData exists for the nonce
            // If AnchorData exists, the seal was already consumed, so increment nonce
            let anchor_data_collection_type = format!("0x{}::CSVSeal::AnchorDataCollection", 
                self.config.seal_contract.module_address.strip_prefix("0x").unwrap_or(&self.config.seal_contract.module_address));
            log::debug!("APTOS: Checking for anchor collection resource type: {}", anchor_data_collection_type);
            match self.rpc.get_resource(addr, &anchor_data_collection_type, None).await {
                Ok(Some(_collection)) => {
                    // AnchorDataCollection exists, check if AnchorData for this nonce exists
                    // Note: We can't directly query SmartTable entries via RPC, so we'll try create_seal
                    // and handle the EAnchorDataExists error by incrementing nonce
                    log::debug!("APTOS: AnchorDataCollection exists, will attempt to create seal with nonce {}", effective_nonce);
                }
                Ok(None) => {
                    // AnchorDataCollection doesn't exist, need to initialize it (REQUIRED)
                    log::debug!("APTOS: Initializing anchor collection (REQUIRED)");
                    self.init_anchor_collection(addr).await.map_err(|e| {
                        AptosError::InitializationFailed {
                            operation: "init_anchor_collection".to_string(),
                            reason: e.to_string(),
                        }
                    })?;
                }
                Err(e) => {
                    log::warn!("APTOS: Failed to check anchor collection: {}, assuming it exists", e);
                }
            }

            log::debug!("APTOS: Deploying seal on-chain via create_seal entry function");
            
            // Retry loop for EAnchorDataExists error
            let max_retries = 5;
            let mut retry_count = 0;
            loop {
                match self.deploy_seal_on_chain(addr, effective_nonce).await {
                    Ok(()) => {
                        log::debug!("APTOS: Seal deployed on-chain successfully with nonce {}", effective_nonce);
                        break;
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("EAnchorDataExists") && retry_count < max_retries {
                            log::warn!("APTOS: AnchorData already exists for nonce {}, incrementing and retrying (attempt {}/{})", effective_nonce, retry_count + 1, max_retries);
                            effective_nonce = effective_nonce.saturating_add(1);
                            retry_count += 1;
                        } else {
                            return Err(Box::new(ProtocolError::PublishFailed(format!(
                                "Failed to deploy seal on-chain: {}",
                                e
                            ))) as Box<dyn std::error::Error>);
                        }
                    }
                }
            }
            effective_nonce
        } else {
            nonce
        };

        Ok(AptosSealPoint::new(addr, format!("{}::CSVSeal::Seal", self.config.seal_contract.module_address), nonce))
    }

    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash {
        let core_seal =
            CoreSealPoint::new(seal_point.account_address.to_vec(), Some(seal_point.nonce), None)
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
        transition_dag: csv_protocol::seal_protocol::DagSegment,
    ) -> Result<ProofBundle, Box<dyn std::error::Error + 'static>> {
        let inclusion = self.verify_inclusion(anchor.clone()).await?;
        let finality = self.verify_finality(anchor.clone()).await?;
        let seal_ref = CoreSealPoint::new(anchor.event_handle.to_vec(), Some(anchor.version), None)
            .map_err(|e| {
                Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
            })?;

        let anchor_ref =
            CoreCommitAnchor::new(anchor.event_handle.to_vec(), anchor.version, vec![]).map_err(
                |e| Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>,
            )?;

        // Use csv_protocol::proof_taxonomy::InclusionProof (struct) instead of csv_protocol::cross_chain::InclusionProof (enum)
        let inclusion_proof = csv_protocol::proof_taxonomy::InclusionProof::new(
            inclusion.transaction_proof.clone(),
            csv_hash::Hash::zero(), // block_hash - would need to extract from proof
            inclusion.version,
            0, // leaf_index
        )
        .map_err(|e| {
            Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
        })?;

        let finality_proof = FinalityProof::new(vec![], finality.version, finality.is_certified)
            .map_err(|e| {
                Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>
            })?;

        // Convert DagSegment to DAGSegment for state transition DAG
        // Compute node_id from anchor hashes to ensure uniqueness
        let mut node_id_data = Vec::new();
        node_id_data.extend_from_slice(transition_dag.anchor_from.as_bytes());
        node_id_data.extend_from_slice(transition_dag.anchor_to.as_bytes());
        let node_id = csv_hash::Hash::new(csv_hash::csv_tagged_hash("dag-node-id", &node_id_data));

        // Create a single DAGNode from the transition data
        let dag_node = csv_hash::dag::DAGNode::new(
            node_id,
            transition_dag.transition_data.clone(),
            vec![transition_dag.proof.clone()], // Use proof as signature
            vec![], // No witnesses for single transition
            vec![transition_dag.anchor_from], // Parent is the source anchor
        );

        // Compute root_commitment from the node
        let root_commitment = dag_node.hash();
        let dag_segment = csv_hash::dag::DAGSegment::new(vec![dag_node], root_commitment);

        // Extract signatures from DAG node
        let signatures: Vec<Vec<u8>> = dag_segment.nodes
            .iter()
            .flat_map(|node| node.signatures.clone())
            .collect();

        if signatures.is_empty() {
            log::warn!("APTOS: No signatures found in transition_dag - proof bundle may not be verifiable");
        } else {
            log::info!("APTOS: Extracted {} signatures from DAGSegment", signatures.len());
        }

        ProofBundle::with_signature_scheme(
            csv_protocol::SignatureScheme::Ed25519,
            dag_segment,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
        .map_err(|e| Box::new(std::io::Error::other(e.to_string())) as Box<dyn std::error::Error>)
    }

    async fn rollback(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        log::warn!(
            "Rollback requested for anchor at version {}",
            anchor.version
        );
        #[cfg(feature = "rpc")]
        let current_version = self
            .rpc_as_ledger_reader()
            .get_latest_version()
            .await
            .map_err(|e| ProtocolError::NetworkError(e.to_string()))?;

        #[cfg(not(feature = "rpc"))]
        let current_version = anchor.version;

        // If anchor version is beyond current tip, rollback
        if anchor.version > current_version {
            return Err(Box::new(ProtocolError::ReorgInvalid(format!(
                "Anchor version {} beyond current tip {}",
                anchor.version, current_version
            ))) as Box<dyn std::error::Error>);
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

    /// Get RPC client as specific subtraits for operations that need them
    pub(crate) fn rpc_as_transaction_reader(&self) -> &(dyn AptosTransactionReader + Send + Sync) {
        self.rpc.as_ref()
    }

    pub(crate) fn rpc_as_ledger_reader(&self) -> &(dyn AptosLedgerReader + Send + Sync) {
        self.rpc.as_ref()
    }

    pub(crate) fn rpc_as_transaction_submitter(
        &self,
    ) -> &(dyn AptosTransactionSubmitter + Send + Sync) {
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

    /// Query the seal resource from on-chain for a given account address.
    #[cfg(feature = "rpc")]
    pub async fn get_seal_from_chain(&self, account_address: [u8; 32]) -> Result<AptosSealPoint, Box<dyn std::error::Error + Send + Sync>> {
        use crate::types::AptosSealPoint;

        let module_address = &self.config.seal_contract.module_address;
        let resource_type = format!("{}::CSVSeal::SealCollection", module_address);
        let addr_hex = format_address(account_address);
        let base_url = self.config.rpc_url.trim_end_matches('/');
        let url = if base_url.ends_with("/v1") {
            format!("{}/accounts/{}/resources", base_url, addr_hex)
        } else {
            format!("{}/v1/accounts/{}/resources", base_url, addr_hex)
        };

        log::debug!("APTOS: Querying seal resource from chain at {}", url);

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| format!("Failed to query seal resource: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to query seal resource: HTTP {}", response.status()).into());
        }

        let resources: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let resource_array = resources
            .as_array()
            .ok_or_else(|| "Expected array of resources".to_string())?;

        // Find the SealCollection resource
        for resource in resource_array {
            if let Some(res_type) = resource.get("type").and_then(|t| t.as_str()) {
                log::debug!("APTOS: Checking resource type: {}", res_type);
                // Match both with and without hex prefix
                if res_type.contains("CSVSeal::SealCollection") {
                    log::debug!("APTOS: Found matching resource type");
                    if let Some(data) = resource.get("data") {
                        // next_nonce might be a string or a number
                        let next_nonce = data.get("next_nonce")
                            .and_then(|n| n.as_str())
                            .and_then(|s| s.parse::<u64>().ok())
                            .or_else(|| data.get("next_nonce").and_then(|n| n.as_u64()));
                        
                        if let Some(next_nonce) = next_nonce {
                            log::debug!("APTOS: Found SealCollection with next_nonce {}", next_nonce);
                            // The seal nonce should be next_nonce - 1 for the most recent unconsumed seal
                            // This is the correct production behavior for sequential nonce allocation
                            let nonce = if next_nonce > 0 { next_nonce - 1 } else { 0 };
                            return Ok(AptosSealPoint {
                                account_address,
                                resource_type,
                                nonce,
                            });
                        }
                    }
                }
            }
        }

        Err("Seal resource not found on-chain".into())
    }

    /// Initialize the seal collection for an account.
    #[cfg(feature = "rpc")]
    async fn init_seal_collection(
        &self,
        account_address: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sha3::{Digest, Sha3_256};

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        // Derive sender address from signing key
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00);
        let hash = Sha3_256::digest(&data);
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&hash[..32]);

        // Get account sequence number
        let sequence_number = self
            .rpc
            .get_account_sequence_number(sender)
            .await
            .map_err(|e| format!("Failed to get sequence number: {}", e))?;

        // Get ledger info
        let ledger = self
            .rpc
            .get_ledger_info()
            .await
            .map_err(|e| format!("Failed to get ledger info: {}", e))?;

        let expiration_secs = (ledger.ledger_timestamp / 1_000_000) + 600;
        let module_address = &self.config.seal_contract.module_address;

        // Build transaction for init_seal_collection
        log::debug!("APTOS: Building init_seal_collection transaction");
        let raw_transaction = self
            .build_init_seal_collection_transaction(
                sender,
                sequence_number,
                expiration_secs,
                module_address,
            )
            .map_err(|e| format!("Failed to build transaction: {}", e))?;

        // Sign the transaction using the existing helper
        let (public_key, signature, _signing_message) =
            Self::sign_raw_transaction(&raw_transaction, signing_key)?;

        // Build the signed transaction JSON
        let sender_hex = format_address(sender);
        let signed_tx = serde_json::json!({
            "sender": sender_hex,
            "sequence_number": sequence_number.to_string(),
            "max_gas_amount": self.config.transaction.max_gas.to_string(),
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiration_secs.to_string(),
            "payload": {
                "type": "entry_function_payload",
                "function": format!("{}::CSVSeal::init_seal_collection", module_address),
                "type_arguments": [],
                "arguments": []
            },
            "signature": {
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(public_key.to_bytes())),
                "signature": format!("0x{}", hex::encode(signature.to_bytes()))
            }
        });

        // Submit the transaction using the JSON format
        log::debug!("APTOS: Submitting init_seal_collection transaction");
        let tx_hash = self
            .rpc
            .submit_signed_transaction(signed_tx)
            .await
            .map_err(|e| format!("Failed to submit init_seal_collection transaction: {}", e))?;

        log::debug!("APTOS: init_seal_collection transaction submitted: 0x{}", hex::encode(tx_hash));
        Ok(())
    }

    /// Initialize the AnchorDataCollection resource on-chain.
    #[cfg(feature = "rpc")]
    async fn init_anchor_collection(
        &self,
        account_address: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sha3::{Digest, Sha3_256};

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        // Derive sender address from signing key
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00);
        let hash = Sha3_256::digest(&data);
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&hash[..32]);

        // Get account sequence number
        let sequence_number = self
            .rpc
            .get_account_sequence_number(sender)
            .await
            .map_err(|e| format!("Failed to get sequence number: {}", e))?;

        // Get ledger info
        let ledger = self
            .rpc
            .get_ledger_info()
            .await
            .map_err(|e| format!("Failed to get ledger info: {}", e))?;

        let expiration_secs = (ledger.ledger_timestamp / 1_000_000) + 600;
        let module_address = &self.config.seal_contract.module_address;

        // Build transaction for init_anchor_collection
        log::debug!("APTOS: Building init_anchor_collection transaction");
        let raw_transaction = self
            .build_init_anchor_collection_transaction(
                sender,
                sequence_number,
                expiration_secs,
                module_address,
            )
            .map_err(|e| format!("Failed to build transaction: {}", e))?;

        // Sign the transaction using the existing helper
        let (public_key, signature, _signing_message) =
            Self::sign_raw_transaction(&raw_transaction, signing_key)?;

        // Build the signed transaction JSON
        let sender_hex = format_address(sender);
        let signed_tx = serde_json::json!({
            "sender": sender_hex,
            "sequence_number": sequence_number.to_string(),
            "max_gas_amount": self.config.transaction.max_gas.to_string(),
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiration_secs.to_string(),
            "payload": {
                "type": "entry_function_payload",
                "function": format!("{}::CSVSeal::init_anchor_collection", module_address),
                "type_arguments": [],
                "arguments": []
            },
            "signature": {
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(public_key.to_bytes())),
                "signature": format!("0x{}", hex::encode(signature.to_bytes()))
            }
        });

        // Submit the transaction using the JSON format
        log::debug!("APTOS: Submitting init_anchor_collection transaction");
        let tx_hash = self
            .rpc
            .submit_signed_transaction(signed_tx)
            .await
            .map_err(|e| format!("Failed to submit init_anchor_collection transaction: {}", e))?;

        log::debug!("APTOS: init_anchor_collection transaction submitted: 0x{}", hex::encode(tx_hash));
        Ok(())
    }

    /// Build a raw transaction for the init_seal_collection entry function.
    #[cfg(feature = "rpc")]
    fn build_init_seal_collection_transaction(
        &self,
        sender: [u8; 32],
        sequence_number: u64,
        expiration_secs: u64,
        module_address: &str,
    ) -> Result<
        aptos_sdk::transaction::types::RawTransaction,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use aptos_sdk::transaction::EntryFunction;
        use aptos_sdk::transaction::payload::TransactionPayload;
        use aptos_sdk::transaction::types::RawTransaction;
        use aptos_sdk::types::{AccountAddress, ChainId, MoveModuleId};

        let module_addr = AccountAddress::from_hex(module_address)
            .map_err(|e| format!("Invalid module address: {}", e))?;

        let module_name = aptos_sdk::types::Identifier::new("CSVSeal")
            .map_err(|e| format!("Invalid module name: {}", e))?;
        let module_id = MoveModuleId::new(module_addr, module_name);

        let entry_function = EntryFunction::new(module_id, "init_seal_collection", vec![], vec![]);

        let sender_addr = AccountAddress::new(sender);
        let payload = TransactionPayload::EntryFunction(entry_function);
        let max_gas = self.config.transaction.max_gas;
        let chain_id = ChainId::new(self.config.network.chain_id());

        Ok(RawTransaction::new(
            sender_addr,
            sequence_number,
            payload,
            max_gas,
            100,
            expiration_secs,
            chain_id,
        ))
    }

    /// Build a raw transaction for the init_anchor_collection entry function.
    #[cfg(feature = "rpc")]
    fn build_init_anchor_collection_transaction(
        &self,
        sender: [u8; 32],
        sequence_number: u64,
        expiration_secs: u64,
        module_address: &str,
    ) -> Result<
        aptos_sdk::transaction::types::RawTransaction,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use aptos_sdk::transaction::EntryFunction;
        use aptos_sdk::transaction::payload::TransactionPayload;
        use aptos_sdk::transaction::types::RawTransaction;
        use aptos_sdk::types::{AccountAddress, ChainId, MoveModuleId};

        let module_addr = AccountAddress::from_hex(module_address)
            .map_err(|e| format!("Invalid module address: {}", e))?;

        let module_name = aptos_sdk::types::Identifier::new("CSVSeal")
            .map_err(|e| format!("Invalid module name: {}", e))?;
        let module_id = MoveModuleId::new(module_addr, module_name);

        let entry_function = EntryFunction::new(module_id, "init_anchor_collection", vec![], vec![]);

        let sender_addr = AccountAddress::new(sender);
        let payload = TransactionPayload::EntryFunction(entry_function);
        let max_gas = self.config.transaction.max_gas;
        let chain_id = ChainId::new(self.config.network.chain_id());

        Ok(RawTransaction::new(
            sender_addr,
            sequence_number,
            payload,
            max_gas,
            100,
            expiration_secs,
            chain_id,
        ))
    }

    /// Deploy the seal on-chain by calling the create_seal Move entry function.
    #[cfg(feature = "rpc")]
    async fn deploy_seal_on_chain(
        &self,
        seal_address: [u8; 32],
        nonce: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use sha3::{Digest, Sha3_256};

        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or("No signing key configured")?;

        // Derive sender address from signing key
        let public_key = signing_key.verifying_key().to_bytes();
        let mut data = public_key.to_vec();
        data.push(0x00);
        let hash = Sha3_256::digest(&data);
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&hash[..32]);

        // Get account sequence number
        let sequence_number = self
            .rpc
            .get_account_sequence_number(sender)
            .await
            .map_err(|e| format!("Failed to get sequence number: {}", e))?;

        // Get ledger info
        let ledger = self
            .rpc
            .get_ledger_info()
            .await
            .map_err(|e| format!("Failed to get ledger info: {}", e))?;

        let expiration_secs = (ledger.ledger_timestamp / 1_000_000) + 600;
        let module_address = &self.config.seal_contract.module_address;

        // Build transaction for create_seal
        log::debug!("APTOS: Building create_seal transaction");
        let raw_transaction = self
            .build_create_seal_transaction(
                sender,
                sequence_number,
                expiration_secs,
                module_address,
                nonce,
            )
            .map_err(|e| format!("Failed to build create_seal transaction: {}", e))?;

        // Sign the transaction
        let (public_key, signature, _signing_message) =
            Self::sign_raw_transaction(&raw_transaction, signing_key)?;

        // Build the signed transaction JSON
        let sender_hex = format_address(sender);
        let signed_tx = serde_json::json!({
            "sender": sender_hex,
            "sequence_number": sequence_number.to_string(),
            "max_gas_amount": self.config.transaction.max_gas.to_string(),
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiration_secs.to_string(),
            "payload": {
                "type": "entry_function_payload",
                "function": format!("{}::CSVSeal::create_seal", module_address),
                "type_arguments": [],
                "arguments": [nonce.to_string()]
            },
            "signature": {
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(public_key.to_bytes())),
                "signature": format!("0x{}", hex::encode(signature.to_bytes()))
            }
        });

        // Submit the transaction using the JSON format
        log::debug!("APTOS: Submitting create_seal transaction");
        let tx_hash = self
            .rpc
            .submit_signed_transaction(signed_tx.clone())
            .await
            .map_err(|e| format!("Failed to submit create_seal transaction: {}", e))?;

        log::debug!("APTOS: create_seal transaction submitted successfully");

        // Wait for the transaction to be confirmed before returning
        log::debug!("APTOS: Waiting for create_seal transaction confirmation...");
        log::debug!("APTOS: Transaction hash: 0x{}", hex::encode(tx_hash));
        
        // Use Aptos SDK's FullnodeClient for transaction confirmation
        #[cfg(feature = "rpc")]
        {
            use aptos_sdk::api::FullnodeClient;
            use aptos_sdk::config::AptosConfig;
            use aptos_sdk::types::HashValue;
            use std::time::Duration;
            
            let config = AptosConfig::custom(&self.config.rpc_url)
                .map_err(|e| format!("Failed to create AptosConfig: {}", e))?;
            let client = FullnodeClient::new(config)
                .map_err(|e| format!("Failed to create FullnodeClient: {}", e))?;
            let hash_value = HashValue::new(tx_hash);
            
            match client.wait_for_transaction(&hash_value, Some(Duration::from_secs(20))).await {
                Ok(response) => {
                    let inner = response.into_inner();
                    let success = inner.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    let vm_status = inner.get("vm_status").and_then(|v| v.as_str()).unwrap_or("unknown");
                    
                    log::debug!("APTOS: Transaction response received - success: {}, vm_status: {}", success, vm_status);
                    if success {
                        log::debug!("APTOS: create_seal transaction confirmed successfully");
                        Ok(())
                    } else {
                        Err(format!("create_seal transaction failed: {}", vm_status).into())
                    }
                }
                Err(e) => {
                    Err(format!("Failed to wait for transaction confirmation: {}", e).into())
                }
            }
        }
        
        #[cfg(not(feature = "rpc"))]
        {
            Err("RPC feature not enabled for transaction confirmation".into())
        }
    }

    /// Build a raw transaction for the create_seal entry function.
    #[cfg(feature = "rpc")]
    fn build_create_seal_transaction(
        &self,
        sender: [u8; 32],
        sequence_number: u64,
        expiration_secs: u64,
        module_address: &str,
        nonce: u64,
    ) -> Result<
        aptos_sdk::transaction::types::RawTransaction,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use aptos_sdk::transaction::EntryFunction;
        use aptos_sdk::transaction::payload::TransactionPayload;
        use aptos_sdk::transaction::types::RawTransaction;
        use aptos_sdk::types::{AccountAddress, ChainId, MoveModuleId};

        let module_addr = AccountAddress::from_hex(module_address)
            .map_err(|e| format!("Invalid module address: {}", e))?;

        let module_name = aptos_sdk::types::Identifier::new("CSVSeal")
            .map_err(|e| format!("Invalid module name: {}", e))?;
        let module_id = MoveModuleId::new(module_addr, module_name);

        // Convert nonce to Move value (u64) - BCS-encoded
        let nonce_arg =
            aptos_bcs::to_bytes(&nonce).map_err(|e| format!("Failed to serialize nonce: {}", e))?;

        let entry_function = EntryFunction::new(module_id, "create_seal", vec![], vec![nonce_arg]);

        let sender_addr = AccountAddress::new(sender);
        let payload = TransactionPayload::EntryFunction(entry_function);
        let max_gas = self.config.transaction.max_gas;
        let chain_id = ChainId::new(self.config.network.chain_id());

        Ok(RawTransaction::new(
            sender_addr,
            sequence_number,
            payload,
            max_gas,
            100,
            expiration_secs,
            chain_id,
        ))
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn test_adapter() -> AptosSealProtocol {
        AptosSealProtocol::with_test().unwrap()
    }

    #[tokio::test]
    async fn test_create_seal() {
        let adapter = test_adapter();
        let seal = adapter.create_seal(None).await.unwrap();
        assert!(seal.nonce > 0, "nonce should be a positive timestamp, got {}", seal.nonce);
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
        assert_eq!(&adapter.domain_separator()[..10], b"CSV-APTOS-");
        assert_eq!(adapter.domain_separator()[10], 4); // Devnet chain_id
    }

    #[test]
    #[cfg(feature = "rpc")]
    fn test_raw_transaction_signature_uses_aptos_signing_message() {
        use ed25519_dalek::SigningKey;

        let adapter = test_adapter();
        let raw_transaction = adapter
            .build_create_seal_transaction(
                [2u8; 32],
                7,
                1_800_000_000,
                &adapter.config.seal_contract.module_address,
                42,
            )
            .unwrap();
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);

        let (public_key, signature, signing_message) =
            AptosSealProtocol::sign_raw_transaction(&raw_transaction, &signing_key).unwrap();

        public_key.verify(&signing_message, &signature).unwrap();

        let raw_bcs = bcs::to_bytes(&raw_transaction).unwrap();
        assert_ne!(signing_message, raw_bcs);
        assert!(public_key.verify(&raw_bcs, &signature).is_err());
    }

    #[tokio::test]
    #[cfg(feature = "rpc")]
    async fn test_consume_seal_json_argument_is_raw_commitment() {
        use ed25519_dalek::SigningKey;

        let config = AptosConfig::default();
        let rpc = Box::new(crate::rpc::MockAptosRpc::new(5000));
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let adapter = AptosSealProtocol::from_config(config, rpc)
            .unwrap()
            .with_signing_key(signing_key);
        let seal = AptosSealPoint::new([1u8; 32], "csv_seal".to_string(), 42);
        let commitment = [0xAB; 32];

        let (tx_json, _) = adapter
            .build_and_sign_entry_function(&seal, commitment)
            .await
            .unwrap();

        // arguments[0] is the nonce (string), arguments[1] is the commitment (0x-prefixed hex)
        let argument = tx_json["payload"]["arguments"][1].as_str().unwrap();
        let bcs_argument = aptos_bcs::to_bytes(&commitment.to_vec()).unwrap();

        assert_eq!(argument, format!("0x{}", hex::encode(commitment)));
        assert_ne!(argument, format!("0x{}", hex::encode(bcs_argument)));
    }

    #[tokio::test]
    #[cfg(feature = "rpc")]
    #[ignore = "Requires manual runtime setup due to nested block_on in verify_finality()"]
    async fn test_verify_finality() {
        let adapter = test_adapter();
        let anchor = AptosCommitAnchor::new(1500, [1u8; 32], 0);
        let result = adapter.verify_finality(anchor).await;
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
            "{}::CSVSeal::{}",
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
        let result = adapter.publish(commitment, seal, commitment).await;
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
        adapter.publish(commitment, seal.clone(), commitment).await.unwrap();

        // Try to publish again with same seal
        let commitment2 = Hash::new([2u8; 32]);
        let result = adapter.publish(commitment2, seal, commitment2).await;
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
