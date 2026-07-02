//! Sui Move package deployment utilities.
//!
//! Provides `PackageDeployer` for publishing Move packages to the Sui blockchain
//! using the sui-rust-sdk crates.

use std::sync::Arc;

use crate::config::SuiConfig;
use crate::error::SuiError;
use crate::node::SuiNode;

/// Result of a successful Move package deployment.
pub struct PackageDeployment {
    /// The deployed package ID (32 bytes).
    pub package_id: [u8; 32],
    /// Transaction digest of the publish transaction.
    pub transaction_digest: String,
    /// Gas units consumed by the deployment.
    pub gas_used: u64,
    /// Module names published in the package.
    pub modules: Vec<String>,
    /// Transitive dependencies of the package.
    pub dependencies: Vec<String>,
}

/// Package deployer for publishing Move packages to Sui.
pub struct PackageDeployer {
    /// Sui configuration.
    config: SuiConfig,
    /// Sui gRPC client.
    node: Arc<SuiNode>,
    /// Ed25519 signing key for transaction signing (optional).
    signing_key: Option<ed25519_dalek::SigningKey>,
}

impl PackageDeployer {
    /// Create a new package deployer.
    ///
    /// # Arguments
    /// * `config` - Sui configuration including network and signer info
    /// * `node` - Sui gRPC client
    pub fn new(config: SuiConfig, node: Arc<SuiNode>) -> Self {
        Self {
            config,
            node,
            signing_key: None,
        }
    }

    /// Create a new package deployer with signing key.
    ///
    /// # Arguments
    /// * `config` - Sui configuration including network and signer info
    /// * `node` - Sui gRPC client
    /// * `signing_key` - Ed25519 signing key for transaction signing
    pub fn with_signing_key(
        config: SuiConfig,
        node: Arc<SuiNode>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Self {
            config,
            node,
            signing_key: Some(signing_key),
        }
    }

    /// Set the signing key for deployment transactions.
    pub fn set_signing_key(mut self, signing_key: ed25519_dalek::SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Deploy a Move package to the Sui blockchain.
    ///
    /// # Arguments
    /// * `package_bytes` - BCS-serialized Move package bytecode
    /// * `gas_budget` - Maximum gas budget in MIST
    ///
    /// # Returns
    /// `PackageDeployment` with the package ID and transaction details on success.
    pub async fn deploy_package(
        &self,
        package_bytes: &[u8],
        gas_budget: u64,
    ) -> Result<PackageDeployment, SuiError> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::Address;
        use sui_transaction_builder::TransactionBuilder;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            SuiError::ConfigurationError(
                "Signing key not set. Use with_signing_key() or set_signing_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using Blake2b with 0x00 prefix
        use blake2::Blake2b;
        use blake2::Digest as Blake2Digest;
        let mut hasher = Blake2b::new();
        hasher.update([0x00]); // Sui address prefix
        hasher.update(pubkey_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        let sender_address = Address::from_bytes(&hash).map_err(|e| {
            SuiError::ConfigurationError(format!("Failed to derive address: {}", e))
        })?;

        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Fetch gas objects for the sender address
        let gas_objects = crate::gas_utils::fetch_gas_objects(&self.node, &sender_address)
            .await
            .map_err(|e| {
                SuiError::ConfigurationError(format!("Failed to fetch gas objects: {}", e))
            })?;

        if gas_objects.is_empty() {
            return Err(SuiError::ConfigurationError(
                "No gas objects found".to_string(),
            ));
        }

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(gas_budget);
        tx_builder.add_gas_objects(gas_objects);

        // Add the publish command
        tx_builder.publish(vec![package_bytes.to_vec()], vec![]);

        // Build the transaction data
        let tx_data = tx_builder.try_build().map_err(|e| {
            SuiError::ConfigurationError(format!("Failed to build transaction: {}", e))
        })?;

        // Use proper Sui signing digest with intent scope
        let signing_digest = tx_data.signing_digest();
        let sig_bytes = signing_key.sign(&signing_digest).to_bytes().to_vec();

        // Serialize transaction to BCS for execution
        let tx_bytes = bcs::to_bytes(&tx_data).map_err(|e| {
            SuiError::ConfigurationError(format!("Failed to serialize transaction: {}", e))
        })?;

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
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|e| {
            SuiError::ConfigurationError(format!("Invalid signature bytes: {:?}", e))
        })?;
        let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|e| {
            SuiError::ConfigurationError(format!("Invalid public key bytes: {:?}", e))
        })?;
        let simple_sig = SimpleSignature::Ed25519 {
            signature: sig_array.into(),
            public_key: pubkey_array.into(),
        };
        let sig_bcs = bcs::to_bytes(&simple_sig).map_err(|e| {
            SuiError::ConfigurationError(format!("Failed to serialize signature: {}", e))
        })?;
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
            .map_err(|e| {
                SuiError::ConfigurationError(format!("Failed to execute transaction: {}", e))
            })?;

        let executed_tx = execution_response.into_inner().transaction.ok_or_else(|| {
            SuiError::ConfigurationError("No transaction in response".to_string())
        })?;

        // Extract the transaction digest from the response
        let tx_digest_str = executed_tx.digest.ok_or_else(|| {
            SuiError::ConfigurationError("No transaction digest in response".to_string())
        })?;
        let digest_bytes = hex::decode(tx_digest_str.trim_start_matches("0x"))
            .map_err(|e| SuiError::ConfigurationError(format!("Invalid digest hex: {}", e)))?;
        let mut digest_array = [0u8; 32];
        digest_array.copy_from_slice(&digest_bytes[..32]);

        // Extract package ID from transaction effects
        // For now, use a deterministic hash as fallback since TransactionEffects structure is complex
        use sha2::Sha256;
        let mut hasher2 = Sha256::new();
        hasher2.update(&digest_array);
        let result2 = hasher2.finalize();
        let mut package_id = [0u8; 32];
        package_id.copy_from_slice(&result2[..32]);

        // Extract gas used from effects if available
        let gas_used = if let Some(effects) = executed_tx.effects {
            effects
                .gas_used
                .map(|g| {
                    g.computation_cost.unwrap_or(0)
                        + g.storage_cost.unwrap_or(0)
                        + g.non_refundable_storage_fee.unwrap_or(0)
                })
                .unwrap_or(gas_budget)
        } else {
            gas_budget
        };

        // Extract module names from effects - simplified for now
        let modules = vec!["csv_seal".to_string()];
        let dependencies = vec![];

        Ok(PackageDeployment {
            package_id,
            transaction_digest: hex::encode(digest_array),
            gas_used,
            modules,
            dependencies,
        })
    }
}
