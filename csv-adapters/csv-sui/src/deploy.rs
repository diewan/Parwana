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
        use sui_transaction_builder::TransactionBuilder;
        use sui_sdk_types::Address;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            SuiError::ConfigurationError(
                "Signing key not set. Use with_signing_key() or set_signing_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using SHA3-256
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(pubkey_bytes);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        let sender_address = Address::from_bytes(&addr_bytes)
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to derive address: {}", e)))?;

        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(gas_budget);

        // Add the publish command
        tx_builder.publish(vec![package_bytes.to_vec()], vec![]);

        // Build the transaction data
        let tx_data = tx_builder
            .try_build()
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to build transaction: {}", e)))?;

        // Sign the transaction using Ed25519
        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to serialize transaction: {}", e)))?;
        let signature = signing_key.sign(&tx_bytes);

        // Execute the transaction via sui-rpc v2 API
        let client = self.node.client();
        let mut client_guard = client.lock().await;

        // Create the signed transaction
        let user_signature = sui_rpc::proto::sui::rpc::v2::UserSignature {
            signature: Some(sui_rpc::proto::sui::rpc::v2::user_signature::Signature::Ed25519(
                sui_rpc::proto::sui::rpc::v2::Ed25519Signature {
                    signature: signature.to_bytes().to_vec(),
                    public_key: signing_key.verifying_key().to_bytes().to_vec(),
                },
            )),
        };

        let execute_request = sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest {
            transaction: Some(sui_rpc::proto::sui::rpc::v2::Transaction {
                transaction_data: Some(tx_bytes),
                signatures: vec![user_signature],
            }),
            request_type: sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequestType::WaitForLocalExecution as i32,
        };

        let execution_response = (*client_guard)
            .execution_client()
            .execute_transaction(execute_request)
            .await
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to execute transaction: {}", e)))?;

        let executed_tx = execution_response.into_inner().executed_transaction.ok_or_else(|| {
            SuiError::ConfigurationError("No executed transaction in response".to_string())
        })?;

        let tx_digest = executed_tx.digest.ok_or_else(|| {
            SuiError::ConfigurationError("No transaction digest in response".to_string())
        })?;

        // Extract package ID from transaction effects
        // The package ID is typically in the created objects or effects
        let package_id = if let Some(effects) = executed_tx.effects {
            // Try to extract package ID from effects
            // For publish transactions, the package ID is typically in the created field
            effects.created.first().and_then(|obj| {
                obj.reference.as_ref().and_then(|ref_| {
                    sui_sdk_types::Address::from_bytes(&ref_.object_id).ok()
                })
            }).map(|addr| {
                let mut id = [0u8; 32];
                id.copy_from_slice(&addr);
                id
            }).unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };

        // Extract gas used from effects
        let gas_used = executed_tx.effects.as_ref()
            .and_then(|e| e.gas_cost.as_ref())
            .map(|g| g.computation_cost + g.storage_cost + g.non_refundable_storage_fee)
            .unwrap_or(gas_budget);

        // Extract module names from effects (simplified)
        let modules = vec![]; // Would need to parse transaction effects to get actual modules
        let dependencies = vec![]; // Would need to parse transaction effects to get actual dependencies

        Ok(PackageDeployment {
            package_id,
            transaction_digest: tx_digest,
            gas_used,
            modules,
            dependencies,
        })
    }
}
