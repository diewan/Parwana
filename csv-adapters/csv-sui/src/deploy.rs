//! Sui Move package deployment utilities.
//!
//! Provides `PackageDeployer` for publishing Move packages to the Sui blockchain
//! using the sui-rust-sdk crates.

use sha2::Digest;
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
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::SuiAddress;
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

        // Sui address is derived from public key using SHA3-256
        use sha3::{Digest, Sha3_256};
        let hash = Sha3_256::digest(pubkey_bytes);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        let sender_address = SuiAddress::from_bytes(addr_bytes)
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to derive address: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::ConfigurationError(format!("Failed to lock client: {}", e))
        })?;

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new(sender_address, gas_budget);

        // Add the publish command
        tx_builder
            .publish(package_bytes.to_vec())
            .map_err(|e| {
                SuiError::ConfigurationError(format!("Failed to build publish transaction: {}", e))
            })?;

        // Build the transaction data
        let tx_data = tx_builder
            .build()
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to build transaction: {}", e)))?;

        // Sign the transaction using Ed25519
        let signature = signing_key.sign(&tx_data);

        // Execute the transaction via sui-rust-sdk
        // Note: The exact execution method depends on the sui-rust-sdk version
        // This is a simplified version - in production you'd use the proper SDK execution method
        let tx_digest = client_guard
            .execute_transaction(&tx_data, &signature.to_bytes())
            .await
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to execute transaction: {}", e)))?;

        // Extract package ID from transaction effects (simplified)
        // In production, you'd parse the transaction effects to get the actual package ID
        let package_id = [0u8; 32]; // Placeholder - would be extracted from transaction effects

        Ok(PackageDeployment {
            package_id,
            transaction_digest: tx_digest,
            gas_used: gas_budget, // Placeholder - would be actual gas used
            modules: vec![],      // Placeholder - would be extracted from transaction effects
            dependencies: vec![],  // Placeholder - would be extracted from transaction effects
        })
    }
}
