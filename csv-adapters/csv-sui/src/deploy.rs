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
}

impl PackageDeployer {
    /// Create a new package deployer.
    ///
    /// # Arguments
    /// * `config` - Sui configuration including network and signer info
    /// * `node` - Sui gRPC client
    pub fn new(config: SuiConfig, node: Arc<SuiNode>) -> Self {
        Self { config, node }
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
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::SuiAddress;
        use sui_transaction_builder::TransactionBuilder;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            SuiError::ConfigurationError(format!("Failed to lock client: {}", e))
        })?;
        
        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new(
            self.config.transaction.sender,
            gas_budget,
        );
        
        // Add the publish command
        tx_builder.publish(package_bytes.to_vec())
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to build publish transaction: {}", e)))?;
        
        // Build the transaction data
        let tx_data = tx_builder.build()
            .map_err(|e| SuiError::ConfigurationError(format!("Failed to build transaction: {}", e)))?;
        
        // Sign the transaction (this requires proper signing key management)
        // For now, return an error indicating signing key management is needed
        return Err(SuiError::ConfigurationError(
            "Transaction signing requires proper signing key management. Implement signing key handling.".to_string(),
        ));
        
        // Once signing is implemented, the flow would be:
        // 1. Sign the transaction with the private key
        // 2. Execute the transaction via sui-rust-sdk
        // 3. Wait for confirmation
        // 4. Extract package ID from transaction effects
        // 5. Return PackageDeployment
    }
}
