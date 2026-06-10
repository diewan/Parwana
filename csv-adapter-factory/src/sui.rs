//! Sui adapter factory implementation.

use async_trait::async_trait;
use super::{AdapterFactory, AdapterConfig, AdapterResult, FactoryError, NetworkType};
use csv_protocol::backend::ChainBackend;
use csv_adapter_core::ChainAdapter;
use std::sync::Arc;

#[cfg(feature = "sui")]
use csv_sui::{
    config::SuiConfig,
    ops::SuiBackend,
    node::SuiNode,
    config::SuiNetwork,
    runtime_adapter::SuiRuntimeAdapter,
    seal_protocol::SuiSealProtocol,
};

/// Sui adapter factory.
pub struct SuiFactory;

#[cfg(feature = "sui")]
#[async_trait]
impl AdapterFactory for SuiFactory {
    async fn create_adapter(&self, config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        let network = match config.network {
            NetworkType::Testnet => SuiNetwork::Testnet,
            NetworkType::Mainnet => SuiNetwork::Mainnet,
        };

        // Select the highest priority gRPC endpoint (Sui uses gRPC)
        let grpc_endpoint = config.rpc_endpoints
            .iter()
            .filter(|e| e.protocol == super::RpcProtocol::Grpc)
            .min_by_key(|e| e.priority)
            .or_else(|| {
                // Fallback to any endpoint if no gRPC found
                config.rpc_endpoints.iter().min_by_key(|e| e.priority)
            })
            .ok_or_else(|| FactoryError::InvalidConfig("No RPC endpoint found".to_string()))?;

        // Parse package ID if provided
        let package_id = config.contract_address.as_deref();

        let sui_config = SuiConfig {
            network,
            rpc_url: grpc_endpoint.url.clone(),
            checkpoint: csv_sui::config::CheckpointConfig::default(),
            transaction: csv_sui::config::TransactionConfig::default(),
            seal_contract: csv_sui::config::SealContractConfig {
                package_id: package_id.map(|s| s.to_string()),
                ..Default::default()
            },
            signer_address: None,
            signer_private_key: config.secret_key
                .as_bytes()
                .map(|bytes| bytes.to_vec()),
        };

        // Create RPC client
        let node = Arc::new(
            SuiNode::new(&grpc_endpoint.url)
                .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui RPC client: {}", e)))?
        );

        // Create seal protocol
        let seal_protocol = SuiSealProtocol::from_config(sui_config, node.clone())
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui seal protocol: {}", e)))?;

        // Create ChainBackend with signing key if secret key is provided
        let sui_backend = if let Some(key_bytes) = config.secret_key.as_bytes() {
            log::info!("Factory: Creating Sui seal protocol with signing key");
            if key_bytes.len() == 32 {
                use ed25519_dalek::SigningKey;
                let key_array: [u8; 32] = {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(key_bytes);
                    arr
                };
                let signing_key = SigningKey::from_bytes(&key_array);
                Arc::new(
                    SuiBackend::from_seal_protocol_with_key(Arc::new(seal_protocol), node.clone(), signing_key)
                        .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui backend with key: {}", e)))?
                )
            } else {
                log::warn!("Factory: Invalid Sui private key length (expected 32 bytes, got {})", key_bytes.len());
                Arc::new(
                    SuiBackend::from_seal_protocol(Arc::new(seal_protocol), node.clone())
                        .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui backend: {}", e)))?
                )
            }
        } else {
            log::warn!("Factory: No secret key provided, creating Sui seal protocol without signing key (read-only mode)");
            Arc::new(
                SuiBackend::from_seal_protocol(Arc::new(seal_protocol), node.clone())
                    .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui backend: {}", e)))?
            )
        };
        
        let chain_backend: Arc<dyn ChainBackend> = sui_backend.clone();

        // Create ChainAdapter for TransferCoordinator using SuiRuntimeAdapter
        let chain_adapter: Box<dyn ChainAdapter> = Box::new(
            SuiRuntimeAdapter::new(sui_backend)
        );

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "sui"
    }
}
