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
            signer_private_key: config.private_key.and_then(|k| hex::decode(k).ok()),
        };

        // Create RPC client
        let node = SuiNode::new(&grpc_endpoint.url)
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui RPC client: {}", e)))?;

        // Create ChainBackend
        let sui_backend = Arc::new(
            SuiBackend::new(sui_config, Arc::new(node))
        );
        
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
