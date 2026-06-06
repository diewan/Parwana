//! Aptos adapter factory implementation.

use async_trait::async_trait;
use super::{AdapterFactory, AdapterConfig, AdapterResult, FactoryError, NetworkType};
use csv_protocol::backend::ChainBackend;
use csv_adapter_core::ChainAdapter;
use std::sync::Arc;

#[cfg(feature = "aptos")]
use csv_aptos::{
    ops::AptosBackend,
    rpc::AptosRpc,
    node::AptosNode,
    config::AptosNetwork,
    runtime_adapter::AptosRuntimeAdapter,
};

/// Aptos adapter factory.
pub struct AptosFactory;

#[cfg(feature = "aptos")]
#[async_trait]
impl AdapterFactory for AptosFactory {
    async fn create_adapter(&self, config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        let network = match config.network {
            NetworkType::Testnet => AptosNetwork::Testnet,
            NetworkType::Mainnet => AptosNetwork::Mainnet,
        };

        // Select the highest priority REST endpoint (Aptos uses REST)
        let rest_endpoint = config.rpc_endpoints
            .iter()
            .filter(|e| e.protocol == super::RpcProtocol::Rest)
            .min_by_key(|e| e.priority)
            .or_else(|| {
                // Fallback to any endpoint if no REST found
                config.rpc_endpoints.iter().min_by_key(|e| e.priority)
            })
            .ok_or_else(|| FactoryError::InvalidConfig("No RPC endpoint found".to_string()))?;

        // Create RPC client
        let rpc: Box<dyn AptosRpc + Send + Sync> = Box::new(AptosNode::new(&rest_endpoint.url));

        // Create ChainBackend
        let aptos_backend = Arc::new(
            AptosBackend::new(rpc, network)
        );
        
        let chain_backend: Arc<dyn ChainBackend> = aptos_backend.clone();

        // Create ChainAdapter for TransferCoordinator using AptosRuntimeAdapter
        let chain_adapter: Box<dyn ChainAdapter> = Box::new(
            AptosRuntimeAdapter::new(aptos_backend)
        );

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "aptos"
    }
}
