//! Aptos adapter factory implementation.

use async_trait::async_trait;
use super::{AdapterFactory, AdapterConfig, AdapterResult, FactoryError, NetworkType};
use csv_protocol::chain_adapter_traits::ChainBackend;
use csv_adapter_core::ChainAdapter;
use std::sync::Arc;

#[cfg(feature = "aptos")]
use csv_aptos::{
    ops::AptosBackend,
    rpc::AptosRpc,
    node::AptosNode,
    config::{AptosNetwork, AptosConfig},
    runtime_adapter::AptosRuntimeAdapter,
    seal_protocol::AptosSealProtocol,
};
use csv_protocol::deployment_manifest::get_aptos_module_address;

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

        // Create seal protocol with signing key if provided
        // Use deployment manifest for module address, fall back to config
        let module_address = get_aptos_module_address()
            .unwrap_or_else(|_| config.contract_address.clone().unwrap_or_else(|| "0x1".to_string()));
        
        let aptos_config = AptosConfig {
            network,
            rpc_url: rest_endpoint.url.clone(),
            seal_contract: csv_aptos::config::SealContractConfig {
                module_address,
                ..Default::default()
            },
            ..Default::default()
        };

        let seal_protocol = if let Some(key_bytes) = config.secret_key.as_bytes() {
            log::info!("Factory: Creating Aptos seal protocol with signing key");
            let key_hex = hex::encode(key_bytes);
            AptosSealProtocol::with_rpc_and_signing_key(
                aptos_config,
                &rest_endpoint.url,
                &key_hex,
            )
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create seal protocol with signing key: {}", e)))?
        } else {
            log::warn!("Factory: No secret key provided, creating Aptos seal protocol without signing key (read-only mode)");
            AptosSealProtocol::from_config(
                aptos_config,
                Box::new(AptosNode::new(&rest_endpoint.url)) as Box<dyn AptosRpc + Send + Sync>
            )
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create seal protocol: {}", e)))?
        };

        let seal_protocol = Arc::new(seal_protocol);

        // Create ChainBackend from seal protocol
        let aptos_backend = Arc::new(
            AptosBackend::from_seal_protocol(seal_protocol)
                .map_err(|e| FactoryError::CreationFailed(format!("Failed to create backend: {}", e)))?
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
