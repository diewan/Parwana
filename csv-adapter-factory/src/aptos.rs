//! Aptos adapter factory implementation.

use super::{AdapterConfig, AdapterFactory, AdapterResult, FactoryError, NetworkType};
use async_trait::async_trait;
use csv_adapter_core::ChainAdapter;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

#[cfg(feature = "aptos")]
use csv_aptos::{
    config::{AptosConfig, AptosNetwork},
    node::AptosNode,
    ops::AptosBackend,
    rpc::AptosRpc,
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
        let rest_endpoint = config
            .rpc_endpoints
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
        let module_address = get_aptos_module_address().unwrap_or_else(|_| {
            config
                .contract_address
                .clone()
                .unwrap_or_else(|| "0x1".to_string())
        });

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
            AptosSealProtocol::with_rpc_and_signing_key(aptos_config, &rest_endpoint.url, &key_hex)
                .map_err(|e| {
                    FactoryError::CreationFailed(format!(
                        "Failed to create seal protocol with signing key: {}",
                        e
                    ))
                })?
        } else {
            log::warn!(
                "Factory: No secret key provided, creating Aptos seal protocol without signing key (read-only mode)"
            );
            AptosSealProtocol::from_config(
                aptos_config,
                Box::new(AptosNode::new(&rest_endpoint.url)) as Box<dyn AptosRpc + Send + Sync>,
            )
            .map_err(|e| {
                FactoryError::CreationFailed(format!("Failed to create seal protocol: {}", e))
            })?
        };

        let seal_protocol = Arc::new(seal_protocol);

        // Create ChainBackend from seal protocol
        let mut aptos_backend_inner =
            AptosBackend::from_seal_protocol(seal_protocol).map_err(|e| {
                FactoryError::CreationFailed(format!("Failed to create backend: {}", e))
            })?;
        // Attach the RFC-0012 mint verifier signing key if provided (env). Without
        // it the backend signs no attestation and mint fails closed by design.
        if let Some(vk) = super::load_mint_verifier_key() {
            aptos_backend_inner = aptos_backend_inner.with_verifier_key(vk);
            log::info!("Factory: Aptos adapter configured with mint verifier key");
        } else {
            log::warn!(
                "Factory: no mint verifier key ({}) — Aptos mint will fail closed",
                super::MINT_VERIFIER_KEY_ENV
            );
        }
        let aptos_backend = Arc::new(aptos_backend_inner);

        let chain_backend: Arc<dyn ChainBackend> = aptos_backend.clone();

        // Create ChainAdapter for TransferCoordinator using AptosRuntimeAdapter
        let chain_adapter: Box<dyn ChainAdapter> =
            Box::new(AptosRuntimeAdapter::new(aptos_backend));

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "aptos"
    }
}
