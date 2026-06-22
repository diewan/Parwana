//! Sui adapter factory implementation.

use async_trait::async_trait;
use super::{AdapterFactory, AdapterConfig, AdapterResult, FactoryError, NetworkType};
use csv_protocol::chain_adapter_traits::ChainBackend;
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

        // Convert SharedSecretHandle to SecretKey for SuiConfig
        let signer_private_key = config.secret_key.as_bytes().map(|key_bytes| {
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key_bytes);
            csv_keys::memory::SecretKey::new(key_array)
        });

        // Derive signer address from private key if available
        let signer_address = if let Some(ref key) = signer_private_key {
            let key_bytes = key.expose_secret();
            use blake2::Blake2b;
            use blake2::Digest;
            let mut hasher = Blake2b::new();
            hasher.update([0x00]); // Sui address prefix
            hasher.update(key_bytes);
            let hash: [u8; 32] = hasher.finalize().into();
            Some(format!("0x{}", hex::encode(hash)))
        } else {
            None
        };

        let sui_config = SuiConfig {
            network,
            rpc_url: grpc_endpoint.url.clone(),
            checkpoint: csv_sui::config::CheckpointConfig::default(),
            transaction: csv_sui::config::TransactionConfig::default(),
            seal_contract: csv_sui::config::SealContractConfig {
                package_id: package_id.map(|s| s.to_string()),
                ..Default::default()
            },
            signer_address,
            signer_private_key,
        };

        // Create RPC client
        let node = Arc::new(
            SuiNode::new(&grpc_endpoint.url)
                .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui RPC client: {}", e)))?
        );

        // Create seal protocol (signer is now in config, not passed separately)
        let seal_protocol = SuiSealProtocol::from_config(sui_config.clone(), node.clone())
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui seal protocol: {}", e)))?;

        // Log signer status
        if sui_config.signer_private_key.is_some() {
            log::info!("Factory: Creating Sui adapter with signer configured");
        } else {
            log::warn!("Factory: Creating Sui adapter in read-only mode (no signer configured)");
        }

        // Create backend - seal_protocol already has the signer from config
        let sui_backend = Arc::new(
            SuiBackend::from_seal_protocol(Arc::new(seal_protocol), node.clone())
                .map_err(|e| FactoryError::CreationFailed(format!("Failed to create Sui backend: {}", e)))?
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
