//! Sui adapter factory implementation.

use super::{AdapterConfig, AdapterFactory, AdapterResult, FactoryError, NetworkType};
use async_trait::async_trait;
use csv_adapter_core::ChainAdapter;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

#[cfg(feature = "sui")]
use csv_sui::{
    config::SuiConfig, config::SuiNetwork, node::SuiNode, ops::SuiBackend,
    runtime_adapter::SuiRuntimeAdapter, seal_protocol::SuiSealProtocol,
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
        let grpc_endpoint = config
            .rpc_endpoints
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

        // The thin-registry mint authority is the shared `Registry` object id
        // (RFC-0012 §9.2 `destinationContract`), which is distinct from the
        // package id and recorded in the deployment manifest post-publish. If it
        // is not yet set the adapter fails closed at mint time — never defaulted
        // — so read it best-effort here and leave `None` otherwise.
        let registry_id = csv_protocol::deployment_manifest::get_sui_registry_id().ok();
        if registry_id.is_none() {
            log::warn!(
                "Factory: Sui registry_id not set in deployment manifest — \
                 thin-registry mint will fail closed until it is recorded"
            );
        }

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
                registry_id,
                ..Default::default()
            },
            signer_address,
            signer_private_key,
        };

        // Create RPC client
        let node = Arc::new(SuiNode::new(&grpc_endpoint.url).map_err(|e| {
            FactoryError::CreationFailed(format!("Failed to create Sui RPC client: {}", e))
        })?);

        // Create seal protocol (signer is now in config, not passed separately)
        let seal_protocol = SuiSealProtocol::from_config(sui_config.clone(), node.clone())
            .map_err(|e| {
                FactoryError::CreationFailed(format!("Failed to create Sui seal protocol: {}", e))
            })?;

        // Log signer status
        if sui_config.signer_private_key.is_some() {
            log::info!("Factory: Creating Sui adapter with signer configured");
        } else {
            log::debug!("Factory: Creating Sui adapter in read-only mode (no signer configured)");
        }

        // Create backend - seal_protocol already has the signer from config
        let mut sui_backend_inner = if let Some(key) = sui_config.signer_private_key.as_ref() {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(key.expose_secret());
            SuiBackend::from_seal_protocol_with_key(
                Arc::new(seal_protocol),
                node.clone(),
                signing_key,
            )
        } else {
            SuiBackend::from_seal_protocol(Arc::new(seal_protocol), node.clone())
        }
        .map_err(|e| {
            FactoryError::CreationFailed(format!("Failed to create Sui backend: {}", e))
        })?;
        // Attach the RFC-0012 mint verifier signing key(s) if provided (env).
        // Resolution is destination-chain-scoped (CSV_MINT_VERIFIER_KEY_SUI
        // overrides the CSV_MINT_VERIFIER_KEY default for Sui only) and may carry
        // multiple signers for an M-of-N registry. With none configured the
        // backend signs no attestation and mint fails closed by design.
        let verifier_keys = super::load_mint_verifier_keys("sui");
        if verifier_keys.is_empty() {
            log::debug!(
                "Factory: no mint verifier key configured — Sui mint will fail closed \
                 (set {} or CSV_MINT_VERIFIER_KEY_SUI)",
                super::MINT_VERIFIER_KEY_ENV
            );
        } else {
            log::info!(
                "Factory: Sui adapter configured with {} mint verifier signer(s)",
                verifier_keys.len()
            );
            sui_backend_inner = sui_backend_inner.with_verifier_keys(verifier_keys);
        }
        let sui_backend = Arc::new(sui_backend_inner);

        let chain_backend: Arc<dyn ChainBackend> = sui_backend.clone();

        // Create ChainAdapter for TransferCoordinator using SuiRuntimeAdapter
        let chain_adapter: Box<dyn ChainAdapter> = Box::new(SuiRuntimeAdapter::new(sui_backend));

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "sui"
    }
}
