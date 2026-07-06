//! Solana adapter factory implementation.

use super::{AdapterConfig, AdapterFactory, AdapterResult, FactoryError, NetworkType};
use async_trait::async_trait;
use csv_adapter_core::ChainAdapter;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

#[cfg(feature = "solana")]
use csv_solana::{
    config::{Network as SolanaNetwork, SolanaConfig},
    node::SolanaNode,
    ops::SolanaBackend,
    runtime_adapter::SolanaRuntimeAdapter,
    seal_protocol::SolanaSealProtocol,
};

/// Solana adapter factory.
pub struct SolanaFactory;

#[cfg(feature = "solana")]
#[async_trait]
impl AdapterFactory for SolanaFactory {
    async fn create_adapter(&self, config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        let network = match config.network {
            NetworkType::Testnet => SolanaNetwork::Devnet,
            NetworkType::Mainnet => SolanaNetwork::Mainnet,
        };

        // Select the highest priority JSON-RPC endpoint (Solana uses JSON-RPC)
        let jsonrpc_endpoint = config
            .rpc_endpoints
            .iter()
            .filter(|e| e.protocol == super::RpcProtocol::JsonRpc)
            .min_by_key(|e| e.priority)
            .or_else(|| {
                // Fallback to any endpoint if no JSON-RPC found
                config.rpc_endpoints.iter().min_by_key(|e| e.priority)
            })
            .ok_or_else(|| FactoryError::InvalidConfig("No RPC endpoint found".to_string()))?;

        // Create RPC client
        let rpc = Box::new(SolanaNode::new(&jsonrpc_endpoint.url));

        // Build SolanaConfig with keypair from secret_key
        let sol_config = {
            let mut cfg = SolanaConfig::for_network(network);
            cfg.rpc_url = jsonrpc_endpoint.url.clone();
            if let Some(program_id) = config.program_id {
                cfg = cfg.with_csv_program_id(program_id);
            }
            // Convert SharedSecretHandle to SecretKey for SolanaConfig
            if let Some(key_bytes) = config.secret_key.as_bytes() {
                let secret_key = csv_keys::memory::SecretKey::new(*key_bytes);
                cfg = cfg.with_keypair(secret_key);
            }
            cfg
        };

        // Create SolanaSealProtocol with wallet if keypair provided
        let seal_protocol = SolanaSealProtocol::from_config(sol_config, rpc)
            .map_err(|e| FactoryError::InvalidConfig(format!("Solana config error: {}", e)))?;

        // Create ChainBackend from seal protocol
        let mut solana_backend = SolanaBackend::from_seal_protocol(Arc::new(seal_protocol))
            .map_err(|e| FactoryError::InvalidConfig(format!("Solana backend error: {}", e)))?;
        // Attach the RFC-0012 mint verifier signing key if provided (env). Without
        // it the backend signs no attestation and mint fails closed by design.
        if let Some(vk) = super::load_mint_verifier_key() {
            solana_backend = solana_backend.with_verifier_key(vk);
            log::info!("Factory: Solana adapter configured with mint verifier key");
        } else {
            log::warn!(
                "Factory: no mint verifier key ({}) — Solana mint will fail closed",
                super::MINT_VERIFIER_KEY_ENV
            );
        }
        let solana_backend = Arc::new(solana_backend);

        let chain_backend: Arc<dyn ChainBackend> = solana_backend.clone();

        // Create ChainAdapter for TransferCoordinator using SolanaRuntimeAdapter
        let chain_adapter: Box<dyn ChainAdapter> =
            Box::new(SolanaRuntimeAdapter::new(solana_backend));

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "solana"
    }
}
