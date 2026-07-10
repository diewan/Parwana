//! Ethereum adapter factory implementation.

use super::{AdapterConfig, AdapterFactory, AdapterResult, FactoryError, NetworkType};
use async_trait::async_trait;
use csv_adapter_core::ChainAdapter;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

#[cfg(feature = "ethereum")]
use csv_ethereum::{
    config::EthereumConfig, config::Network as EthNetwork, node::EthereumNode,
    ops::EthereumBackend, rpc::EthereumRpc, runtime_adapter::EthereumRuntimeAdapter,
};

/// Ethereum adapter factory.
pub struct EthereumFactory;

#[cfg(feature = "ethereum")]
#[async_trait]
impl AdapterFactory for EthereumFactory {
    async fn create_adapter(&self, config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        let network = match config.network {
            NetworkType::Testnet => EthNetwork::Sepolia,
            NetworkType::Mainnet => EthNetwork::Mainnet,
        };

        // Select the highest priority REST endpoint (Ethereum uses JSON-RPC)
        let rest_endpoint = config
            .rpc_endpoints
            .iter()
            .filter(|e| e.protocol == super::RpcProtocol::JsonRpc)
            .min_by_key(|e| e.priority)
            .or_else(|| {
                // Fallback to any endpoint if no JSON-RPC found
                config.rpc_endpoints.iter().min_by_key(|e| e.priority)
            })
            .ok_or_else(|| FactoryError::InvalidConfig("No RPC endpoint found".to_string()))?;

        // Parse contract address if provided
        let contract_address = if let Some(ref addr) = config.contract_address {
            let address_bytes = hex::decode(addr.trim_start_matches("0x")).map_err(|e| {
                FactoryError::InvalidConfig(format!("Invalid contract address: {}", e))
            })?;
            let addr_array: [u8; 20] = address_bytes.try_into().map_err(|_| {
                FactoryError::InvalidConfig("Contract address must be 20 bytes".to_string())
            })?;
            Some(addr_array)
        } else {
            None
        };

        // Extract secret key for signer
        let secret_key = config.secret_key;

        let eth_config = EthereumConfig {
            network,
            finality_depth: if config.network == NetworkType::Testnet {
                15
            } else {
                12
            },
            use_checkpoint_finality: config.network == NetworkType::Mainnet,
            rpc_url: rest_endpoint.url.clone(),
            private_key: None, // SharedSecretHandle is not compatible with Option<SecretKey>
            contract_address,
        };

        // Create RPC client
        let contract_addr_for_rpc = contract_address.unwrap_or([0u8; 20]);
        let mut rpc = EthereumNode::new(&rest_endpoint.url, contract_addr_for_rpc)
            .await
            .map_err(|e| {
                FactoryError::CreationFailed(format!("Failed to create Ethereum RPC client: {}", e))
            })?;

        // Add signer if private key is provided
        if let Some(key_bytes) = secret_key.as_bytes() {
            let private_key_hex = hex::encode(key_bytes);
            rpc = rpc.with_signer(&private_key_hex).map_err(|e| {
                FactoryError::CreationFailed(format!("Failed to configure Ethereum signer: {}", e))
            })?;
        }

        // Create ChainBackend. Fails closed (no mock fallback) if construction fails.
        let mut eth_backend =
            EthereumBackend::new(Box::new(rpc) as Box<dyn EthereumRpc>, eth_config).map_err(
                |e| {
                    FactoryError::CreationFailed(format!(
                        "Failed to construct Ethereum chain backend: {}",
                        e
                    ))
                },
            )?;
        // Attach the RFC-0012 mint verifier signing key(s) if provided (env).
        // This is distinct from the EVM transaction signer configured above: the
        // wallet pays gas, while these keys authorize the §9.2 attestation digest.
        // Resolution is destination-chain-scoped (CSV_MINT_VERIFIER_KEY_ETHEREUM
        // overrides the CSV_MINT_VERIFIER_KEY default for Ethereum only) and may
        // carry multiple signers for an M-of-N registry.
        let verifier_keys = super::load_mint_verifier_keys("ethereum");
        if verifier_keys.is_empty() {
            log::debug!(
                "Factory: no mint verifier key configured — Ethereum mint will fail closed \
                 (set {} or CSV_MINT_VERIFIER_KEY_ETHEREUM)",
                super::MINT_VERIFIER_KEY_ENV
            );
        } else {
            log::info!(
                "Factory: Ethereum adapter configured with {} mint verifier signer(s)",
                verifier_keys.len()
            );
            eth_backend = eth_backend.with_verifier_keys(verifier_keys);
        }
        let eth_backend = Arc::new(eth_backend);

        let chain_backend: Arc<dyn ChainBackend> = eth_backend.clone();

        // Create ChainAdapter for TransferCoordinator using EthereumRuntimeAdapter
        let chain_adapter: Box<dyn ChainAdapter> =
            Box::new(EthereumRuntimeAdapter::new(eth_backend));

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "ethereum"
    }
}
