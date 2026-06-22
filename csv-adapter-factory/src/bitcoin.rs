//! Bitcoin adapter factory implementation.

use async_trait::async_trait;
use super::{AdapterFactory, AdapterConfig, AdapterResult, FactoryError, NetworkType};
use csv_protocol::chain_adapter_traits::ChainBackend;
use csv_adapter_core::ChainAdapter;
use std::sync::Arc;

#[cfg(feature = "bitcoin")]
use csv_bitcoin::{
    config::BitcoinConfig,
    ops::BitcoinBackend,
    rpc::BitcoinRpc,
    seal_protocol::BitcoinSealProtocol,
    mempool_rpc::MempoolSignetRpc,
    runtime_adapter::BitcoinRuntimeAdapter,
    Network as BtcNetwork,
};

/// Bitcoin adapter factory.
pub struct BitcoinFactory;

#[cfg(feature = "bitcoin")]
#[async_trait]
impl AdapterFactory for BitcoinFactory {
    async fn create_adapter(&self, config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        let network = match config.network {
            NetworkType::Testnet => BtcNetwork::Signet,
            NetworkType::Mainnet => BtcNetwork::Mainnet,
        };

        // Extract seed for wallet creation (64-byte BIP-39 seed takes precedence)
        // Allow read-only mode if neither seed nor secret key is available
        let seed = if let Some(seed_hex) = &config.seed {
            Some(seed_hex.clone())
        } else if config.secret_key.as_bytes().is_some() {
            config.secret_key.as_bytes().map(|bytes| hex::encode(bytes))
        } else {
            log::warn!("Factory: No seed or secret key provided, creating Bitcoin adapter in read-only mode");
            None
        };

        // Select the highest priority REST endpoint
        let rest_endpoint = config.rpc_endpoints
            .iter()
            .filter(|e| e.protocol == super::RpcProtocol::Rest)
            .min_by_key(|e| e.priority)
            .ok_or_else(|| FactoryError::InvalidConfig("No REST RPC endpoint found".to_string()))?;

        let has_sanad_seals = !config.sanad_seals.is_empty();
        
        // Auto-detect RPC backend from URL
        let rpc_backend = csv_bitcoin::BitcoinRpcBackend::detect_from_url(&rest_endpoint.url)
            .unwrap_or(csv_bitcoin::BitcoinRpcBackend::BitcoinCoreJsonRpc);
        
        let btc_config = BitcoinConfig {
            network: network,
            finality_depth: 6,
            publication_timeout_seconds: 3600,
            rpc_url: rest_endpoint.url.clone(),
            rpc_backend,
            api_key: rest_endpoint.api_key.clone(),
            xpub: None,
            private_key: None,
            seed: seed,
            account: config.account,
            index: config.index,
            utxos: config.utxos.into_iter().map(|u| csv_bitcoin::config::UtxoConfig {
                txid: u.txid,
                vout: u.vout,
                value: u.value,
                account: u.account,
                index: u.index,
                script_pubkey: u.script_pubkey,
            }).collect(),
            sanad_seals: config.sanad_seals.into_iter().map(|s| csv_bitcoin::config::SanadSealConfig {
                sanad_id: s.sanad_id,
                anchor_txid: s.anchor_txid,
                vout: s.vout,
            }).collect(),
        };

        // Create ChainBackend from config first — this registers all sanad_seals
        // Use appropriate RPC implementation based on detected backend type
        let rpc_client: Box<dyn BitcoinRpc + Send + Sync> = match rpc_backend {
            csv_bitcoin::BitcoinRpcBackend::BitcoinCoreJsonRpc => {
                Box::new(csv_bitcoin::BitcoinJsonRpc::new(rest_endpoint.url.clone()))
            }
            csv_bitcoin::BitcoinRpcBackend::MempoolRest => {
                Box::new(MempoolSignetRpc::with_url_and_key(
                    rest_endpoint.url.clone(),
                    rest_endpoint.api_key.clone(),
                ))
            }
            csv_bitcoin::BitcoinRpcBackend::BlockstreamRest => {
                // TODO: Implement BlockstreamRest RPC
                Box::new(MempoolSignetRpc::with_url_and_key(
                    rest_endpoint.url.clone(),
                    rest_endpoint.api_key.clone(),
                ))
            }
        };

        let seal = BitcoinSealProtocol::from_config(btc_config, rpc_client)
            .map_err(|e| FactoryError::CreationFailed(
                format!("Failed to create BitcoinSealProtocol for ChainBackend: {}", e)
            ))?;
        let seal_arc = Arc::new(seal);

        // Load UTXO data for every registered sanad_seal from RPC (needed for spending)
        if has_sanad_seals {
            if let Err(e) = seal_arc.load_sanad_seal_utxos().await {
                log::warn!("Failed to load sanad seal UTXOs: {}", e);
            }
        }

        let chain_backend: Arc<dyn ChainBackend> = Arc::new(
            BitcoinBackend::from_seal_protocol(Arc::clone(&seal_arc))
                .map_err(|e| FactoryError::CreationFailed(format!("Failed to create BitcoinBackend: {}", e)))?
        );

        // Create ChainAdapter from the SAME seal_arc — shares the wallet + sanad_seals
        let btc_network_for_runtime = network.to_bitcoin_network();
        let rpc_adapter: Box<dyn BitcoinRpc + Send + Sync> = match rpc_backend {
            csv_bitcoin::BitcoinRpcBackend::BitcoinCoreJsonRpc => {
                Box::new(csv_bitcoin::BitcoinJsonRpc::new(rest_endpoint.url.clone()))
            }
            csv_bitcoin::BitcoinRpcBackend::MempoolRest => {
                Box::new(MempoolSignetRpc::with_url_and_key(
                    rest_endpoint.url.clone(),
                    rest_endpoint.api_key.clone(),
                ))
            }
            csv_bitcoin::BitcoinRpcBackend::BlockstreamRest => {
                // TODO: Implement BlockstreamRest RPC
                Box::new(MempoolSignetRpc::with_url_and_key(
                    rest_endpoint.url.clone(),
                    rest_endpoint.api_key.clone(),
                ))
            }
        };

        let chain_adapter: Box<dyn ChainAdapter> = Box::new(
            BitcoinRuntimeAdapter::from_seal_protocol(
                btc_network_for_runtime,
                Arc::clone(&seal_arc),
                rpc_adapter,
            )
        );

        Ok(AdapterResult {
            chain_backend,
            chain_adapter: Some(chain_adapter),
        })
    }

    fn chain_id(&self) -> &str {
        "bitcoin"
    }
}

#[cfg(not(feature = "bitcoin"))]
#[async_trait]
impl AdapterFactory for BitcoinFactory {
    async fn create_adapter(&self, _config: AdapterConfig) -> Result<AdapterResult, FactoryError> {
        Err(FactoryError::FeatureNotEnabled("bitcoin".to_string()))
    }

    fn chain_id(&self) -> &str {
        "bitcoin"
    }
}
