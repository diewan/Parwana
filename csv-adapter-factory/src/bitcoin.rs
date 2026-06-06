//! Bitcoin adapter factory implementation.

use async_trait::async_trait;
use super::{AdapterFactory, AdapterConfig, AdapterResult, FactoryError, NetworkType};
use csv_protocol::backend::ChainBackend;
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
    wallet::SealWallet,
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

        // Clone private_key for wallet creation
        let private_key_clone = config.private_key.clone();

        // Select the highest priority REST endpoint
        let rest_endpoint = config.rpc_endpoints
            .iter()
            .filter(|e| e.protocol == super::RpcProtocol::Rest)
            .min_by_key(|e| e.priority)
            .ok_or_else(|| FactoryError::InvalidConfig("No REST RPC endpoint found".to_string()))?;

        let btc_config = BitcoinConfig {
            network: network,
            finality_depth: 6,
            publication_timeout_seconds: 3600,
            rpc_url: rest_endpoint.url.clone(),
            rpc_backend: csv_bitcoin::BitcoinRpcBackend::MempoolRest,
            api_key: rest_endpoint.api_key.clone(),
            xpub: None,
            private_key: None,
            seed: private_key_clone,
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

        // Create wallet from seed for both adapters
        let seed_bytes = if let Some(ref seed_hex) = config.private_key {
            hex::decode(seed_hex)
                .map_err(|e| FactoryError::InvalidConfig(format!("Invalid seed hex: {}", e)))?
        } else {
            return Err(FactoryError::InvalidConfig("Seed is required for Bitcoin adapter".to_string()));
        };

        if seed_bytes.len() != 64 {
            return Err(FactoryError::InvalidConfig("Seed must be 64 bytes".to_string()));
        }

        let mut seed_array = [0u8; 64];
        seed_array.copy_from_slice(&seed_bytes);

        let wallet = SealWallet::from_seed(&seed_array, network.to_bitcoin_network())
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create wallet: {}", e)))?;

        // Create RPC client for ChainAdapter
        let rpc_adapter: Box<dyn BitcoinRpc + Send + Sync> = Box::new(
            MempoolSignetRpc::with_url_and_key(
                rest_endpoint.url.clone(),
                rest_endpoint.api_key.clone(),
            )
        );

        // Create ChainAdapter for TransferCoordinator using BitcoinRuntimeAdapter
        let btc_network_for_runtime = network.to_bitcoin_network();

        let chain_adapter: Box<dyn ChainAdapter> = Box::new(
            BitcoinRuntimeAdapter::new(btc_network_for_runtime, wallet, rpc_adapter)
        );

        // Create ChainBackend adapter from config
        let rpc_backend: Box<dyn BitcoinRpc + Send + Sync> = Box::new(
            MempoolSignetRpc::with_url_and_key(
                rest_endpoint.url.clone(),
                rest_endpoint.api_key.clone(),
            )
        );

        let seal_protocol_backend = BitcoinSealProtocol::from_config(btc_config, rpc_backend)
            .map_err(|e| FactoryError::CreationFailed(format!("Failed to create BitcoinSealProtocol for ChainBackend: {}", e)))?;

        let chain_backend: Arc<dyn ChainBackend> = Arc::new(
            BitcoinBackend::from_seal_protocol(Arc::new(seal_protocol_backend))
                .map_err(|e| FactoryError::CreationFailed(format!("Failed to create BitcoinBackend: {}", e)))?
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
