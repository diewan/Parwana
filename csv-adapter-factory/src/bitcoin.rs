//! Bitcoin adapter factory implementation.

use super::{AdapterConfig, AdapterFactory, AdapterResult, FactoryError, NetworkType};
use async_trait::async_trait;
use csv_chain_ports::ChainAdapter;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

#[cfg(feature = "bitcoin")]
use csv_bitcoin::{
    Network as BtcNetwork, config::BitcoinConfig, ops::BitcoinBackend,
    runtime_adapter::BitcoinRuntimeAdapter, seal_protocol::BitcoinSealProtocol,
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
            config.secret_key.as_bytes().map(hex::encode)
        } else {
            log::debug!(
                "Factory: No seed or secret key provided, creating Bitcoin adapter in read-only mode"
            );
            None
        };

        // Select the highest priority endpoint that can serve Bitcoin queries.
        // The endpoint's declared `protocol` drives backend selection explicitly —
        // we do NOT sniff the URL string.
        let rpc_endpoint = config
            .rpc_endpoints
            .iter()
            .filter(|e| {
                matches!(
                    e.protocol,
                    super::RpcProtocol::Rest
                        | super::RpcProtocol::JsonRpc
                        | super::RpcProtocol::Blockbook
                )
            })
            .min_by_key(|e| e.priority)
            .ok_or_else(|| {
                FactoryError::InvalidConfig(
                    "No REST, JSON-RPC, or Blockbook endpoint found".to_string(),
                )
            })?;

        let has_sanad_seals = !config.sanad_seals.is_empty();

        // Map the endpoint's explicitly-declared protocol to a Bitcoin backend.
        let rpc_backend = match rpc_endpoint.protocol {
            super::RpcProtocol::JsonRpc => csv_bitcoin::BitcoinRpcBackend::BitcoinCoreJsonRpc,
            super::RpcProtocol::Blockbook => csv_bitcoin::BitcoinRpcBackend::BlockbookRest,
            _ => csv_bitcoin::BitcoinRpcBackend::MempoolRest,
        };

        // Address scanning needs a REST indexer: reuse the endpoint URL if it is
        // itself REST (esplora or Blockbook), otherwise pick the highest-priority
        // REST-ish endpoint if any.
        let indexer_url = if rpc_backend.is_rest() {
            Some(rpc_endpoint.url.clone())
        } else {
            config
                .rpc_endpoints
                .iter()
                .filter(|e| {
                    matches!(
                        e.protocol,
                        super::RpcProtocol::Rest | super::RpcProtocol::Blockbook
                    )
                })
                .min_by_key(|e| e.priority)
                .map(|e| e.url.clone())
        };

        let btc_config = BitcoinConfig {
            network,
            finality_depth: 6,
            publication_timeout_seconds: 3600,
            rpc_url: rpc_endpoint.url.clone(),
            rpc_backend,
            indexer_url,
            api_key: rpc_endpoint.api_key.clone(),
            xpub: None,
            private_key: None,
            seed,
            account: config.account,
            index: config.index,
            utxos: config
                .utxos
                .into_iter()
                .map(|u| csv_bitcoin::config::UtxoConfig {
                    txid: u.txid,
                    vout: u.vout,
                    value: u.value,
                    account: u.account,
                    index: u.index,
                    script_pubkey: u.script_pubkey,
                })
                .collect(),
            sanad_seals: config
                .sanad_seals
                .into_iter()
                .map(|s| csv_bitcoin::config::SanadSealConfig {
                    sanad_id: s.sanad_id,
                    anchor_txid: s.anchor_txid,
                    vout: s.vout,
                    commitment: s.commitment,
                })
                .collect(),
        };

        // Create ChainBackend from config first — this registers all sanad_seals.
        // Transport selection lives entirely in `BitcoinRpcBackend::build_rpc`.
        let rpc_client =
            rpc_backend.build_rpc(rpc_endpoint.url.clone(), rpc_endpoint.api_key.clone());

        let seal = BitcoinSealProtocol::from_config(btc_config, rpc_client).map_err(|e| {
            FactoryError::CreationFailed(format!(
                "Failed to create BitcoinSealProtocol for ChainBackend: {}",
                e
            ))
        })?;
        let seal_arc = Arc::new(seal);

        // Load UTXO data for every registered sanad_seal from RPC (needed for spending)
        if has_sanad_seals && let Err(e) = seal_arc.load_sanad_seal_utxos().await {
            log::warn!("Failed to load sanad seal UTXOs: {}", e);
        }

        let chain_backend: Arc<dyn ChainBackend> = Arc::new(
            BitcoinBackend::from_seal_protocol(Arc::clone(&seal_arc)).map_err(|e| {
                FactoryError::CreationFailed(format!("Failed to create BitcoinBackend: {}", e))
            })?,
        );

        // Create ChainAdapter from the SAME seal_arc — shares the wallet + sanad_seals
        let btc_network_for_runtime = network.to_bitcoin_network();
        let rpc_adapter =
            rpc_backend.build_rpc(rpc_endpoint.url.clone(), rpc_endpoint.api_key.clone());

        let chain_adapter: Box<dyn ChainAdapter> =
            Box::new(BitcoinRuntimeAdapter::from_seal_protocol(
                btc_network_for_runtime,
                Arc::clone(&seal_arc),
                rpc_adapter,
            ));

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
