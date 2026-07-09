//! Bitcoin wallet operations implementing the WalletOperations trait
//!
//! This module provides chain-specific wallet operations for Bitcoin,
//! implementing the generic WalletOperations trait from csv-wallet.

use crate::rpc::BitcoinRpc;
use crate::wallet::{Bip86Path, SealWallet};
use async_trait::async_trait;
use bitcoin::{Network as BtcNetwork, OutPoint, Txid, hashes::Hash};
use csv_hash::chain_id::ChainId;
use csv_wallet::error::WalletError;
use csv_wallet::wallet_traits::WalletOperations;
use std::collections::HashMap;

#[cfg(any(feature = "rpc", feature = "signet-rest"))]
use std::sync::Arc;

#[cfg(any(feature = "rpc", feature = "signet-rest"))]
use reqwest::Client as ReqwestClient;
#[cfg(any(feature = "rpc", feature = "signet-rest"))]
use serde_json::Value;

/// Network type for wallet operations
#[derive(Debug, Clone, Copy)]
pub enum Network {
    Main,
    Test,
    Dev,
}

impl Network {
    fn to_bitcoin_network(self) -> BtcNetwork {
        match self {
            Network::Main => BtcNetwork::Bitcoin,
            Network::Test => BtcNetwork::Signet,
            Network::Dev => BtcNetwork::Regtest,
        }
    }

    fn esplora_url(&self) -> &'static str {
        match self {
            Network::Main => "https://mempool.space/api",
            Network::Test => "https://mempool.space/signet/api",
            Network::Dev => "http://localhost:3000/api",
        }
    }
}

/// Comprehensive UTXO data with wallet integration
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub scriptpubkey_hex: Option<String>,
    pub outpoint: OutPoint,
    pub derivation_path: Bip86Path,
}

/// Bitcoin wallet operations implementation
pub struct BitcoinWalletOperations {
    network: Network,
    #[cfg(any(feature = "rpc", feature = "signet-rest"))]
    http_client: Option<Arc<ReqwestClient>>,
}

impl BitcoinWalletOperations {
    /// Create new Bitcoin wallet operations
    pub fn new(network: Network) -> Self {
        Self {
            network,
            #[cfg(any(feature = "rpc", feature = "signet-rest"))]
            http_client: None,
        }
    }

    /// Create new Bitcoin wallet operations with HTTP client
    #[cfg(any(feature = "rpc", feature = "signet-rest"))]
    pub fn with_http(network: Network) -> Self {
        Self {
            network,
            http_client: Some(Arc::new(ReqwestClient::new())),
        }
    }

    /// Convert network to Bitcoin network type
    fn btc_network(&self) -> BtcNetwork {
        self.network.to_bitcoin_network()
    }

    /// Get the HTTP client if configured
    #[cfg(any(feature = "rpc", feature = "signet-rest"))]
    fn http_client(&self) -> Result<&Arc<ReqwestClient>, WalletError> {
        self.http_client
            .as_ref()
            .ok_or_else(|| WalletError::RpcNotConfigured("Bitcoin".to_string()))
    }
}

#[async_trait]
impl WalletOperations for BitcoinWalletOperations {
    fn chain_id(&self) -> ChainId {
        ChainId::new("bitcoin")
    }

    fn derive_address(&self, seed: &[u8], account: u32, index: u32) -> Result<String, WalletError> {
        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation(format!(
                "Seed must be at least 64 bytes, got {}",
                seed.len()
            )));
        }

        let wallet = SealWallet::from_seed(&seed_array, self.btc_network())
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to create wallet: {}", e)))?;

        let key = wallet
            .get_funding_address(account, index)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive address: {}", e)))?;

        Ok(key.address.to_string())
    }

    async fn get_balance(&self, _address: &str) -> Result<String, WalletError> {
        #[cfg(any(feature = "rpc", feature = "signet-rest"))]
        {
            let client = self.http_client()?;
            let url = format!("{}/address/{}", self.network.esplora_url(), _address);

            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to get balance: {}", e)))?;

            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;

            let balance = data["chain_stats"]
                .get("funded_txo_sum")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            Ok(balance.to_string())
        }

        #[cfg(not(any(feature = "rpc", feature = "signet-rest")))]
        {
            Err(WalletError::RpcNotConfigured("Bitcoin".to_string()))
        }
    }

    async fn sign_transaction(
        &self,
        _seed: &[u8],
        _tx_data: &[u8],
    ) -> Result<Vec<u8>, WalletError> {
        // Fail closed. The previous implementation treated `tx_data` as a raw
        // 32-byte digest and produced a bare ECDSA signature over it, with no
        // sighash construction, no input/prevout binding, and no witness
        // assembly. That is not a spendable Bitcoin signature and must never be
        // returned. A real implementation must build the correct sighash for
        // each input and assemble a valid signed transaction.
        Err(WalletError::Signing(
            "Bitcoin transaction signing is not implemented: refusing to \
             produce a bare ECDSA signature that is not bound to a proper \
             sighash. Use a real Bitcoin transaction signing path before \
             broadcasting."
                .to_string(),
        ))
    }

    async fn broadcast_transaction(&self, _signed_tx: &[u8]) -> Result<String, WalletError> {
        #[cfg(any(feature = "rpc", feature = "signet-rest"))]
        {
            let client = self.http_client()?;
            let url = format!("{}/tx", self.network.esplora_url());

            let tx_hex = hex::encode(_signed_tx);

            let response = client.post(&url).body(tx_hex).send().await.map_err(|e| {
                WalletError::RpcError(format!("Failed to broadcast transaction: {}", e))
            })?;

            let txid: String = response
                .text()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;

            Ok(txid)
        }

        #[cfg(not(any(feature = "rpc", feature = "signet-rest")))]
        {
            Err(WalletError::RpcNotConfigured("Bitcoin".to_string()))
        }
    }

    async fn get_transaction_status(
        &self,
        _tx_hash: &str,
    ) -> Result<HashMap<String, String>, WalletError> {
        #[cfg(any(feature = "rpc", feature = "signet-rest"))]
        {
            let client = self.http_client()?;
            let url = format!("{}/tx/{}", self.network.esplora_url(), _tx_hash);

            let response =
                client.get(&url).send().await.map_err(|e| {
                    WalletError::RpcError(format!("Failed to get transaction: {}", e))
                })?;

            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;

            let mut status = HashMap::new();
            status.insert("txid".to_string(), _tx_hash.to_string());
            status.insert(
                "status".to_string(),
                data["status"]
                    .get("confirmed")
                    .and_then(|v| v.as_bool())
                    .map(|c| {
                        if c {
                            "confirmed".to_string()
                        } else {
                            "pending".to_string()
                        }
                    })
                    .unwrap_or("unknown".to_string()),
            );
            status.insert(
                "block_height".to_string(),
                data["status"]
                    .get("block_height")
                    .and_then(|v| v.as_u64())
                    .map(|h| h.to_string())
                    .unwrap_or_default(),
            );

            Ok(status)
        }

        #[cfg(not(any(feature = "rpc", feature = "signet-rest")))]
        {
            Err(WalletError::RpcNotConfigured("Bitcoin".to_string()))
        }
    }

    async fn scan_utxos(
        &self,
        seed: &[u8],
        account: u32,
        _index: u32,
        rpc_url: &str,
        indexer_kind: Option<&str>,
    ) -> Result<Vec<(String, u32, u64, Option<String>)>, WalletError> {
        // Address→UTXO discovery is a REST capability. `indexer_kind` explicitly
        // selects the REST flavour (esplora vs Blockbook) — we never sniff the
        // URL. `rpc_url` is the indexer base the caller resolved from
        // BitcoinConfig::indexer_url. A JSON-RPC URL here fails closed with a
        // clear error rather than being silently rerouted to a public indexer.
        #[cfg(feature = "signet-rest")]
        {
            use crate::config::BitcoinRpcBackend;
            let backend = match indexer_kind {
                Some("blockbook") | Some("alchemy") => BitcoinRpcBackend::BlockbookRest,
                Some("blockstream") => BitcoinRpcBackend::BlockstreamRest,
                // None / "esplora" / "mempool" / anything else → esplora REST.
                _ => BitcoinRpcBackend::MempoolRest,
            };
            let rpc = backend.build_rpc(rpc_url.to_string(), None);
            Self::scan_utxos(seed, self.network, account, 20, rpc.as_ref()).await
        }
        #[cfg(not(feature = "signet-rest"))]
        {
            let _ = (seed, account, rpc_url, indexer_kind);
            Err(WalletError::RpcError(
                "UTXO scanning requires the `signet-rest` feature (REST indexer client)"
                    .to_string(),
            ))
        }
    }
}

/// Additional Bitcoin-specific wallet operations
impl BitcoinWalletOperations {
    /// Derive a Bitcoin funding address from seed
    pub fn derive_funding_address(
        seed: &[u8],
        network: Network,
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
        let ops = Self::new(network);
        ops.derive_address(seed, account, index)
    }

    /// Scan for UTXOs on Bitcoin network with comprehensive wallet integration
    /// Returns the wallet with UTXOs added for signing operations
    pub async fn scan_utxos_with_wallet(
        seed: &[u8],
        network: Network,
        account: u32,
        gap_limit: usize,
        rpc: &dyn BitcoinRpc,
    ) -> Result<(SealWallet, Vec<WalletUtxo>), WalletError> {
        let btc_network = network.to_bitcoin_network();

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation(
                "Seed must be at least 64 bytes".to_string(),
            ));
        }

        let wallet = SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to create wallet: {}", e)))?;

        let mut wallet_utxos = Vec::new();

        for index in 0..gap_limit as u32 {
            let key = wallet.get_funding_address(account, index).map_err(|e| {
                WalletError::KeyDerivation(format!("Failed to derive address: {}", e))
            })?;
            let address_str = key.address.to_string();

            // Address→UTXO discovery goes through the injected REST indexer client.
            // Fail closed on RPC error: a failed query must not be silently treated
            // as "address empty" when we are about to load these UTXOs for signing.
            let found = rpc
                .get_utxos_for_address(address_str.clone())
                .await
                .map_err(|e| {
                    WalletError::RpcError(format!(
                        "UTXO scan failed for address {}: {}",
                        address_str, e
                    ))
                })?;

            for utxo in found {
                // UtxoInfo.txid is internal byte order (RPC clients normalize on parse).
                let outpoint = OutPoint {
                    txid: Txid::from_byte_array(utxo.txid),
                    vout: utxo.vout,
                };
                let value = utxo.amount_sat;

                // scriptPubKey is needed for correct sighash calculation; fetch it
                // via the same client (esplora /tx/{txid}).
                let scriptpubkey_hex = rpc
                    .get_utxo_scriptpubkey(utxo.txid, utxo.vout)
                    .await
                    .ok()
                    .flatten();

                let derivation_path = Bip86Path::external(account, index);

                if let Some(spk_hex) = scriptpubkey_hex.as_ref() {
                    if let Ok(spk_bytes) = hex::decode(spk_hex) {
                        let script_pubkey = bitcoin::ScriptBuf::from_bytes(spk_bytes);
                        wallet.add_utxo_with_scriptpubkey(
                            outpoint,
                            value,
                            derivation_path.clone(),
                            Some(script_pubkey),
                            None,
                        );
                    } else {
                        wallet.add_utxo(outpoint, value, derivation_path.clone());
                    }
                } else {
                    wallet.add_utxo(outpoint, value, derivation_path.clone());
                }

                // Persist txid in display format (reversed internal order), matching
                // what downstream UTXO records expect.
                let mut display = utxo.txid;
                display.reverse();
                wallet_utxos.push(WalletUtxo {
                    txid: hex::encode(display),
                    vout: utxo.vout,
                    value,
                    scriptpubkey_hex,
                    outpoint,
                    derivation_path,
                });
            }
        }

        Ok((wallet, wallet_utxos))
    }

    /// Validate a UTXO on-chain - check transaction exists, is confirmed, and is unspent
    pub async fn validate_utxo_onchain(
        txid: &str,
        vout: u32,
        rpc_url: &str,
    ) -> Result<(bool, bool, bool, Option<serde_json::Value>), WalletError> {
        let tx_url = format!("{}/tx/{}", rpc_url, txid);
        let tx_response = reqwest::get(&tx_url).await;

        let (tx_exists, tx_data, is_confirmed) = match tx_response {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let status = data.get("status").and_then(|s| s.as_object());
                    let confirmed = status
                        .and_then(|s| s.get("confirmed"))
                        .and_then(|c| c.as_bool())
                        .unwrap_or(false);
                    (true, Some(data), confirmed)
                } else {
                    (true, None, false)
                }
            }
            Ok(resp) if resp.status() == 404 => (false, None, false),
            Ok(_) => (true, None, false),
            Err(_) => (true, None, false),
        };

        if !tx_exists {
            return Ok((false, false, false, None));
        }

        // Check if UTXO is unspent
        let spend_url = format!("{}/tx/{}/outspend/{}", rpc_url, txid, vout);
        let spend_response = reqwest::get(&spend_url).await;

        let is_unspent = match spend_response {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(spend_status) = resp.json::<serde_json::Value>().await {
                    let spent = spend_status
                        .get("spent")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    !spent
                } else {
                    false
                }
            }
            _ => false,
        };

        Ok((tx_exists, is_confirmed, is_unspent, tx_data))
    }

    /// Scan for UTXOs on Bitcoin network with comprehensive verification
    pub async fn scan_utxos(
        seed: &[u8],
        network: Network,
        account: u32,
        gap_limit: usize,
        rpc: &dyn BitcoinRpc,
    ) -> Result<Vec<(String, u32, u64, Option<String>)>, WalletError> {
        let btc_network = network.to_bitcoin_network();

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation(
                "Seed must be at least 64 bytes".to_string(),
            ));
        }

        let wallet = SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to create wallet: {}", e)))?;

        let mut utxos = Vec::new();
        // Track per-address RPC outcomes so that a fully-unreachable indexer
        // (every address query failing) is reported as a hard error instead of
        // being silently reinterpreted as "wallet has no UTXOs". Conflating "RPC
        // is down" with "address is empty" would let Sanad creation proceed (or
        // report a false negative) on stale/missing chain data, which violates
        // the fail-closed requirement for UTXO discovery feeding seal-backed
        // Sanad creation.
        let mut addresses_checked = 0usize;
        let mut rpc_failures = 0usize;
        let mut last_rpc_error: Option<String> = None;

        for index in 0..gap_limit as u32 {
            let key = wallet.get_funding_address(account, index).map_err(|e| {
                WalletError::KeyDerivation(format!("Failed to derive address: {}", e))
            })?;
            let address_str = key.address.to_string();
            addresses_checked += 1;

            match rpc.get_utxos_for_address(address_str.clone()).await {
                Ok(found) => {
                    for utxo in found {
                        // scriptPubKey (needed downstream for sighash) is fetched via
                        // the same client; a missing/failed lookup is tolerated as None.
                        let scriptpubkey_hex = rpc
                            .get_utxo_scriptpubkey(utxo.txid, utxo.vout)
                            .await
                            .ok()
                            .flatten();

                        // Emit txid in display format (reversed internal order).
                        let mut display = utxo.txid;
                        display.reverse();
                        utxos.push((
                            hex::encode(display),
                            utxo.vout,
                            utxo.amount_sat,
                            scriptpubkey_hex,
                        ));
                    }
                }
                Err(e) => {
                    rpc_failures += 1;
                    last_rpc_error = Some(format!(
                        "get_utxos_for_address({}) failed: {}",
                        address_str, e
                    ));
                }
            }
        }

        // Fail closed: if every address query failed at the RPC layer, we cannot
        // distinguish "wallet is empty" from "indexer is unreachable". Returning
        // Ok(vec![]) here would let callers (e.g. `csv sanad create --chain
        // bitcoin`) report "no UTXOs found, fund the address" when the real
        // problem is an unreachable indexer - masking the failure instead of
        // surfacing it.
        if addresses_checked > 0 && rpc_failures == addresses_checked {
            return Err(WalletError::RpcError(format!(
                "UTXO scan failed for all {} address(es): {}",
                addresses_checked,
                last_rpc_error.unwrap_or_else(|| "unknown error".to_string())
            )));
        }

        Ok(utxos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id() {
        let ops = BitcoinWalletOperations::new(Network::Test);
        assert_eq!(ops.chain_id().as_str(), "bitcoin");
    }

    #[test]
    fn test_derive_address() {
        let ops = BitcoinWalletOperations::new(Network::Test);
        let seed = [42u8; 64];
        let address = ops.derive_address(&seed, 0, 0);
        assert!(address.is_ok());
        let addr_str = address.unwrap();
        // Testnet taproot addresses start with "tb1p"
        assert!(addr_str.starts_with("tb1p"));
    }

    /// Regression test: when the configured RPC/indexer endpoint is completely
    /// unreachable, `scan_utxos` must fail closed (return Err) instead of
    /// silently reporting an empty UTXO set. Conflating "RPC down" with
    /// "wallet empty" would let `csv sanad create --chain bitcoin` either
    /// proceed on stale state or tell the user to fund an address that may
    /// already be funded, masking a real infrastructure failure.
    /// A `BitcoinRpc` whose address-index queries always fail, standing in for an
    /// unreachable/erroring indexer. Only the methods `scan_utxos` touches need
    /// real behaviour; the rest defer to the trait defaults.
    struct FailingIndexerRpc;

    #[async_trait]
    impl BitcoinRpc for FailingIndexerRpc {
        async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            Err("unreachable".into())
        }
        async fn get_block_hash(
            &self,
            _height: u64,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            Err("unreachable".into())
        }
        async fn is_utxo_unspent(
            &self,
            _txid: [u8; 32],
            _vout: u32,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Err("unreachable".into())
        }
        async fn send_raw_transaction(
            &self,
            _tx: Vec<u8>,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            Err("unreachable".into())
        }
        async fn get_tx_confirmations(
            &self,
            _txid: [u8; 32],
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            Err("unreachable".into())
        }
        async fn get_utxos_for_address(
            &self,
            _address: String,
        ) -> Result<Vec<crate::rpc::UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
            Err("indexer unreachable: connection refused".into())
        }
        fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync> {
            Box::new(FailingIndexerRpc)
        }
    }

    #[tokio::test]
    async fn test_scan_utxos_fails_closed_when_rpc_unreachable() {
        let seed = [7u8; 64];
        let rpc = FailingIndexerRpc;

        let result = BitcoinWalletOperations::scan_utxos(
            &seed,
            Network::Test,
            0,
            /* gap_limit */ 2,
            &rpc,
        )
        .await;

        assert!(
            result.is_err(),
            "scan_utxos must fail closed when the RPC endpoint is unreachable for every address, got: {:?}",
            result
        );
        let err = result.unwrap_err();
        match err {
            WalletError::RpcError(msg) => {
                assert!(
                    msg.contains("UTXO scan failed"),
                    "unexpected RpcError message: {}",
                    msg
                );
            }
            other => panic!("expected WalletError::RpcError, got {:?}", other),
        }
    }
}
