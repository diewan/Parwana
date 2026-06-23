//! Bitcoin wallet operations implementing the WalletOperations trait
//!
//! This module provides chain-specific wallet operations for Bitcoin,
//! implementing the generic WalletOperations trait from csv-wallet.

use crate::wallet::{Bip86Path, SealWallet};
use async_trait::async_trait;
use bitcoin::{hashes::Hash, Network as BtcNetwork, OutPoint, Txid};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey as SecpPublicKey};
use csv_hash::chain_id::ChainId;
use csv_wallet::error::WalletError;
use csv_wallet::wallet_traits::WalletOperations;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(any(feature = "rpc", feature = "signet-rest"))]
use reqwest::Client as ReqwestClient;
#[cfg(feature = "rpc")]
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
        self.http_client.as_ref().ok_or_else(|| {
            WalletError::RpcNotConfigured("Bitcoin".to_string())
        })
    }
}

#[async_trait]
impl WalletOperations for BitcoinWalletOperations {
    fn chain_id(&self) -> ChainId {
        ChainId::new("bitcoin")
    }

    fn derive_address(
        &self,
        seed: &[u8],
        account: u32,
        index: u32,
    ) -> Result<String, WalletError> {
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

    async fn get_balance(&self, address: &str) -> Result<String, WalletError> {
        #[cfg(any(feature = "rpc", feature = "signet-rest"))]
        {
            let client = self.http_client()?;
            let url = format!("{}/address/{}", self.network.esplora_url(), address);
            
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to get balance: {}", e)))?;
            
            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;
            
            let balance = data["chain_stats"].get("funded_txo_sum")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            
            Ok(balance.to_string())
        }
        
        #[cfg(not(any(feature = "rpc", feature = "signet-rest")))]
        {
            Err(WalletError::RpcNotConfigured("Bitcoin".to_string()))
        }
    }

    async fn sign_transaction(&self, seed: &[u8], tx_data: &[u8]) -> Result<Vec<u8>, WalletError> {
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation(format!(
                "Seed must be at least 64 bytes, got {}",
                seed.len()
            )));
        }

        // Derive secp256k1 private key from seed
        let secret_key = SecretKey::from_slice(&seed_array[..32])
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive private key: {}", e)))?;
        
        let secp = Secp256k1::new();
        let _public_key = SecpPublicKey::from_secret_key(&secp, &secret_key);
        
        // Sign the transaction data (simplified - in production would use proper Bitcoin transaction signing)
        let message = secp256k1::Message::from_digest_slice(tx_data)
            .map_err(|e| WalletError::Signing(format!("Failed to create message: {}", e)))?;
        let signature = secp.sign_ecdsa(&message, &secret_key);
        
        Ok(signature.serialize_compact().to_vec())
    }

    async fn broadcast_transaction(&self, signed_tx: &[u8]) -> Result<String, WalletError> {
        #[cfg(any(feature = "rpc", feature = "signet-rest"))]
        {
            let client = self.http_client()?;
            let url = format!("{}/tx", self.network.esplora_url());
            
            let tx_hex = hex::encode(signed_tx);
            
            let response = client
                .post(&url)
                .body(tx_hex)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to broadcast transaction: {}", e)))?;
            
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


    async fn get_transaction_status(&self, tx_hash: &str) -> Result<HashMap<String, String>, WalletError> {
        #[cfg(any(feature = "rpc", feature = "signet-rest"))]
        {
            let client = self.http_client()?;
            let url = format!("{}/tx/{}", self.network.esplora_url(), tx_hash);
            
            let response = client
                .get(&url)
                .send()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to get transaction: {}", e)))?;
            
            let data: Value = response
                .json()
                .await
                .map_err(|e| WalletError::RpcError(format!("Failed to parse response: {}", e)))?;
            
            let mut status = HashMap::new();
            status.insert("txid".to_string(), tx_hash.to_string());
            status.insert("status".to_string(), data["status"].get("confirmed")
                .and_then(|v| v.as_bool())
                .map(|c| if c { "confirmed".to_string() } else { "pending".to_string() })
                .unwrap_or("unknown".to_string()));
            status.insert("block_height".to_string(), data["status"].get("block_height")
                .and_then(|v| v.as_u64())
                .map(|h| h.to_string())
                .unwrap_or_default());
            
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
    ) -> Result<Vec<(String, u32, u64, Option<String>)>, WalletError> {
        Self::scan_utxos(seed, self.network, account, 20, rpc_url).await
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
        rpc_url: &str,
    ) -> Result<(SealWallet, Vec<WalletUtxo>), WalletError> {
        let btc_network = network.to_bitcoin_network();

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation("Seed must be at least 64 bytes".to_string()));
        }

        let wallet = SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to create wallet: {}", e)))?;

        let mut wallet_utxos = Vec::new();

        for index in 0..gap_limit as u32 {
            let key = wallet
                .get_funding_address(account, index)
                .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive address: {}", e)))?;
            let address_str = key.address.to_string();

            // Fetch UTXOs for this address using mempool RPC
            let url = format!("{}/address/{}/utxo", rpc_url, address_str);
            let response = reqwest::get(&url).await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let utxo_list: Vec<serde_json::Value> = resp
                        .json()
                        .await
                        .unwrap_or_default();

                    if !utxo_list.is_empty() {
                        for utxo in utxo_list {
                            let txid = utxo
                                .get("txid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let vout = utxo
                                .get("vout")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let value = utxo
                                .get("value")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);

                            // Fetch scriptPubKey from the transaction endpoint
                            let scriptpubkey_hex = if !txid.is_empty() {
                                let tx_url = format!("{}/tx/{}", rpc_url, txid);
                                if let Ok(tx_resp) = reqwest::get(&tx_url).await {
                                    if tx_resp.status().is_success() {
                                        if let Ok(tx_data) = tx_resp.json::<serde_json::Value>().await {
                                            if let Some(vouts) =
                                                tx_data.get("vout").and_then(|v| v.as_array())
                                            {
                                                if let Some(vout_data) = vouts.get(vout as usize) {
                                                    vout_data
                                                        .get("scriptpubkey")
                                                        .and_then(|v| v.as_str())
                                                        .map(|s| s.to_string())
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            // Create OutPoint - mempool.space returns txids in display format (reversed bytes)
                            let txid_bytes = match hex::decode(txid) {
                                Ok(bytes) if bytes.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    arr
                                }
                                _ => continue,
                            };
                            let mut internal_txid = txid_bytes;
                            internal_txid.reverse();
                            let txid_hash = Txid::from_byte_array(internal_txid);
                            let outpoint = OutPoint {
                                txid: txid_hash,
                                vout,
                            };

                            // Create Bip86Path
                            let derivation_path = Bip86Path::external(account, index);

                            // Add UTXO to wallet with scriptPubKey if available
                            if let Some(ref spk_hex) = scriptpubkey_hex {
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

                            wallet_utxos.push(WalletUtxo {
                                txid: txid.to_string(),
                                vout,
                                value,
                                scriptpubkey_hex,
                                outpoint,
                                derivation_path,
                            });
                        }
                    }
                }
                Ok(_resp) => {
                    // Non-success status - skip this address
                    continue;
                }
                Err(_) => {
                    // Request failed - skip this address
                    continue;
                }
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
        rpc_url: &str,
    ) -> Result<Vec<(String, u32, u64, Option<String>)>, WalletError> {
        let btc_network = network.to_bitcoin_network();

        // Convert seed slice to array
        let mut seed_array = [0u8; 64];
        if seed.len() >= 64 {
            seed_array.copy_from_slice(&seed[..64]);
        } else {
            return Err(WalletError::KeyDerivation("Seed must be at least 64 bytes".to_string()));
        }

        let wallet = SealWallet::from_seed(&seed_array, btc_network)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to create wallet: {}", e)))?;

        let mut utxos = Vec::new();

        for index in 0..gap_limit as u32 {
            let key = wallet
                .get_funding_address(account, index)
                .map_err(|e| WalletError::KeyDerivation(format!("Failed to derive address: {}", e)))?;
            let address_str = key.address.to_string();

            // Fetch UTXOs for this address using mempool RPC
            let url = format!("{}/address/{}/utxo", rpc_url, address_str);
            let response = reqwest::get(&url).await;

            match response {
                Ok(resp) if resp.status().is_success() => {
                    let utxo_list: Vec<serde_json::Value> = resp
                        .json()
                        .await
                        .unwrap_or_default();

                    if !utxo_list.is_empty() {
                        for utxo in utxo_list {
                            let txid = utxo
                                .get("txid")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let vout = utxo
                                .get("vout")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let value = utxo
                                .get("value")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);

                            // Fetch scriptPubKey from the transaction endpoint
                            let scriptpubkey_hex = if !txid.is_empty() {
                                let tx_url = format!("{}/tx/{}", rpc_url, txid);
                                if let Ok(tx_resp) = reqwest::get(&tx_url).await {
                                    if tx_resp.status().is_success() {
                                        if let Ok(tx_data) = tx_resp.json::<serde_json::Value>().await {
                                            if let Some(vouts) =
                                                tx_data.get("vout").and_then(|v| v.as_array())
                                            {
                                                if let Some(vout_data) = vouts.get(vout as usize) {
                                                    vout_data
                                                        .get("scriptpubkey")
                                                        .and_then(|v| v.as_str())
                                                        .map(|s| s.to_string())
                                                } else {
                                                    None
                                                }
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            utxos.push((txid.to_string(), vout, value, scriptpubkey_hex));
                        }
                    }
                }
                Ok(_resp) => {
                    // Non-success status - skip this address
                    continue;
                }
                Err(_) => {
                    // Request failed - skip this address
                    continue;
                }
            }
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
}
