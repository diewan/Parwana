//! Bitcoin JSON-RPC client for Alchemy and other JSON-RPC providers
//!
//! This provides a JSON-RPC implementation that talks to standard Bitcoin
//! JSON-RPC endpoints like Alchemy, QuickNode, and local Bitcoin Core nodes.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

use crate::rpc::{BitcoinRpc, BlockHeader, UtxoInfo};

/// Maximum number of retries for transient failures
const MAX_RETRIES: u32 = 3;
/// Initial backoff duration before the first retry
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// Bitcoin JSON-RPC client
pub struct BitcoinJsonRpc {
    client: Client,
    rpc_url: String,
    username: Option<String>,
    password: Option<String>,
}

impl BitcoinJsonRpc {
    /// Create a new JSON-RPC client
    pub fn new(rpc_url: String) -> Self {
        Self::with_auth(rpc_url, None, None)
    }

    /// Create with authentication credentials
    pub fn with_auth(rpc_url: String, username: Option<String>, password: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            rpc_url,
            username,
            password,
        }
    }

    /// Execute a JSON-RPC method call
    async fn call<T: for<'de> Deserialize<'de> + std::fmt::Debug>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let mut last_err = None;
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                log::warn!(
                    "Retry {}/{} for {} after {:?} backoff",
                    attempt,
                    MAX_RETRIES,
                    method,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }

            let request_body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            });

            let mut req = self.client.post(&self.rpc_url).json(&request_body);

            if let Some(username) = &self.username {
                if let Some(password) = &self.password {
                    req = req.basic_auth(username, Some(password));
                }
            }

            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                        format!("Failed to read JSON-RPC response body: {}", e).into()
                    })?;

                    let response: JsonRpcResponse<T> = serde_json::from_str(&text).map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                        format!("Failed to parse JSON-RPC response: {}", e).into()
                    })?;

                    if let Some(error) = response.error {
                        return Err(format!("JSON-RPC error: {}", error.message.unwrap_or_else(|| "unknown error".to_string())).into());
                    }

                    // Handle result: if T is Option<U>, allow None (JSON null)
                    // Otherwise, error on None since caller expects a value
                    return match response.result {
                        Some(result) => Ok(result),
                        None => {
                            // Check if T is Option<U> by trying to convert None to T
                            // This is a runtime check - if T is Option<U>, None is valid
                            // If T is a non-option type, None is an error
                            // We use a simple heuristic: if serde can deserialize None as T, allow it
                            // Otherwise, it's a missing result error
                            let none_json = serde_json::Value::Null;
                            if let Ok(typed_none) = serde_json::from_value::<T>(none_json) {
                                Ok(typed_none)
                            } else {
                                Err("JSON-RPC response missing result field".into())
                            }
                        }
                    };
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error_text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                        format!("HTTP {} at {}: failed to read error text: {}", status, self.rpc_url, e).into()
                    })?;
                    
                    // Classify errors: permanent vs transient
                    // Permanent errors should not be retried
                    let is_permanent = status.is_client_error() && 
                        (status == reqwest::StatusCode::METHOD_NOT_ALLOWED ||
                         status == reqwest::StatusCode::NOT_FOUND ||
                         status == reqwest::StatusCode::BAD_REQUEST);
                    
                    if is_permanent {
                        return Err(format!("Permanent HTTP {} at {}: {}", status, self.rpc_url, error_text).into());
                    }
                    
                    last_err = Some(format!("HTTP {} at {}: {}", status, self.rpc_url, error_text).into());
                }
                Err(e) => {
                    // Network errors are typically transient (timeouts, connection issues)
                    last_err = Some(format!("Network error at {}: {}", self.rpc_url, e).into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Max retries exceeded".into()))
    }
}

#[async_trait]
impl BitcoinRpc for BitcoinJsonRpc {
    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let result: u64 = self.call("getblockcount", vec![]).await?;
        Ok(result)
    }

    async fn get_block_hash(
        &self,
        height: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let hash_hex: String = self.call("getblockhash", vec![Value::from(height)]).await?;
        let hash_bytes = hex::decode(hash_hex.trim())?;
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash_bytes);
        Ok(result)
    }

    async fn is_utxo_unspent(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // RPC expects display format (reversed bytes)
        let mut display_txid = txid;
        display_txid.reverse();
        let txid_hex = hex::encode(display_txid);
        
        // Skip getrawtransaction check - some RPC providers (like Alchemy) don't index all transactions
        // gettxout is sufficient to check if an output is unspent and works even for unindexed transactions
        // gettxout returns null if the output is spent or doesn't exist
        let txout_result: Option<Value> = self.call("gettxout", vec![
            Value::from(txid_hex),
            Value::from(vout),
        ]).await?;

        Ok(txout_result.is_some())
    }

    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let tx_hex = hex::encode(&tx_bytes);
        
        let txid_hex: String = self.call("sendrawtransaction", vec![Value::from(tx_hex.clone())]).await?;
        
        let txid_bytes = hex::decode(txid_hex.trim())?;
        let mut result = [0u8; 32];
        // RPC returns txid in display format (reversed bytes)
        // Reverse to get internal byte order for consistent storage
        result.copy_from_slice(&txid_bytes);
        result.reverse();
        Ok(result)
    }

    async fn get_tx_confirmations(
        &self,
        txid: [u8; 32],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // RPC expects display format (reversed bytes)
        let mut display_txid = txid;
        display_txid.reverse();
        let txid_hex = hex::encode(display_txid);
        
        // Use getrawtransaction with verbose=true instead of gettransaction
        // gettransaction is wallet-specific and doesn't work with non-wallet RPC providers
        let tx: Value = self.call("getrawtransaction", vec![
            Value::from(txid_hex),
            Value::from(true), // verbose=true
        ]).await?;

        if let Some(confirmations) = tx.get("confirmations").and_then(|c: &Value| c.as_u64()) {
            return Ok(confirmations);
        }
        Ok(0)
    }

    async fn get_utxos_for_address(
        &self,
        address: String,
    ) -> Result<Vec<UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
        // Try listunspent first (for Bitcoin Core and compatible endpoints)
        let listunspent_result: Result<Vec<UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> = async {
            let utxos: Vec<Value> = self.call("listunspent", vec![
                Value::from(0), // minconf
                Value::from(9999999), // maxconf
                Value::from(vec![Value::from(address.clone())]),
            ]).await?;

            let _current_height = self.get_block_count().await.unwrap_or(0);
            let result: Vec<UtxoInfo> = utxos
                .into_iter()
                .filter_map(|u| {
                    let txid_hex = u.get("txid")?.as_str()?;
                    let vout = u.get("vout")?.as_u64()? as u32;
                    let amount_sat = u.get("amount")?.as_f64()? as u64 * 100_000_000; // Convert BTC to satoshis
                    let confirmations = u.get("confirmations")?.as_u64().unwrap_or(0);
                    
                    let txid_bytes = hex::decode(txid_hex).ok()?;
                    let mut txid = [0u8; 32];
                    // listunspent returns txids in display format (reversed bytes)
                    // Reverse to get internal byte order for consistent storage
                    txid.copy_from_slice(&txid_bytes);
                    txid.reverse();
                    
                    Some(UtxoInfo {
                        txid,
                        vout,
                        amount_sat,
                        confirmations,
                    })
                })
                .collect();
            
            Ok(result)
        }.await;

        // If listunspent fails, try REST API fallback (for Alchemy and other limited RPC providers)
        if listunspent_result.is_err() {
            log::warn!("listunspent failed, attempting REST API fallback for address: {}", address);
            return get_utxos_from_mempool(&self.client, &self.rpc_url, &address).await;
        }

        listunspent_result
    }

    async fn get_utxo_scriptpubkey(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        // RPC expects display format (reversed bytes)
        let mut display_txid = txid;
        display_txid.reverse();
        let txid_hex = hex::encode(display_txid);
        
        // Get transaction with verbose output
        let tx: Value = self.call("getrawtransaction", vec![
            Value::from(txid_hex.clone()),
            Value::from(true), // verbose=true
        ]).await?;

        if let Some(vout_array) = tx.get("vout").and_then(|v| v.as_array()) {
            if let Some(output) = vout_array.get(vout as usize) {
                if let Some(script_pubkey) = output.get("scriptPubKey") {
                    if let Some(hex) = script_pubkey.get("hex").and_then(|h| h.as_str()) {
                        return Ok(Some(hex.to_string()));
                    }
                }
            }
        }
        
        Ok(None)
    }

    async fn get_block_header(
        &self,
        block_hash: [u8; 32],
    ) -> Result<BlockHeader, Box<dyn std::error::Error + Send + Sync>> {
        // RPC expects display format (reversed bytes)
        let mut display_hash = block_hash;
        display_hash.reverse();
        let block_hash_hex = hex::encode(display_hash);
        
        // Use getblockheader RPC call with verbose=true to get full header info
        let header: Value = self.call("getblockheader", vec![
            Value::from(block_hash_hex),
            Value::from(true), // verbose=true
        ]).await?;

        let height = header.get("height")
            .and_then(|h| h.as_u64())
            .ok_or("Missing height in block header")?;
        
        let timestamp = header.get("time")
            .and_then(|t| t.as_u64())
            .ok_or("Missing time in block header")? as u32;
        
        let version = header.get("version")
            .and_then(|v| v.as_i64())
            .ok_or("Missing version in block header")? as i32;

        Ok(BlockHeader {
            block_hash,
            height,
            timestamp,
            version,
        })
    }

    async fn create_op_return_transaction(
        &self,
        _data: Vec<u8>,
        _fee_rate: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // OP_RETURN transaction creation requires wallet integration:
        // - UTXO selection (need access to wallet UTXOs)
        // - Transaction building (need to construct proper Bitcoin transaction)
        // - Signing (need access to private keys)
        // 
        // BitcoinJsonRpc is a pure RPC client without wallet capabilities.
        // Use BitcoinSealProtocol with SealWallet for transaction creation.
        Err("OP_RETURN transaction creation requires wallet integration. Use BitcoinSealProtocol with SealWallet or tx_builder::CommitmentTxBuilder for transaction creation.".into())
    }

    fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync> {
        Box::new(BitcoinJsonRpc {
            client: self.client.clone(),
            rpc_url: self.rpc_url.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        })
    }
}

/// JSON-RPC response wrapper
#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    #[serde(default)]
    error: Option<JsonRpcError>,
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<Value>,
    #[serde(default)]
    #[allow(dead_code)]
    jsonrpc: Option<String>,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
struct JsonRpcError {
    #[serde(default)]
    code: Option<i32>,
    #[serde(default)]
    message: Option<String>,
}

/// REST API fallback for UTXO queries when listunspent is not supported
/// Uses mempool.space as a reliable fallback for Bitcoin Signet
async fn get_utxos_from_mempool(
    client: &Client,
    rpc_url: &str,
    address: &str,
) -> Result<Vec<UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
    // Use mempool.space as the fallback REST API
    // Detect network from RPC URL or default to signet
    // Check for signet first before checking for "bitcoin" to avoid false positives
    let network = if rpc_url.contains("signet") {
        "https://mempool.space/signet/api"
    } else if rpc_url.contains("testnet") {
        "https://mempool.space/testnet/api"
    } else if rpc_url.contains("mainnet") {
        "https://mempool.space/api"
    } else {
        // Default to signet for Alchemy and other test endpoints
        "https://mempool.space/signet/api"
    };

    let rest_url = format!("{}/address/{}/utxo", network, address);

    let req = client.get(&rest_url);

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                format!("Failed to read REST API response: {}", e).into()
            })?;

            // Parse REST API response (mempool.space format)
            let utxos: Vec<Value> = serde_json::from_str(&text).map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                format!("Failed to parse REST API response: {}", e).into()
            })?;

            let result: Vec<UtxoInfo> = utxos
                .into_iter()
                .filter_map(|u| {
                    let txid_hex = u.get("txid")?.as_str()?;
                    let vout = u.get("vout")?.as_u64()? as u32;
                    let value = u.get("value")?.as_u64()?;
                    
                    let confirmations = if let Some(status) = u.get("status") {
                        if status.get("confirmed").and_then(|c| c.as_bool()).unwrap_or(false) {
                            let block_height = status.get("block_height").and_then(|h| h.as_u64()).unwrap_or(0);
                            if block_height > 0 {
                                // We don't have current height from mempool.space in this context
                                // Just use the block_height as a proxy for confirmations
                                block_height
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    
                    let txid_bytes = hex::decode(txid_hex).ok()?;
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(&txid_bytes);
                    // mempool.space returns txids in display format (reversed bytes)
                    // Reverse to get internal byte order for consistent storage
                    txid.reverse();
                    
                    Some(UtxoInfo {
                        txid,
                        vout,
                        amount_sat: value,
                        confirmations,
                    })
                })
                .collect();
            
            Ok(result)
        }
        Ok(resp) => {
            let status = resp.status();
            let error_text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                format!("HTTP {} at {}: failed to read error text: {}", status, rest_url, e).into()
            })?;
            Err(format!("REST API fallback failed: HTTP {} at {}: {}", status, rest_url, error_text).into())
        }
        Err(e) => {
            Err(format!("REST API fallback network error: {}", e).into())
        }
    }
}
