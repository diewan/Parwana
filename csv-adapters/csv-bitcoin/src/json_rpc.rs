//! Bitcoin JSON-RPC client for Alchemy and other JSON-RPC providers
//!
//! This provides a JSON-RPC implementation that talks to standard Bitcoin
//! JSON-RPC endpoints like Alchemy, QuickNode, and local Bitcoin Core nodes.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

use crate::rpc::{BitcoinRpc, UtxoInfo};

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

                    return response.result.ok_or_else(|| {
                        "JSON-RPC response missing result field".into()
                    });
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
        
        // Try to get the transaction to see if it exists
        let _tx_result: Value = self.call("getrawtransaction", vec![
            Value::from(txid_hex.clone()),
            Value::from(false), // verbose=false
        ]).await?;

        // Transaction exists, now check if the output is spent
        // Using gettxout to check if output is still unspent
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
        // Use listunspent to get UTXOs for an address
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
