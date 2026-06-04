//! Real Bitcoin Signet RPC via mempool.space public REST API
//!
//! This provides a production-ready RPC implementation that talks to
//! the mempool.space Signet REST API — no local Bitcoin Core node needed.
//!
//! Includes automatic retry with exponential backoff for transient failures.
//! Enable the `signet-rest` feature to use this implementation.

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use bitcoin_hashes::Hash as BitcoinHash;
use reqwest::Client;
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

use crate::proofs::extract_merkle_proof_from_block;
use crate::rpc::BitcoinRpc;
use crate::types::BitcoinInclusionProof;

/// Base URL for mempool.space Signet API
pub const MEMPOOL_SIGNET_BASE: &str = "https://mempool.space/signet/api";

/// Maximum number of retries for transient failures
const MAX_RETRIES: u32 = 3;
/// Initial backoff duration before the first retry
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// Real Bitcoin Signet RPC client backed by mempool.space REST API
pub struct MempoolSignetRpc {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

impl MempoolSignetRpc {
    /// Create a new RPC client for Signet (default: mempool.space)
    pub fn new() -> Self {
        Self::with_url(MEMPOOL_SIGNET_BASE.to_string())
    }

    /// Create with a custom base URL (for self-hosted mempool instances)
    pub fn with_url(base_url: String) -> Self {
        Self::with_url_and_key(base_url, None)
    }

    /// Create with a custom base URL and optional API key
    pub fn with_url_and_key(base_url: String, api_key: Option<String>) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        #[cfg(target_arch = "wasm32")]
        let client = Client::builder()
            .build()
            .expect("Failed to create HTTP client");

        // Strip trailing slashes to avoid double slashes in URL construction
        let base_url = base_url.trim_end_matches('/').to_string();

        Self { client, base_url, api_key }
    }

    #[cfg(target_arch = "wasm32")]
    fn run_http<T, F>(_future: F) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
    where
        T: 'static,
        F: std::future::Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>>
            + 'static,
    {
        // In WASM, we cannot block on async operations
        // The BitcoinRpc trait is synchronous by design, which is incompatible with WASM
        // This implementation is intentionally disabled for WASM targets
        // Use a different RPC implementation for WASM (e.g., browser-native fetch)
        Err(
            "MempoolSignetRpc is not supported on WASM - use a WASM-compatible RPC implementation"
                .into(),
        )
    }

    /// HTTP GET with automatic retry and exponential backoff
    #[cfg(not(target_arch = "wasm32"))]
    async fn get_with_retry<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        url: &str,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let url = url.to_string();
        let api_key = self.api_key.clone();

        let mut last_err = None;
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                log::warn!(
                    "Retry {}/{} for {} after {:?} backoff",
                    attempt,
                    MAX_RETRIES,
                    url,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }

            let mut request = client.get(&url);
            if let Some(key) = &api_key {
                request = request.header("x-api-key", key);
            }

       match request.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| e.into())?;
                    return serde_json::from_str::<T>(&text).map_err(|e| {
                        e.into()
                    });
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error_text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                        format!("HTTP {} at {}: failed to read error text: {}", status, url, e).into()
                    })?;
                    last_err = Some(format!("HTTP {} at {}: {}", status, url, error_text).into());
                }
                Err(e) => {
                    last_err = Some(format!("Network error at {}: {}", url, e).into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Max retries exceeded".into()))
    }

    #[cfg(target_arch = "wasm32")]
    fn get_with_retry<T: serde::de::DeserializeOwned + 'static>(
        &self,
        _url: &str,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        Err("MempoolSignetRpc is not supported on WASM".into())
    }

    /// HTTP GET text with retry
    #[cfg(not(target_arch = "wasm32"))]
    async fn get_text_with_retry(
        &self,
        url: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let url = url.to_string();

        let mut last_err = None;
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    return resp.text().await.map_err(|e| e.into());
                }
                Ok(resp) => {
                    last_err = Some(format!("HTTP {} at {}", resp.status(), url).into());
                }
                Err(e) => {
                    last_err = Some(format!("Network error at {}: {}", url, e).into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Max retries exceeded".into()))
    }

    #[cfg(target_arch = "wasm32")]
    fn get_text_with_retry(
        &self,
        _url: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Err("MempoolSignetRpc is not supported on WASM".into())
    }

    /// HTTP POST text with retry
    #[cfg(not(target_arch = "wasm32"))]
    async fn post_text_with_retry(
        &self,
        url: &str,
        body: String,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let url = url.to_string();

        let mut last_err = None;
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }

            match client
                .post(&url)
                .header("Content-Type", "text/plain")
                .body(body.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    return resp.text().await.map_err(|e| e.into());
                }
                Ok(resp) => {
                    let status = resp.status();
                    let error_text = resp.text().await.map_err(|e| {
                        format!(
                            "HTTP {} at {}: failed to read error text: {}",
                            status, url, e
                        )
                    })?;
                    last_err = Some(format!("HTTP {} at {}: {}", status, url, error_text).into());
                }
                Err(e) => {
                    last_err = Some(format!("Network error at {}: {}", url, e).into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Max retries exceeded".into()))
    }

    #[cfg(target_arch = "wasm32")]
    fn post_text_with_retry(
        &self,
        _url: &str,
        _body: String,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Err("MempoolSignetRpc is not supported on WASM".into())
    }

    /// Get block info (height, tx count, etc.)
    async fn get_block_info(
        &self,
        block_hash: &str,
    ) -> Result<BlockInfo, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/block/{}", self.base_url, block_hash);
        self.get_with_retry(&url).await
    }

    /// Get transaction status (confirmed/unconfirmed, block height, hash)
    async fn get_tx_status(
        &self,
        txid: &str,
    ) -> Result<TxStatus, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/tx/{}/status", self.base_url, txid);
        self.get_with_retry(&url).await
    }

    /// Get full transaction details (inputs, outputs, fee, etc.)
    async fn get_tx(
        &self,
        txid: &str,
    ) -> Result<TxDetail, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        self.get_with_retry(&url).await
    }

    /// Get raw transaction hex
    async fn get_tx_hex(
        &self,
        txid: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/tx/{}/hex", self.base_url, txid);
        self.get_text_with_retry(&url).await
    }

    /// Get block txids for Merkle proof extraction
    async fn get_block_txids(
        &self,
        block_hash: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/block/{}/txids", self.base_url, block_hash);
        self.get_with_retry(&url).await
    }

    /// Wait for transaction to reach required confirmations
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn wait_for_confirmation(
        &self,
        txid: [u8; 32],
        required_confirmations: u64,
        timeout_secs: u64,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let txid_hex = hex::encode(txid);
        let start = Instant::now();
        let poll_interval = Duration::from_secs(10);

        loop {
            if start.elapsed() > Duration::from_secs(timeout_secs) {
                return Err("Timeout waiting for confirmation".into());
            }

            match self.get_tx_status(&txid_hex).await {
                Ok(status) => {
                    if status.confirmed {
                        let tx_height = status.block_height.unwrap_or(0) as u64;
                        let new_height = self.get_block_count().await?;
                        let confirmations = new_height.saturating_sub(tx_height) + 1;

                        if confirmations >= required_confirmations {
                            return Ok(confirmations);
                        }

                        log::info!(
                            "Tx {} has {} confirmations, waiting for {}...",
                            &txid_hex[..16],
                            confirmations,
                            required_confirmations
                        );
                    }
                }
                Err(e) => {
                    log::debug!("Tx {} not found yet: {}", &txid_hex[..16], e);
                }
            }

            std::thread::sleep(poll_interval);
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn wait_for_confirmation(
        &self,
        _txid: [u8; 32],
        _required_confirmations: u64,
        _timeout_secs: u64,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Err("MempoolSignetRpc is not supported on WASM".into())
    }

    /// Extract Merkle proof for a transaction from its containing block
    async fn extract_merkle_proof(
        &self,
        txid: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<BitcoinInclusionProof, Box<dyn std::error::Error + Send + Sync>> {
        let block_hash_hex = hex::encode(block_hash);

        let all_txids_hex = self.get_block_txids(&block_hash_hex).await?;
        let all_txids: Vec<[u8; 32]> = all_txids_hex
            .iter()
            .map(|t| {
                let decoded = hex::decode(t)?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;

        let block_info = self.get_block_info(&block_hash_hex).await?;
        let block_height = block_info.height;

        extract_merkle_proof_from_block(txid, &all_txids, block_hash, block_height as u64)
            .ok_or_else(|| "Failed to extract Merkle proof for txid".into())
    }
}

impl Default for MempoolSignetRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BitcoinRpc for MempoolSignetRpc {
    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        self.get_with_retry(&url).await
    }

    async fn get_block_hash(
        &self,
        height: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/block-height/{}", self.base_url, height);
        let hash_hex: String = self.get_text_with_retry(&url).await?;
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
        // Mempool.space API expects txid in display format (reversed bytes)
        // Seal protocol passes internal byte order txids, so reverse for API
        let mut display_txid = txid;
        display_txid.reverse();
        let txid_hex = hex::encode(display_txid);
        let spend_url = format!("{}/tx/{}/outspend/{}", self.base_url, txid_hex, vout);
        let spend_status: OutSpendStatus = self.get_with_retry(&spend_url).await?;
        Ok(!spend_status.spent)
    }

    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/tx", self.base_url);
        let tx_hex = hex::encode(&tx_bytes);

        let txid_hex = self.post_text_with_retry(&url, tx_hex).await?;
        let txid_bytes = hex::decode(txid_hex.trim())?;
        let mut result = [0u8; 32];
        result.copy_from_slice(&txid_bytes);
        Ok(result)
    }

    async fn get_tx_confirmations(
        &self,
        txid: [u8; 32],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // Mempool.space API expects txid in display format (reversed bytes)
        // Seal protocol passes internal byte order txids, so reverse for API
        let mut display_txid = txid;
        display_txid.reverse();
        let txid_hex = hex::encode(display_txid);

        match self.get_tx_status(&txid_hex).await {
            Ok(status) => {
                if status.confirmed {
                    let current_height = self.get_block_count().await?;
                    let tx_height = status.block_height.unwrap_or(0) as u64;
                    Ok(current_height.saturating_sub(tx_height) + 1)
                } else {
                    Ok(0)
                }
            }
            Err(_) => Ok(0),
        }
    }

    async fn get_inclusion_proof(
        &self,
        txid: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<BitcoinInclusionProof, Box<dyn std::error::Error + Send + Sync>> {
        self.extract_merkle_proof(txid, block_hash).await
    }

    async fn estimate_fee_rate(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/v1/fees/recommended", self.base_url);
        let fees: RecommendedFees = self.get_with_retry(&url).await?;
        Ok(fees.half_hour_fee.max(fees.fastest_fee).max(1).min(10_000))
    }

    fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync> {
        Box::new(MempoolSignetRpc {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
        })
    }

    async fn get_utxos_for_address(
        &self,
        address: String,
    ) -> Result<Vec<crate::rpc::UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/address/{}/utxo", self.base_url, address);
        let utxos: Vec<AddressUtxo> = self.get_with_retry(&url).await?;
        let current_height = self.get_block_count().await.unwrap_or(0);
        let result: Vec<crate::rpc::UtxoInfo> = utxos
            .into_iter()
            .filter_map(|u| {
                let txid_bytes = hex::decode(&u.txid).ok()?;
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&txid_bytes);
                // Mempool.space API returns txids in display format (reversed bytes)
                // Keep as-is - seal protocol handles conversion to internal byte order
                let confirmations = if u.status.confirmed {
                    let bh = u.status.block_height.unwrap_or(current_height as u32) as u64;
                    current_height.saturating_sub(bh) + 1
                } else {
                    0
                };
                Some(crate::rpc::UtxoInfo {
                    txid,
                    vout: u.vout,
                    amount_sat: u.value,
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
        // Mempool.space /tx/{txid} endpoint expects display format (reversed bytes)
        let mut display_txid = txid;
        display_txid.reverse();
        let txid_hex = hex::encode(display_txid);
        let url = format!("{}/tx/{}", self.base_url, txid_hex);
        
        log::debug!("Fetching scriptPubKey for txid: {} (internal), vout: {}, URL: {}", hex::encode(txid), vout, url);
        
        let tx_detail: TxDetail = self.get_with_retry(&url).await
            .map_err(|e| {
                log::error!("Failed to fetch tx details for txid {} (display: {}): {}", hex::encode(txid), txid_hex, e);
                e
            })?;

        if let Some(output) = tx_detail.vout.get(vout as usize) {
            Ok(Some(output.scriptpubkey.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Block info response from mempool.space
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BlockInfo {
    pub id: String,
    pub height: u32,
    pub version: u32,
    pub timestamp: u64,
    pub tx_count: u32,
    pub size: u64,
    pub weight: u64,
    pub merkle_root: String,
}

/// Transaction status response
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    #[serde(default)]
    pub block_height: Option<u32>,
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub block_time: Option<u64>,
}

/// Transaction detail response
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TxDetail {
    #[serde(default)]
    pub txid: String,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub locktime: u64,
    #[serde(default)]
    pub vin: Vec<TxInput>,
    #[serde(default)]
    pub vout: Vec<TxOutput>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub weight: u64,
    #[serde(default)]
    pub fee: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TxInput {
    #[serde(default)]
    pub txid: String,
    #[serde(default)]
    pub vout: u32,
    #[serde(default)]
    pub prevout: Option<TxPrevout>,
    #[serde(default)]
    pub scriptsig: String,
    #[serde(default)]
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TxOutput {
    #[serde(default)]
    pub scriptpubkey: String,
    #[serde(default)]
    pub scriptpubkey_asm: String,
    #[serde(default)]
    pub scriptpubkey_type: String,
    #[serde(default)]
    pub scriptpubkey_address: String,
    #[serde(default)]
    pub value: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TxPrevout {
    #[serde(default)]
    pub scriptpubkey: String,
    #[serde(default)]
    pub scriptpubkey_asm: String,
    #[serde(default)]
    pub scriptpubkey_type: String,
    #[serde(default)]
    pub scriptpubkey_address: String,
    #[serde(default)]
    pub value: u64,
}

/// Output spend status
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OutSpendStatus {
    pub spent: bool,
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub vin: Option<u32>,
    #[serde(default)]
    pub status: Option<TxStatus>,
}

/// Get UTXOs for a specific address
pub async fn get_address_utxos(
    rpc: &MempoolSignetRpc,
    address: &bitcoin::Address,
) -> Result<Vec<(OutPoint, u64)>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/address/{}/utxo", rpc.base_url, address);
    let utxos: Vec<AddressUtxo> = rpc.get_with_retry(&url).await?;

    let result: Vec<(OutPoint, u64)> = utxos
        .into_iter()
        .map(|u| {
            let mut txid_bytes = hex::decode(&u.txid)?;
            // mempool.space returns txid in display order (big-endian)
            // Bitcoin internally uses little-endian (hash byte order)
            txid_bytes.reverse();
            let txid = Txid::from_slice(&txid_bytes).expect("valid txid");
            let outpoint = OutPoint::new(txid, u.vout);
            Ok((outpoint, u.value))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;

    Ok(result)
}

/// Address UTXO response
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AddressUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: TxStatus,
}

/// Recommended fee response from mempool.space.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RecommendedFees {
    #[serde(rename = "fastestFee")]
    pub fastest_fee: u64,
    #[serde(rename = "halfHourFee")]
    pub half_hour_fee: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires network"]
    async fn test_get_block_count() {
        let rpc = MempoolSignetRpc::new();
        let height = rpc.get_block_count().await.unwrap();
        assert!(height > 200_000, "Signet height should be > 200k");
        println!("Current Signet height: {}", height);
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn test_get_block_hash() {
        let rpc = MempoolSignetRpc::new();
        let height = rpc.get_block_count().await.unwrap();
        let hash = rpc.get_block_hash(height).await.unwrap();
        assert_ne!(hash, [0u8; 32]);
        println!("Block hash at {}: {}", height, hex::encode(hash));
    }
}
