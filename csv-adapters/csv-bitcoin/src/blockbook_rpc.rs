//! Bitcoin REST client for the Trezor **Blockbook** API shape.
//!
//! This is the transport exposed by Alchemy's Bitcoin "UTXO API"
//! (`https://bitcoin-<network>.g.alchemy.com/v2/<apiKey>` as the base) and by
//! any self-hosted Blockbook instance. It is distinct from both the esplora
//! REST convention ([`MempoolSignetRpc`](crate::mempool_rpc::MempoolSignetRpc))
//! and Bitcoin Core JSON-RPC ([`BitcoinJsonRpc`](crate::json_rpc::BitcoinJsonRpc)):
//!
//! * `GET {base}/api/v2/utxo/{descriptor}` → array of UTXOs, `value` in satoshis
//!   as a decimal string, `txid` in display byte order.
//! * `GET {base}/api/v2/tx/{txid}` → transaction whose `vout[n].hex` is the
//!   scriptPubKey and `vout[n].value` the satoshi string.
//!
//! Crucially — unlike Bitcoin Core JSON-RPC — Blockbook **can** enumerate the
//! UTXOs of an arbitrary address, so it is a valid scanning indexer. Enable the
//! `signet-rest` feature to use this implementation.

use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;

use crate::rpc::{BitcoinRpc, UtxoDetails, UtxoInfo};

/// Maximum number of retries for transient failures.
const MAX_RETRIES: u32 = 3;
/// Initial backoff duration before the first retry.
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// Bitcoin REST client speaking the Blockbook `/api/v2` shape.
pub struct BlockbookRpc {
    client: Client,
    /// Base URL up to but excluding `/api/v2` — for Alchemy this already embeds
    /// the API key in the path (`.../v2/<apiKey>`).
    base_url: String,
    /// Optional API key sent as an `api-key` header (self-hosted Blockbook).
    /// Alchemy carries the key in `base_url`, so this is usually `None`.
    api_key: Option<String>,
}

impl BlockbookRpc {
    /// Create a client for the given Blockbook base URL.
    pub fn with_url(base_url: String) -> Self {
        Self::with_url_and_key(base_url, None)
    }

    /// Create a client with an optional `api-key` header.
    pub fn with_url_and_key(base_url: String, api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        // Strip trailing slashes to avoid `//api/v2` when composing paths.
        let base_url = base_url.trim_end_matches('/').to_string();
        Self { client, base_url, api_key }
    }

    /// GET a JSON document with retry + exponential backoff on transient errors.
    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let mut last_err = None;
        let mut backoff = INITIAL_BACKOFF;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }

            let mut request = self.client.get(url);
            if let Some(key) = &self.api_key {
                request = request.header("api-key", key);
            }

            match request.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let text = resp.text().await.map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| e.into())?;
                    return serde_json::from_str::<T>(&text)
                        .map_err(|e| format!("failed to parse Blockbook response from {}: {}", url, e).into());
                }
                Ok(resp) => {
                    let status = resp.status();
                    // 4xx (bad address, not found) is permanent — don't retry.
                    if status.is_client_error() {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(format!("Blockbook HTTP {} at {}: {}", status, url, body).into());
                    }
                    last_err = Some(format!("Blockbook HTTP {} at {}", status, url).into());
                }
                Err(e) => {
                    last_err = Some(format!("Blockbook network error at {}: {}", url, e).into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| "Max retries exceeded".into()))
    }

    /// Convert an internal-order txid (trait contract) to display hex for URLs.
    fn display_txid(txid: [u8; 32]) -> String {
        let mut display = txid;
        display.reverse();
        hex::encode(display)
    }

    async fn fetch_tx(
        &self,
        display_txid: &str,
    ) -> Result<BlockbookTx, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v2/tx/{}", self.base_url, display_txid);
        self.get_json(&url).await
    }
}

#[async_trait]
impl BitcoinRpc for BlockbookRpc {
    async fn get_utxos_for_address(
        &self,
        address: String,
    ) -> Result<Vec<UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v2/utxo/{}", self.base_url, address);
        let utxos: Vec<BlockbookUtxo> = self.get_json(&url).await?;

        utxos
            .into_iter()
            .map(|u| {
                let mut txid_bytes = hex::decode(&u.txid)
                    .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                        format!("invalid txid hex '{}': {}", u.txid, e).into()
                    })?;
                if txid_bytes.len() != 32 {
                    return Err(format!("txid '{}' is not 32 bytes", u.txid).into());
                }
                // Blockbook returns display byte order; store internal order to
                // match the BitcoinRpc trait contract (as MempoolSignetRpc does).
                txid_bytes.reverse();
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&txid_bytes);

                let amount_sat = u.value.parse::<u64>().map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                    format!("invalid satoshi value '{}': {}", u.value, e).into()
                })?;

                Ok(UtxoInfo {
                    txid,
                    vout: u.vout,
                    amount_sat,
                    confirmations: u.confirmations.unwrap_or(0),
                })
            })
            .collect()
    }

    async fn get_utxo_scriptpubkey(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let tx = self.fetch_tx(&Self::display_txid(txid)).await?;
        Ok(tx.vout.into_iter().find(|o| o.n == vout).map(|o| o.hex))
    }

    async fn get_utxo_details(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<Option<UtxoDetails>, Box<dyn std::error::Error + Send + Sync>> {
        let tx = self.fetch_tx(&Self::display_txid(txid)).await?;
        let Some(output) = tx.vout.into_iter().find(|o| o.n == vout) else {
            return Ok(None);
        };
        let value = output.value.parse::<u64>().map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
            format!("invalid satoshi value '{}': {}", output.value, e).into()
        })?;
        Ok(Some(UtxoDetails {
            txid,
            vout,
            value,
            script_pubkey: output.hex,
        }))
    }

    async fn is_utxo_unspent(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let tx = self.fetch_tx(&Self::display_txid(txid)).await?;
        // `spent` is present on the output when Blockbook knows of a spend.
        Ok(tx
            .vout
            .into_iter()
            .find(|o| o.n == vout)
            .map(|o| !o.spent.unwrap_or(false))
            .unwrap_or(false))
    }

    async fn get_tx_confirmations(
        &self,
        txid: [u8; 32],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let tx = self.fetch_tx(&Self::display_txid(txid)).await?;
        Ok(tx.confirmations.unwrap_or(0))
    }

    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // Blockbook: GET /api/v2/sendtx/{hex} returns { "result": "<txid>" }.
        let url = format!("{}/api/v2/sendtx/{}", self.base_url, hex::encode(&tx_bytes));
        let resp: BlockbookSendTx = self.get_json(&url).await?;
        let mut txid_bytes = hex::decode(resp.result.trim())?;
        if txid_bytes.len() != 32 {
            return Err("Blockbook sendtx returned a non-32-byte txid".into());
        }
        // Response txid is display order; store internal order.
        txid_bytes.reverse();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        Ok(txid)
    }

    async fn estimate_fee_rate(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // Blockbook: GET /api/v2/estimatefee/{blocks} → { "result": "<btc/kvB>" }.
        // Target 2 blocks; result is BTC per 1000 vbytes as a decimal string.
        let url = format!("{}/api/v2/estimatefee/2", self.base_url);
        let resp: BlockbookEstimateFee = self.get_json(&url).await?;
        let btc_per_kvb: f64 = resp.result.parse().map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
            format!("invalid estimatefee result '{}': {}", resp.result, e).into()
        })?;
        // BTC/kvB → sat/vB: * 1e8 sat/BTC / 1000 vB/kvB. Clamp to a sane range.
        let sat_per_vb = (btc_per_kvb * 100_000_000.0 / 1000.0).round() as i64;
        Ok(sat_per_vb.clamp(1, 10_000) as u64)
    }

    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v2", self.base_url);
        let status: BlockbookStatus = self.get_json(&url).await?;
        Ok(status.backend.blocks)
    }

    async fn get_block_hash(
        &self,
        height: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/api/v2/block-index/{}", self.base_url, height);
        let idx: BlockbookBlockIndex = self.get_json(&url).await?;
        let hash_bytes = hex::decode(idx.block_hash.trim())?;
        if hash_bytes.len() != 32 {
            return Err("Blockbook block-index returned a non-32-byte hash".into());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        Ok(hash)
    }

    fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync> {
        Box::new(BlockbookRpc {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            api_key: self.api_key.clone(),
        })
    }
}

/// One entry of `GET /api/v2/utxo/{descriptor}`.
#[derive(Debug, serde::Deserialize)]
struct BlockbookUtxo {
    txid: String,
    vout: u32,
    /// Satoshis as a decimal string.
    value: String,
    #[serde(default)]
    confirmations: Option<u64>,
}

/// Subset of `GET /api/v2/tx/{txid}`.
#[derive(Debug, serde::Deserialize)]
struct BlockbookTx {
    #[serde(default)]
    confirmations: Option<u64>,
    #[serde(default)]
    vout: Vec<BlockbookTxOutput>,
}

#[derive(Debug, serde::Deserialize)]
struct BlockbookTxOutput {
    /// Satoshis as a decimal string.
    #[serde(default)]
    value: String,
    n: u32,
    /// scriptPubKey hex.
    #[serde(default)]
    hex: String,
    #[serde(default)]
    spent: Option<bool>,
}

/// `GET /api/v2/sendtx/{hex}` response.
#[derive(Debug, serde::Deserialize)]
struct BlockbookSendTx {
    result: String,
}

/// `GET /api/v2/estimatefee/{blocks}` response (fee in BTC/kvB as a string).
#[derive(Debug, serde::Deserialize)]
struct BlockbookEstimateFee {
    result: String,
}

/// `GET /api/v2` status document (only the fields we need).
#[derive(Debug, serde::Deserialize)]
struct BlockbookStatus {
    backend: BlockbookBackend,
}

#[derive(Debug, serde::Deserialize)]
struct BlockbookBackend {
    blocks: u64,
}

/// `GET /api/v2/block-index/{height}` response.
#[derive(Debug, serde::Deserialize)]
struct BlockbookBlockIndex {
    #[serde(rename = "blockHash")]
    block_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_txid_reverses_internal_order() {
        let mut internal = [0u8; 32];
        internal[0] = 0xaa;
        internal[31] = 0xbb;
        // Display order is the byte-reversed internal order.
        let disp = BlockbookRpc::display_txid(internal);
        assert!(disp.starts_with("bb"));
        assert!(disp.ends_with("aa"));
    }

    #[test]
    fn parses_utxo_list_payload() {
        // Representative Alchemy/Blockbook `GET /api/v2/utxo/{addr}` payload:
        // value is a satoshi decimal string, txid is display order.
        let json = r#"[
            {"txid":"aabb","vout":1,"value":"12345","height":200000,"confirmations":6},
            {"txid":"ccdd","vout":0,"value":"1","coinbase":false}
        ]"#;
        let utxos: Vec<BlockbookUtxo> = serde_json::from_str(json).unwrap();
        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos[0].vout, 1);
        assert_eq!(utxos[0].value.parse::<u64>().unwrap(), 12345);
        assert_eq!(utxos[0].confirmations, Some(6));
        // `confirmations` omitted on the second (unconfirmed) entry.
        assert_eq!(utxos[1].confirmations, None);
    }

    #[test]
    fn parses_tx_payload_scriptpubkey_and_value() {
        // Representative `GET /api/v2/tx/{txid}` payload: vout carries `n`, `hex`
        // (scriptPubKey), `value` (sat string) and optional `spent`.
        let json = r#"{
            "txid":"aabb",
            "confirmations":10,
            "vout":[
                {"value":"5000","n":0,"hex":"5120deadbeef","addresses":["tb1p.."],"spent":true},
                {"value":"600","n":1,"hex":"0014abcd"}
            ]
        }"#;
        let tx: BlockbookTx = serde_json::from_str(json).unwrap();
        assert_eq!(tx.confirmations, Some(10));
        let out0 = tx.vout.iter().find(|o| o.n == 0).unwrap();
        assert_eq!(out0.hex, "5120deadbeef");
        assert_eq!(out0.value.parse::<u64>().unwrap(), 5000);
        assert_eq!(out0.spent, Some(true));
        let out1 = tx.vout.iter().find(|o| o.n == 1).unwrap();
        assert_eq!(out1.spent, None);
    }

    #[test]
    fn parses_status_and_block_index() {
        let status: BlockbookStatus =
            serde_json::from_str(r#"{"backend":{"blocks":250000}}"#).unwrap();
        assert_eq!(status.backend.blocks, 250000);
        let idx: BlockbookBlockIndex =
            serde_json::from_str(r#"{"blockHash":"00ff"}"#).unwrap();
        assert_eq!(idx.block_hash, "00ff");
    }
}
