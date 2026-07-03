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

use crate::proofs::extract_merkle_proof_from_block;
use crate::rpc::{BitcoinRpc, UtxoDetails, UtxoInfo};
use crate::types::BitcoinInclusionProof;

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
        Self {
            client,
            base_url,
            api_key,
        }
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
                    let text = resp
                        .text()
                        .await
                        .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| e.into())?;
                    return serde_json::from_str::<T>(&text).map_err(|e| {
                        format!("failed to parse Blockbook response from {}: {}", url, e).into()
                    });
                }
                Ok(resp) => {
                    let status = resp.status();
                    // 4xx (bad address, not found) is permanent — don't retry.
                    if status.is_client_error() {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(
                            format!("Blockbook HTTP {} at {}: {}", status, url, body).into()
                        );
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

    /// Fetch one page of a Blockbook block document
    /// (`GET /api/v2/block/{hash}?page=N`). Blockbook paginates a block's
    /// transaction list (default 1000 per page).
    async fn fetch_block_page(
        &self,
        block_hash_hex: &str,
        page: u64,
    ) -> Result<BlockbookBlock, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/api/v2/block/{}?page={}",
            self.base_url, block_hash_hex, page
        );
        self.get_json(&url).await
    }

    /// Decode a page's `txs[].txid` (display byte order) into internal-order
    /// txids, appending them to `out`. Internal order matches the convention the
    /// Merkle helpers (and `MempoolSignetRpc`) operate in.
    fn decode_block_txids(
        page: &BlockbookBlock,
        out: &mut Vec<[u8; 32]>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for tx in &page.txs {
            let mut bytes = hex::decode(&tx.txid)
                .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                    format!("invalid block txid hex '{}': {}", tx.txid, e).into()
                })?;
            if bytes.len() != 32 {
                return Err(format!("block txid '{}' is not 32 bytes", tx.txid).into());
            }
            bytes.reverse();
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            out.push(id);
        }
        Ok(())
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
                let mut txid_bytes =
                    hex::decode(&u.txid).map_err::<Box<dyn std::error::Error + Send + Sync>, _>(
                        |e| format!("invalid txid hex '{}': {}", u.txid, e).into(),
                    )?;
                if txid_bytes.len() != 32 {
                    return Err(format!("txid '{}' is not 32 bytes", u.txid).into());
                }
                // Blockbook returns display byte order; store internal order to
                // match the BitcoinRpc trait contract (as MempoolSignetRpc does).
                txid_bytes.reverse();
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&txid_bytes);

                let amount_sat = u
                    .value
                    .parse::<u64>()
                    .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
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
        let value = output
            .value
            .parse::<u64>()
            .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
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
        let btc_per_kvb: f64 = resp
            .result
            .parse()
            .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
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

    async fn get_inclusion_proof(
        &self,
        txid: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<BitcoinInclusionProof, Box<dyn std::error::Error + Send + Sync>> {
        // `block_hash` is display byte order (as `get_block_hash` returns it), so
        // it hex-encodes directly for the Blockbook URL.
        let block_hash_hex = hex::encode(block_hash);

        // Walk every page of the block's transaction list to reconstruct the
        // full, ordered txid set the Merkle proof is computed over.
        let first = self.fetch_block_page(&block_hash_hex, 1).await?;
        let total_pages = first.total_pages.unwrap_or(1).max(1);
        let block_height = first.height;

        let mut all_txids: Vec<[u8; 32]> = Vec::with_capacity(first.tx_count.unwrap_or(0) as usize);
        Self::decode_block_txids(&first, &mut all_txids)?;
        for page in 2..=total_pages {
            let doc = self.fetch_block_page(&block_hash_hex, page).await?;
            Self::decode_block_txids(&doc, &mut all_txids)?;
        }

        extract_merkle_proof_from_block(txid, &all_txids, block_hash, block_height)
            .ok_or_else(|| "Failed to extract Merkle proof for txid".into())
    }

    async fn get_raw_block_header(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Blockbook exposes no raw-header endpoint, but its block document
        // carries every field of the 80-byte header. Reconstruct the canonical
        // serialization so SPV verification (which reads the Merkle root at
        // bytes 36..68) sees a real header.
        let block_hash_hex = hex::encode(block_hash);
        let block = self.fetch_block_page(&block_hash_hex, 1).await?;
        block.reconstruct_raw_header()
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

/// Subset of `GET /api/v2/block/{hash}` — the block-header fields plus the
/// paginated transaction list needed for Merkle-proof extraction.
#[derive(Debug, serde::Deserialize)]
struct BlockbookBlock {
    #[serde(rename = "totalPages", default)]
    total_pages: Option<u64>,
    #[serde(default)]
    height: u64,
    #[serde(rename = "txCount", default)]
    tx_count: Option<u64>,
    #[serde(rename = "previousBlockHash", default)]
    previous_block_hash: Option<String>,
    #[serde(default)]
    version: Option<i64>,
    #[serde(rename = "merkleRoot", default)]
    merkle_root: Option<String>,
    #[serde(default)]
    time: Option<i64>,
    /// Compact difficulty target, hex string (e.g. `"1d00ffff"`).
    #[serde(default)]
    bits: Option<String>,
    /// Nonce as a decimal string.
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    txs: Vec<BlockbookBlockTx>,
}

#[derive(Debug, serde::Deserialize)]
struct BlockbookBlockTx {
    txid: String,
}

impl BlockbookBlock {
    /// Rebuild the canonical 80-byte block header from the document's fields.
    ///
    /// Bitcoin serializes the header as: version (4, LE), previous block hash
    /// (32, internal order), Merkle root (32, internal order), time (4, LE),
    /// bits (4, LE), nonce (4, LE). Blockbook reports the two hashes in display
    /// (big-endian) order, so they are byte-reversed here.
    fn reconstruct_raw_header(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        fn hash_to_internal(
            display_hex: &str,
            field: &str,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            let mut bytes = hex::decode(display_hex.trim()).map_err::<Box<
                dyn std::error::Error + Send + Sync,
            >, _>(|e| {
                format!("invalid {} hex '{}': {}", field, display_hex, e).into()
            })?;
            if bytes.len() != 32 {
                return Err(format!("{} '{}' is not 32 bytes", field, display_hex).into());
            }
            bytes.reverse();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }

        let merkle_root = self
            .merkle_root
            .as_deref()
            .ok_or_else::<Box<dyn std::error::Error + Send + Sync>, _>(|| {
                "Blockbook block document missing merkleRoot".into()
            })?;
        let merkle_internal = hash_to_internal(merkle_root, "merkleRoot")?;

        // The genesis block has no previous hash; zero-fill in that case.
        let prev_internal = match self.previous_block_hash.as_deref() {
            Some(h) if !h.is_empty() => hash_to_internal(h, "previousBlockHash")?,
            _ => [0u8; 32],
        };

        let version = self.version.unwrap_or(0) as u32;
        let time = self.time.unwrap_or(0) as u32;

        let bits = self
            .bits
            .as_deref()
            .ok_or_else::<Box<dyn std::error::Error + Send + Sync>, _>(|| {
                "Blockbook block document missing bits".into()
            })?;
        let bits_u32 = u32::from_str_radix(bits.trim().trim_start_matches("0x"), 16)
            .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                format!("invalid bits '{}': {}", bits, e).into()
            })?;

        let nonce = self
            .nonce
            .as_deref()
            .ok_or_else::<Box<dyn std::error::Error + Send + Sync>, _>(|| {
                "Blockbook block document missing nonce".into()
            })?;
        let nonce_u32 = nonce
            .trim()
            .parse::<u64>()
            .map_err::<Box<dyn std::error::Error + Send + Sync>, _>(|e| {
                format!("invalid nonce '{}': {}", nonce, e).into()
            })? as u32;

        let mut header = Vec::with_capacity(80);
        header.extend_from_slice(&version.to_le_bytes());
        header.extend_from_slice(&prev_internal);
        header.extend_from_slice(&merkle_internal);
        header.extend_from_slice(&time.to_le_bytes());
        header.extend_from_slice(&bits_u32.to_le_bytes());
        header.extend_from_slice(&nonce_u32.to_le_bytes());
        debug_assert_eq!(header.len(), 80);
        Ok(header)
    }
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
        let idx: BlockbookBlockIndex = serde_json::from_str(r#"{"blockHash":"00ff"}"#).unwrap();
        assert_eq!(idx.block_hash, "00ff");
    }

    /// The canonical 80-byte header of the Bitcoin mainnet genesis block.
    const GENESIS_RAW_HEADER: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    #[test]
    fn reconstructs_genesis_header_from_blockbook_fields() {
        // Representative `GET /api/v2/block/{hash}` shape for the genesis block:
        // hashes in display byte order, bits as hex, nonce as a decimal string.
        let json = r#"{
            "page":1,"totalPages":1,"height":0,"txCount":1,
            "previousBlockHash":"0000000000000000000000000000000000000000000000000000000000000000",
            "version":1,
            "merkleRoot":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            "time":1231006505,
            "bits":"1d00ffff",
            "nonce":"2083236893",
            "txs":[{"txid":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"}]
        }"#;
        let block: BlockbookBlock = serde_json::from_str(json).unwrap();
        let header = block.reconstruct_raw_header().unwrap();

        // Byte-for-byte match with the real serialized genesis header.
        assert_eq!(hex::encode(&header), GENESIS_RAW_HEADER);
        assert_eq!(header.len(), 80);

        // The Merkle root the SPV verifier reads (bytes 36..68) is the internal
        // (byte-reversed) form of the display `merkleRoot`.
        let expected_root: Vec<u8> = {
            let mut b =
                hex::decode("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                    .unwrap();
            b.reverse();
            b
        };
        assert_eq!(&header[36..68], expected_root.as_slice());

        // rust-bitcoin (used by the full SPV verifier) must accept it and derive
        // the real genesis block hash from it.
        let parsed: bitcoin::block::Header =
            bitcoin::consensus::encode::deserialize(&header).unwrap();
        assert_eq!(
            parsed.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn decodes_paginated_block_txids_to_internal_order() {
        let json = r#"{
            "page":1,"totalPages":1,"height":100,"txCount":1,
            "txs":[{"txid":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"}]
        }"#;
        let block: BlockbookBlock = serde_json::from_str(json).unwrap();
        let mut out = Vec::new();
        BlockbookRpc::decode_block_txids(&block, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        // Display order is byte-reversed into internal order.
        assert_eq!(out[0][0], 0x99);
        assert_eq!(out[0][31], 0xaa);
    }
}
