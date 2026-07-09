//! RPC Interface for Celestia Node
//!
//! This module provides the RPC interface to communicate with a Celestia
//! node. It uses the Tendermint JSON-RPC protocol for communication.
//!
//! ## RPC Endpoints
//!
//! - `blob.Submit` - Submit a blob to Celestia
//! - `blob.Get` - Get a blob by height, namespace, and commitment
//! - `blob.GetProof` - Get inclusion proof for a blob
//! - `header.GetByHeight` - Get block header at height
//! - `header.GetLatestHeight` - Get latest block height
//!
//! ## IPFS RPC
//!
//! For IPFS operations, this module uses the Kubo HTTP API:
//! - `/api/v0/add` - Add data to IPFS
//! - `/api/v0/cat` - Retrieve data by CID
//! - `/api/v0/pin/add` - Pin content
//! - `/api/v0/block/stat` - Get content stats
//!
//! ## Quorum Support
//!
//! When the `quorum` feature is enabled, RPC calls use a quorum client
//! to query multiple providers and reach consensus before accepting responses.

use serde::{Deserialize, Serialize};

#[cfg(feature = "rpc")]
use async_trait::async_trait;
#[cfg(feature = "rpc")]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[cfg(feature = "rpc")]
use crate::commitment::CommitmentProof;
#[cfg(feature = "rpc")]
use crate::da_layer::CelestiaRpc;
#[cfg(feature = "rpc")]
use crate::error::{CelestiaError, Result};
#[cfg(feature = "rpc")]
use crate::namespace::Namespace;
#[cfg(feature = "rpc")]
use crate::types::{CelestiaFinalityProof, CelestiaHeader};

#[cfg(all(feature = "rpc", feature = "quorum"))]
use csv_protocol::rpc::{QuorumClient, QuorumConfig, RpcProvider};

#[cfg(feature = "rpc")]
fn decode_hex_array<const N: usize>(value: &serde_json::Value, field: &str) -> Result<[u8; N]> {
    let hex_value = value[field]
        .as_str()
        .ok_or_else(|| CelestiaError::RpcError(format!("Missing {} in response", field)))?;
    let bytes = hex::decode(hex_value)
        .map_err(|e| CelestiaError::RpcError(format!("Invalid {} hex: {}", field, e)))?;
    bytes
        .try_into()
        .map_err(|_| CelestiaError::RpcError(format!("Invalid {} length", field)))
}

/// Celestia node RPC client
#[derive(Clone, Debug)]
pub struct CelestiaNode {
    /// RPC endpoint URL
    endpoint: String,
    /// HTTP client
    #[cfg(feature = "rpc")]
    client: reqwest::Client,
    /// Quorum client for multi-provider consensus (when quorum feature is enabled)
    #[cfg(all(feature = "rpc", feature = "quorum"))]
    quorum_client: Option<QuorumClient>,
}

impl CelestiaNode {
    /// Create a new RPC client
    #[cfg(feature = "rpc")]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
            #[cfg(feature = "quorum")]
            quorum_client: None,
        }
    }

    /// Create a new RPC client with quorum support
    #[cfg(all(feature = "rpc", feature = "quorum"))]
    pub fn new_with_quorum(endpoints: Vec<String>, config: QuorumConfig) -> Self {
        let providers: Vec<RpcProvider> = endpoints
            .into_iter()
            .map(|url| RpcProvider::new(url))
            .collect();

        let quorum_client = QuorumClient::new(providers, config);

        Self {
            endpoint: quorum_client
                .providers
                .get(0)
                .map(|p| p.url.clone())
                .unwrap_or_else(|| "http://localhost:26658".to_string()),
            client: reqwest::Client::new(),
            quorum_client: Some(quorum_client),
        }
    }

    /// Create without RPC feature (placeholder)
    #[cfg(not(feature = "rpc"))]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    /// Build a JSON-RPC request
    #[cfg(feature = "rpc")]
    fn build_request(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        })
    }
}

#[cfg(feature = "rpc")]
#[async_trait]
impl CelestiaRpc for CelestiaNode {
    async fn submit_blob(&self, namespace: Namespace, data: &[u8]) -> Result<(u64, [u8; 32])> {
        use sha2::{Digest, Sha256};

        // Compute commitment
        let commitment: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(namespace.as_bytes());
            hasher.update(data);
            hasher.finalize().into()
        };

        let base64_data = BASE64.encode(data);
        let namespace_hex = hex::encode(namespace.as_bytes());

        let params = serde_json::json!({
            "blobs": [{
                "namespace": namespace_hex,
                "data": base64_data,
                "share_version": 0,
                "commitment": hex::encode(commitment),
            }],
            "gas_price": 0.01,
        });

        let request = self.build_request("blob.Submit", params);

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("HTTP error: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("JSON error: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(CelestiaError::RpcError(format!("RPC error: {}", error)));
        }

        // Parse height from response
        let height = result["result"]["height"]
            .as_u64()
            .ok_or_else(|| CelestiaError::RpcError("Missing height in response".to_string()))?;

        Ok((height, commitment))
    }

    async fn get_blob(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: [u8; 32],
    ) -> Result<Vec<u8>> {
        let params = serde_json::json!({
            "height": height,
            "namespace": hex::encode(namespace.as_bytes()),
            "commitment": hex::encode(commitment),
        });

        let request = self.build_request("blob.Get", params);

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("HTTP error: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("JSON error: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(CelestiaError::RpcError(format!("RPC error: {}", error)));
        }

        let data_b64 = result["result"]["data"]
            .as_str()
            .ok_or_else(|| CelestiaError::RpcError("Missing data in response".to_string()))?;

        BASE64
            .decode(data_b64)
            .map_err(|e| CelestiaError::DeserializationError(format!("Base64 decode error: {}", e)))
    }

    async fn get_latest_height(&self) -> Result<u64> {
        #[cfg(all(feature = "rpc", feature = "quorum"))]
        if let Some(ref quorum) = self.quorum_client {
            let data = quorum
                .query_quorum("header.GetLatestHeight", &[])
                .await
                .map_err(|e| CelestiaError::RpcError(format!("Quorum error: {}", e)))?;
            let result: serde_json::Value = serde_json::from_slice(&data)
                .map_err(|e| CelestiaError::RpcError(format!("JSON error: {}", e)))?;
            return result["result"]
                .as_u64()
                .ok_or_else(|| CelestiaError::RpcError("Missing height in response".to_string()));
        }

        let request = self.build_request("header.GetLatestHeight", serde_json::json!([]));

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("HTTP error: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("JSON error: {}", e)))?;

        result["result"]
            .as_u64()
            .ok_or_else(|| CelestiaError::RpcError("Missing height in response".to_string()))
    }

    async fn get_header(&self, height: u64) -> Result<CelestiaHeader> {
        let params = serde_json::json!({"height": height});
        let request = self.build_request("header.GetByHeight", params);

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("HTTP error: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("JSON error: {}", e)))?;

        // Parse extended header
        let header_json = &result["result"]["header"];

        let chain_id = header_json["chain_id"]
            .as_str()
            .ok_or_else(|| CelestiaError::RpcError("Missing chain_id in response".to_string()))?
            .to_string();

        let header_height = header_json["height"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| CelestiaError::RpcError("Missing height in response".to_string()))?;

        let hash = decode_hex_array::<32>(header_json, "hash")?;
        let data_root = decode_hex_array::<32>(header_json, "data_hash")?;

        Ok(CelestiaHeader::new(
            chain_id,
            header_height,
            hash,
            data_root,
        ))
    }

    async fn get_commitment_proof(
        &self,
        height: u64,
        commitment: [u8; 32],
    ) -> Result<CommitmentProof> {
        // Use the blob.GetProof RPC to fetch a real commitment proof from the Celestia node
        let namespace = Namespace::metadata();
        let params = serde_json::json!({
            "height": height,
            "namespace": hex::encode(namespace.as_bytes()),
            "commitment": hex::encode(commitment),
        });

        let request = self.build_request("blob.GetProof", params);

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("HTTP error: {}", e)))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| CelestiaError::RpcError(format!("JSON error: {}", e)))?;

        if let Some(error) = result.get("error") {
            return Err(CelestiaError::RpcError(format!("RPC error: {}", error)));
        }

        // Parse proof data from response
        let proof_result = &result["result"];

        // Extract row_root from the proof (hex-encoded, 32 bytes)
        let row_root = decode_hex_array::<32>(proof_result, "row_root")?;

        // Get the block header to extract data_root and block_hash
        let header = self.get_header(height).await?;

        Ok(CommitmentProof::new(
            height,
            namespace,
            crate::commitment::BlobCommitment::new(commitment),
            row_root,
            header.data_root,
            header.hash,
        ))
    }

    async fn get_finality_proof(&self, height: u64) -> Result<CelestiaFinalityProof> {
        let _header = self.get_header(height).await?;
        Err(CelestiaError::RpcError(
            "Celestia RPC finality proof requires validator commit signatures".to_string(),
        ))
    }
}

/// RPC request/response types for serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitBlobRequest {
    pub namespace: String,
    pub data: String, // base64 encoded
    pub share_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitBlobResponse {
    pub height: u64,
    pub commitment: String, // hex encoded
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlobRequest {
    pub height: u64,
    pub namespace: String,
    pub commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetBlobResponse {
    pub namespace: String,
    pub data: String, // base64 encoded
    pub share_version: u32,
    pub commitment: String,
}

/// IPFS RPC client using Kubo HTTP API
#[derive(Clone, Debug)]
pub struct IpfsRpcClient {
    /// IPFS API endpoint
    endpoint: String,
    /// HTTP client
    #[cfg(feature = "rpc")]
    client: reqwest::Client,
}

impl IpfsRpcClient {
    /// Create new IPFS RPC client
    #[cfg(feature = "rpc")]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Create without RPC feature
    #[cfg(not(feature = "rpc"))]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

#[cfg(feature = "rpc")]
impl crate::ipfs::IpfsClient for IpfsRpcClient {
    fn put<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<crate::ipfs::IpfsCid>> + Send + 'a>,
    > {
        Box::pin(async move {
            let form = reqwest::multipart::Form::new()
                .part("file", reqwest::multipart::Part::bytes(data.to_vec()));

            let url = format!("{}/api/v0/add", self.endpoint);
            let response = self
                .client
                .post(&url)
                .multipart(form)
                .send()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("HTTP error: {}", e)))?;

            let result: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("JSON error: {}", e)))?;

            let cid = result["Hash"]
                .as_str()
                .ok_or_else(|| CelestiaError::IpfsError("Missing CID in response".to_string()))?;

            crate::ipfs::IpfsCid::from_string(cid)
        })
    }

    fn get(
        &self,
        cid: &crate::ipfs::IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let cid_str = cid.as_str().to_string();
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();

        Box::pin(async move {
            let url = format!("{}/api/v0/cat?arg={}", endpoint, cid_str);
            let response = client
                .post(&url)
                .send()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("HTTP error: {}", e)))?;

            let bytes = response
                .bytes()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("Read error: {}", e)))?;

            Ok(bytes.to_vec())
        })
    }

    fn exists(
        &self,
        cid: &crate::ipfs::IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>> {
        let cid_str = cid.as_str().to_string();
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();

        Box::pin(async move {
            let url = format!("{}/api/v0/block/stat?arg={}", endpoint, cid_str);
            let response = client.post(&url).send().await;

            match response {
                Ok(resp) => Ok(resp.status().is_success()),
                Err(_) => Ok(false),
            }
        })
    }

    fn pin(
        &self,
        cid: &crate::ipfs::IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        let cid_str = cid.as_str().to_string();
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();

        Box::pin(async move {
            let url = format!("{}/api/v0/pin/add?arg={}", endpoint, cid_str);
            let response = client
                .post(&url)
                .send()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("HTTP error: {}", e)))?;

            if response.status().is_success() {
                Ok(())
            } else {
                Err(CelestiaError::IpfsError(format!(
                    "Pin failed: {}",
                    response.status()
                )))
            }
        })
    }

    fn unpin(
        &self,
        cid: &crate::ipfs::IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        let cid_str = cid.as_str().to_string();
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();

        Box::pin(async move {
            let url = format!("{}/api/v0/pin/rm?arg={}", endpoint, cid_str);
            let response = client
                .post(&url)
                .send()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("HTTP error: {}", e)))?;

            if response.status().is_success() {
                Ok(())
            } else {
                Err(CelestiaError::IpfsError(format!(
                    "Unpin failed: {}",
                    response.status()
                )))
            }
        })
    }

    fn stat(
        &self,
        cid: &crate::ipfs::IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + '_>> {
        let cid_str = cid.as_str().to_string();
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();

        Box::pin(async move {
            let url = format!("{}/api/v0/block/stat?arg={}", endpoint, cid_str);
            let response = client
                .post(&url)
                .send()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("HTTP error: {}", e)))?;

            let result: serde_json::Value = response
                .json()
                .await
                .map_err(|e| CelestiaError::IpfsError(format!("JSON error: {}", e)))?;

            result["Size"]
                .as_u64()
                .ok_or_else(|| CelestiaError::IpfsError("Missing size in response".to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_celestia_node_creation() {
        let node = CelestiaNode::new("http://localhost:26658");
        assert_eq!(node.endpoint, "http://localhost:26658");
    }

    #[test]
    fn test_ipfs_rpc_client_creation() {
        let client = IpfsRpcClient::new("http://localhost:5001");
        assert_eq!(client.endpoint, "http://localhost:5001");
    }

    #[test]
    fn test_submit_blob_request_serialization() {
        let request = SubmitBlobRequest {
            namespace: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            data: "dGVzdCBkYXRh".to_string(), // base64 of "test data"
            share_version: 0,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("namespace"));
        assert!(json.contains("data"));
    }
}
