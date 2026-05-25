//! IPFS transport for proof bundle storage and retrieval.
//!
//! This module provides IPFS as a secondary storage fallback for ProofBundles
//! when Nostr is unavailable. IPFS offers decentralized, content-addressable storage
//! that can be used as a reliable backup for proof bundles.

#[cfg(feature = "ipfs")]
use async_trait::async_trait;
#[cfg(feature = "ipfs")]
use csv_protocol::proof_types::ProofBundle;
#[cfg(feature = "ipfs")]
use tokio_stream::wrappers::ReceiverStream;
#[cfg(feature = "ipfs")]
use tracing::{debug, info, warn};

#[cfg(feature = "ipfs")]
use crate::{DeliveredProof, EventId, ProofFilter, ProofTransport, TransportError};

#[cfg(feature = "ipfs")]
/// IPFS client configuration.
#[derive(Clone, Debug)]
pub struct IpfsConfig {
    /// IPFS API endpoint URL.
    pub api_url: String,
    /// Gateway URL for retrieving content.
    pub gateway_url: String,
    /// Timeout for IPFS operations (seconds).
    pub timeout_secs: u64,
}

#[cfg(feature = "ipfs")]
impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: "http://127.0.0.1:5001/api/v0".to_string(),
            gateway_url: "https://ipfs.io/ipfs".to_string(),
            timeout_secs: 30,
        }
    }
}

#[cfg(feature = "ipfs")]
/// IPFS transport for proof bundles.
///
/// Stores ProofBundles as IPLD objects on IPFS and provides retrieval via CID.
pub struct IpfsTransport {
    config: IpfsConfig,
    connected: bool,
    client: Option<reqwest::Client>,
}

#[cfg(feature = "ipfs")]
impl IpfsTransport {
    /// Create a new IPFS transport with the given configuration.
    pub fn new(config: IpfsConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .ok();

        Self {
            config,
            connected: false,
            client,
        }
    }

    /// Create a new IPFS transport with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(IpfsConfig::default())
    }

    /// Connect to the IPFS node.
    pub async fn connect(&mut self) -> Result<(), TransportError> {
        if let Some(ref client) = self.client {
            // Test connectivity by calling the IPFS version endpoint
            let url = format!("{}/version", self.config.api_url);
            match client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        self.connected = true;
                        info!("Connected to IPFS node at {}", self.config.api_url);
                        return Ok(());
                    } else {
                        warn!(
                            "IPFS node returned status {}: {}",
                            response.status(),
                            self.config.api_url
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to connect to IPFS node: {}", e);
                }
            }
        }

        self.connected = false;
        Err(TransportError::Network(format!(
            "Failed to connect to IPFS at {}",
            self.config.api_url
        )))
    }

    /// Add a ProofBundle to IPFS.
    ///
    /// Returns the CID (Content Identifier) of the stored object.
    pub async fn add_proof(&self, proof: &ProofBundle) -> Result<String, TransportError> {
        if !self.connected {
            return Err(TransportError::NotInitialized);
        }

        let client = self.client.as_ref().ok_or(TransportError::NotInitialized)?;

        // Serialize the proof bundle
        let proof_bytes = crate::serialize_proof(proof)?;

        // Upload to IPFS
        let url = format!("{}/add", self.config.api_url);
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(proof_bytes)
                .file_name("proof_bundle.json")
                .mime_str("application/json")
                .map_err(|e| TransportError::Serialization(e.to_string()))?,
        );

        let response = client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("IPFS add failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(TransportError::PublishFailed);
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        let cid = result["Hash"]
            .as_str()
            .ok_or_else(|| TransportError::InvalidEvent("No CID in response".to_string()))?;

        debug!(cid, "Stored ProofBundle on IPFS");
        Ok(cid.to_string())
    }

    /// Retrieve a ProofBundle from IPFS by CID.
    pub async fn get_proof(&self, cid: &str) -> Result<ProofBundle, TransportError> {
        if !self.connected {
            return Err(TransportError::NotInitialized);
        }

        let client = self.client.as_ref().ok_or(TransportError::NotInitialized)?;

        // Try gateway first (faster for public content)
        let gateway_url = format!("{}/{}", self.config.gateway_url, cid);
        match client.get(&gateway_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let bytes = response.bytes().await.map_err(|e| {
                        TransportError::Network(format!("Failed to download: {}", e))
                    })?;
                    let proof = crate::deserialize_proof(&bytes)?;
                    debug!(cid, "Retrieved ProofBundle from IPFS gateway");
                    return Ok(proof);
                }
            }
            Err(e) => {
                debug!(cid, error = %e, "Gateway retrieval failed, trying API");
            }
        }

        // Fallback to IPFS API
        let api_url = format!("{}/cat?arg={}", self.config.api_url, cid);
        let response = client
            .get(&api_url)
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("IPFS cat failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(TransportError::InvalidEvent(format!(
                "Failed to retrieve CID {}",
                cid
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| TransportError::Network(format!("Failed to download: {}", e)))?;
        let proof = crate::deserialize_proof(&bytes)?;
        debug!(cid, "Retrieved ProofBundle from IPFS API");
        Ok(proof)
    }

    /// Pin a ProofBundle to ensure it's not garbage collected.
    pub async fn pin_proof(&self, cid: &str) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::NotInitialized);
        }

        let client = self.client.as_ref().ok_or(TransportError::NotInitialized)?;

        let url = format!("{}/pin/add?arg={}", self.config.api_url, cid);
        let response = client
            .post(&url)
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("IPFS pin failed: {}", e)))?;

        if response.status().is_success() {
            debug!(cid, "Pinned ProofBundle on IPFS");
            Ok(())
        } else {
            Err(TransportError::PublishFailed)
        }
    }
}

#[cfg(feature = "ipfs")]
#[async_trait]
impl ProofTransport for IpfsTransport {
    /// Broadcast a proof bundle to IPFS.
    ///
    /// Returns an EventId containing the IPFS CID.
    async fn broadcast_proof(&self, proof: &ProofBundle) -> Result<EventId, TransportError> {
        let cid = self.add_proof(proof).await?;

        // Pin the proof to ensure persistence
        self.pin_proof(&cid).await?;

        Ok(EventId::new(cid))
    }

    /// Subscribe to incoming proofs from IPFS.
    ///
    /// Note: IPFS is not a pub/sub system, so this returns an empty stream.
    /// IPFS is used as a storage fallback, not for real-time delivery.
    async fn subscribe_proofs(
        &self,
        _filter: ProofFilter,
    ) -> Result<ReceiverStream<DeliveredProof>, TransportError> {
        warn!("IPFS does not support real-time proof subscriptions");
        // Return an empty stream since IPFS doesn't support pub/sub
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(tokio_stream::wrappers::ReceiverStream::new(rx))
    }

    /// Check if connected to IPFS node.
    async fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get the transport name.
    fn transport_name(&self) -> &str {
        "ipfs"
    }

    /// Disconnect from IPFS node.
    async fn disconnect(&self) {
        info!("IPFS transport disconnected");
    }
}

#[cfg(all(test, feature = "ipfs"))]
mod tests {
    use super::*;

    #[test]
    fn test_ipfs_config_default() {
        let config = IpfsConfig::default();
        assert_eq!(config.api_url, "http://127.0.0.1:5001/api/v0");
        assert_eq!(config.gateway_url, "https://ipfs.io/ipfs");
        assert_eq!(config.timeout_secs, 30);
    }

    #[tokio::test]
    async fn test_ipfs_transport_creation() {
        let transport = IpfsTransport::with_defaults();
        assert_eq!(transport.transport_name(), "ipfs");
        assert!(!transport.is_connected().await);
    }
}
