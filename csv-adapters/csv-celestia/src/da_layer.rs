//! Data Availability Layer for Celestia + IPFS
//!
//! This module defines the `DataAvailabilityLayer` trait and its
//! implementation that combines Celestia DA guarantees with IPFS storage.
//!
//! ## Architecture
//!
//! ```text
//! +-------------------+      +------------------+
//! |   Sanad Proof     |----->|  IPFS (Storage)  |
//! |   (Large STARK)   |      |  - Cheap         |
//! +-------------------+      |  - Persistent    |
//!           |                +------------------+
//!           v                         |
//! +-------------------+               v
//! | Celestia (Anchor) |<-----+------ CID
//! | - DA Guarantee    |      |
//! | - Light Clients   |      +---> [Small anchor]
//! +-------------------+
//! ```

use async_trait::async_trait;

use crate::blob::Blob;
use crate::commitment::{BlobCommitment, CommitmentProof, FraudProof};
use crate::error::{CelestiaError, Result};
use crate::ipfs::{IpfsCid, IpfsClient, IpfsReference};
use crate::metadata::{MetadataBatch, SanadMetadata};
use crate::namespace::Namespace;
use crate::proof_id::{ProofId, ProofLocation};
use crate::types::{CelestiaFinalityProof, CelestiaHeader};

/// Data Availability Layer trait
///
/// This trait abstracts over different DA implementations:
/// - Pure Celestia (blobs directly on DA layer)
/// - IPFS-backed (CIDs anchored on Celestia)
/// - Hybrid (metadata on Celestia, data on IPFS)
#[async_trait]
pub trait DataAvailabilityLayer: Send + Sync {
    /// Submit a blob to the DA layer
    ///
    /// Returns the ProofId that uniquely identifies this blob's location.
    async fn submit_blob(&self, blob: Blob) -> Result<ProofId>;

    /// Retrieve a blob by its proof ID
    async fn get_blob(&self, proof_id: &ProofId) -> Result<Blob>;

    /// Verify that a blob is available on the DA layer
    ///
    /// Performs data availability sampling to confirm the data can be retrieved.
    async fn verify_availability(&self, proof_id: &ProofId, samples: u32) -> Result<bool>;

    /// Get the commitment proof for a blob
    async fn get_commitment_proof(&self, proof_id: &ProofId) -> Result<CommitmentProof>;

    /// Verify finality for a proof
    async fn verify_finality(&self, proof_id: &ProofId) -> Result<CelestiaFinalityProof>;

    /// Get the latest block height
    async fn get_latest_height(&self) -> Result<u64>;

    /// Get block header at height
    async fn get_header(&self, height: u64) -> Result<CelestiaHeader>;

    /// Store data on IPFS and anchor CID on Celestia
    async fn store_on_ipfs(&self, data: &[u8], namespace: Namespace) -> Result<ProofLocation>;

    /// Retrieve data from IPFS
    async fn get_from_ipfs(&self, cid: &IpfsCid) -> Result<Vec<u8>>;

    /// Submit Sanad metadata
    async fn submit_metadata(&self, metadata: SanadMetadata) -> Result<ProofId>;

    /// Get Sanad metadata by ID
    async fn get_metadata(&self, proof_id: &ProofId) -> Result<SanadMetadata>;

    /// Submit a batch of metadata
    async fn submit_metadata_batch(&self, batch: MetadataBatch) -> Result<ProofId>;

    /// Submit a fraud proof
    async fn submit_fraud_proof(&self, fraud_proof: FraudProof) -> Result<ProofId>;

    /// Namespace being used
    fn namespace(&self) -> Namespace;
}

/// Configuration for the DA layer
#[derive(Clone, Debug)]
pub struct DaLayerConfig {
    /// Celestia RPC endpoint
    pub celestia_rpc: String,
    /// Celestia namespace to use
    pub namespace: Namespace,
    /// IPFS API endpoint (if using IPFS)
    pub ipfs_api: Option<String>,
    /// IPFS pinning service (optional)
    pub ipfs_pinning: Option<String>,
    /// Use IPFS for data larger than this threshold (bytes)
    pub ipfs_threshold: usize,
    /// Max blob size for direct Celestia storage
    pub max_celestia_blob_size: usize,
    /// Confirmation depth for finality
    pub confirmation_depth: u32,
    /// Enable data availability sampling
    pub enable_sampling: bool,
    /// Number of samples for availability verification
    pub sample_count: u32,
}

impl Default for DaLayerConfig {
    fn default() -> Self {
        Self {
            celestia_rpc: "http://localhost:26658".to_string(),
            namespace: Namespace::metadata(),
            ipfs_api: Some("http://localhost:5001".to_string()),
            ipfs_pinning: None,
            ipfs_threshold: 1024 * 1024,             // 1MB
            max_celestia_blob_size: 2 * 1024 * 1024, // 2MB
            confirmation_depth: 1,                   // Tendermint has instant finality
            enable_sampling: true,
            sample_count: 15,
        }
    }
}

impl DaLayerConfig {
    /// Create a new config with custom RPC endpoint
    pub fn with_rpc(rpc_url: impl Into<String>) -> Self {
        Self {
            celestia_rpc: rpc_url.into(),
            ..Default::default()
        }
    }

    /// Set the namespace
    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespace = namespace;
        self
    }

    /// Enable IPFS with custom threshold
    pub fn with_ipfs(mut self, api_url: impl Into<String>, threshold: usize) -> Self {
        self.ipfs_api = Some(api_url.into());
        self.ipfs_threshold = threshold;
        self
    }

    /// Disable IPFS
    pub fn without_ipfs(mut self) -> Self {
        self.ipfs_api = None;
        self.ipfs_threshold = usize::MAX;
        self
    }
}

/// Implementation of DataAvailabilityLayer
pub struct CelestiaDaLayer<C, I> {
    /// Configuration
    config: DaLayerConfig,
    /// Celestia RPC client
    celestia_client: C,
    /// IPFS client (optional)
    ipfs_client: Option<I>,
}

/// Celestia RPC client trait
#[async_trait]
pub trait CelestiaRpc: Send + Sync {
    /// Submit blob to Celestia
    async fn submit_blob(&self, namespace: Namespace, data: &[u8]) -> Result<(u64, [u8; 32])>;

    /// Get blob by height and namespace
    async fn get_blob(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: [u8; 32],
    ) -> Result<Vec<u8>>;

    /// Get latest height
    async fn get_latest_height(&self) -> Result<u64>;

    /// Get block header
    async fn get_header(&self, height: u64) -> Result<CelestiaHeader>;

    /// Get commitment proof
    async fn get_commitment_proof(
        &self,
        height: u64,
        commitment: [u8; 32],
    ) -> Result<CommitmentProof>;

    /// Get finality proof
    async fn get_finality_proof(&self, height: u64) -> Result<CelestiaFinalityProof>;
}

/// Mock Celestia RPC for testing
#[derive(Clone, Debug, Default)]
#[allow(clippy::type_complexity)]
pub struct MockCelestiaRpc {
    storage: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<(u64, String, [u8; 32]), Vec<u8>>>,
    >,
    current_height: std::sync::Arc<tokio::sync::RwLock<u64>>,
}

impl MockCelestiaRpc {
    /// Create new mock
    pub fn new() -> Self {
        Self {
            storage: std::sync::Arc::new(
                tokio::sync::RwLock::new(std::collections::HashMap::new()),
            ),
            current_height: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        }
    }

    /// Increment height
    pub async fn increment_height(&self) {
        let mut height = self.current_height.write().await;
        *height += 1;
    }

    /// Set height
    pub async fn set_height(&self, height: u64) {
        let mut h = self.current_height.write().await;
        *h = height;
    }
}

#[async_trait]
impl CelestiaRpc for MockCelestiaRpc {
    async fn submit_blob(&self, namespace: Namespace, data: &[u8]) -> Result<(u64, [u8; 32])> {
        let height = *self.current_height.read().await;
        let commitment = BlobCommitment::compute(&namespace, data);

        let mut storage = self.storage.write().await;
        storage.insert(
            (height, namespace.to_hex(), *commitment.as_bytes()),
            data.to_vec(),
        );

        Ok((height, *commitment.as_bytes()))
    }

    async fn get_blob(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: [u8; 32],
    ) -> Result<Vec<u8>> {
        let storage = self.storage.read().await;
        storage
            .get(&(height, namespace.to_hex(), commitment))
            .cloned()
            .ok_or_else(|| {
                CelestiaError::DataNotFound(format!(
                    "Blob at height {} with commitment {:.8} not found",
                    height,
                    hex::encode(&commitment[..4])
                ))
            })
    }

    async fn get_latest_height(&self) -> Result<u64> {
        Ok(*self.current_height.read().await)
    }

    async fn get_header(&self, height: u64) -> Result<CelestiaHeader> {
        Ok(CelestiaHeader::new(
            "celestia-mock",
            height,
            [height as u8; 32],
            [height as u8; 32],
        ))
    }

    async fn get_commitment_proof(
        &self,
        height: u64,
        commitment: [u8; 32],
    ) -> Result<CommitmentProof> {
        let namespace = Namespace::metadata();
        Ok(CommitmentProof::new(
            height,
            namespace,
            BlobCommitment::new(commitment),
            [height as u8; 32], // row_root
            [height as u8; 32], // data_root
            [height as u8; 32], // block_hash
        ))
    }

    async fn get_finality_proof(&self, height: u64) -> Result<CelestiaFinalityProof> {
        Ok(
            CelestiaFinalityProof::new(height, [height as u8; 32], [height as u8; 32])
                .with_quorum(vec![vec![1, 2, 3]]),
        )
    }
}

impl<C, I> CelestiaDaLayer<C, I>
where
    C: CelestiaRpc,
    I: IpfsClient,
{
    /// Create a new DA layer
    pub fn new(config: DaLayerConfig, celestia_client: C, ipfs_client: Option<I>) -> Self {
        Self {
            config,
            celestia_client,
            ipfs_client,
        }
    }

    /// Check if IPFS should be used for this data size
    fn should_use_ipfs(&self, size: usize) -> bool {
        self.ipfs_client.is_some() && size >= self.config.ipfs_threshold
    }

    /// Submit blob with automatic IPFS fallback for large data
    async fn submit_with_auto_ipfs(&self, blob: Blob) -> Result<ProofLocation> {
        let size = blob.size();

        if self.should_use_ipfs(size) {
            // Store on IPFS and anchor CID on Celestia
            let ipfs = self
                .ipfs_client
                .as_ref()
                .expect("IPFS client must be present when IPFS is enabled");
            let cid = ipfs.put(&blob.data).await?;

            // Create anchor data (CID + metadata)
            let ipfs_ref = IpfsReference::new(cid.clone(), size as u64)
                .with_content_type("application/octet-stream")
                .pinned();
            let anchor_data = ipfs_ref.to_anchor_bytes();

            // Anchor on Celestia
            let (height, commitment) = self
                .celestia_client
                .submit_blob(blob.namespace, &anchor_data)
                .await?;

            Ok(ProofLocation::hybrid(
                ProofId::new(height, blob.namespace, commitment),
                cid.as_str(),
            ))
        } else {
            // Direct Celestia storage
            let (height, commitment) = self
                .celestia_client
                .submit_blob(blob.namespace, &blob.data)
                .await?;

            let proof_id = ProofId::new(height, blob.namespace, commitment);
            Ok(ProofLocation::celestia(proof_id))
        }
    }
}

#[async_trait]
impl<C, I> DataAvailabilityLayer for CelestiaDaLayer<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    async fn submit_blob(&self, blob: Blob) -> Result<ProofId> {
        let location = self.submit_with_auto_ipfs(blob).await?;
        match location {
            ProofLocation::Celestia { proof_id } => Ok(proof_id),
            ProofLocation::Hybrid { metadata_id, .. } => Ok(metadata_id),
            _ => Err(CelestiaError::InternalError(
                "Unexpected IPFS-only location from submit".to_string(),
            )),
        }
    }

    async fn get_blob(&self, proof_id: &ProofId) -> Result<Blob> {
        let data = self
            .celestia_client
            .get_blob(proof_id.height, proof_id.namespace, proof_id.commitment)
            .await?;

        Blob::new(proof_id.namespace, data)
    }

    async fn verify_availability(&self, proof_id: &ProofId, _samples: u32) -> Result<bool> {
        // For mock/testing, just check if data exists
        let result = self
            .celestia_client
            .get_blob(proof_id.height, proof_id.namespace, proof_id.commitment)
            .await;

        Ok(result.is_ok())
    }

    async fn get_commitment_proof(&self, proof_id: &ProofId) -> Result<CommitmentProof> {
        self.celestia_client
            .get_commitment_proof(proof_id.height, proof_id.commitment)
            .await
    }

    async fn verify_finality(&self, proof_id: &ProofId) -> Result<CelestiaFinalityProof> {
        self.celestia_client
            .get_finality_proof(proof_id.height)
            .await
    }

    async fn get_latest_height(&self) -> Result<u64> {
        self.celestia_client.get_latest_height().await
    }

    async fn get_header(&self, height: u64) -> Result<CelestiaHeader> {
        self.celestia_client.get_header(height).await
    }

    async fn store_on_ipfs(&self, data: &[u8], namespace: Namespace) -> Result<ProofLocation> {
        let Some(ipfs) = self.ipfs_client.as_ref() else {
            return Err(CelestiaError::FeatureNotEnabled(
                "IPFS not configured".to_string(),
            ));
        };

        let cid = ipfs.put(data).await?;
        let ipfs_ref = IpfsReference::new(cid.clone(), data.len() as u64);
        let anchor_data = ipfs_ref.to_anchor_bytes();

        let (height, _commitment) = self
            .celestia_client
            .submit_blob(namespace, &anchor_data)
            .await?;

        Ok(ProofLocation::ipfs_backed(height, cid.as_str(), namespace))
    }

    async fn get_from_ipfs(&self, cid: &IpfsCid) -> Result<Vec<u8>> {
        let Some(ipfs) = self.ipfs_client.as_ref() else {
            return Err(CelestiaError::FeatureNotEnabled(
                "IPFS not configured".to_string(),
            ));
        };

        ipfs.get(cid).await
    }

    async fn submit_metadata(&self, metadata: SanadMetadata) -> Result<ProofId> {
        let json = metadata.to_json()?;
        let blob = Blob::new(self.config.namespace, json.into_bytes())?;
        self.submit_blob(blob).await
    }

    async fn get_metadata(&self, proof_id: &ProofId) -> Result<SanadMetadata> {
        let blob = self.get_blob(proof_id).await?;
        let json = String::from_utf8(blob.data).map_err(|e| {
            CelestiaError::DeserializationError(format!("Invalid UTF8 in metadata: {}", e))
        })?;
        SanadMetadata::from_json(&json)
    }

    async fn submit_metadata_batch(&self, batch: MetadataBatch) -> Result<ProofId> {
        let json = serde_json::to_vec(&batch)
            .map_err(|e| CelestiaError::SerializationError(format!("JSON: {}", e)))?;
        let blob = Blob::new(self.config.namespace, json)?;
        self.submit_blob(blob).await
    }

    async fn submit_fraud_proof(&self, fraud_proof: FraudProof) -> Result<ProofId> {
        let namespace = Namespace::fraud_proofs();
        let data = serde_json::to_vec(&fraud_proof)
            .map_err(|e| CelestiaError::SerializationError(format!("JSON: {}", e)))?;
        let blob = Blob::new(namespace, data)?;
        self.submit_blob(blob).await
    }

    fn namespace(&self) -> Namespace {
        self.config.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::Blob;
    use crate::ipfs::MockIpfsClient;
    use crate::metadata::ProofInfo;

    async fn setup_test_da() -> CelestiaDaLayer<MockCelestiaRpc, MockIpfsClient> {
        let celestia = MockCelestiaRpc::new();
        celestia.set_height(100).await;

        let ipfs = MockIpfsClient::new();
        let config = DaLayerConfig::default();

        CelestiaDaLayer::new(config, celestia, Some(ipfs))
    }

    #[tokio::test]
    async fn test_submit_and_get_blob() {
        let da = setup_test_da().await;
        let ns = Namespace::bitcoin_stark();
        let data = vec![1, 2, 3, 4, 5];
        let blob = Blob::new(ns, data.clone()).unwrap();

        let proof_id = da.submit_blob(blob).await.unwrap();

        // Increment height to simulate block progression
        da.celestia_client.increment_height().await;

        let retrieved = da.get_blob(&proof_id).await.unwrap();
        assert_eq!(retrieved.data, data);
    }

    #[tokio::test]
    async fn test_verify_availability() {
        let da = setup_test_da().await;
        let ns = Namespace::bitcoin_stark();
        let blob = Blob::new(ns, vec![1, 2, 3]).unwrap();

        let proof_id = da.submit_blob(blob).await.unwrap();

        let available = da.verify_availability(&proof_id, 5).await.unwrap();
        assert!(available);
    }

    #[tokio::test]
    async fn test_store_on_ipfs() {
        let da = setup_test_da().await;
        let ns = Namespace::bitcoin_stark();
        let data = b"large data for ipfs";

        let location = da.store_on_ipfs(data, ns).await.unwrap();

        assert!(location.uses_ipfs());
        assert!(location.cid().is_some());
    }

    #[tokio::test]
    async fn test_submit_metadata() {
        let da = setup_test_da().await;
        let ns = Namespace::bitcoin_stark();
        let proof_id = crate::proof_id::ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };

        let metadata = crate::metadata::SanadMetadata::new(
            "stark-proof",
            "bitcoin",
            location,
            crate::commitment::BlobCommitment::new([0u8; 32]),
            ProofInfo {
                size: 1024,
                format: "stark".to_string(),
                proof_system: "starkware".to_string(),
                estimated_verification_time_ms: 100,
                public_inputs_count: 10,
                circuit_id: None,
                verifier_key_ref: None,
            },
        );

        let result = da.submit_metadata(metadata).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_default() {
        let config = DaLayerConfig::default();
        assert_eq!(config.celestia_rpc, "http://localhost:26658");
        assert_eq!(config.ipfs_threshold, 1024 * 1024);
        assert!(config.enable_sampling);
    }

    #[test]
    fn test_config_builder() {
        let config = DaLayerConfig::with_rpc("https://celestia.example.com")
            .with_namespace(Namespace::bitcoin_stark())
            .with_ipfs("https://ipfs.example.com", 512 * 1024);

        assert_eq!(config.celestia_rpc, "https://celestia.example.com");
        assert_eq!(config.ipfs_threshold, 512 * 1024);
    }
}
