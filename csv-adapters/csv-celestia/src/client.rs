//! Celestia Client with IPFS Fallback
//!
//! This module provides a high-level client that combines Celestia DA
//! with IPFS storage for efficient handling of both small and large proofs.
//!
//! ## Storage Strategy
//!
//! ```text
//! Data Size < 1MB:    Direct Celestia blob submission
//! Data Size >= 1MB:   Store on IPFS, anchor CID on Celestia
//! ```

use crate::blob::Blob;
use crate::commitment::BlobCommitment;
use crate::da_layer::{CelestiaDaLayer, CelestiaRpc, DaLayerConfig, DataAvailabilityLayer};
use crate::error::{CelestiaError, Result};
use crate::ipfs::{IpfsCid, IpfsClient, MockIpfsClient};
use crate::metadata::SanadMetadata;
use crate::namespace::Namespace;
use crate::proof_id::{ProofId, ProofLocation};
use crate::types::{CelestiaHeader, CelestiaSealPoint};

/// High-level Celestia client
pub struct CelestiaClient<C, I> {
    /// Inner DA layer
    da_layer: CelestiaDaLayer<C, I>,
    /// Default namespace
    default_namespace: Namespace,
}

/// Configuration for the Celestia client
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// DA layer configuration
    pub da_config: DaLayerConfig,
    /// Default namespace for operations
    pub default_namespace: Namespace,
    /// Auto-detect and use IPFS for large data
    pub auto_ipfs: bool,
    /// IPFS size threshold (bytes)
    pub ipfs_threshold: usize,
    /// Retry attempts for failed operations
    pub retry_attempts: u32,
    /// Timeout for operations (seconds)
    pub timeout_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        let da_config = DaLayerConfig::default();
        Self {
            da_config: da_config.clone(),
            default_namespace: da_config.namespace,
            auto_ipfs: true,
            ipfs_threshold: 1024 * 1024, // 1MB
            retry_attempts: 3,
            timeout_secs: 30,
        }
    }
}

impl<C, I> CelestiaClient<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    /// Create a new client
    pub fn new(da_layer: CelestiaDaLayer<C, I>, default_namespace: Namespace) -> Self {
        Self {
            da_layer,
            default_namespace,
        }
    }

    /// Create from configuration
    pub fn from_config(config: ClientConfig, celestia_rpc: C, ipfs_client: Option<I>) -> Self {
        let da_layer = CelestiaDaLayer::new(config.da_config, celestia_rpc, ipfs_client);
        Self::new(da_layer, config.default_namespace)
    }

    /// Store data on Celestia (with automatic IPFS fallback)
    ///
    /// # Arguments
    /// * `data` - Data to store
    /// * `namespace` - Optional namespace (uses default if None)
    pub async fn store(
        &self,
        data: Vec<u8>,
        namespace: Option<Namespace>,
    ) -> Result<ProofLocation> {
        let ns = namespace.unwrap_or(self.default_namespace);
        let blob = Blob::new(ns, data)?;
        let proof_id = self.da_layer.submit_blob(blob).await?;
        Ok(ProofLocation::celestia(proof_id))
    }

    /// Store data on IPFS and anchor on Celestia
    ///
    /// Use this for large data that shouldn't go directly to Celestia.
    pub async fn store_large(
        &self,
        data: Vec<u8>,
        namespace: Option<Namespace>,
    ) -> Result<ProofLocation> {
        let ns = namespace.unwrap_or(self.default_namespace);
        self.da_layer.store_on_ipfs(&data, ns).await
    }

    /// Retrieve data by proof location
    pub async fn retrieve(&self, location: &ProofLocation) -> Result<Vec<u8>> {
        match location {
            ProofLocation::Celestia { proof_id } => {
                let blob = self.da_layer.get_blob(proof_id).await?;
                Ok(blob.data)
            }
            ProofLocation::IpfsBacked { .. } | ProofLocation::Hybrid { .. } => {
                let cid_str = location.cid().ok_or_else(|| {
                    CelestiaError::InvalidCid("IPFS location missing CID".to_string())
                })?;
                let cid = IpfsCid::from_string(cid_str)?;
                self.da_layer.get_from_ipfs(&cid).await
            }
        }
    }

    /// Store Sanad metadata
    pub async fn store_metadata(&self, metadata: SanadMetadata) -> Result<ProofId> {
        self.da_layer.submit_metadata(metadata).await
    }

    /// Get Sanad metadata by proof ID
    pub async fn get_metadata(&self, proof_id: &ProofId) -> Result<SanadMetadata> {
        self.da_layer.get_metadata(proof_id).await
    }

    /// Create a seal point for a new Sanad
    pub async fn create_seal(&self) -> Result<CelestiaSealPoint> {
        let height = self.da_layer.get_latest_height().await?;
        let proof_id = ProofId::new(height, self.default_namespace, [0u8; 32]);
        Ok(CelestiaSealPoint::new(proof_id, height))
    }

    /// Verify data availability
    pub async fn check_availability(&self, proof_id: &ProofId, samples: u32) -> Result<bool> {
        self.da_layer.verify_availability(proof_id, samples).await
    }

    /// Get the latest block height
    pub async fn get_latest_height(&self) -> Result<u64> {
        self.da_layer.get_latest_height().await
    }

    /// Get block header
    pub async fn get_header(&self, height: u64) -> Result<CelestiaHeader> {
        self.da_layer.get_header(height).await
    }

    /// Get the commitment for data
    pub fn compute_commitment(&self, data: &[u8], namespace: Option<Namespace>) -> BlobCommitment {
        let ns = namespace.unwrap_or(self.default_namespace);
        BlobCommitment::compute(&ns, data)
    }

    /// Verify that retrieved data matches expected commitment
    pub async fn verify_data(
        &self,
        location: &ProofLocation,
        expected: &BlobCommitment,
    ) -> Result<bool> {
        let data = self.retrieve(location).await?;
        let ns = location
            .namespace()
            .cloned()
            .unwrap_or(self.default_namespace);
        let computed = BlobCommitment::compute(&ns, &data);
        Ok(computed.as_bytes() == expected.as_bytes())
    }

    /// Wait for data to be available with retries
    pub async fn wait_for_availability(
        &self,
        proof_id: &ProofId,
        max_attempts: u32,
        delay_ms: u64,
    ) -> Result<()> {
        for attempt in 0..max_attempts {
            match self.check_availability(proof_id, 1).await {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    if attempt < max_attempts - 1 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    }
                }
                Err(e) => {
                    if attempt == max_attempts - 1 {
                        return Err(e);
                    }
                }
            }
        }
        Err(CelestiaError::InclusionTimeout(max_attempts))
    }
}

/// Builder for creating Celestia clients
pub struct CelestiaClientBuilder<C, I> {
    config: ClientConfig,
    celestia_rpc: Option<C>,
    ipfs_client: Option<I>,
}

impl<C, I> CelestiaClientBuilder<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: ClientConfig::default(),
            celestia_rpc: None,
            ipfs_client: None,
        }
    }

    /// Set DA configuration
    pub fn with_da_config(mut self, config: DaLayerConfig) -> Self {
        self.config.da_config = config;
        self
    }

    /// Set default namespace
    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.config.default_namespace = namespace;
        self.config.da_config.namespace = namespace;
        self
    }

    /// Set Celestia RPC client
    pub fn with_celestia_rpc(mut self, rpc: C) -> Self {
        self.celestia_rpc = Some(rpc);
        self
    }

    /// Set IPFS client
    pub fn with_ipfs(mut self, ipfs: I) -> Self {
        self.ipfs_client = Some(ipfs);
        self
    }

    /// Set IPFS threshold
    pub fn with_ipfs_threshold(mut self, threshold: usize) -> Self {
        self.config.ipfs_threshold = threshold;
        self.config.da_config.ipfs_threshold = threshold;
        self
    }

    /// Build the client
    pub fn build(self) -> Result<CelestiaClient<C, I>> {
        let celestia_rpc = self.celestia_rpc.ok_or_else(|| {
            CelestiaError::InvalidInput("Celestia RPC client required".to_string())
        })?;

        let da_layer = CelestiaDaLayer::new(self.config.da_config, celestia_rpc, self.ipfs_client);

        Ok(CelestiaClient::new(da_layer, self.config.default_namespace))
    }
}

impl<C, I> Default for CelestiaClientBuilder<C, I>
where
    C: CelestiaRpc + Send + Sync,
    I: IpfsClient + Send + Sync,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience type alias for test client
pub type TestCelestiaClient = CelestiaClient<crate::da_layer::MockCelestiaRpc, MockIpfsClient>;

/// Create a test client with mock implementations
pub async fn create_test_client() -> TestCelestiaClient {
    let celestia = crate::da_layer::MockCelestiaRpc::new();
    celestia.set_height(100).await;

    let ipfs = MockIpfsClient::new();
    let config = ClientConfig::default();

    let da_layer = CelestiaDaLayer::new(config.da_config, celestia, Some(ipfs));
    CelestiaClient::new(da_layer, Namespace::metadata())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::BlobCommitment;
    use crate::metadata::{ProofInfo, SanadMetadata};
    use crate::proof_id::ProofLocation;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let client = create_test_client().await;
        let data = vec![1, 2, 3, 4, 5];

        let location = client.store(data.clone(), None).await.unwrap();
        assert!(location.is_direct_celestia());

        let retrieved = client.retrieve(&location).await.unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_store_large() {
        let client = create_test_client().await;
        let data = vec![0u8; 1024 * 1024 + 1]; // Just over 1MB

        let location = client.store_large(data.clone(), None).await.unwrap();
        assert!(location.uses_ipfs());

        let retrieved = client.retrieve(&location).await.unwrap();
        assert_eq!(retrieved.len(), data.len());
    }

    #[tokio::test]
    async fn test_metadata_storage() {
        let client = create_test_client().await;
        let ns = Namespace::bitcoin_stark();
        let proof_id = crate::proof_id::ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };

        let metadata = SanadMetadata::new(
            "stark-proof",
            "bitcoin",
            location,
            BlobCommitment::new([0u8; 32]),
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

        let proof_id = client.store_metadata(metadata.clone()).await.unwrap();
        let retrieved = client.get_metadata(&proof_id).await.unwrap();

        assert_eq!(retrieved.id, metadata.id);
        assert_eq!(retrieved.sanad_type, metadata.sanad_type);
    }

    #[tokio::test]
    async fn test_compute_commitment() {
        let client = create_test_client().await;
        let data = b"test data";

        let commitment = client.compute_commitment(data, None);
        let expected = BlobCommitment::compute(&client.default_namespace, data);

        assert_eq!(commitment.as_bytes(), expected.as_bytes());
    }

    #[tokio::test]
    async fn test_verify_data() {
        let client = create_test_client().await;
        let data = vec![1, 2, 3, 4, 5];

        let location = client.store(data.clone(), None).await.unwrap();
        let commitment = client.compute_commitment(&data, None);

        let verified = client.verify_data(&location, &commitment).await.unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn test_create_seal() {
        let client = create_test_client().await;
        let seal = client.create_seal().await.unwrap();

        assert!(seal.is_valid());
        assert!(!seal.consumed);
    }

    #[tokio::test]
    async fn test_check_availability() {
        let client = create_test_client().await;
        let data = vec![1, 2, 3];

        let location = client.store(data, None).await.unwrap();
        let proof_id = match location {
            ProofLocation::Celestia { proof_id } => proof_id,
            _ => panic!("Expected direct Celestia"),
        };

        let available = client.check_availability(&proof_id, 5).await.unwrap();
        assert!(available);
    }

    #[tokio::test]
    async fn test_get_latest_height() {
        let client = create_test_client().await;
        let height = client.get_latest_height().await.unwrap();
        assert_eq!(height, 100);
    }

    #[tokio::test]
    async fn test_builder() {
        let celestia = crate::da_layer::MockCelestiaRpc::new();
        let ipfs = MockIpfsClient::new();

        let client = CelestiaClientBuilder::new()
            .with_celestia_rpc(celestia)
            .with_ipfs(ipfs)
            .with_namespace(Namespace::bitcoin_stark())
            .with_ipfs_threshold(512 * 1024)
            .build()
            .unwrap();

        assert_eq!(client.default_namespace, Namespace::bitcoin_stark());
    }
}
