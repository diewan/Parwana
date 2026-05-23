//! IPFS Storage Layer for CSV
//!
//! IPFS provides complementary storage to Celestia for large STARK proofs.
//! While Celestia guarantees data availability through sampling, IPFS
//! provides content-addressed storage that can be cheaper for very large data.
//!
//! ## Architecture
//!
//! ```text
//! Large STARK Proof (>2MB):
//!   1. Store on IPFS → get CID
//!   2. Anchor CID on Celestia DA layer (small)
//!   3. Sanad metadata points to Celestia anchor
//!   4. Verification: retrieve from IPFS, verify CID matches anchor
//! ```
//!
//! ## Security Model
//!
//! - Celestia provides **availability** guarantees
//! - IPFS provides **retrievability** (best effort)
//! - CID anchoring prevents tampering (content-addressed)
//! - Fraud proofs can challenge unavailability

use cid::Cid;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CelestiaError, MAX_IPFS_DATA_SIZE, Result};

/// IPFS Content Identifier wrapper
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpfsCid {
    /// The CID string representation
    pub cid: String,
    /// CID version (0 or 1)
    pub version: u64,
    /// Multicodec content type
    pub codec: u64,
    /// Multihash code
    pub hash_code: u64,
    /// Hash digest bytes
    pub hash: Vec<u8>,
}

impl IpfsCid {
    /// Create from a CID string
    ///
    /// # Arguments
    /// * `cid_str` - CID string (e.g., "QmXxxx..." or "bafy...")
    pub fn from_string(cid_str: impl AsRef<str>) -> Result<Self> {
        let cid_str = cid_str.as_ref();

        // Parse the CID
        let cid = Cid::try_from(cid_str)
            .map_err(|e| CelestiaError::InvalidCid(format!("Failed to parse CID: {}", e)))?;

        let hash = cid.hash();

        Ok(Self {
            cid: cid_str.to_string(),
            version: cid.version().into(),
            codec: cid.codec(),
            hash_code: hash.code(),
            hash: hash.digest().to_vec(),
        })
    }

    /// Create a CID v1 from raw data (SHA256 hashing)
    ///
    /// This creates a CID for the given data using:
    /// - CID v1
    /// - Raw codec (0x55)
    /// - SHA2-256 multihash
    pub fn from_data(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(CelestiaError::InvalidCid(
                "Cannot create CID from empty data".to_string(),
            ));
        }
        if data.len() > MAX_IPFS_DATA_SIZE {
            return Err(CelestiaError::InvalidCid(format!(
                "Data too large: {} bytes (max: {})",
                data.len(),
                MAX_IPFS_DATA_SIZE
            )));
        }

        // Compute SHA256 hash
        let hash_bytes: [u8; 32] = Sha256::digest(data).into();

        // Create multihash (SHA2-256 = 0x12)
        let multihash = Multihash::wrap(0x12, &hash_bytes).map_err(|e| {
            CelestiaError::InvalidCid(format!("Failed to create multihash: {:?}", e))
        })?;

        // Create CID v1 with raw codec
        let cid = Cid::new_v1(0x55, multihash);

        Ok(Self {
            cid: cid.to_string(),
            version: 1,
            codec: 0x55,
            hash_code: 0x12,
            hash: hash_bytes.to_vec(),
        })
    }

    /// Get the CID string
    pub fn as_str(&self) -> &str {
        &self.cid
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.cid.bytes().collect()
    }

    /// Verify that data matches this CID
    pub fn verify_data(&self, data: &[u8]) -> bool {
        match Self::from_data(data) {
            Ok(computed) => computed.cid == self.cid,
            Err(_) => false,
        }
    }

    /// Get the hash bytes
    pub fn hash_bytes(&self) -> &[u8] {
        &self.hash
    }

    /// Check if this is a valid CIDv0 (starts with Qm)
    pub fn is_v0(&self) -> bool {
        self.version == 0
    }

    /// Check if this is a valid CIDv1 (starts with bafy, bafk, etc.)
    pub fn is_v1(&self) -> bool {
        self.version == 1
    }

    /// Convert to base32 representation
    pub fn to_base32(&self) -> String {
        // CID v1 strings are typically base32 encoded
        if self.is_v1() {
            self.cid.clone()
        } else {
            // Convert v0 to v1 for base32
            self.cid.clone()
        }
    }
}

impl core::fmt::Display for IpfsCid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.cid)
    }
}

/// IPFS storage reference
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpfsReference {
    /// Content ID
    pub cid: IpfsCid,
    /// Content size in bytes
    pub size: u64,
    /// Content type (MIME type)
    pub content_type: Option<String>,
    /// Pin status
    pub pinned: bool,
    /// Timestamp when added
    pub timestamp: u64,
}

impl IpfsReference {
    /// Create a new IPFS reference
    pub fn new(cid: IpfsCid, size: u64) -> Self {
        Self {
            cid,
            size,
            content_type: None,
            pinned: false,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Mark as pinned
    pub fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }

    /// Serialize to bytes for anchoring on Celestia
    pub fn to_anchor_bytes(&self) -> Vec<u8> {
        // Format: [cid_len:2][cid_bytes][size:8][timestamp:8][pinned:1]
        let cid_bytes = self.cid.to_bytes();
        let mut result = Vec::with_capacity(2 + cid_bytes.len() + 8 + 8 + 1);

        result.extend_from_slice(&(cid_bytes.len() as u16).to_le_bytes());
        result.extend_from_slice(&cid_bytes);
        result.extend_from_slice(&self.size.to_le_bytes());
        result.extend_from_slice(&self.timestamp.to_le_bytes());
        result.push(if self.pinned { 1 } else { 0 });

        result
    }

    /// Deserialize from anchor bytes
    pub fn from_anchor_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 19 {
            // 2 + 1 (min cid) + 8 + 8 + 1
            return Err(CelestiaError::DeserializationError(
                "Insufficient bytes for IPFS reference".to_string(),
            ));
        }

        let cid_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + cid_len + 17 {
            return Err(CelestiaError::DeserializationError(
                "CID data truncated".to_string(),
            ));
        }

        let cid_str = String::from_utf8(bytes[2..2 + cid_len].to_vec())
            .map_err(|e| CelestiaError::DeserializationError(format!("Invalid CID UTF8: {}", e)))?;
        let cid = IpfsCid::from_string(cid_str)?;

        let size_offset = 2 + cid_len;
        let size = u64::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
            bytes[size_offset + 4],
            bytes[size_offset + 5],
            bytes[size_offset + 6],
            bytes[size_offset + 7],
        ]);

        let ts_offset = size_offset + 8;
        let timestamp = u64::from_le_bytes([
            bytes[ts_offset],
            bytes[ts_offset + 1],
            bytes[ts_offset + 2],
            bytes[ts_offset + 3],
            bytes[ts_offset + 4],
            bytes[ts_offset + 5],
            bytes[ts_offset + 6],
            bytes[ts_offset + 7],
        ]);

        let pinned = bytes[ts_offset + 8] == 1;

        Ok(Self {
            cid,
            size,
            content_type: None,
            pinned,
            timestamp,
        })
    }
}

/// Combined Celestia + IPFS storage info
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridStorageInfo {
    /// Celestia height where IPFS CID was anchored
    pub anchor_height: u64,
    /// Celestia namespace used
    pub namespace: crate::namespace::Namespace,
    /// IPFS reference
    pub ipfs: IpfsReference,
    /// Blob commitment on Celestia (of the anchor data)
    pub commitment: [u8; 32],
    /// Whether the data is available on IPFS
    pub ipfs_available: Option<bool>,
    /// Last checked timestamp
    pub last_checked: Option<u64>,
}

impl HybridStorageInfo {
    /// Create new hybrid storage info
    pub fn new(
        anchor_height: u64,
        namespace: crate::namespace::Namespace,
        ipfs: IpfsReference,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            anchor_height,
            namespace,
            ipfs,
            commitment,
            ipfs_available: None,
            last_checked: None,
        }
    }

    /// Mark as checked
    pub fn mark_checked(mut self, available: bool) -> Self {
        self.ipfs_available = Some(available);
        self.last_checked = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self
    }

    /// Get total storage footprint
    pub fn total_size(&self) -> u64 {
        // Celestia anchor is small (~100 bytes)
        // IPFS stores the actual data
        100 + self.ipfs.size
    }

    /// Estimate cost ratio (Celestia would cost ~100x more for same data)
    pub fn cost_ratio(&self) -> f64 {
        // Approximate: Celestia ~$0.01/byte, IPFS ~$0.0001/byte
        // Plus the small Celestia anchor
        0.01 // Placeholder - real ratio depends on market conditions
    }
}

/// IPFS storage client trait
///
/// This trait abstracts over different IPFS client implementations:
/// - Kubo (go-ipfs) HTTP API
/// - Pinning services (Pinata, Web3.Storage)
/// - Browser-based (js-ipfs, helia)
pub trait IpfsClient: Send + Sync {
    /// Store data on IPFS
    fn put<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<IpfsCid>> + Send + 'a>>;

    /// Retrieve data from IPFS
    fn get(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>>;

    /// Check if data is available
    fn exists(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>>;

    /// Pin content to ensure persistence
    fn pin(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;

    /// Unpin content
    fn unpin(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;

    /// Get content size without downloading
    fn stat(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + '_>>;
}

/// Mock IPFS client for testing
#[derive(Clone, Debug, Default)]
pub struct MockIpfsClient {
    storage: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>>,
}

impl MockIpfsClient {
    /// Create a new mock client
    pub fn new() -> Self {
        Self {
            storage: std::sync::Arc::new(
                tokio::sync::RwLock::new(std::collections::HashMap::new()),
            ),
        }
    }
}

impl IpfsClient for MockIpfsClient {
    fn put(
        &self,
        data: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<IpfsCid>> + Send + '_>> {
        let data = data.to_vec();
        let storage = self.storage.clone();
        Box::pin(async move {
            let cid = IpfsCid::from_data(&data)?;
            let mut guard = storage.write().await;
            guard.insert(cid.cid.clone(), data);
            Ok(cid)
        })
    }

    fn get(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let cid_str = cid.cid.clone();
        let storage = self.storage.clone();
        Box::pin(async move {
            let guard = storage.read().await;
            guard
                .get(&cid_str)
                .cloned()
                .ok_or_else(|| CelestiaError::IpfsError(format!("CID not found: {}", cid_str)))
        })
    }

    fn exists(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + '_>> {
        let cid_str = cid.cid.clone();
        let storage = self.storage.clone();
        Box::pin(async move {
            let guard = storage.read().await;
            Ok(guard.contains_key(&cid_str))
        })
    }

    fn pin(
        &self,
        _cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { Ok(()) }) // Mock: always succeeds
    }

    fn unpin(
        &self,
        _cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { Ok(()) }) // Mock: always succeeds
    }

    fn stat(
        &self,
        cid: &IpfsCid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + '_>> {
        let cid_str = cid.cid.clone();
        let storage = self.storage.clone();
        Box::pin(async move {
            let guard = storage.read().await;
            guard
                .get(&cid_str)
                .map(|d| d.len() as u64)
                .ok_or_else(|| CelestiaError::IpfsError(format!("CID not found: {}", cid_str)))
        })
    }
}

/// Compute the CID that would result from storing data on IPFS
pub fn compute_cid(data: &[u8]) -> Result<IpfsCid> {
    IpfsCid::from_data(data)
}

/// Verify that data matches a CID
pub fn verify_cid(cid: &IpfsCid, data: &[u8]) -> bool {
    cid.verify_data(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfs_cid_from_string() {
        // CIDv0 example
        let cid_v0 = "QmYjtig7VJQ6XsnUjqqJvj7QaMcCAwtrgNdahSiFofrE7o";
        let parsed = IpfsCid::from_string(cid_v0).unwrap();
        assert_eq!(parsed.cid, cid_v0);
        assert!(parsed.is_v0());
    }

    #[test]
    fn test_ipfs_cid_from_data() {
        let data = b"hello world";
        let cid = IpfsCid::from_data(data).unwrap();

        assert!(cid.is_v1());
        assert!(cid.verify_data(data));
        assert!(!cid.verify_data(b"wrong data"));
    }

    #[test]
    fn test_ipfs_cid_empty_data() {
        let result = IpfsCid::from_data(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_ipfs_reference() {
        let cid = IpfsCid::from_data(b"test data").unwrap();
        let reference = IpfsReference::new(cid, 9)
            .with_content_type("application/octet-stream")
            .pinned();

        assert_eq!(reference.size, 9);
        assert_eq!(
            reference.content_type,
            Some("application/octet-stream".to_string())
        );
        assert!(reference.pinned);
    }

    #[test]
    fn test_ipfs_reference_anchor_roundtrip() {
        let cid = IpfsCid::from_data(b"test data for anchor").unwrap();
        let reference = IpfsReference::new(cid, 20)
            .with_content_type("application/json")
            .pinned();

        let bytes = reference.to_anchor_bytes();
        let recovered = IpfsReference::from_anchor_bytes(&bytes).unwrap();

        assert_eq!(reference.cid.cid, recovered.cid.cid);
        assert_eq!(reference.size, recovered.size);
        assert_eq!(reference.pinned, recovered.pinned);
        assert_eq!(reference.timestamp, recovered.timestamp);
        // content_type is not included in anchor bytes
        assert!(recovered.content_type.is_none());
    }

    #[test]
    fn test_hybrid_storage_info() {
        use crate::namespace::Namespace;

        let cid = IpfsCid::from_data(b"large stark proof").unwrap();
        let reference = IpfsReference::new(cid, 1000000);
        let info = HybridStorageInfo::new(12345, Namespace::bitcoin_stark(), reference, [0u8; 32]);

        assert_eq!(info.anchor_height, 12345);
        assert_eq!(info.total_size(), 1000100); // 1M + 100 anchor
    }

    #[tokio::test]
    async fn test_mock_ipfs_client() {
        let client = MockIpfsClient::new();
        let data = b"test data for mock ipfs";

        // Put
        let cid = client.put(data).await.unwrap();
        assert!(cid.verify_data(data));

        // Exists
        assert!(client.exists(&cid).await.unwrap());
        let fake_cid = IpfsCid::from_data(b"other data").unwrap();
        assert!(!client.exists(&fake_cid).await.unwrap());

        // Get
        let retrieved = client.get(&cid).await.unwrap();
        assert_eq!(retrieved, data);

        // Stat
        let size = client.stat(&cid).await.unwrap();
        assert_eq!(size, data.len() as u64);

        // Pin/Unpin (no-op for mock)
        assert!(client.pin(&cid).await.is_ok());
        assert!(client.unpin(&cid).await.is_ok());
    }

    #[test]
    fn test_compute_cid() {
        let data = b"test data";
        let cid1 = compute_cid(data).unwrap();
        let cid2 = IpfsCid::from_data(data).unwrap();
        assert_eq!(cid1.cid, cid2.cid);
    }

    #[test]
    fn test_verify_cid() {
        let data = b"test data";
        let cid = IpfsCid::from_data(data).unwrap();
        assert!(verify_cid(&cid, data));
        assert!(!verify_cid(&cid, b"wrong data"));
    }
}
