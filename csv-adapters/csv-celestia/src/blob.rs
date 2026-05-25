//! Celestia Blob Types
//!
//! Blobs are the fundamental unit of data posted to Celestia's Data Availability layer.
//! Each blob is identified by its namespace and contains arbitrary data (typically
//! STARK proofs for CSV validation).
//!
//! ## Blob Structure
//!
//! ```text
//! Blob:
//!   - namespace: 28 bytes (Celestia namespace)
//!   - data: variable bytes (the actual proof/data)
//!   - commitment: 32 bytes (hash of namespace + data)
//! ```
//!
//! ## Usage for CSV
//!
//! 1. Large STARK proofs are encoded as blob data
//! 2. Blobs are submitted to Celestia DA layer
//! 3. Only the commitment (32 bytes) is anchored on-chain
//! 4. Light clients verify proof availability via sampling

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CelestiaError, MAX_BLOB_SIZE, Result};
use crate::namespace::Namespace;

/// A blob of data for Celestia DA layer
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    /// Namespace this blob belongs to
    pub namespace: Namespace,
    /// Raw blob data (the proof or payload)
    pub data: Vec<u8>,
    /// Cached commitment (computed on creation)
    #[serde(skip)]
    commitment: Option<[u8; 32]>,
}

impl Blob {
    /// Create a new blob
    ///
    /// # Arguments
    /// * `namespace` - The namespace for this blob
    /// * `data` - The blob payload data
    ///
    /// # Errors
    /// Returns error if data exceeds MAX_BLOB_SIZE or is empty
    ///
    /// # Example
    /// ```
    /// use csv_celestia::{Blob, Namespace};
    ///
    /// let namespace = Namespace::bitcoin_stark();
    /// let data = vec![1, 2, 3, 4, 5];
    /// let blob = Blob::new(namespace, data).unwrap();
    /// ```
    pub fn new(namespace: Namespace, data: Vec<u8>) -> Result<Self> {
        if data.is_empty() {
            return Err(CelestiaError::EmptyBlob);
        }
        if data.len() > MAX_BLOB_SIZE {
            return Err(CelestiaError::blob_too_large(data.len()));
        }

        let mut blob = Self {
            namespace,
            data,
            commitment: None,
        };

        // Pre-compute commitment
        blob.commitment = Some(blob.compute_commitment());

        Ok(blob)
    }

    /// Get the blob size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Compute the blob commitment
    ///
    /// The commitment is: SHA256(namespace || data)
    /// This uniquely identifies the blob and is what's anchored on-chain.
    pub fn compute_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update(&self.data);
        hasher.finalize().into()
    }

    /// Get the cached commitment
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment.unwrap_or_else(|| self.compute_commitment())
    }

    /// Get commitment as hex string
    pub fn commitment_hex(&self) -> String {
        hex::encode(self.commitment())
    }

    /// Check if this blob is for a specific namespace
    pub fn is_in_namespace(&self, namespace: &Namespace) -> bool {
        self.namespace == *namespace
    }

    /// Create a blob from raw parts (for deserialization)
    ///
    /// # Safety
    /// The commitment is recomputed and must match the expected value.
    pub fn from_parts(namespace: Namespace, data: Vec<u8>) -> Result<Self> {
        Self::new(namespace, data)
    }

    /// Verify that a given commitment matches this blob
    pub fn verify_commitment(&self, expected: &[u8; 32]) -> bool {
        self.commitment() == *expected
    }

    /// Split blob data into chunks of specified size
    ///
    /// Useful for parallel processing or network transmission.
    pub fn chunks(&self, chunk_size: usize) -> impl Iterator<Item = &[u8]> {
        self.data.chunks(chunk_size)
    }

    /// Get the number of shares this blob would occupy
    ///
    /// Celestia organizes data into shares (typically 512 bytes each).
    pub fn share_count(&self, share_size: usize) -> usize {
        self.data.len().div_ceil(share_size)
    }

    /// Serialize blob to bytes (namespace || data)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(28 + self.data.len());
        result.extend_from_slice(self.namespace.as_bytes());
        result.extend_from_slice(&self.data);
        result
    }

    /// Deserialize blob from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 29 {
            return Err(CelestiaError::DeserializationError(
                "Blob too small (need at least 29 bytes: 28 namespace + 1 data)".to_string(),
            ));
        }

        let namespace = Namespace::from_slice(&bytes[..28])?;
        let data = bytes[28..].to_vec();

        Self::new(namespace, data)
    }

    /// Create an empty blob (for testing/placeholders)
    #[cfg(test)]
    pub fn empty(namespace: Namespace) -> Self {
        Self {
            namespace,
            data: vec![0],
            commitment: None,
        }
    }
}

/// Blob with submission metadata
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobWithMetadata {
    /// The blob data
    pub blob: Blob,
    /// Timestamp when blob was created
    pub created_at: u64,
    /// Optional description/tag
    pub description: Option<String>,
    /// Content type hint (e.g., "application/stark-proof")
    pub content_type: Option<String>,
    /// Original chain that produced this proof
    pub source_chain: Option<String>,
}

impl BlobWithMetadata {
    /// Create a new blob with metadata
    pub fn new(
        blob: Blob,
        description: Option<String>,
        content_type: Option<String>,
        source_chain: Option<String>,
    ) -> Self {
        Self {
            blob,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            description,
            content_type,
            source_chain,
        }
    }

    /// Get the commitment (delegates to inner blob)
    pub fn commitment(&self) -> [u8; 32] {
        self.blob.commitment()
    }

    /// Get the namespace (delegates to inner blob)
    pub fn namespace(&self) -> &Namespace {
        &self.blob.namespace
    }
}

/// Collection of related blobs (e.g., a large proof split across multiple blobs)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobBundle {
    /// Bundle ID (hash of all commitments)
    pub bundle_id: [u8; 32],
    /// Blobs in this bundle (ordered)
    pub blobs: Vec<Blob>,
    /// Total data size
    pub total_size: usize,
}

impl BlobBundle {
    /// Create a new blob bundle from individual blobs
    pub fn new(blobs: Vec<Blob>) -> Result<Self> {
        if blobs.is_empty() {
            return Err(CelestiaError::invalid_input("Blob bundle cannot be empty"));
        }

        let total_size: usize = blobs.iter().map(|b| b.size()).sum();

        // Compute bundle ID as hash of all commitments
        let mut hasher = Sha256::new();
        for blob in &blobs {
            hasher.update(blob.commitment());
        }
        let bundle_id: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            bundle_id,
            blobs,
            total_size,
        })
    }

    /// Get the number of blobs
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Check if bundle is empty
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Reconstruct full data from all blobs
    pub fn reconstruct_data(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size);
        for blob in &self.blobs {
            result.extend_from_slice(&blob.data);
        }
        result
    }

    /// Verify all blobs are in the same namespace
    pub fn verify_namespace_consistency(&self) -> bool {
        if self.blobs.len() < 2 {
            return true;
        }
        let first_ns = &self.blobs[0].namespace;
        self.blobs.iter().all(|b| &b.namespace == first_ns)
    }
}

impl CelestiaError {
    /// Create an invalid input error
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidProofId(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_creation() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![1, 2, 3, 4, 5];
        let blob = Blob::new(ns, data.clone()).unwrap();

        assert_eq!(blob.size(), 5);
        assert!(blob.is_in_namespace(&ns));
        assert!(!blob.is_in_namespace(&Namespace::sui_stark()));
    }

    #[test]
    fn test_empty_blob_fails() {
        let ns = Namespace::bitcoin_stark();
        assert!(matches!(
            Blob::new(ns, vec![]),
            Err(CelestiaError::EmptyBlob)
        ));
    }

    #[test]
    fn test_blob_too_large() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![0u8; MAX_BLOB_SIZE + 1];
        assert!(matches!(
            Blob::new(ns, data),
            Err(CelestiaError::BlobTooLarge { .. })
        ));
    }

    #[test]
    fn test_commitment_determinism() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![1, 2, 3, 4, 5];
        let blob1 = Blob::new(ns, data.clone()).unwrap();
        let blob2 = Blob::new(ns, data).unwrap();

        assert_eq!(blob1.commitment(), blob2.commitment());
    }

    #[test]
    fn test_commitment_verification() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![1, 2, 3, 4, 5];
        let blob = Blob::new(ns, data).unwrap();

        let commitment = blob.commitment();
        assert!(blob.verify_commitment(&commitment));

        let wrong = [0u8; 32];
        assert!(!blob.verify_commitment(&wrong));
    }

    #[test]
    fn test_blob_chunks() {
        let ns = Namespace::bitcoin_stark();
        let data: Vec<u8> = (0..100).collect();
        let blob = Blob::new(ns, data).unwrap();

        let chunks: Vec<&[u8]> = blob.chunks(10).collect();
        assert_eq!(chunks.len(), 10);
        assert_eq!(chunks[0].len(), 10);
    }

    #[test]
    fn test_share_count() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![0u8; 1000];
        let blob = Blob::new(ns, data).unwrap();

        assert_eq!(blob.share_count(512), 2);
        assert_eq!(blob.share_count(256), 4);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![1, 2, 3, 4, 5];
        let blob = Blob::new(ns, data).unwrap();

        let bytes = blob.to_bytes();
        let recovered = Blob::from_bytes(&bytes).unwrap();

        assert_eq!(blob.namespace, recovered.namespace);
        assert_eq!(blob.data, recovered.data);
        assert_eq!(blob.commitment(), recovered.commitment());
    }

    #[test]
    fn test_blob_with_metadata() {
        let ns = Namespace::bitcoin_stark();
        let blob = Blob::new(ns, vec![1, 2, 3]).unwrap();
        let with_meta = BlobWithMetadata::new(
            blob,
            Some("Test proof".to_string()),
            Some("application/stark-proof".to_string()),
            Some("bitcoin".to_string()),
        );

        assert_eq!(with_meta.description, Some("Test proof".to_string()));
        assert_eq!(
            with_meta.content_type,
            Some("application/stark-proof".to_string())
        );
    }

    #[test]
    fn test_blob_bundle() {
        let ns = Namespace::bitcoin_stark();
        let blobs = vec![
            Blob::new(ns, vec![1, 2, 3]).unwrap(),
            Blob::new(ns, vec![4, 5, 6]).unwrap(),
            Blob::new(ns, vec![7, 8, 9]).unwrap(),
        ];

        let bundle = BlobBundle::new(blobs).unwrap();
        assert_eq!(bundle.len(), 3);
        assert_eq!(bundle.total_size, 9);

        let reconstructed = bundle.reconstruct_data();
        assert_eq!(reconstructed, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_bundle_namespace_consistency() {
        let ns1 = Namespace::bitcoin_stark();
        let ns2 = Namespace::sui_stark();

        let blobs = vec![
            Blob::new(ns1, vec![1, 2, 3]).unwrap(),
            Blob::new(ns1, vec![4, 5, 6]).unwrap(),
        ];
        let bundle = BlobBundle::new(blobs).unwrap();
        assert!(bundle.verify_namespace_consistency());

        let mixed = vec![
            Blob::new(ns1, vec![1, 2, 3]).unwrap(),
            Blob::new(ns2, vec![4, 5, 6]).unwrap(),
        ];
        let bundle_mixed = BlobBundle::new(mixed).unwrap();
        assert!(!bundle_mixed.verify_namespace_consistency());
    }
}
