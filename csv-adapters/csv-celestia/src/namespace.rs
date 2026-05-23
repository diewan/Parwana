//! Celestia Namespace IDs
//!
//! Celestia uses 28-byte namespace identifiers to isolate different applications'
//! data on the Data Availability (DA) layer.
//!
//! ## Namespace Structure
//!
//! ```text
//! Namespace (28 bytes):
//!   - version (1 byte): Namespace version
//!   - id (27 bytes): Application-specific identifier
//! ```
//!
//! ## CSV Namespace Scheme
//!
//! For CSV Sanad proofs:
//! - version = 0x00 (standard)
//! - id[0:4] = "csv\0" (magic)
//! - id[4:8] = chain_id (4 bytes, e.g., "btc\0", "sui\0")
//! - id[8:16] = sanad_type (8 bytes identifier)
//! - id[16:27] = reserved/padding
//!
//! Example: `csv\0btc\0stark-v1\0\0\0\0\0` (28 bytes total)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CelestiaError, Result};

/// Size of a Celestia namespace in bytes
pub const NAMESPACE_SIZE: usize = 28;

/// Version byte offset
const VERSION_OFFSET: usize = 0;

/// ID offset (after version byte)
const ID_OFFSET: usize = 1;

/// CSV magic bytes (4 bytes: "csv\0")
const CSV_MAGIC: &[u8] = b"csv\0";

/// A Celestia namespace identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Namespace([u8; NAMESPACE_SIZE]);

impl Namespace {
    /// Create a new namespace from raw bytes
    ///
    /// # Arguments
    /// * `bytes` - 28-byte array
    ///
    /// # Errors
    /// Returns error if bytes are not exactly 28 bytes
    pub fn new(bytes: [u8; NAMESPACE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create a namespace from a byte slice
    ///
    /// # Errors
    /// Returns error if slice is not exactly 28 bytes
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != NAMESPACE_SIZE {
            return Err(CelestiaError::InvalidNamespace(format!(
                "Expected {} bytes, got {}",
                NAMESPACE_SIZE,
                slice.len()
            )));
        }
        let mut bytes = [0u8; NAMESPACE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Create a CSV-specific namespace for Sanad proofs
    ///
    /// # Arguments
    /// * `chain_id` - 4-byte chain identifier (e.g., "btc\0", "sui\0")
    /// * `sanad_type` - 8-byte sanad type identifier
    ///
    /// # Returns
    /// A properly formatted CSV namespace
    ///
    /// # Example
    /// ```
    /// use csv_celestia::Namespace;
    ///
    /// let ns = Namespace::csv(b"btc\0", b"stark-v1");
    /// assert_eq!(ns.version(), 0x00);
    /// ```
    pub fn csv(chain_id: &[u8; 4], sanad_type: &[u8; 8]) -> Self {
        let mut bytes = [0u8; NAMESPACE_SIZE];

        // Version byte
        bytes[VERSION_OFFSET] = 0x00;

        // CSV magic
        bytes[ID_OFFSET..ID_OFFSET + 4].copy_from_slice(CSV_MAGIC);

        // Chain ID
        bytes[ID_OFFSET + 4..ID_OFFSET + 8].copy_from_slice(chain_id);

        // Sanad type
        bytes[ID_OFFSET + 8..ID_OFFSET + 16].copy_from_slice(sanad_type);

        // Remaining bytes are zero (padding)

        Self(bytes)
    }

    /// Create a namespace from a string using SHA256 hash
    ///
    /// This is useful for creating deterministic namespaces from human-readable names.
    /// The first 27 bytes of the SHA256 hash are used as the ID, with version 0x00.
    pub fn from_name(name: &str) -> Self {
        let hash = Sha256::digest(name.as_bytes());
        let mut bytes = [0u8; NAMESPACE_SIZE];
        bytes[VERSION_OFFSET] = 0x00;
        bytes[ID_OFFSET..].copy_from_slice(&hash[..NAMESPACE_SIZE - 1]);
        Self(bytes)
    }

    /// Get the version byte
    pub fn version(&self) -> u8 {
        self.0[VERSION_OFFSET]
    }

    /// Get the ID bytes (27 bytes)
    pub fn id(&self) -> &[u8] {
        &self.0[ID_OFFSET..]
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; NAMESPACE_SIZE] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CelestiaError::InvalidNamespace(format!("Invalid hex: {}", e)))?;
        Self::from_slice(&bytes)
    }

    /// Check if this is a CSV-formatted namespace
    pub fn is_csv(&self) -> bool {
        self.0[ID_OFFSET..ID_OFFSET + 4] == CSV_MAGIC[..]
    }

    /// Get chain ID from CSV namespace (if valid CSV namespace)
    pub fn chain_id(&self) -> Option<[u8; 4]> {
        if !self.is_csv() {
            return None;
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&self.0[ID_OFFSET + 4..ID_OFFSET + 8]);
        Some(id)
    }

    /// Get sanad type from CSV namespace (if valid CSV namespace)
    pub fn sanad_type(&self) -> Option<[u8; 8]> {
        if !self.is_csv() {
            return None;
        }
        let mut type_bytes = [0u8; 8];
        type_bytes.copy_from_slice(&self.0[ID_OFFSET + 8..ID_OFFSET + 16]);
        Some(type_bytes)
    }

    /// Create namespace for Bitcoin STARK proofs
    pub fn bitcoin_stark() -> Self {
        Self::csv(b"btc\0", b"stark-v1")
    }

    /// Create namespace for Sui STARK proofs
    pub fn sui_stark() -> Self {
        Self::csv(b"sui\0", b"stark-v1")
    }

    /// Create namespace for Solana STARK proofs
    pub fn solana_stark() -> Self {
        Self::csv(b"sol\0", b"stark-v1")
    }

    /// Create namespace for Ethereum STARK proofs
    pub fn ethereum_stark() -> Self {
        Self::csv(b"eth\0", b"stark-v1")
    }

    /// Create namespace for Aptos STARK proofs
    pub fn aptos_stark() -> Self {
        Self::csv(b"apt\0", b"stark-v1")
    }

    /// Create namespace for fraud proofs
    pub fn fraud_proofs() -> Self {
        Self::csv(b"all\0", b"fraud-pr")
    }

    /// Create namespace for metadata
    pub fn metadata() -> Self {
        Self::csv(b"all\0", b"metadata")
    }
}

impl AsRef<[u8]> for Namespace {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Namespace> for [u8; NAMESPACE_SIZE] {
    fn from(ns: Namespace) -> Self {
        ns.0
    }
}

impl TryFrom<&[u8]> for Namespace {
    type Error = CelestiaError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        Self::from_slice(slice)
    }
}

impl core::fmt::Display for Namespace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_creation() {
        let bytes = [0u8; NAMESPACE_SIZE];
        let ns = Namespace::new(bytes);
        assert_eq!(ns.version(), 0);
        assert_eq!(ns.as_bytes(), &bytes);
    }

    #[test]
    fn test_csv_namespace() {
        let ns = Namespace::csv(b"btc\0", b"stark-v1");
        assert!(ns.is_csv());
        assert_eq!(ns.chain_id(), Some(*b"btc\0"));
        assert_eq!(ns.sanad_type(), Some(*b"stark-v1"));
    }

    #[test]
    fn test_from_slice() {
        let bytes = vec![0u8; NAMESPACE_SIZE];
        let ns = Namespace::from_slice(&bytes).unwrap();
        assert_eq!(ns.as_bytes(), &bytes[..]);

        let short = vec![0u8; 10];
        assert!(Namespace::from_slice(&short).is_err());
    }

    #[test]
    fn test_from_name() {
        let ns1 = Namespace::from_name("test-namespace");
        let ns2 = Namespace::from_name("test-namespace");
        assert_eq!(ns1, ns2); // Deterministic

        let ns3 = Namespace::from_name("different-namespace");
        assert_ne!(ns1, ns3);
    }

    #[test]
    fn test_hex_roundtrip() {
        let ns = Namespace::csv(b"btc\0", b"stark-v1");
        let hex = ns.to_hex();
        let recovered = Namespace::from_hex(&hex).unwrap();
        assert_eq!(ns, recovered);
    }

    #[test]
    fn test_predefined_namespaces() {
        let bitcoin = Namespace::bitcoin_stark();
        assert!(bitcoin.is_csv());
        assert_eq!(bitcoin.chain_id(), Some(*b"btc\0"));

        let sui = Namespace::sui_stark();
        assert!(sui.is_csv());
        assert_eq!(sui.chain_id(), Some(*b"sui\0"));

        let fraud = Namespace::fraud_proofs();
        assert!(fraud.is_csv());
        assert_eq!(fraud.sanad_type(), Some(*b"fraud-pr"));
    }

    #[test]
    fn test_display() {
        let ns = Namespace::new([0u8; NAMESPACE_SIZE]);
        let s = format!("{}", ns);
        assert_eq!(s.len(), NAMESPACE_SIZE * 2); // hex encoding
    }
}
