//! Proof IDs for Celestia DA Layer
//!
//! A ProofId uniquely identifies where a Sanad proof is stored on Celestia.
//! It contains:
//! - Block height where the blob was included
//! - Namespace the blob belongs to
//! - Commitment (hash) of the blob data
//!
//! This small identifier (~68 bytes) is what gets anchored on-chain, while
//! the actual proof data lives on the cheap DA layer.
//!
//! ## Format
//!
//! ```text
//! ProofId:
//!   - height: u64 (8 bytes) - Celestia block height
//!   - namespace: [u8; 28] - Celestia namespace
//!   - commitment: [u8; 32] - SHA256(namespace || data)
//! ```
//!
//! ## IPFS Extension
//!
//! For even cheaper storage, large proofs can be stored on IPFS with only
//! the CID (Content Identifier) anchored via Celestia. The `ProofLocation`
//! type supports both direct Celestia storage and IPFS-backed storage.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CelestiaError, Result};
use crate::namespace::Namespace;

/// Unique identifier for a proof stored on Celestia DA layer
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofId {
    /// Celestia block height where blob was included
    pub height: u64,
    /// Namespace the blob belongs to
    pub namespace: Namespace,
    /// Commitment (hash) of the blob
    pub commitment: [u8; 32],
}

impl ProofId {
    /// Size of a serialized ProofId in bytes
    pub const SIZE: usize = 8 + 28 + 32; // height + namespace + commitment

    /// Create a new proof ID
    ///
    /// # Arguments
    /// * `height` - Celestia block height
    /// * `namespace` - Blob namespace
    /// * `commitment` - 32-byte blob commitment
    pub fn new(height: u64, namespace: Namespace, commitment: [u8; 32]) -> Self {
        Self {
            height,
            namespace,
            commitment,
        }
    }

    /// Serialize to bytes
    ///
    /// Format: [height(8) || namespace(28) || commitment(32)]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut result = [0u8; Self::SIZE];
        result[0..8].copy_from_slice(&self.height.to_le_bytes());
        result[8..36].copy_from_slice(self.namespace.as_bytes());
        result[36..68].copy_from_slice(&self.commitment);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CelestiaError::InvalidProofId(format!(
                "Expected {} bytes, got {}",
                Self::SIZE,
                bytes.len()
            )));
        }

        let height = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);

        let namespace = Namespace::from_slice(&bytes[8..36])?;

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&bytes[36..68]);

        Ok(Self {
            height,
            namespace,
            commitment,
        })
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CelestiaError::InvalidProofId(format!("Invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Get a short display form (first 16 chars of hex)
    pub fn short(&self) -> String {
        format!("{:.16}", self.to_hex())
    }

    /// Compute a hash of this ProofId for additional indexing
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        hasher.finalize().into()
    }
}

impl core::fmt::Display for ProofId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}@{}:{:.16}",
            self.height,
            self.namespace,
            hex::encode(&self.commitment[..8])
        )
    }
}

/// Extended proof location supporting both Celestia and IPFS storage
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofLocation {
    /// Direct storage on Celestia DA layer
    Celestia {
        /// Proof ID on Celestia
        proof_id: ProofId,
    },
    /// IPFS-backed storage with Celestia anchor
    IpfsBacked {
        /// Celestia height where IPFS CID was anchored
        anchor_height: u64,
        /// IPFS Content Identifier
        cid: String,
        /// Optional Celestia namespace for the anchor
        namespace: Namespace,
    },
    /// Hybrid: Large data on IPFS, metadata on Celestia
    Hybrid {
        /// Proof ID for metadata on Celestia
        metadata_id: ProofId,
        /// IPFS CID for the actual proof data
        data_cid: String,
    },
}

impl ProofLocation {
    /// Create a direct Celestia location
    pub fn celestia(proof_id: ProofId) -> Self {
        Self::Celestia { proof_id }
    }

    /// Create an IPFS-backed location
    pub fn ipfs_backed(anchor_height: u64, cid: impl Into<String>, namespace: Namespace) -> Self {
        Self::IpfsBacked {
            anchor_height,
            cid: cid.into(),
            namespace,
        }
    }

    /// Create a hybrid location (metadata on Celestia, data on IPFS)
    pub fn hybrid(metadata_id: ProofId, data_cid: impl Into<String>) -> Self {
        Self::Hybrid {
            metadata_id,
            data_cid: data_cid.into(),
        }
    }

    /// Get the Celestia height for this location
    pub fn height(&self) -> u64 {
        match self {
            Self::Celestia { proof_id } => proof_id.height,
            Self::IpfsBacked { anchor_height, .. } => *anchor_height,
            Self::Hybrid { metadata_id, .. } => metadata_id.height,
        }
    }

    /// Get the namespace if available
    pub fn namespace(&self) -> Option<&Namespace> {
        match self {
            Self::Celestia { proof_id } => Some(&proof_id.namespace),
            Self::IpfsBacked { namespace, .. } => Some(namespace),
            Self::Hybrid { metadata_id, .. } => Some(&metadata_id.namespace),
        }
    }

    /// Get the CID if this is IPFS-backed or hybrid
    pub fn cid(&self) -> Option<&str> {
        match self {
            Self::Celestia { .. } => None,
            Self::IpfsBacked { cid, .. } => Some(cid),
            Self::Hybrid { data_cid, .. } => Some(data_cid),
        }
    }

    /// Check if this location uses IPFS
    pub fn uses_ipfs(&self) -> bool {
        matches!(self, Self::IpfsBacked { .. } | Self::Hybrid { .. })
    }

    /// Check if this is a direct Celestia location
    pub fn is_direct_celestia(&self) -> bool {
        matches!(self, Self::Celestia { .. })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Celestia { proof_id } => {
                let mut result = vec![0x01]; // Discriminant for Celestia
                result.extend_from_slice(&proof_id.to_bytes());
                result
            }
            Self::IpfsBacked {
                anchor_height,
                cid,
                namespace,
            } => {
                let mut result = vec![0x02]; // Discriminant for IPFS
                result.extend_from_slice(&anchor_height.to_le_bytes());
                result.extend_from_slice(namespace.as_bytes());
                let cid_bytes = cid.as_bytes();
                result.extend_from_slice(&(cid_bytes.len() as u16).to_le_bytes());
                result.extend_from_slice(cid_bytes);
                result
            }
            Self::Hybrid {
                metadata_id,
                data_cid,
            } => {
                let mut result = vec![0x03]; // Discriminant for Hybrid
                result.extend_from_slice(&metadata_id.to_bytes());
                let cid_bytes = data_cid.as_bytes();
                result.extend_from_slice(&(cid_bytes.len() as u16).to_le_bytes());
                result.extend_from_slice(cid_bytes);
                result
            }
        }
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(CelestiaError::DeserializationError(
                "Empty bytes for ProofLocation".to_string(),
            ));
        }

        match bytes[0] {
            0x01 => {
                if bytes.len() < 1 + ProofId::SIZE {
                    return Err(CelestiaError::DeserializationError(
                        "Insufficient bytes for Celestia ProofLocation".to_string(),
                    ));
                }
                let proof_id = ProofId::from_bytes(&bytes[1..1 + ProofId::SIZE])?;
                Ok(Self::Celestia { proof_id })
            }
            0x02 => {
                if bytes.len() < 1 + 8 + 28 + 2 {
                    return Err(CelestiaError::DeserializationError(
                        "Insufficient bytes for IPFS ProofLocation".to_string(),
                    ));
                }
                let anchor_height = u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                let namespace = Namespace::from_slice(&bytes[9..37])?;
                let cid_len = u16::from_le_bytes([bytes[37], bytes[38]]) as usize;
                if bytes.len() < 39 + cid_len {
                    return Err(CelestiaError::DeserializationError(
                        "CID data truncated".to_string(),
                    ));
                }
                let cid = String::from_utf8(bytes[39..39 + cid_len].to_vec()).map_err(|e| {
                    CelestiaError::DeserializationError(format!("Invalid CID UTF8: {}", e))
                })?;
                Ok(Self::IpfsBacked {
                    anchor_height,
                    cid,
                    namespace,
                })
            }
            0x03 => {
                if bytes.len() < 1 + ProofId::SIZE + 2 {
                    return Err(CelestiaError::DeserializationError(
                        "Insufficient bytes for Hybrid ProofLocation".to_string(),
                    ));
                }
                let metadata_id = ProofId::from_bytes(&bytes[1..1 + ProofId::SIZE])?;
                let cid_offset = 1 + ProofId::SIZE;
                let cid_len =
                    u16::from_le_bytes([bytes[cid_offset], bytes[cid_offset + 1]]) as usize;
                if bytes.len() < cid_offset + 2 + cid_len {
                    return Err(CelestiaError::DeserializationError(
                        "CID data truncated".to_string(),
                    ));
                }
                let data_cid =
                    String::from_utf8(bytes[cid_offset + 2..cid_offset + 2 + cid_len].to_vec())
                        .map_err(|e| {
                            CelestiaError::DeserializationError(format!("Invalid CID UTF8: {}", e))
                        })?;
                Ok(Self::Hybrid {
                    metadata_id,
                    data_cid,
                })
            }
            _ => Err(CelestiaError::DeserializationError(format!(
                "Unknown ProofLocation discriminant: {}",
                bytes[0]
            ))),
        }
    }
}

impl core::fmt::Display for ProofLocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Celestia { proof_id } => {
                write!(f, "Celestia({})", proof_id)
            }
            Self::IpfsBacked {
                anchor_height, cid, ..
            } => {
                write!(f, "IPFS@{}:{:.16}", anchor_height, cid)
            }
            Self::Hybrid {
                metadata_id,
                data_cid,
            } => {
                write!(f, "Hybrid({}/{:.16})", metadata_id, data_cid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_id_creation() {
        let ns = Namespace::bitcoin_stark();
        let commitment = [0u8; 32];
        let proof_id = ProofId::new(12345, ns, commitment);

        assert_eq!(proof_id.height, 12345);
        assert_eq!(proof_id.commitment, commitment);
    }

    #[test]
    fn test_proof_id_bytes_roundtrip() {
        let ns = Namespace::bitcoin_stark();
        let commitment = [42u8; 32];
        let proof_id = ProofId::new(99999, ns, commitment);

        let bytes = proof_id.to_bytes();
        let recovered = ProofId::from_bytes(&bytes).unwrap();

        assert_eq!(proof_id, recovered);
    }

    #[test]
    fn test_proof_id_hex_roundtrip() {
        let ns = Namespace::sui_stark();
        let commitment = [0xABu8; 32];
        let proof_id = ProofId::new(1000000, ns, commitment);

        let hex = proof_id.to_hex();
        let recovered = ProofId::from_hex(&hex).unwrap();

        assert_eq!(proof_id, recovered);
    }

    #[test]
    fn test_proof_id_short() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(123, ns, [0xFFu8; 32]);
        let short = proof_id.short();
        assert_eq!(short.len(), 16);
    }

    #[test]
    fn test_proof_id_display() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let s = format!("{}", proof_id);
        assert!(s.contains("12345"));
        assert!(s.contains("@"));
    }

    #[test]
    fn test_proof_location_celestia() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::celestia(proof_id);

        assert!(location.is_direct_celestia());
        assert!(!location.uses_ipfs());
        assert_eq!(location.height(), 12345);
        assert!(location.cid().is_none());
    }

    #[test]
    fn test_proof_location_ipfs() {
        let ns = Namespace::metadata();
        let location = ProofLocation::ipfs_backed(12345, "QmTest123456789", ns);

        assert!(!location.is_direct_celestia());
        assert!(location.uses_ipfs());
        assert_eq!(location.height(), 12345);
        assert_eq!(location.cid(), Some("QmTest123456789"));
    }

    #[test]
    fn test_proof_location_hybrid() {
        let ns = Namespace::fraud_proofs();
        let metadata_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::hybrid(metadata_id, "QmData123456789");

        assert!(!location.is_direct_celestia());
        assert!(location.uses_ipfs());
        assert_eq!(location.height(), 12345);
        assert_eq!(location.cid(), Some("QmData123456789"));
    }

    #[test]
    fn test_proof_location_bytes_roundtrip() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);

        // Test Celestia
        let loc1 = ProofLocation::celestia(proof_id);
        let bytes1 = loc1.to_bytes();
        let recovered1 = ProofLocation::from_bytes(&bytes1).unwrap();
        assert_eq!(loc1, recovered1);

        // Test IPFS
        let loc2 = ProofLocation::ipfs_backed(12345, "QmTest", Namespace::metadata());
        let bytes2 = loc2.to_bytes();
        let recovered2 = ProofLocation::from_bytes(&bytes2).unwrap();
        assert_eq!(loc2, recovered2);

        // Test Hybrid
        let loc3 = ProofLocation::hybrid(proof_id, "QmData");
        let bytes3 = loc3.to_bytes();
        let recovered3 = ProofLocation::from_bytes(&bytes3).unwrap();
        assert_eq!(loc3, recovered3);
    }

    #[test]
    fn test_proof_location_display() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);

        let loc1 = ProofLocation::celestia(proof_id);
        assert!(format!("{}", loc1).contains("Celestia"));

        let loc2 = ProofLocation::ipfs_backed(12345, "QmTest", ns);
        assert!(format!("{}", loc2).contains("IPFS"));

        let loc3 = ProofLocation::hybrid(proof_id, "QmData");
        assert!(format!("{}", loc3).contains("Hybrid"));
    }
}
