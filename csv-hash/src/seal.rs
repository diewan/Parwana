//! Seal and Anchor reference types
//!
//! Seals represent single-use sanads to authorize state transitions.
//! Anchors represent on-chain references containing commitments.

use anyhow::Result;
use csv_codec::canonical::{from_canonical_cbor, to_canonical_cbor};
use std::vec::Vec;

/// Maximum allowed size for seal identifiers (1KB)
pub const MAX_SEAL_ID_SIZE: usize = 1024;

/// Maximum allowed size for anchor identifiers (1KB)
pub const MAX_ANCHOR_ID_SIZE: usize = 1024;

/// Maximum allowed size for anchor metadata (4KB)
pub const MAX_ANCHOR_METADATA_SIZE: usize = 4096;

/// A specific point on any chain that acts as a seal.
///
/// Bitcoin uses `OutPoint` (txid + vout) to identify a specific output.
/// A Bitcoin seal IS an OutPoint. `SealPoint` generalizes this concept.
///
/// The concrete meaning is chain-specific:
/// - Bitcoin: UTXO OutPoint
/// - Ethereum: Contract address + storage slot
/// - Sui: Object ID
/// - Aptos: Resource address + key
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SealPoint {
    /// Chain-specific seal identifier
    pub id: Vec<u8>,
    /// Optional nonce for replay resistance
    pub nonce: Option<u64>,
}

impl SealPoint {
    /// Create a new SealPoint from raw bytes
    ///
    /// # Arguments
    /// * `id` - Chain-specific seal identifier (max 1KB)
    /// * `nonce` - Optional nonce for replay resistance
    ///
    /// # Errors
    /// Returns an error if the id exceeds the maximum allowed size
    pub fn new(id: Vec<u8>, nonce: Option<u64>) -> Result<Self, &'static str> {
        if id.len() > MAX_SEAL_ID_SIZE {
            return Err("id exceeds maximum allowed size (1KB)");
        }
        if id.is_empty() {
            return Err("id cannot be empty");
        }
        Ok(Self { id, nonce })
    }

    /// Create a new SealPoint without validation.
    ///
    /// # Safety
    /// The caller MUST ensure:
    /// - `id` is non-empty and ≤ 1024 bytes (MAX_SEAL_ID_SIZE)
    /// - This is only used for deserialized data already verified by `from_bytes()`
    ///   or internal protocol conversions where size is guaranteed by construction.
    ///
    /// Violating these requirements causes undefined behavior in downstream code
    /// that assumes valid seal IDs (e.g., hash map lookups, size assertions).
    pub unsafe fn new_unchecked(id: Vec<u8>, nonce: Option<u64>) -> Self {
        Self { id, nonce }
    }

    /// Serialize to bytes (DEPRECATED - use to_canonical_bytes for protocol-critical paths)
    ///
    /// # Deprecated
    /// This method is deprecated for protocol-critical hashing. Use `to_canonical_bytes()` instead.
    /// Manual serialization is forbidden in protocol-critical hashing paths per AUDIT.md.
    ///
    /// Format: `[nonce_flag(1) | nonce_bytes(8 if flag=1) | id_len(varuint) | id]`
    /// The nonce_flag is 1 for `Some(nonce)`, 0 for `None`.
    #[deprecated(
        since = "1.0.0",
        note = "Use to_canonical_bytes() for protocol-critical paths"
    )]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.id.len());
        if let Some(nonce) = self.nonce {
            out.push(1);
            out.extend_from_slice(&nonce.to_le_bytes());
        } else {
            out.push(0);
        }
        out.extend_from_slice(&(self.id.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.id);
        out
    }

    /// Deserialize from bytes
    ///
    /// # Errors
    /// Returns an error if the bytes are malformed or id exceeds the maximum allowed size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("empty bytes");
        }
        let mut pos = 0;

        let nonce = match bytes[pos] {
            0 => {
                pos += 1;
                None
            }
            1 => {
                pos += 1;
                if bytes.len() < pos + 8 {
                    return Err("insufficient bytes for nonce");
                }
                let nonce_bytes = [
                    bytes[pos],
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                    bytes[pos + 4],
                    bytes[pos + 5],
                    bytes[pos + 6],
                    bytes[pos + 7],
                ];
                pos += 8;
                Some(u64::from_le_bytes(nonce_bytes))
            }
            _ => return Err("invalid nonce flag"),
        };

        if bytes.len() < pos + 4 {
            return Err("insufficient bytes for id length");
        }
        let id_len =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;

        if bytes.len() < pos + id_len {
            return Err("insufficient bytes for id");
        }
        let id = bytes[pos..pos + id_len].to_vec();

        if id.len() > MAX_SEAL_ID_SIZE {
            return Err("id exceeds maximum allowed size (1KB)");
        }

        Ok(Self { id, nonce })
    }

    /// Serialize to canonical CBOR bytes for hashing.
    ///
    /// This is the ONLY approved method for serializing SealPoint in hashing paths.
    /// Manual `to_vec()` is forbidden in protocol-critical hashing.
    ///
    /// # Errors
    /// Returns `anyhow::Error::SerializationError` if encoding fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        to_canonical_cbor(self).map_err(|e| anyhow::Error::msg(e.to_string()))
    }

    /// Deserialize from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `anyhow::Error::DeserializationError` if decoding fails.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        from_canonical_cbor(bytes).map_err(|e| anyhow::Error::msg(e.to_string()))
    }
}

/// The anchor for a commitment on-chain.
///
/// Represents where a commitment was anchored on-chain.
///
/// The concrete meaning is chain-specific:
/// - Bitcoin: Transaction ID + output index
/// - Ethereum: Transaction hash + log index
/// - Sui: Object ID + version
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CommitAnchor {
    /// Chain-specific anchor identifier
    pub anchor_id: Vec<u8>,
    /// Block height or equivalent ordering
    pub block_height: u64,
    /// Optional metadata (chain-specific)
    pub metadata: Vec<u8>,
}

impl CommitAnchor {
    /// Create a new CommitAnchor
    ///
    /// # Arguments
    /// * `anchor_id` - Chain-specific anchor identifier (max 1KB)
    /// * `block_height` - Block height or equivalent ordering
    /// * `metadata` - Optional metadata (max 4KB)
    ///
    /// # Errors
    /// Returns an error if anchor_id or metadata exceeds maximum allowed size
    pub fn new(
        anchor_id: Vec<u8>,
        block_height: u64,
        metadata: Vec<u8>,
    ) -> Result<Self, &'static str> {
        if anchor_id.len() > MAX_ANCHOR_ID_SIZE {
            return Err("anchor_id exceeds maximum allowed size (1KB)");
        }
        if anchor_id.is_empty() {
            return Err("anchor_id cannot be empty");
        }
        if metadata.len() > MAX_ANCHOR_METADATA_SIZE {
            return Err("metadata exceeds maximum allowed size (4KB)");
        }
        Ok(Self {
            anchor_id,
            block_height,
            metadata,
        })
    }

    /// Create without validation (adapter compatibility).
    ///
    /// # Safety
    /// Caller must ensure `anchor_id` is non-empty and within size limits.
    pub unsafe fn new_unchecked(anchor_id: Vec<u8>, block_height: u64, metadata: Vec<u8>) -> Self {
        Self {
            anchor_id,
            block_height,
            metadata,
        }
    }

    /// Serialize to bytes (DEPRECATED - use to_canonical_bytes for protocol-critical paths)
    ///
    /// # Deprecated
    /// This method is deprecated for protocol-critical hashing. Use `to_canonical_bytes()` instead.
    /// Manual serialization is forbidden in protocol-critical hashing paths per AUDIT.md.
    #[deprecated(
        since = "1.0.0",
        note = "Use to_canonical_bytes() for protocol-critical paths"
    )]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 + self.anchor_id.len() + 4 + self.metadata.len());
        out.extend_from_slice(&self.block_height.to_le_bytes());
        out.extend_from_slice(&(self.anchor_id.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.anchor_id);
        out.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.metadata);
        out
    }

    /// Deserialize from bytes
    ///
    /// # Errors
    /// Returns an error if the bytes are malformed or fields exceed maximum allowed size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("insufficient bytes for block_height");
        }
        let block_height = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let mut pos = 8;

        if bytes.len() < pos + 4 {
            return Err("insufficient bytes for anchor_id length");
        }
        let anchor_id_len =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;

        if bytes.len() < pos + anchor_id_len {
            return Err("insufficient bytes for anchor_id");
        }
        let anchor_id = bytes[pos..pos + anchor_id_len].to_vec();
        pos += anchor_id_len;

        if anchor_id.len() > MAX_ANCHOR_ID_SIZE {
            return Err("anchor_id exceeds maximum allowed size (1KB)");
        }

        if bytes.len() < pos + 4 {
            return Err("insufficient bytes for metadata length");
        }
        let metadata_len =
            u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;

        if bytes.len() < pos + metadata_len {
            return Err("insufficient bytes for metadata");
        }
        let metadata = bytes[pos..pos + metadata_len].to_vec();

        if metadata.len() > MAX_ANCHOR_METADATA_SIZE {
            return Err("metadata exceeds maximum allowed size (4KB)");
        }

        Ok(Self {
            anchor_id,
            block_height,
            metadata,
        })
    }

    /// Serialize to canonical CBOR bytes for hashing.
    ///
    /// This is the ONLY approved method for serializing CommitAnchor in hashing paths.
    /// Manual `to_vec()` is forbidden in protocol-critical hashing.
    ///
    /// # Errors
    /// Returns `anyhow::Error::SerializationError` if encoding fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        to_canonical_cbor(self).map_err(|e| anyhow::Error::msg(e.to_string()))
    }

    /// Deserialize from canonical CBOR bytes.
    ///
    /// # Errors
    /// Returns `anyhow::Error::DeserializationError` if decoding fails.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        from_canonical_cbor(bytes).map_err(|e| anyhow::Error::msg(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_point_creation() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        assert_eq!(seal.id, vec![1, 2, 3]);
        assert_eq!(seal.nonce, Some(42));
    }

    #[test]
    fn test_seal_point_to_vec_roundtrip() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        let bytes = seal.to_vec();
        let restored = SealPoint::from_bytes(&bytes).unwrap();
        assert_eq!(seal, restored);
    }

    #[test]
    fn test_seal_point_too_large() {
        let large_id = vec![0u8; 1025];
        assert!(SealPoint::new(large_id, None).is_err());
    }

    #[test]
    fn test_seal_point_empty_id() {
        assert!(SealPoint::new(vec![], None).is_err());
    }

    #[test]
    fn test_commit_anchor_creation() {
        let anchor = CommitAnchor::new(vec![1, 2, 3], 100, vec![4, 5]).unwrap();
        assert_eq!(anchor.anchor_id, vec![1, 2, 3]);
        assert_eq!(anchor.block_height, 100);
        assert_eq!(anchor.metadata, vec![4, 5]);
    }

    #[test]
    fn test_commit_anchor_to_vec_roundtrip() {
        let anchor = CommitAnchor::new(vec![1, 2, 3], 100, vec![4, 5]).unwrap();
        let bytes = anchor.to_vec();
        let restored = CommitAnchor::from_bytes(&bytes).unwrap();
        assert_eq!(anchor, restored);
    }

    #[test]
    fn test_commit_anchor_too_large_anchor_id() {
        let large_id = vec![0u8; 1025];
        assert!(CommitAnchor::new(large_id, 100, vec![]).is_err());
    }

    #[test]
    fn test_commit_anchor_too_large_metadata() {
        let large_metadata = vec![0u8; 4097];
        assert!(CommitAnchor::new(vec![1, 2, 3], 100, large_metadata).is_err());
    }

    #[test]
    fn test_commit_anchor_empty_anchor_id() {
        assert!(CommitAnchor::new(vec![], 100, vec![]).is_err());
    }

    #[test]
    fn test_canonical_bytes_roundtrip() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        let bytes = seal.to_canonical_bytes().unwrap();
        let restored = SealPoint::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(seal, restored);
    }

    #[test]
    fn test_commit_anchor_canonical_bytes_roundtrip() {
        let anchor = CommitAnchor::new(vec![1, 2, 3], 100, vec![4, 5]).unwrap();
        let bytes = anchor.to_canonical_bytes().unwrap();
        let restored = CommitAnchor::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(anchor, restored);
    }
}
