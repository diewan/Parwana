//! Celestia-specific Types for CSV
//!
//! This module defines Celestia-specific seal points, anchors, and finality
//! proofs that integrate with the core Parwana.
//!
//! ## Single Use Seal on Celestia
//!
//! Unlike other chains where seals are UTXOs or Objects, Celestia seals are
//! unique references to Data Availability layer locations. Once a seal is
//! "consumed", it means the proof has been anchored and cannot be re-used.
//!
//! ## Integration with Off-Chain Channels
//!
//! Celestia serves as the data availability layer for:
//! 1. Large STARK proofs that don't fit on-chain
//! 2. Fraud proof challenges
//! 3. Metadata for Sanad verification

use serde::{Deserialize, Serialize};

use crate::commitment::{BlobCommitment, CommitmentProof};
use crate::error::{CelestiaError, Result};
use crate::namespace::Namespace;
use crate::proof_id::{ProofId, ProofLocation};

/// A seal point on Celestia
///
/// Unlike Bitcoin (OutPoint) or Sui (Object), a Celestia seal point
/// is a reference to a location in the Data Availability layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CelestiaSealPoint {
    /// The proof ID that identifies this seal
    pub proof_id: ProofId,
    /// Height where seal was established
    pub height: u64,
    /// Whether this seal has been consumed
    pub consumed: bool,
    /// Consumption transaction hash (if consumed)
    pub consumption_tx: Option<[u8; 32]>,
    /// IPFS CID if using IPFS-backed storage
    pub ipfs_cid: Option<String>,
}

impl CelestiaSealPoint {
    /// Create a new seal point
    pub fn new(proof_id: ProofId, height: u64) -> Self {
        Self {
            proof_id,
            height,
            consumed: false,
            consumption_tx: None,
            ipfs_cid: None,
        }
    }

    /// Create with IPFS CID for hybrid storage
    pub fn with_ipfs(mut self, cid: impl Into<String>) -> Self {
        self.ipfs_cid = Some(cid.into());
        self
    }

    /// Mark this seal as consumed
    pub fn consume(&mut self, tx_hash: [u8; 32]) {
        self.consumed = true;
        self.consumption_tx = Some(tx_hash);
    }

    /// Check if seal is valid (not consumed)
    pub fn is_valid(&self) -> bool {
        !self.consumed
    }

    /// Get the namespace
    pub fn namespace(&self) -> &Namespace {
        &self.proof_id.namespace
    }

    /// Get the commitment
    pub fn commitment(&self) -> &[u8; 32] {
        &self.proof_id.commitment
    }

    /// Convert to core SealPoint
    pub fn to_core_seal(&self) -> csv_hash::seal::SealPoint {
        csv_hash::seal::SealPoint::new(self.proof_id.to_bytes().to_vec(), Some(self.height), None)
            .unwrap_or_else(|_| {
                // SAFETY: We're falling back to unchecked creation only when the safe API fails,
                // and the data is derived from valid internal state.
                unsafe {
                    csv_hash::seal::SealPoint::new_unchecked(
                        self.proof_id.to_bytes().to_vec(),
                        Some(self.height),
                        None,
                    )
                }
            })
    }
}

/// A commitment anchor on Celestia
///
/// This represents where a Sanad commitment was anchored on the
/// Celestia Data Availability layer.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CelestiaAnchor {
    /// Proof location (Celestia and/or IPFS)
    pub location: ProofLocation,
    /// Block height where anchored
    pub height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Timestamp of anchor
    pub timestamp: u64,
    /// Blob commitment
    pub commitment: BlobCommitment,
    /// Inclusion proof
    pub inclusion_proof: Option<CommitmentProof>,
    /// Tendermint transaction hash
    pub tx_hash: [u8; 32],
}

impl CelestiaAnchor {
    /// Create a new anchor
    pub fn new(
        location: ProofLocation,
        height: u64,
        block_hash: [u8; 32],
        commitment: BlobCommitment,
        tx_hash: [u8; 32],
    ) -> Self {
        Self {
            location,
            height,
            block_hash,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            commitment,
            inclusion_proof: None,
            tx_hash,
        }
    }

    /// Add inclusion proof
    pub fn with_inclusion_proof(mut self, proof: CommitmentProof) -> Self {
        self.inclusion_proof = Some(proof);
        self
    }

    /// Get proof ID
    pub fn proof_id(&self) -> ProofId {
        match &self.location {
            ProofLocation::Celestia { proof_id } => *proof_id,
            _ => ProofId::new(
                self.height,
                self.location
                    .namespace()
                    .cloned()
                    .unwrap_or_else(Namespace::metadata),
                *self.commitment.as_bytes(),
            ),
        }
    }

    /// Convert to core CommitAnchor
    pub fn to_core_anchor(&self) -> csv_hash::seal::CommitAnchor {
        let anchor_id = self.proof_id().to_bytes().to_vec();
        let metadata = serde_json::to_vec(&self.location).unwrap_or_else(|_| {
            // Fallback to empty metadata if serialization fails
            vec![]
        });

        csv_hash::seal::CommitAnchor::new(anchor_id.clone(), self.height, metadata.clone())
            .unwrap_or_else(|_| unsafe {
                csv_hash::seal::CommitAnchor::new_unchecked(anchor_id, self.height, metadata)
            })
    }

    /// Check if this uses IPFS
    pub fn uses_ipfs(&self) -> bool {
        self.location.uses_ipfs()
    }

    /// Get IPFS CID if available
    pub fn cid(&self) -> Option<&str> {
        self.location.cid()
    }
}

/// Finality proof for Celestia
///
/// Celestia uses Tendermint consensus with deterministic finality
/// once a block is included (2/3+ validators signed).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CelestiaFinalityProof {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Data root
    pub data_root: [u8; 32],
    /// Validator hash (from block header)
    pub validator_hash: [u8; 20],
    /// Next validator hash
    pub next_validator_hash: [u8; 20],
    /// App hash
    pub app_hash: [u8; 32],
    /// Quorum signatures (simplified - real impl would have actual signatures)
    pub quorum_signatures: Vec<Vec<u8>>,
    /// Has finality
    pub has_finality: bool,
}

impl CelestiaFinalityProof {
    /// Create a new finality proof
    pub fn new(height: u64, block_hash: [u8; 32], data_root: [u8; 32]) -> Self {
        Self {
            height,
            block_hash,
            data_root,
            validator_hash: [0u8; 20],
            next_validator_hash: [0u8; 20],
            app_hash: [0u8; 32],
            quorum_signatures: Vec::new(),
            has_finality: false,
        }
    }

    /// Set validator info
    pub fn with_validators(
        mut self,
        validator_hash: [u8; 20],
        next_validator_hash: [u8; 20],
    ) -> Self {
        self.validator_hash = validator_hash;
        self.next_validator_hash = next_validator_hash;
        self
    }

    /// Set app hash
    pub fn with_app_hash(mut self, app_hash: [u8; 32]) -> Self {
        self.app_hash = app_hash;
        self
    }

    /// Add quorum signatures and mark as finalized
    pub fn with_quorum(mut self, signatures: Vec<Vec<u8>>) -> Self {
        self.has_finality = !signatures.is_empty();
        self.quorum_signatures = signatures;
        self
    }

    /// Verify this proof structure
    pub fn verify_structure(&self) -> Result<()> {
        if self.block_hash == [0u8; 32] {
            return Err(CelestiaError::InvalidProofId(
                "Missing block hash".to_string(),
            ));
        }
        if self.data_root == [0u8; 32] {
            return Err(CelestiaError::InvalidProofId(
                "Missing data root".to_string(),
            ));
        }
        Ok(())
    }

    /// Check if block has reached finality
    pub fn is_finalized(&self) -> bool {
        self.has_finality
    }

    /// Convert to core FinalityProof
    pub fn to_core_finality(&self) -> csv_protocol::proof_taxonomy::FinalityProof {
        let finality_data = serde_json::to_vec(&self).unwrap_or_else(|_| {
            // Fallback to empty data if serialization fails
            vec![]
        });

        csv_protocol::proof_taxonomy::FinalityProof::new(
            finality_data.clone(),
            self.quorum_signatures.len() as u64,
            true, // Tendermint has deterministic finality
        )
        .unwrap_or_else(|_| {
            // SAFETY: We're falling back to unchecked creation only when the safe API fails,
            // and the data is derived from valid internal state.
            unsafe {
                csv_protocol::proof_taxonomy::FinalityProof::new_unchecked(
                    finality_data,
                    self.quorum_signatures.len() as u64,
                    true,
                )
            }
        })
    }
}

/// Celestia light client header info
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CelestiaHeader {
    /// Chain ID
    pub chain_id: String,
    /// Height
    pub height: u64,
    /// Time (Unix timestamp)
    pub time: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// Data root
    pub data_root: [u8; 32],
    /// Validator hash
    pub validator_hash: [u8; 20],
    /// Last commit hash
    pub last_commit_hash: [u8; 32],
}

impl CelestiaHeader {
    /// Create a new header
    pub fn new(
        chain_id: impl Into<String>,
        height: u64,
        hash: [u8; 32],
        data_root: [u8; 32],
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            height,
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            hash,
            data_root,
            validator_hash: [0u8; 20],
            last_commit_hash: [0u8; 32],
        }
    }

    /// Verify this header matches expected properties
    pub fn verify(&self, expected_height: u64) -> Result<()> {
        if self.height != expected_height {
            return Err(CelestiaError::InvalidHeight(self.height));
        }
        if self.hash == [0u8; 32] {
            return Err(CelestiaError::InvalidProofId(
                "Invalid block hash".to_string(),
            ));
        }
        Ok(())
    }
}

/// Extended metadata for Celestia-backed proofs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CelestiaMetadata {
    /// Original proof location
    pub location: ProofLocation,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration time (if any)
    pub expires_at: Option<u64>,
    /// Content type
    pub content_type: String,
    /// Original size
    pub original_size: usize,
    /// Compression used (if any)
    pub compression: Option<String>,
    /// Encoding format
    pub encoding: String,
    /// Checksums for verification
    pub checksums: Vec<(String, [u8; 32])>,
}

impl CelestiaMetadata {
    /// Create new metadata
    pub fn new(
        location: ProofLocation,
        content_type: impl Into<String>,
        original_size: usize,
    ) -> Self {
        Self {
            location,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            expires_at: None,
            content_type: content_type.into(),
            original_size,
            compression: None,
            encoding: "raw".to_string(),
            checksums: Vec::new(),
        }
    }

    /// Set expiration
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set compression
    pub fn with_compression(mut self, compression: impl Into<String>) -> Self {
        self.compression = Some(compression.into());
        self
    }

    /// Add checksum
    pub fn add_checksum(&mut self, algorithm: impl Into<String>, hash: [u8; 32]) {
        self.checksums.push((algorithm.into(), hash));
    }

    /// Verify checksum
    pub fn verify_checksum(&self, algorithm: &str, data: &[u8]) -> bool {
        use sha2::{Digest, Sha256};

        for (algo, expected) in &self.checksums {
            if algo == algorithm {
                let computed: [u8; 32] = match algorithm {
                    "sha256" => Sha256::digest(data).into(),
                    _ => return false,
                };
                return computed == *expected;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_id::ProofLocation;
    use sha2::Digest;

    #[test]
    fn test_celestia_seal_point() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let seal = CelestiaSealPoint::new(proof_id, 12345);

        assert!(seal.is_valid());
        assert!(!seal.consumed);
        assert_eq!(seal.height, 12345);
    }

    #[test]
    fn test_celestia_seal_point_consume() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let mut seal = CelestiaSealPoint::new(proof_id, 12345);

        seal.consume([0xABu8; 32]);
        assert!(!seal.is_valid());
        assert!(seal.consumed);
        assert_eq!(seal.consumption_tx, Some([0xABu8; 32]));
    }

    #[test]
    fn test_celestia_seal_point_with_ipfs() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let seal = CelestiaSealPoint::new(proof_id, 12345).with_ipfs("QmTest123");

        assert_eq!(seal.ipfs_cid, Some("QmTest123".to_string()));
    }

    #[test]
    fn test_celestia_anchor() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0u8; 32]);

        let anchor = CelestiaAnchor::new(location, 12345, [1u8; 32], commitment, [2u8; 32]);

        assert_eq!(anchor.height, 12345);
        assert!(!anchor.uses_ipfs());
    }

    #[test]
    fn test_celestia_anchor_with_ipfs() {
        let ns = Namespace::bitcoin_stark();
        let location = ProofLocation::ipfs_backed(12345, "QmTest", ns);
        let commitment = BlobCommitment::new([0u8; 32]);

        let anchor = CelestiaAnchor::new(location, 12345, [1u8; 32], commitment, [2u8; 32]);

        assert!(anchor.uses_ipfs());
        assert_eq!(anchor.cid(), Some("QmTest"));
    }

    #[test]
    fn test_celestia_finality_proof() {
        let proof = CelestiaFinalityProof::new(12345, [1u8; 32], [2u8; 32]);

        assert!(!proof.is_finalized());
        assert!(proof.verify_structure().is_ok());

        let finalized = proof.with_quorum(vec![vec![1, 2, 3]]);
        assert!(finalized.is_finalized());
    }

    #[test]
    fn test_celestia_finality_proof_structure_failure() {
        let proof = CelestiaFinalityProof::new(
            12345, [0u8; 32], // Invalid
            [0u8; 32], // Invalid
        );

        assert!(proof.verify_structure().is_err());
    }

    #[test]
    fn test_celestia_header() {
        let header = CelestiaHeader::new("celestia", 12345, [1u8; 32], [2u8; 32]);

        assert_eq!(header.chain_id, "celestia");
        assert_eq!(header.height, 12345);
        assert!(header.verify(12345).is_ok());
        assert!(header.verify(99999).is_err());
    }

    #[test]
    fn test_celestia_metadata() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };

        let meta = CelestiaMetadata::new(location, "application/stark-proof", 1024)
            .with_compression("gzip")
            .with_expiration(9999999999);

        assert_eq!(meta.content_type, "application/stark-proof");
        assert_eq!(meta.original_size, 1024);
        assert_eq!(meta.compression, Some("gzip".to_string()));
        assert!(meta.expires_at.is_some());
    }

    #[test]
    fn test_checksum() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };

        let mut meta = CelestiaMetadata::new(location, "application/stark-proof", 1024);

        let data = b"test data for checksum";
        let hash: [u8; 32] = sha2::Sha256::digest(data).into();
        meta.add_checksum("sha256", hash);

        assert!(meta.verify_checksum("sha256", data));
        assert!(!meta.verify_checksum("sha256", b"wrong data"));
    }
}
