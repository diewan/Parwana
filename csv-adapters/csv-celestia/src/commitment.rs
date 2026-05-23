//! Blob Commitments and Inclusion Proofs
//!
//! This module provides commitment verification and inclusion proof types
//! for Celestia Data Availability. The commitment scheme uses Celestia's
//! native blob commitment which is a SHA256 hash of the namespace + data.
//!
//! ## Inclusion Proofs
//!
//! Celestia uses a Merkle tree over row roots (DataRoot). Each blob's
//! commitment can be proven included via:
//! 1. Row inclusion proof (blob is in specific row)
//! 2. DataRoot inclusion (row root is in the DataRoot)
//! 3. Tendermint block header (DataRoot is in block)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::blob::Blob;
use crate::error::{CelestiaError, Result};
use crate::namespace::Namespace;

/// Blob commitment (32-byte hash)
///
/// This is computed as SHA256(namespace || data) and is what gets
/// anchored on-chain when referencing a Celestia blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobCommitment([u8; 32]);

impl BlobCommitment {
    /// Create from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute commitment from a blob
    pub fn from_blob(blob: &Blob) -> Self {
        Self(blob.commitment())
    }

    /// Compute commitment from namespace and data
    pub fn compute(namespace: &Namespace, data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| {
            CelestiaError::CommitmentVerificationFailed(format!("Invalid hex: {}", e))
        })?;
        if bytes.len() != 32 {
            return Err(CelestiaError::CommitmentVerificationFailed(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Verify that a blob matches this commitment
    pub fn verify(&self, blob: &Blob) -> bool {
        self.0 == blob.commitment()
    }

    /// Verify against raw namespace and data
    pub fn verify_raw(&self, namespace: &Namespace, data: &[u8]) -> bool {
        self.0 == Self::compute(namespace, data).0
    }
}

impl From<[u8; 32]> for BlobCommitment {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<BlobCommitment> for [u8; 32] {
    fn from(commitment: BlobCommitment) -> Self {
        commitment.0
    }
}

/// Inclusion proof for a blob in Celestia
///
/// Contains the necessary data to verify that a blob was included
/// at a specific height in a specific namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentProof {
    /// Block height where blob was included
    pub height: u64,
    /// Namespace
    pub namespace: Namespace,
    /// Blob commitment
    pub commitment: BlobCommitment,
    /// Row root (Merkle root of shares in the row containing this blob)
    pub row_root: [u8; 32],
    /// Row index where blob is located
    pub row_index: u32,
    /// Index within row
    pub share_index: u32,
    /// Merkle proof path from blob to row root
    pub row_proof: Vec<[u8; 32]>,
    /// Data root (Merkle root of all row roots)
    pub data_root: [u8; 32],
    /// Merkle proof path from row root to data root
    pub data_proof: Vec<[u8; 32]>,
    /// Block hash (Tendermint block header hash)
    pub block_hash: [u8; 32],
    /// Share range (start, end) in the row
    pub share_range: (u32, u32),
}

impl CommitmentProof {
    /// Create a new commitment proof
    pub fn new(
        height: u64,
        namespace: Namespace,
        commitment: BlobCommitment,
        row_root: [u8; 32],
        data_root: [u8; 32],
        block_hash: [u8; 32],
    ) -> Self {
        Self {
            height,
            namespace,
            commitment,
            row_root,
            row_index: 0,
            share_index: 0,
            row_proof: Vec::new(),
            data_root,
            data_proof: Vec::new(),
            block_hash,
            share_range: (0, 0),
        }
    }

    /// Set row proof data
    pub fn with_row_proof(
        mut self,
        row_index: u32,
        share_index: u32,
        proof: Vec<[u8; 32]>,
        range: (u32, u32),
    ) -> Self {
        self.row_index = row_index;
        self.share_index = share_index;
        self.row_proof = proof;
        self.share_range = range;
        self
    }

    /// Set data proof data
    pub fn with_data_proof(mut self, proof: Vec<[u8; 32]>) -> Self {
        self.data_proof = proof;
        self
    }

    /// Verify this proof is well-formed
    ///
    /// Note: Full cryptographic verification requires Celestia light client
    /// verification which is not implemented here (requires WASM verifier).
    pub fn verify_structure(&self) -> Result<()> {
        // Check that we have necessary components
        if self.row_root == [0u8; 32] {
            return Err(CelestiaError::CommitmentVerificationFailed(
                "Missing row root".to_string(),
            ));
        }
        if self.data_root == [0u8; 32] {
            return Err(CelestiaError::CommitmentVerificationFailed(
                "Missing data root".to_string(),
            ));
        }
        if self.block_hash == [0u8; 32] {
            return Err(CelestiaError::CommitmentVerificationFailed(
                "Missing block hash".to_string(),
            ));
        }
        Ok(())
    }

    /// Get the proof ID for this commitment
    pub fn proof_id(&self) -> crate::proof_id::ProofId {
        crate::proof_id::ProofId::new(self.height, self.namespace, *self.commitment.as_bytes())
    }
}

/// Data availability sampling result
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AvailabilityProof {
    /// Block height
    pub height: u64,
    /// Data root at this height
    pub data_root: [u8; 32],
    /// Number of samples taken
    pub samples: u32,
    /// Samples that passed
    pub successful_samples: u32,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

impl AvailabilityProof {
    /// Create a new availability proof
    pub fn new(height: u64, data_root: [u8; 32]) -> Self {
        Self {
            height,
            data_root,
            samples: 0,
            successful_samples: 0,
            confidence: 0.0,
        }
    }

    /// Add a successful sample
    pub fn add_sample(&mut self, success: bool) {
        self.samples += 1;
        if success {
            self.successful_samples += 1;
        }
        self.update_confidence();
    }

    /// Check if availability is proven above threshold
    pub fn is_available(&self, threshold: f64) -> bool {
        self.confidence >= threshold && self.samples > 0
    }

    fn update_confidence(&mut self) {
        if self.samples == 0 {
            self.confidence = 0.0;
            return;
        }
        // Simple model: confidence = successful / total
        // Real implementation would use more sophisticated statistical model
        self.confidence = self.successful_samples as f64 / self.samples as f64;
    }
}

/// Multi-layer proof combining Celestia DA with IPFS storage
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridProof {
    /// Direct Celestia storage proof
    Direct(CommitmentProof),
    /// IPFS-backed with Celestia anchor
    IpfsBacked {
        /// Proof that IPFS CID was anchored on Celestia
        anchor_proof: CommitmentProof,
        /// IPFS CID
        cid: String,
        /// Merkle DAG root of the IPFS content
        dag_root: [u8; 32],
    },
}

impl HybridProof {
    /// Create a direct Celestia proof
    pub fn direct(proof: CommitmentProof) -> Self {
        Self::Direct(proof)
    }

    /// Create an IPFS-backed proof
    pub fn ipfs_backed(
        anchor_proof: CommitmentProof,
        cid: impl Into<String>,
        dag_root: [u8; 32],
    ) -> Self {
        Self::IpfsBacked {
            anchor_proof,
            cid: cid.into(),
            dag_root,
        }
    }

    /// Get the height for this proof
    pub fn height(&self) -> u64 {
        match self {
            Self::Direct(proof) => proof.height,
            Self::IpfsBacked { anchor_proof, .. } => anchor_proof.height,
        }
    }

    /// Get the namespace for this proof
    pub fn namespace(&self) -> &Namespace {
        match self {
            Self::Direct(proof) => &proof.namespace,
            Self::IpfsBacked { anchor_proof, .. } => &anchor_proof.namespace,
        }
    }

    /// Check if this is an IPFS-backed proof
    pub fn is_ipfs_backed(&self) -> bool {
        matches!(self, Self::IpfsBacked { .. })
    }

    /// Get the CID if IPFS-backed
    pub fn cid(&self) -> Option<&str> {
        match self {
            Self::Direct(_) => None,
            Self::IpfsBacked { cid, .. } => Some(cid),
        }
    }
}

/// Fraud proof for challenging invalid data availability claims
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudProof {
    /// Height being challenged
    pub challenged_height: u64,
    /// Commitment being challenged
    pub challenged_commitment: BlobCommitment,
    /// Evidence of fraud (e.g., missing share, invalid merkle proof)
    pub evidence: FraudEvidence,
    /// Challenger's signature
    pub challenger_signature: Vec<u8>,
    /// Timestamp of challenge
    pub challenge_time: u64,
}

/// Types of fraud evidence
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FraudEvidence {
    /// Share not found at claimed location
    MissingShare { row_index: u32, share_index: u32 },
    /// Invalid Merkle proof
    InvalidMerkleProof {
        proof_index: u32,
        expected_root: [u8; 32],
        actual_root: [u8; 32],
    },
    /// Invalid namespace in share
    InvalidNamespace {
        expected: Namespace,
        actual: Namespace,
    },
    /// Data not retrievable from IPFS
    IpfsUnavailable { cid: String, error: String },
    /// Content hash mismatch (IPFS CID doesn't match content)
    ContentMismatch {
        cid: String,
        computed_hash: [u8; 32],
    },
}

impl FraudProof {
    /// Create a new fraud proof
    pub fn new(
        challenged_height: u64,
        challenged_commitment: BlobCommitment,
        evidence: FraudEvidence,
    ) -> Self {
        Self {
            challenged_height,
            challenged_commitment,
            evidence,
            challenger_signature: Vec::new(),
            challenge_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add challenger signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.challenger_signature = signature;
        self
    }

    /// Verify the fraud proof structure
    pub fn verify_structure(&self) -> Result<()> {
        if self.challenger_signature.is_empty() {
            return Err(CelestiaError::FraudProofError(
                "Missing challenger signature".to_string(),
            ));
        }
        if self.challenged_commitment.as_bytes() == &[0u8; 32] {
            return Err(CelestiaError::FraudProofError(
                "Invalid challenged commitment".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::Blob;

    #[test]
    fn test_blob_commitment() {
        let ns = Namespace::bitcoin_stark();
        let data = vec![1, 2, 3, 4, 5];
        let blob = Blob::new(ns, data.clone()).unwrap();

        let commitment1 = BlobCommitment::from_blob(&blob);
        let commitment2 = BlobCommitment::compute(&ns, &data);

        assert_eq!(commitment1, commitment2);
        assert!(commitment1.verify(&blob));
        assert!(commitment1.verify_raw(&ns, &data));
    }

    #[test]
    fn test_commitment_hex() {
        let commitment = BlobCommitment::new([0xABu8; 32]);
        let hex = commitment.to_hex();
        assert_eq!(hex.len(), 64);

        let recovered = BlobCommitment::from_hex(&hex).unwrap();
        assert_eq!(commitment, recovered);
    }

    #[test]
    fn test_commitment_proof() {
        let ns = Namespace::bitcoin_stark();
        let commitment = BlobCommitment::new([0u8; 32]);

        let proof = CommitmentProof::new(
            12345, ns, commitment, [1u8; 32], // row_root
            [2u8; 32], // data_root
            [3u8; 32], // block_hash
        );

        assert_eq!(proof.height, 12345);
        assert!(proof.verify_structure().is_ok());
    }

    #[test]
    fn test_commitment_proof_structure_failure() {
        let ns = Namespace::bitcoin_stark();
        let commitment = BlobCommitment::new([0u8; 32]);

        let proof = CommitmentProof::new(
            12345, ns, commitment, [0u8; 32], // zero row_root - should fail
            [2u8; 32], [3u8; 32],
        );

        assert!(proof.verify_structure().is_err());
    }

    #[test]
    fn test_availability_proof() {
        let mut proof = AvailabilityProof::new(12345, [0u8; 32]);
        assert!(!proof.is_available(0.5));

        proof.add_sample(true);
        proof.add_sample(true);
        proof.add_sample(false);

        assert!(proof.is_available(0.5));
        assert!(!proof.is_available(0.9));
    }

    #[test]
    fn test_hybrid_proof() {
        let ns = Namespace::bitcoin_stark();
        let celestia_proof = CommitmentProof::new(
            12345,
            ns,
            BlobCommitment::new([0u8; 32]),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let direct = HybridProof::direct(celestia_proof.clone());
        assert!(!direct.is_ipfs_backed());
        assert_eq!(direct.height(), 12345);

        let ipfs = HybridProof::ipfs_backed(celestia_proof, "QmTest", [4u8; 32]);
        assert!(ipfs.is_ipfs_backed());
        assert_eq!(ipfs.cid(), Some("QmTest"));
    }

    #[test]
    fn test_fraud_proof() {
        let commitment = BlobCommitment::new([1u8; 32]);
        let evidence = FraudEvidence::MissingShare {
            row_index: 5,
            share_index: 10,
        };

        let fraud = FraudProof::new(12345, commitment, evidence).with_signature(vec![1, 2, 3]);

        assert_eq!(fraud.challenged_height, 12345);
        assert!(fraud.verify_structure().is_ok());
    }

    #[test]
    fn test_fraud_proof_structure_failure() {
        let commitment = BlobCommitment::new([0u8; 32]);
        let evidence = FraudEvidence::InvalidMerkleProof {
            proof_index: 0,
            expected_root: [0u8; 32],
            actual_root: [1u8; 32],
        };

        let fraud = FraudProof::new(12345, commitment, evidence);
        // Missing signature
        assert!(fraud.verify_structure().is_err());
    }

    #[test]
    fn test_proof_id_from_commitment() {
        let ns = Namespace::bitcoin_stark();
        let commitment = BlobCommitment::new([0xABu8; 32]);

        let proof = CommitmentProof::new(12345, ns, commitment, [1u8; 32], [2u8; 32], [3u8; 32]);

        let proof_id = proof.proof_id();
        assert_eq!(proof_id.height, 12345);
        assert_eq!(proof_id.namespace, ns);
        assert_eq!(proof_id.commitment, [0xABu8; 32]);
    }
}
