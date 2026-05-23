//! Sanad Metadata for Celestia + IPFS
//!
//! This module provides metadata structures that point to proofs stored on
//! Celestia and IPFS. The metadata serves as the "index" for verification:
//!
//! ## Verification Flow
//!
//! ```text
//! 1. Sanad Metadata points to ProofLocation
//! 2. Retrieve proof from Celestia and/or IPFS
//! 3. Verify proof matches commitment in metadata
//! 4. Verify state transition using proof
//! ```
//!
//! ## Fraud Proof Flow
//!
//! ```text
//! 1. Challenge: Metadata claims proof exists at location
//! 2. Fraud prover retrieves proof and finds it invalid
//! 3. Fraud proof posted to Celestia fraud namespace
//! 4. Sanad invalidated if fraud proven
//!

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commitment::{BlobCommitment, FraudEvidence, FraudProof};
use crate::error::{CelestiaError, Result};
use crate::namespace::Namespace;
use crate::proof_id::{ProofId, ProofLocation};
use crate::types::CelestiaMetadata;

/// Metadata for a Sanad that uses Celestia for data availability
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadMetadata {
    /// Unique identifier for this metadata
    pub id: [u8; 32],
    /// Sanad type (e.g., "stark-proof", "zk-verification")
    pub sanad_type: String,
    /// Source chain that produced this Sanad
    pub source_chain: String,
    /// Target chain for verification (if cross-chain)
    pub target_chain: Option<String>,
    /// Proof location (Celestia and/or IPFS)
    pub proof_location: ProofLocation,
    /// Commitment to the proof data
    pub proof_commitment: BlobCommitment,
    /// Metadata about the proof
    pub proof_info: ProofInfo,
    /// Verification requirements
    pub verification: VerificationRequirements,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration (if time-bound)
    pub expires_at: Option<u64>,
    /// Additional metadata
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Information about the proof
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInfo {
    /// Proof size in bytes
    pub size: u64,
    /// Proof format (e.g., "stark", "snark", "bulletproofs")
    pub format: String,
    /// ZK proof system used
    pub proof_system: String,
    /// Estimated verification time (milliseconds)
    pub estimated_verification_time_ms: u64,
    /// Number of public inputs
    pub public_inputs_count: u32,
    /// Circuit identifier
    pub circuit_id: Option<String>,
    /// Verifier key reference (if not included)
    pub verifier_key_ref: Option<ProofLocation>,
}

/// Requirements for verification
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequirements {
    /// Minimum confirmation depth on Celestia
    pub min_celestia_depth: u32,
    /// Whether IPFS availability is required
    pub require_ipfs_available: bool,
    /// Whether to verify inclusion proof
    pub verify_inclusion: bool,
    /// Whether to verify finality
    pub verify_finality: bool,
    /// Staking requirement for challenge (in basis points)
    pub challenge_stake_bps: u32,
}

impl Default for VerificationRequirements {
    fn default() -> Self {
        Self {
            min_celestia_depth: 1, // Tendermint has instant finality
            require_ipfs_available: false,
            verify_inclusion: true,
            verify_finality: true,
            challenge_stake_bps: 1000, // 10% stake required
        }
    }
}

impl SanadMetadata {
    /// Create new Sanad metadata
    pub fn new(
        sanad_type: impl Into<String>,
        source_chain: impl Into<String>,
        proof_location: ProofLocation,
        proof_commitment: BlobCommitment,
        proof_info: ProofInfo,
    ) -> Self {
        let id = Self::compute_id(&proof_location, &proof_commitment);

        Self {
            id,
            sanad_type: sanad_type.into(),
            source_chain: source_chain.into(),
            target_chain: None,
            proof_location,
            proof_commitment,
            proof_info,
            verification: VerificationRequirements::default(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Set target chain
    pub fn with_target_chain(mut self, chain: impl Into<String>) -> Self {
        self.target_chain = Some(chain.into());
        self
    }

    /// Set verification requirements
    pub fn with_verification(mut self, verification: VerificationRequirements) -> Self {
        self.verification = verification;
        self
    }

    /// Set expiration
    pub fn with_expiration(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add extra metadata
    pub fn add_extra(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.extra.insert(key.into(), value);
    }

    /// Compute unique ID from proof location and commitment
    fn compute_id(location: &ProofLocation, commitment: &BlobCommitment) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(location.to_bytes());
        hasher.update(commitment.as_bytes());
        hasher.finalize().into()
    }

    /// Verify metadata structure
    pub fn verify_structure(&self) -> Result<()> {
        // Check ID matches
        let expected_id = Self::compute_id(&self.proof_location, &self.proof_commitment);
        if self.id != expected_id {
            return Err(CelestiaError::MetadataValidationFailed(
                "ID mismatch - possible tampering".to_string(),
            ));
        }

        // Check expiration
        if let Some(expires) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > expires {
                return Err(CelestiaError::MetadataValidationFailed(
                    "Metadata has expired".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get the proof ID for the main proof
    pub fn proof_id(&self) -> Option<ProofId> {
        match &self.proof_location {
            ProofLocation::Celestia { proof_id } => Some(*proof_id),
            ProofLocation::IpfsBacked {
                anchor_height,
                namespace,
                ..
            } => Some(ProofId::new(
                *anchor_height,
                *namespace,
                *self.proof_commitment.as_bytes(),
            )),
            ProofLocation::Hybrid { metadata_id, .. } => Some(*metadata_id),
        }
    }

    /// Get the namespace
    pub fn namespace(&self) -> Option<Namespace> {
        self.proof_location.namespace().cloned()
    }

    /// Check if IPFS is used
    pub fn uses_ipfs(&self) -> bool {
        self.proof_location.uses_ipfs()
    }

    /// Get IPFS CID if available
    pub fn cid(&self) -> Option<&str> {
        self.proof_location.cid()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| CelestiaError::SerializationError(format!("JSON: {}", e)))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| CelestiaError::DeserializationError(format!("JSON: {}", e)))
    }

    /// Convert to Celestia metadata format
    pub fn to_celestia_metadata(&self) -> CelestiaMetadata {
        let mut meta = CelestiaMetadata::new(
            self.proof_location.clone(),
            &self.proof_info.format,
            self.proof_info.size as usize,
        );

        meta.add_checksum("sha256", *self.proof_commitment.as_bytes());

        if let Some(expires) = self.expires_at {
            meta = meta.with_expiration(expires);
        }

        meta
    }
}

/// Challenge status for fraud proofs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeStatus {
    /// No challenge has been made
    Unchallenged,
    /// Challenge is pending resolution
    Pending {
        challenger: String,
        challenge_time: u64,
        stake_amount: u64,
    },
    /// Challenge was successful (Sanad is invalid)
    Successful {
        challenger: String,
        resolution_time: u64,
        fraud_proof: FraudProof,
    },
    /// Challenge was rejected
    Rejected {
        challenger: String,
        resolution_time: u64,
        reason: String,
    },
}

/// Challenge record stored on Celestia
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    /// ID of the Sanad being challenged
    pub sanad_id: [u8; 32],
    /// Challenger address/identity
    pub challenger: String,
    /// Challenge timestamp
    pub challenge_time: u64,
    /// Fraud evidence
    pub evidence: FraudEvidence,
    /// Challenge stake amount
    pub stake: u64,
    /// Challenge status
    pub status: ChallengeStatus,
    /// Celestia height where challenge was posted
    pub celestia_height: u64,
    /// Challenge transaction hash
    pub tx_hash: [u8; 32],
}

impl ChallengeRecord {
    /// Create a new challenge record
    pub fn new(
        sanad_id: [u8; 32],
        challenger: impl Into<String>,
        evidence: FraudEvidence,
        stake: u64,
        celestia_height: u64,
        tx_hash: [u8; 32],
    ) -> Self {
        let challenge_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            sanad_id,
            challenger: challenger.into(),
            challenge_time,
            evidence,
            stake,
            status: ChallengeStatus::Pending {
                challenger: String::new(),
                challenge_time,
                stake_amount: stake,
            },
            celestia_height,
            tx_hash,
        }
    }

    /// Mark challenge as successful
    pub fn succeed(mut self, fraud_proof: FraudProof, resolver: impl Into<String>) -> Self {
        self.status = ChallengeStatus::Successful {
            challenger: resolver.into(),
            resolution_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            fraud_proof,
        };
        self
    }

    /// Mark challenge as rejected
    pub fn reject(mut self, reason: impl Into<String>, resolver: impl Into<String>) -> Self {
        self.status = ChallengeStatus::Rejected {
            challenger: resolver.into(),
            resolution_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            reason: reason.into(),
        };
        self
    }

    /// Check if challenge is still pending
    pub fn is_pending(&self) -> bool {
        matches!(self.status, ChallengeStatus::Pending { .. })
    }

    /// Check if challenge was successful
    pub fn is_successful(&self) -> bool {
        matches!(self.status, ChallengeStatus::Successful { .. })
    }
}

/// Index entry for looking up Sanad metadata by various criteria
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataIndex {
    /// Metadata ID
    pub id: [u8; 32],
    /// Sanad type
    pub sanad_type: String,
    /// Source chain
    pub source_chain: String,
    /// Celestia height
    pub celestia_height: u64,
    /// IPFS CID (if applicable)
    pub ipfs_cid: Option<String>,
    /// Timestamp
    pub timestamp: u64,
    /// Quick lookup key
    pub lookup_key: String,
}

impl MetadataIndex {
    /// Create a new index entry
    pub fn new(metadata: &SanadMetadata, celestia_height: u64) -> Self {
        let lookup_key = format!(
            "{}:{}:{}",
            metadata.source_chain,
            metadata.sanad_type,
            hex::encode(&metadata.id[..8])
        );

        Self {
            id: metadata.id,
            sanad_type: metadata.sanad_type.clone(),
            source_chain: metadata.source_chain.clone(),
            celestia_height,
            ipfs_cid: metadata.cid().map(|s| s.to_string()),
            timestamp: metadata.created_at,
            lookup_key,
        }
    }

    /// Get the full lookup key
    pub fn lookup_key(&self) -> &str {
        &self.lookup_key
    }
}

/// Batch of Sanad metadata for efficient DA posting
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataBatch {
    /// Batch ID
    pub batch_id: [u8; 32],
    /// Metadata entries
    pub entries: Vec<SanadMetadata>,
    /// Merkle root of all entry IDs
    pub merkle_root: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

impl MetadataBatch {
    /// Create a new batch
    pub fn new(entries: Vec<SanadMetadata>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let merkle_root = Self::compute_merkle_root(&entries);

        let mut hasher = Sha256::new();
        hasher.update(merkle_root);
        hasher.update(timestamp.to_le_bytes());
        let batch_id: [u8; 32] = hasher.finalize().into();

        Self {
            batch_id,
            entries,
            merkle_root,
            timestamp,
        }
    }

    /// Compute merkle root of entry IDs
    fn compute_merkle_root(entries: &[SanadMetadata]) -> [u8; 32] {
        if entries.is_empty() {
            return [0u8; 32];
        }

        let mut hasher = Sha256::new();
        for entry in entries {
            hasher.update(entry.id);
        }
        hasher.finalize().into()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find entry by ID
    pub fn find_by_id(&self, id: &[u8; 32]) -> Option<&SanadMetadata> {
        self.entries.iter().find(|e| &e.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_id::ProofId;

    fn create_test_proof_info() -> ProofInfo {
        ProofInfo {
            size: 1024,
            format: "stark".to_string(),
            proof_system: "starkware".to_string(),
            estimated_verification_time_ms: 100,
            public_inputs_count: 10,
            circuit_id: Some("circuit-v1".to_string()),
            verifier_key_ref: None,
        }
    }

    #[test]
    fn test_sanad_metadata_creation() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0xABu8; 32]);
        let proof_info = create_test_proof_info();

        let metadata =
            SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info);

        assert_eq!(metadata.sanad_type, "stark-proof");
        assert_eq!(metadata.source_chain, "bitcoin");
        assert!(metadata.verify_structure().is_ok());
    }

    #[test]
    fn test_sanad_metadata_with_ipfs() {
        let ns = Namespace::bitcoin_stark();
        let location = ProofLocation::ipfs_backed(12345, "QmTest123", ns);
        let commitment = BlobCommitment::new([0u8; 32]);
        let proof_info = create_test_proof_info();

        let metadata =
            SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info);

        assert!(metadata.uses_ipfs());
        assert_eq!(metadata.cid(), Some("QmTest123"));
    }

    #[test]
    fn test_metadata_id_computation() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0xABu8; 32]);
        let proof_info = create_test_proof_info();

        let metadata1 = SanadMetadata::new(
            "stark-proof",
            "bitcoin",
            location.clone(),
            commitment,
            proof_info.clone(),
        );

        let metadata2 =
            SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info);

        assert_eq!(metadata1.id, metadata2.id);
    }

    #[test]
    fn test_metadata_json_roundtrip() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0u8; 32]);
        let proof_info = create_test_proof_info();

        let metadata =
            SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info)
                .with_target_chain("ethereum")
                .with_expiration(9999999999);

        let json = metadata.to_json().unwrap();
        let recovered = SanadMetadata::from_json(&json).unwrap();

        assert_eq!(metadata.id, recovered.id);
        assert_eq!(metadata.target_chain, recovered.target_chain);
        assert_eq!(metadata.expires_at, recovered.expires_at);
    }

    #[test]
    fn test_challenge_record() {
        let evidence = FraudEvidence::MissingShare {
            row_index: 5,
            share_index: 10,
        };

        let challenge = ChallengeRecord::new(
            [0u8; 32],
            "challenger1",
            evidence,
            1000,
            12345,
            [0xABu8; 32],
        );

        assert!(challenge.is_pending());
        assert!(!challenge.is_successful());
        assert_eq!(challenge.stake, 1000);

        let fraud_proof = crate::commitment::FraudProof::new(
            12345,
            BlobCommitment::new([0u8; 32]),
            FraudEvidence::MissingShare {
                row_index: 0,
                share_index: 0,
            },
        );

        let resolved = challenge.succeed(fraud_proof, "resolver1");
        assert!(!resolved.is_pending());
        assert!(resolved.is_successful());
    }

    #[test]
    fn test_metadata_index() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0u8; 32]);
        let proof_info = create_test_proof_info();

        let metadata =
            SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info);

        let index = MetadataIndex::new(&metadata, 12345);
        assert_eq!(index.sanad_type, "stark-proof");
        assert_eq!(index.source_chain, "bitcoin");
        assert!(index.lookup_key().contains("bitcoin"));
        assert!(index.lookup_key().contains("stark-proof"));
    }

    #[test]
    fn test_metadata_batch() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0u8; 32]);
        let proof_info = create_test_proof_info();

        let entries = vec![
            SanadMetadata::new(
                "stark-proof",
                "bitcoin",
                location.clone(),
                commitment,
                proof_info.clone(),
            ),
            SanadMetadata::new(
                "stark-proof",
                "bitcoin",
                location.clone(),
                commitment,
                proof_info.clone(),
            ),
            SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info),
        ];

        let batch = MetadataBatch::new(entries);
        assert_eq!(batch.len(), 3);
        assert!(!batch.merkle_root.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_batch_find_by_id() {
        let ns = Namespace::bitcoin_stark();
        let proof_id = ProofId::new(12345, ns, [0u8; 32]);
        let location = ProofLocation::Celestia { proof_id };
        let commitment = BlobCommitment::new([0u8; 32]);
        let proof_info = create_test_proof_info();

        let entry = SanadMetadata::new("stark-proof", "bitcoin", location, commitment, proof_info);
        let id = entry.id;

        let batch = MetadataBatch::new(vec![entry.clone()]);
        assert!(batch.find_by_id(&id).is_some());
        assert!(batch.find_by_id(&[0u8; 32]).is_none());
    }
}
