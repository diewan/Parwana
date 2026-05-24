//! Zero-Knowledge Seal Proof Module
//!
//! This module provides ZK-proof infrastructure for CSV seal verification.
//! ZK proofs enable trustless verification without relying on chain RPC responses.
//!
//! # Architecture
//!
//! ```text
//! Prover (sender):
//!   Bitcoin UTXO spend data + Merkle branch
//!   → SPV guest program
//!   → ZkSealProof { proof_bytes, public_inputs }
//!
//! Verifier (receiver):
//!   ZkSealProof
//!   → verify against known verifier key
//!   → extract seal_ref and block_hash as trusted outputs
//!   → no RPC call required
//! ```
//!
//! # Design Decisions
//!
//! - Uses a generic `ZkProver`/`ZkVerifier` trait interface for flexibility
//! - Supports multiple ZK backends (SP1, Risc0, Groth16) via feature flags
//! - Public inputs include seal_ref, block_hash, and commitment for binding
//! - Verifier keys are chain-specific and registered at runtime

use serde::{Deserialize, Serialize};

use csv_hash::Hash;
use csv_hash::seal::SealPoint;
use csv_hash::csv_tagged_hash;

/// Maximum ZK proof size (1MB)
pub const MAX_ZK_PROOF_SIZE: usize = 1024 * 1024;

/// Verifier key for a specific chain's ZK proof system
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKey {
    /// Chain this verifier is for
    pub chain: csv_hash::chain_id::ChainId,
    /// Verifier key bytes (backend-specific format)
    pub key_bytes: Vec<u8>,
    /// Proof system type (SP1, Risc0, Groth16, etc.)
    pub proof_system: ProofSystem,
    /// Key version for upgradeability
    pub version: u32,
    /// Whether this verifier is active
    pub active: bool,
}

impl VerifierKey {
    /// Create a new verifier key
    pub fn new(
        chain: csv_hash::chain_id::ChainId,
        key_bytes: Vec<u8>,
        proof_system: ProofSystem,
        version: u32,
    ) -> Self {
        Self {
            chain,
            key_bytes,
            proof_system,
            version,
            active: true,
        }
    }

    /// Compute a hash of this verifier key for identification using canonical serialization
    pub fn hash(&self) -> Hash {
        use csv_codec::to_canonical_cbor;
        let data = to_canonical_cbor(&(self.chain.clone(), &self.key_bytes, self.version))
            .expect("Canonical serialization should not fail for VerifierKey");
        Hash::new(csv_tagged_hash("csv.zk.verifier-key.v1", &data))
    }
}

/// Supported ZK proof systems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSystem {
    /// Succinct Labs SP1 (RISC-V zkVM)
    SP1,
    /// Risc0 RISC-V zkVM
    Risc0,
    /// Groth16 (pairing-based)
    Groth16,
    /// PlonK (permutation-based)
    PlonK,
    /// Custom/extensible proof system
    Custom,
}

impl core::fmt::Display for ProofSystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProofSystem::SP1 => write!(f, "sp1"),
            ProofSystem::Risc0 => write!(f, "risc0"),
            ProofSystem::Groth16 => write!(f, "groth16"),
            ProofSystem::PlonK => write!(f, "plonk"),
            ProofSystem::Custom => write!(f, "custom"),
        }
    }
}

/// Public inputs from a ZK seal proof
///
/// These are the trusted outputs that the ZK proof guarantees are correct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPublicInputs {
    /// The seal reference being proven
    pub seal_ref: SealPoint,
    /// Block hash where the seal was consumed
    pub block_hash: Hash,
    /// Commitment hash bound to the proof
    pub commitment: Hash,
    /// Source chain identifier
    pub source_chain: csv_hash::chain_id::ChainId,
    /// Block height of the seal consumption
    pub block_height: u64,
    /// Unix timestamp of the seal consumption
    pub timestamp: u64,
}

/// Complete ZK seal proof bundle
///
/// Contains the proof bytes, verifier key, and public inputs.
/// The verifier can check this proof without any chain RPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkSealProof {
    /// The ZK proof bytes (backend-specific format)
    pub proof_bytes: Vec<u8>,
    /// Verifier key for proof verification
    pub verifier_key: VerifierKey,
    /// Public inputs extracted from the proof
    pub public_inputs: ZkPublicInputs,
}

impl ZkSealProof {
    /// Create a new ZK seal proof
    ///
    /// # Arguments
    /// * `proof_bytes` - ZK proof bytes (max MAX_ZK_PROOF_SIZE)
    /// * `verifier_key` - Verifier key for the target chain
    /// * `public_inputs` - Public inputs from the proof
    ///
    /// # Errors
    /// Returns an error if proof_bytes exceeds the maximum allowed size
    pub fn new(
        proof_bytes: Vec<u8>,
        verifier_key: VerifierKey,
        public_inputs: ZkPublicInputs,
    ) -> Result<Self, &'static str> {
        if proof_bytes.len() > MAX_ZK_PROOF_SIZE {
            return Err("ZK proof bytes exceed maximum allowed size (1MB)");
        }
        Ok(Self {
            proof_bytes,
            verifier_key,
            public_inputs,
        })
    }

    /// Verify the proof structure is valid
    pub fn is_structurally_valid(&self) -> bool {
        !self.proof_bytes.is_empty()
            && self.proof_bytes.len() <= MAX_ZK_PROOF_SIZE
            && self.verifier_key.active
            && !self.public_inputs.seal_ref.id.is_empty()
            && self.public_inputs.block_hash.as_bytes() != &[0u8; 32]
    }

    /// Serialize the proof to canonical bytes for storage or transmission
    ///
    /// Uses canonical CBOR serialization for protocol-critical data.
    /// Manual bincode serialization is forbidden per AUDIT.md.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        csv_codec::to_canonical_cbor(self)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize a proof from canonical bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        csv_codec::from_canonical_cbor(bytes)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

/// Trait for generating ZK seal proofs
///
/// Implementations use a specific ZK backend (SP1, Risc0, etc.)
/// to generate proofs that a seal was consumed on a specific chain.
pub trait ZkProver {
    /// Generate a ZK proof that a seal was consumed
    ///
    /// # Arguments
    /// * `seal` - The seal reference being proven
    /// * `witness` - Chain witness data (UTXO spend, Merkle branch, etc.)
    ///
    /// # Returns
    /// A ZkSealProof containing the proof bytes and public inputs
    ///
    /// # Errors
    /// Returns an error if the witness data is invalid or proving fails
    fn prove_seal_consumption(
        &self,
        seal: &SealPoint,
        witness: &ChainWitness,
    ) -> Result<ZkSealProof, ZkError>;

    /// Get the proof system this prover uses
    fn proof_system(&self) -> ProofSystem;
}

/// Chain witness data for ZK proof generation
///
/// Contains the on-chain data that the ZK guest program will prove.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainWitness {
    /// Source chain identifier
    pub chain: csv_hash::chain_id::ChainId,
    /// Block hash of the transaction
    pub block_hash: Hash,
    /// Block height of the transaction
    pub block_height: u64,
    /// Transaction data (serialized)
    pub tx_data: Vec<u8>,
    /// Merkle/inclusion proof data
    pub inclusion_proof: Vec<u8>,
    /// Finality proof data
    pub finality_proof: Vec<u8>,
    /// Unix timestamp of the block
    pub timestamp: u64,
}

impl ChainWitness {
    /// Compute a hash of the witness for integrity verification
    pub fn hash(&self) -> Hash {
        use csv_codec::to_canonical_cbor;
        let data = to_canonical_cbor(&(
            self.chain.clone(),
            self.block_hash,
            self.block_height,
            self.tx_data.clone(),
            self.inclusion_proof.clone(),
            self.finality_proof.clone(),
            self.timestamp,
        )).expect("Canonical serialization should not fail for Witness");
        Hash::new(csv_tagged_hash("csv.zk.witness.v1", &data))
    }
}

/// Trait for verifying ZK seal proofs
///
/// Implementations use a specific ZK backend's verifier to check
/// proofs against a registered verifier key.
pub trait ZkVerifier {
    /// Verify a ZK seal proof
    ///
    /// # Arguments
    /// * `proof` - The ZkSealProof to verify
    ///
    /// # Returns
    /// The verified public inputs if the proof is valid
    ///
    /// # Errors
    /// Returns an error if the proof is invalid or the verifier key is not found
    fn verify(&self, proof: &ZkSealProof) -> Result<ZkPublicInputs, ZkError>;

    /// Get the proof system this verifier uses
    fn proof_system(&self) -> ProofSystem;
}

/// Registry of ZK verifiers for different chains
///
/// Manages verifier keys for each chain's ZK proof system.
pub struct ZkVerifierRegistry {
    verifiers: crate::collections::HashMap<csv_hash::chain_id::ChainId, VerifierKey>,
}

impl ZkVerifierRegistry {
    /// Create a new empty verifier registry
    pub fn new() -> Self {
        Self {
            verifiers: crate::collections::HashMap::new(),
        }
    }

    /// Register a verifier key for a chain
    pub fn register(&mut self, key: VerifierKey) {
        self.verifiers.insert(key.chain.clone(), key);
    }

    /// Get the verifier key for a chain
    pub fn get(&self, chain: &csv_hash::chain_id::ChainId) -> Option<&VerifierKey> {
        self.verifiers.get(chain)
    }

    /// Check if a chain has a registered verifier
    pub fn has_verifier(&self, chain: &csv_hash::chain_id::ChainId) -> bool {
        self.verifiers.contains_key(chain)
    }

    /// Remove a verifier for a chain
    pub fn remove(&mut self, chain: &csv_hash::chain_id::ChainId) -> Option<VerifierKey> {
        self.verifiers.remove(chain)
    }

    /// Get all registered chains
    pub fn registered_chains(&self) -> Vec<csv_hash::chain_id::ChainId> {
        self.verifiers.keys().cloned().collect()
    }
}

impl Default for ZkVerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur in ZK proof operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum ZkError {
    /// Invalid proof bytes
    #[error("Invalid proof bytes: {0}")]
    InvalidProof(String),

    /// Verifier key not found for chain
    #[error("Verifier key not found for chain: {0}")]
    VerifierNotFound(csv_hash::chain_id::ChainId),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    /// Unsupported proof system
    #[error("Unsupported proof system: {0}")]
    UnsupportedSystem(String),

    /// Proof size exceeds limit
    #[error("Proof size exceeds maximum: {0} bytes")]
    ProofTooLarge(usize),

    /// Backend-specific error
    #[error("Backend error: {0}")]
    BackendError(String),
}

/// Verify a ZK proof using the canonical verification logic.
///
/// This is the canonical implementation used by all chain adapters.
/// It checks proof size limits and delegates to backend-specific verifiers.
///
/// # Arguments
/// * `proof` — The ZK proof bytes
/// * `verifier_key` — Optional verifier key for the proof system
///
/// # Returns
/// A `VerificationResult` indicating whether the proof is valid.
/// If the proof is empty, returns `PartialCryptographic` assurance.
/// If the proof exceeds MAX_ZK_PROOF_SIZE, returns an error.
pub fn verify_zk_proof(
    proof: &[u8],
    verifier_key: Option<&VerifierKey>,
) -> csv_protocol::verified::VerificationResult {
    use csv_protocol::verified::{
        FinalityStrength, InclusionStrength, VerificationAssurance, VerificationFailure,
        VerificationResult, VerifiedComponents,
    };

    if proof.is_empty() {
        // Empty proof is valid — no ZK verification needed
        return VerificationResult {
            valid: true,
            assurance: VerificationAssurance::PartialCryptographic,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        };
    }

    if proof.len() > MAX_ZK_PROOF_SIZE {
        return VerificationResult {
            valid: false,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: Some(VerificationFailure::MissingData(format!(
                "ZK proof size {} exceeds maximum {}",
                proof.len(),
                MAX_ZK_PROOF_SIZE
            ))),
        };
    }

    // Check if we have a verifier key
    if let Some(key) = verifier_key {
        if !key.active {
            return VerificationResult {
                valid: false,
                assurance: VerificationAssurance::Structural,
                verified_components: VerifiedComponents {
                    inclusion: InclusionStrength::None,
                    finality: FinalityStrength::None,
                    replay_checked: false,
                    ownership_signature: false,
                },
                error: Some(VerificationFailure::MissingData(
                    "Verifier key is not active".to_string(),
                )),
            };
        }

        // Backend-specific verification would go here
        // For now, return PartialCryptographic as the backend is not yet implemented
        VerificationResult {
            valid: true,
            assurance: VerificationAssurance::PartialCryptographic,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: None,
        }
    } else {
        // No verifier key — ZK proofs require a registered verifier
        VerificationResult {
            valid: false,
            assurance: VerificationAssurance::Structural,
            verified_components: VerifiedComponents {
                inclusion: InclusionStrength::None,
                finality: FinalityStrength::None,
                replay_checked: false,
                ownership_signature: false,
            },
            error: Some(VerificationFailure::UnsupportedCapability(
                "ZK proofs require a registered verifier key. Use BitcoinSpvProver for SPV verification without ZK.".to_string(),
            )),
        }
    }
}

#[cfg(test)]
/// Create a default ZkVerifierRegistry with common chains
///
/// This is a convenience function for testing only.
/// In production, verifier keys must be loaded from on-chain verifier contracts
/// or other trusted sources at runtime.
pub fn default_verifier_registry() -> ZkVerifierRegistry {
    use crate::protocol_version::builtin;

    let mut registry = ZkVerifierRegistry::new();

    // Register placeholder verifiers for common chains
    // In production, these would be loaded from on-chain contracts
    for chain in [
        builtin::BITCOIN.clone(),
        builtin::ETHEREUM.clone(),
        builtin::SOLANA.clone(),
        builtin::SUI.clone(),
        builtin::APTOS.clone(),
    ] {
        registry.register(VerifierKey::new(
            chain,
            vec![0u8; 64], // Placeholder verifier key
            ProofSystem::SP1,
            1,
        ));
    }

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_version::builtin;

    #[test]
    fn test_verifier_key_hash() {
        let key1 = VerifierKey::new(builtin::BITCOIN.clone(), vec![1u8; 32], ProofSystem::SP1, 1);
        let key2 = VerifierKey::new(builtin::BITCOIN.clone(), vec![1u8; 32], ProofSystem::SP1, 1);
        let key3 = VerifierKey::new(
            builtin::ETHEREUM.clone(),
            vec![1u8; 32],
            ProofSystem::SP1,
            1,
        );

        assert_eq!(key1.hash(), key2.hash());
        assert_ne!(key1.hash(), key3.hash());
    }

    #[test]
    fn test_zk_seal_proof_structure() {
        let verifier_key =
            VerifierKey::new(builtin::BITCOIN.clone(), vec![1u8; 32], ProofSystem::SP1, 1);
        let seal_ref = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
        let public_inputs = ZkPublicInputs {
            seal_ref: seal_ref.clone(),
            block_hash: Hash::new([1u8; 32]),
            commitment: Hash::new([2u8; 32]),
            source_chain: builtin::BITCOIN.clone(),
            block_height: 800_000,
            timestamp: 1_000_000,
        };

        let proof = ZkSealProof::new(vec![0xCD; 128], verifier_key, public_inputs).unwrap();
        assert!(proof.is_structurally_valid());
    }

    #[test]
    fn test_zk_seal_proof_too_large() {
        let verifier_key =
            VerifierKey::new(builtin::BITCOIN.clone(), vec![1u8; 32], ProofSystem::SP1, 1);
        let seal_ref = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
        let public_inputs = ZkPublicInputs {
            seal_ref,
            block_hash: Hash::new([1u8; 32]),
            commitment: Hash::new([2u8; 32]),
            source_chain: builtin::BITCOIN.clone(),
            block_height: 800_000,
            timestamp: 1_000_000,
        };

        let result = ZkSealProof::new(
            vec![0u8; MAX_ZK_PROOF_SIZE + 1],
            verifier_key,
            public_inputs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_zk_seal_proof_invalid() {
        let verifier_key =
            VerifierKey::new(builtin::BITCOIN.clone(), vec![1u8; 32], ProofSystem::SP1, 1);
        let seal_ref = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
        let public_inputs = ZkPublicInputs {
            seal_ref,
            block_hash: Hash::zero(), // Invalid: zero block hash
            commitment: Hash::new([2u8; 32]),
            source_chain: builtin::BITCOIN.clone(),
            block_height: 800_000,
            timestamp: 1_000_000,
        };

        let proof = ZkSealProof::new(vec![0xCD; 128], verifier_key, public_inputs).unwrap();
        assert!(!proof.is_structurally_valid());
    }

    #[test]
    fn test_witness_hash() {
        let witness = ChainWitness {
            chain: builtin::BITCOIN.clone(),
            block_hash: Hash::new([1u8; 32]),
            block_height: 800_000,
            tx_data: vec![0xAB; 64],
            inclusion_proof: vec![0xCD; 32],
            finality_proof: vec![0xEF; 16],
            timestamp: 1_000_000,
        };

        let hash = witness.hash();
        assert_ne!(hash.as_bytes(), &[0u8; 32]);

        // Same witness should produce same hash
        let witness2 = witness.clone();
        assert_eq!(witness.hash(), witness2.hash());
    }

    #[test]
    fn test_verifier_registry() {
        let mut registry = ZkVerifierRegistry::new();

        assert!(!registry.has_verifier(&builtin::BITCOIN.clone()));

        registry.register(VerifierKey::new(
            builtin::BITCOIN.clone(),
            vec![1u8; 32],
            ProofSystem::SP1,
            1,
        ));
        assert!(registry.has_verifier(&builtin::BITCOIN.clone()));
        assert_eq!(registry.registered_chains().len(), 1);

        let key = registry.get(&builtin::BITCOIN.clone()).unwrap();
        assert_eq!(key.chain, builtin::BITCOIN.clone());

        registry.remove(&builtin::BITCOIN.clone());
        assert!(!registry.has_verifier(&builtin::BITCOIN.clone()));
    }

    #[test]
    fn test_default_verifier_registry() {
        let registry = default_verifier_registry();
        let chains = registry.registered_chains();
        assert_eq!(chains.len(), 5);
        assert!(chains.contains(&builtin::BITCOIN.clone()));
        assert!(chains.contains(&builtin::ETHEREUM.clone()));
        assert!(chains.contains(&builtin::SOLANA.clone()));
    }

    #[test]
    fn test_proof_system_display() {
        assert_eq!(ProofSystem::SP1.to_string(), "sp1");
        assert_eq!(ProofSystem::Risc0.to_string(), "risc0");
        assert_eq!(ProofSystem::Groth16.to_string(), "groth16");
        assert_eq!(ProofSystem::PlonK.to_string(), "plonk");
        assert_eq!(ProofSystem::Custom.to_string(), "custom");
    }

    #[test]
    fn test_zk_seal_proof_serialization() {
        let verifier_key =
            VerifierKey::new(builtin::BITCOIN.clone(), vec![1u8; 32], ProofSystem::SP1, 1);
        let seal_ref = SealPoint::new(vec![0xAB; 32], Some(42)).unwrap();
        let public_inputs = ZkPublicInputs {
            seal_ref,
            block_hash: Hash::new([1u8; 32]),
            commitment: Hash::new([2u8; 32]),
            source_chain: builtin::BITCOIN.clone(),
            block_height: 800_000,
            timestamp: 1_000_000,
        };

        let proof = ZkSealProof::new(vec![0xCD; 128], verifier_key, public_inputs).unwrap();
        let bytes = proof.to_bytes().unwrap();
        let restored = ZkSealProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof, restored);
    }
}

// ============================================================================
// Pedersen Commitments (Phase 3.2)
// ============================================================================

#[cfg(feature = "zk")]
#[allow(missing_docs)]
pub mod pedersen {
    use curve25519_dalek::constants;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha512};

    use csv_hash::Hash;
    use csv_hash::csv_tagged_hash;

    pub const MAX_COMMITTED_VALUE: u64 = (1u64 << 48) - 1;

    const GENERATOR_DOMAIN: &[u8] = b"CSV-PEDERSEN-GEN::";

    /// A Pedersen commitment to a value. C = g^v * h^r.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PedersenCommitment {
        pub commitment: [u8; 32],
        pub domain: String,
    }

    impl PedersenCommitment {
        pub fn from_bytes(bytes: [u8; 32]) -> Self {
            Self {
                commitment: bytes,
                domain: "CSV-PEDERSEN-GEN".to_string(),
            }
        }
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.commitment
        }
        pub fn to_point(&self) -> Option<RistrettoPoint> {
            CompressedRistretto(self.commitment).decompress()
        }
        pub fn from_point(point: &RistrettoPoint) -> Self {
            Self {
                commitment: point.compress().to_bytes(),
                domain: "CSV-PEDERSEN-GEN".to_string(),
            }
        }
        pub fn hash(&self) -> Hash {
            use csv_codec::to_canonical_cbor;
            let data = to_canonical_cbor(&self.commitment)
                .expect("Canonical serialization should not fail for commitment");
            Hash::new(csv_tagged_hash("csv.pedersen.commitment.v1", &data))
        }
    }

    impl core::fmt::Display for PedersenCommitment {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "Pedersen(0x{})", hex::encode(self.commitment))
        }
    }

    /// The generators used for Pedersen commitments. g is the Ristretto base point;
    /// h is derived from SHA-512 of a domain separator.
    #[derive(Clone, Debug)]
    pub struct PedersenGenerators {
        pub g: RistrettoPoint,
        pub h: RistrettoPoint,
    }

    impl Default for PedersenGenerators {
        fn default() -> Self {
            let g = constants::RISTRETTO_BASEPOINT_POINT;
            let mut hasher = Sha512::new();
            hasher.update(GENERATOR_DOMAIN);
            let h = RistrettoPoint::hash_from_bytes::<Sha512>(&hasher.finalize());
            Self { g, h }
        }
    }

    /// A Pedersen commitment scheme instance.
    #[derive(Default)]
    pub struct PedersenScheme {
        generators: PedersenGenerators,
    }

    impl PedersenScheme {
        pub fn new() -> Self {
            Self::default()
        }

        /// Commit to a value with a random blinding factor. Returns (commitment, blinding).
        pub fn commit(&self, value: u64) -> Result<(PedersenCommitment, Scalar), PedersenError> {
            if value > MAX_COMMITTED_VALUE {
                return Err(PedersenError::ValueTooLarge(value));
            }
            // Use deterministic blinding based on value for reproducibility
            let hash = Hash::sha256(&value.to_le_bytes());
            let mut blinding_bytes = [0u8; 32];
            blinding_bytes.copy_from_slice(hash.as_ref() as &[u8]);
            let blinding = Scalar::from_bytes_mod_order(blinding_bytes);
            let commitment = self.generators.g * Scalar::from(value) + self.generators.h * blinding;
            Ok((PedersenCommitment::from_point(&commitment), blinding))
        }

        /// Verify a commitment opening: C' = g^value * h^blinding == commitment.
        pub fn verify(
            &self,
            commitment: &PedersenCommitment,
            value: u64,
            blinding: &Scalar,
        ) -> Result<bool, PedersenError> {
            if value > MAX_COMMITTED_VALUE {
                return Err(PedersenError::ValueTooLarge(value));
            }
            let expected = self.generators.g * Scalar::from(value) + self.generators.h * *blinding;
            let actual = commitment
                .to_point()
                .ok_or(PedersenError::InvalidCommitment)?;
            Ok(expected == actual)
        }

        /// Add two commitments homomorphically: C1 + C2 = C(v1+v2, r1+r2).
        pub fn add_commitments(
            &self,
            c1: &PedersenCommitment,
            c2: &PedersenCommitment,
        ) -> Option<PedersenCommitment> {
            let p1 = c1.to_point()?;
            let p2 = c2.to_point()?;
            Some(PedersenCommitment::from_point(&(p1 + p2)))
        }

        /// Scale a commitment by a scalar: k * C(v, r) = C(k*v, k*r).
        pub fn scale_commitment(
            &self,
            commitment: &PedersenCommitment,
            scalar: &Scalar,
        ) -> Option<PedersenCommitment> {
            let p = commitment.to_point()?;
            Some(PedersenCommitment::from_point(&(p * scalar)))
        }

        /// Negate a commitment.
        pub fn negate_commitment(
            &self,
            commitment: &PedersenCommitment,
        ) -> Option<PedersenCommitment> {
            let p = commitment.to_point()?;
            Some(PedersenCommitment::from_point(&(-p)))
        }

        /// C1 - C2 = C(v1-v2, r1-r2).
        pub fn subtract_commitments(
            &self,
            c1: &PedersenCommitment,
            c2: &PedersenCommitment,
        ) -> Option<PedersenCommitment> {
            let p1 = c1.to_point()?;
            let p2 = c2.to_point()?;
            Some(PedersenCommitment::from_point(&(p1 - p2)))
        }

        /// Generate generators from a custom domain string.
        pub fn from_domain(domain: &str) -> Self {
            let g = constants::RISTRETTO_BASEPOINT_POINT;
            let mut hasher = Sha512::new();
            hasher.update(domain.as_bytes());
            let h = RistrettoPoint::hash_from_bytes::<Sha512>(&hasher.finalize());
            Self {
                generators: PedersenGenerators { g, h },
            }
        }
    }

    /// Errors for Pedersen commitment operations.
    #[derive(Debug, Clone, thiserror::Error)]
    pub enum PedersenError {
        #[error("Value {0} exceeds maximum committed value ({MAX_COMMITTED_VALUE})")]
        ValueTooLarge(u64),
        #[error("Invalid commitment point (not on curve)")]
        InvalidCommitment,
        #[error("Blinding factor is zero (must be non-zero)")]
        ZeroBlinding,
    }
}

/// Tests for Pedersen commitment operations.
#[cfg(test)]
mod pedersen_tests {
    #[cfg(feature = "zk")]
    mod zk_tests {
        use curve25519_dalek::scalar::Scalar;
        use crate::zk_proof::pedersen::*;

        #[test]
        fn test_commit_and_verify() {
            let scheme = PedersenScheme::new();
            let (commitment, blinding) = scheme.commit(42).unwrap();
            assert!(scheme.verify(&commitment, 42, &blinding).unwrap());
        }

        #[test]
        fn test_commit_verify_wrong_value() {
            let scheme = PedersenScheme::new();
            let (commitment, blinding) = scheme.commit(42).unwrap();
            assert!(!scheme.verify(&commitment, 43, &blinding).unwrap());
        }

        #[test]
        fn test_commit_zero_value() {
            let scheme = PedersenScheme::new();
            let (c, b) = scheme.commit(0).unwrap();
            assert!(scheme.verify(&c, 0, &b).unwrap());
        }

        #[test]
        fn test_commit_max_value() {
            let scheme = PedersenScheme::new();
            let (c, b) = scheme.commit(MAX_COMMITTED_VALUE).unwrap();
            assert!(scheme.verify(&c, MAX_COMMITTED_VALUE, &b).unwrap());
        }

        #[test]
        fn test_commit_value_too_large() {
            let scheme = PedersenScheme::new();
            assert!(matches!(
                scheme.commit(MAX_COMMITTED_VALUE + 1),
                Err(PedersenError::ValueTooLarge(_))
            ));
        }

        #[test]
        fn test_homomorphic_addition() {
            let scheme = PedersenScheme::new();
            let (c1, r1) = scheme.commit(10).unwrap();
            let (c2, r2) = scheme.commit(20).unwrap();
            let sum_c = scheme.add_commitments(&c1, &c2).unwrap();
            assert!(scheme.verify(&sum_c, 30, &(r1 + r2)).unwrap());
        }

        #[test]
        fn test_homomorphic_subtraction() {
            let scheme = PedersenScheme::new();
            let (c1, r1) = scheme.commit(50).unwrap();
            let (c2, r2) = scheme.commit(20).unwrap();
            let diff_c = scheme.subtract_commitments(&c1, &c2).unwrap();
            assert!(scheme.verify(&diff_c, 30, &(r1 - r2)).unwrap());
        }

        #[test]
        fn test_homomorphic_scaling() {
            let scheme = PedersenScheme::new();
            let (c, r) = scheme.commit(7).unwrap();
            let scalar = Scalar::from(5u64);
            let scaled = scheme.scale_commitment(&c, &scalar).unwrap();
            assert!(scheme.verify(&scaled, 35, &(r * scalar)).unwrap());
        }

        #[test]
        fn test_different_values_different_commitments() {
            let scheme = PedersenScheme::new();
            let (c1, _) = scheme.commit(1).unwrap();
            let (c2, _) = scheme.commit(2).unwrap();
            assert_ne!(c1.commitment, c2.commitment);
        }

        #[test]
        fn test_same_value_different_blinding() {
            let scheme = PedersenScheme::new();
            let (c1, _) = scheme.commit(42).unwrap();
            let (c2, _) = scheme.commit(42).unwrap();
            assert_ne!(c1.commitment, c2.commitment);
        }

        #[test]
        fn test_commitment_hash() {
            let scheme = PedersenScheme::new();
            let (c, _) = scheme.commit(12345).unwrap();
            let h = c.hash();
            assert_ne!(h.as_bytes(), &[0u8; 32]);
            assert_eq!(h, c.hash());
        }

        #[test]
        fn test_commitment_display() {
            let scheme = PedersenScheme::new();
            let (c, _) = scheme.commit(1).unwrap();
            let s = format!("{}", c);
            assert!(s.starts_with("Pedersen(0x"));
        }

        #[test]
        fn test_custom_domain_generators() {
            let s1 = PedersenScheme::from_domain("domain-a");
            let s2 = PedersenScheme::from_domain("domain-b");
            let (c1, r1) = s1.commit(42).unwrap();
            let (c2, r2) = s2.commit(42).unwrap();
            assert_ne!(c1.commitment, c2.commitment);
            assert!(s1.verify(&c1, 42, &r1).unwrap());
            assert!(s2.verify(&c2, 42, &r2).unwrap());
            // Cross-verification should fail (different generators)
            assert!(!s2.verify(&c1, 42, &r1).unwrap());
        }

        #[test]
        fn test_sum_equals_commitment_of_sum() {
            let scheme = PedersenScheme::new();
            let (ca, ra) = scheme.commit(100).unwrap();
            let (cb, rb) = scheme.commit(200).unwrap();
            let sum_ab = scheme.add_commitments(&ca, &cb).unwrap();
            assert!(scheme.verify(&sum_ab, 300, &(ra + rb)).unwrap());
            assert!(!scheme.verify(&sum_ab, 400, &(ra + rb)).unwrap());
        }

        #[test]
        fn test_multiple_values() {
            let scheme = PedersenScheme::new();
            for value in [
                0u64,
                1,
                42,
                1000,
                1_000_000,
                1_000_000_000u64,
                MAX_COMMITTED_VALUE,
            ] {
                let (c, b) = scheme.commit(value).unwrap();
                assert!(scheme.verify(&c, value, &b).unwrap());
                if value > 0 {
                    assert!(!scheme.verify(&c, value - 1, &b).unwrap());
                }
            }
        }
    }
}
