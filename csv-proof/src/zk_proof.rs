//! Adapter-facing zero-knowledge seal proof types.
//!
//! Backends construct these typed proof envelopes; canonical verification remains
//! the responsibility of `csv-verifier`.
#![allow(missing_docs)]

use csv_hash::Hash;
use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

// L0/L1 types (proof data) must NOT use serde - use canonical_cbor instead
// L2 types (metadata) MAY use serde for configuration/indexing

/// Maximum encoded ZK proof size accepted by the protocol.
pub const MAX_ZK_PROOF_SIZE: usize = 1024 * 1024;

/// Supported zero-knowledge proof systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSystem {
    SP1,
    Risc0,
    Groth16,
    PlonK,
    Custom,
}

impl core::fmt::Display for ProofSystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SP1 => write!(f, "sp1"),
            Self::Risc0 => write!(f, "risc0"),
            Self::Groth16 => write!(f, "groth16"),
            Self::PlonK => write!(f, "plonk"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Verification key identifying the proof backend and source chain.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKey {
    pub chain: csv_hash::chain_id::ChainId,
    pub key_bytes: Vec<u8>,
    pub proof_system: ProofSystem,
    pub version: u32,
    pub active: bool,
}

impl VerifierKey {
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
}

/// Public outputs bound by a zero-knowledge seal proof.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPublicInputs {
    pub seal_ref: SealPoint,
    pub block_hash: Hash,
    pub commitment: Hash,
    pub source_chain: csv_hash::chain_id::ChainId,
    pub block_height: u64,
    pub timestamp: u64,
}

/// Complete proof envelope submitted by an adapter.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkSealProof {
    pub proof_bytes: Vec<u8>,
    pub verifier_key: VerifierKey,
    pub public_inputs: ZkPublicInputs,
}

impl ZkSealProof {
    pub fn new(
        proof_bytes: Vec<u8>,
        verifier_key: VerifierKey,
        public_inputs: ZkPublicInputs,
    ) -> Result<Self, ZkError> {
        if proof_bytes.is_empty() {
            return Err(ZkError::InvalidProof("Proof bytes are empty".to_string()));
        }
        if proof_bytes.len() > MAX_ZK_PROOF_SIZE {
            return Err(ZkError::ProofTooLarge(proof_bytes.len()));
        }
        Ok(Self {
            proof_bytes,
            verifier_key,
            public_inputs,
        })
    }
}

/// Chain witness supplied to a zero-knowledge prover.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainWitness {
    pub chain: csv_hash::chain_id::ChainId,
    pub block_hash: Hash,
    pub block_height: u64,
    pub tx_data: Vec<u8>,
    pub inclusion_proof: Vec<u8>,
    pub finality_proof: Vec<u8>,
    pub timestamp: u64,
}

/// Port implemented by adapter proof generators.
pub trait ZkProver {
    fn prove_seal_consumption(
        &self,
        seal: &SealPoint,
        witness: &ChainWitness,
    ) -> Result<ZkSealProof, ZkError>;

    fn proof_system(&self) -> ProofSystem;
}

/// Failures in proof construction or envelope validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ZkError {
    #[error("Invalid proof bytes: {0}")]
    InvalidProof(String),
    #[error("Verifier key not found for chain: {0}")]
    VerifierNotFound(csv_hash::chain_id::ChainId),
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),
    #[error("Unsupported proof system: {0}")]
    UnsupportedSystem(String),
    #[error("Proof size exceeds maximum: {0} bytes")]
    ProofTooLarge(usize),
    #[error("Backend error: {0}")]
    BackendError(String),
}
