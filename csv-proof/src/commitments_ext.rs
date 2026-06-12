//! Advanced commitment types and proof metadata for the CSV protocol.
//!
//! This module extends the basic commitment and proof types to support:
//! - Multiple commitment scheme versions (V2, V3, hash-based, KZG, etc.)
//! - Advanced proof metadata (inclusion proof types, finality proof types)
//! - Extensible commitment scheme registry
//!
//! **Note:** ZK-proof verification is NOT implemented yet.
//! This module provides type infrastructure for indexing and querying.

use csv_codec::{CanonicalEncoding, EncodingFormat};
use csv_hash::Hash;
use std::str::FromStr;

// L0/L1 types (proof data) must NOT use serde - use canonical_cbor instead
// L2 types (metadata) MAY use serde for configuration/indexing

// ---------------------------------------------------------------------------
// Commitment Scheme Types
// ---------------------------------------------------------------------------

/// Commitment scheme type - identifies the cryptographic construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommitmentScheme {
    /// Simple hash-based commitment (SHA-256)
    #[default]
    HashBased,
    /// Pedersen commitment (hiding, binding)
    Pedersen,
    /// KZG polynomial commitment (used in PLONK, Ethereum)
    KZG,
    /// Inner product argument (Bulletproofs)
    Bulletproofs,
    /// Multilinear polynomial commitment (Hyrax, Spartan)
    Multilinear,
    /// FRI-based commitment (STARKs)
    FRI,
    /// Custom/extensible scheme
    Custom,
}

impl core::fmt::Display for CommitmentScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CommitmentScheme::HashBased => write!(f, "hash_based"),
            CommitmentScheme::Pedersen => write!(f, "pedersen"),
            CommitmentScheme::KZG => write!(f, "kzg"),
            CommitmentScheme::Bulletproofs => write!(f, "bulletproofs"),
            CommitmentScheme::Multilinear => write!(f, "multilinear"),
            CommitmentScheme::FRI => write!(f, "fri"),
            CommitmentScheme::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for CommitmentScheme {
    type Err = ();

    /// Parse from string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hash_based" => Ok(CommitmentScheme::HashBased),
            "pedersen" => Ok(CommitmentScheme::Pedersen),
            "kzg" => Ok(CommitmentScheme::KZG),
            "bulletproofs" => Ok(CommitmentScheme::Bulletproofs),
            "multilinear" => Ok(CommitmentScheme::Multilinear),
            "fri" => Ok(CommitmentScheme::FRI),
            "custom" => Ok(CommitmentScheme::Custom),
            _ => Err(()),
        }
    }
}

impl CommitmentScheme {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            CommitmentScheme::HashBased => "hash_based",
            CommitmentScheme::Pedersen => "pedersen",
            CommitmentScheme::KZG => "kzg",
            CommitmentScheme::Bulletproofs => "bulletproofs",
            CommitmentScheme::Multilinear => "multilinear",
            CommitmentScheme::FRI => "fri",
            CommitmentScheme::Custom => "custom",
        }
    }
}

// ---------------------------------------------------------------------------
// Inclusion Proof Types
// ---------------------------------------------------------------------------

/// Type of inclusion proof used to anchor commitment on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InclusionProofType {
    /// Bitcoin-style: Merkle proof (double-SHA256)
    #[default]
    Merkle,
    /// Ethereum-style: Merkle-Patricia Trie proof
    MerklePatricia,
    /// Sui-style: Object proof with checkpoint signature
    ObjectProof,
    /// Aptos-style: Accumulator proof
    Accumulator,
    /// Solana-style: Account state proof
    AccountState,
    /// Custom proof type
    Custom,
}

impl core::fmt::Display for InclusionProofType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InclusionProofType::Merkle => write!(f, "merkle"),
            InclusionProofType::MerklePatricia => write!(f, "merkle_patricia"),
            InclusionProofType::ObjectProof => write!(f, "object_proof"),
            InclusionProofType::Accumulator => write!(f, "accumulator"),
            InclusionProofType::AccountState => write!(f, "account_state"),
            InclusionProofType::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for InclusionProofType {
    type Err = ();

    /// Parse from string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "merkle" => Ok(InclusionProofType::Merkle),
            "merkle_patricia" => Ok(InclusionProofType::MerklePatricia),
            "object_proof" => Ok(InclusionProofType::ObjectProof),
            "accumulator" => Ok(InclusionProofType::Accumulator),
            "account_state" => Ok(InclusionProofType::AccountState),
            "custom" => Ok(InclusionProofType::Custom),
            _ => Err(()),
        }
    }
}

impl InclusionProofType {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            InclusionProofType::Merkle => "merkle",
            InclusionProofType::MerklePatricia => "merkle_patricia",
            InclusionProofType::ObjectProof => "object_proof",
            InclusionProofType::Accumulator => "accumulator",
            InclusionProofType::AccountState => "account_state",
            InclusionProofType::Custom => "custom",
        }
    }
}

// ---------------------------------------------------------------------------
// Finality Proof Types
// ---------------------------------------------------------------------------

/// Type of finality proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FinalityProofType {
    /// Confirmation depth (probabilistic)
    #[default]
    ConfirmationDepth,
    /// Checkpoint finality (deterministic, 2f+1)
    Checkpoint,
    /// Finalized block (Ethereum post-merge)
    FinalizedBlock,
    /// Slot-based (Solana)
    SlotBased,
    /// Custom finality proof
    Custom,
}

impl core::fmt::Display for FinalityProofType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FinalityProofType::ConfirmationDepth => write!(f, "confirmation_depth"),
            FinalityProofType::Checkpoint => write!(f, "checkpoint"),
            FinalityProofType::FinalizedBlock => write!(f, "finalized_block"),
            FinalityProofType::SlotBased => write!(f, "slot_based"),
            FinalityProofType::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for FinalityProofType {
    type Err = ();

    /// Parse from string
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "confirmation_depth" => Ok(FinalityProofType::ConfirmationDepth),
            "checkpoint" => Ok(FinalityProofType::Checkpoint),
            "finalized_block" => Ok(FinalityProofType::FinalizedBlock),
            "slot_based" => Ok(FinalityProofType::SlotBased),
            "custom" => Ok(FinalityProofType::Custom),
            _ => Err(()),
        }
    }
}

impl FinalityProofType {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            FinalityProofType::ConfirmationDepth => "confirmation_depth",
            FinalityProofType::Checkpoint => "checkpoint",
            FinalityProofType::FinalizedBlock => "finalized_block",
            FinalityProofType::SlotBased => "slot_based",
            FinalityProofType::Custom => "custom",
        }
    }
}

// ---------------------------------------------------------------------------
// Proof Metadata
// ---------------------------------------------------------------------------

/// Metadata associated with a proof.
/// L2 type: metadata - MAY use serde for configuration/indexing
#[derive(Debug, Clone, Default)]
pub struct ProofMetadata {
    /// Inclusion proof type
    pub inclusion_proof_type: Option<InclusionProofType>,
    /// Finality proof type
    pub finality_proof_type: Option<FinalityProofType>,
    /// Commitment scheme used
    pub commitment_scheme: Option<CommitmentScheme>,
    /// Proof size in bytes
    pub proof_size_bytes: Option<u64>,
    /// Number of confirmations
    pub confirmations: Option<u64>,
    /// Additional metadata (chain-specific)
    pub extra: Vec<u8>,
}

impl CanonicalEncoding for ProofMetadata {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => self.to_canonical_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e)),
        }
    }
    
    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self> where Self: Sized {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Err(csv_codec::CodecError::DeserializationError("ProofMetadata deserialization not yet implemented".to_string())),
        }
    }
}

impl ProofMetadata {
    /// Encode using MCE format (fixed-width byte concatenation)
    fn encode_mce(&self) -> csv_codec::CodecResult<Vec<u8>> {
        // MCE format for ProofMetadata - same as manual binary for now
        self.to_canonical_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e.to_string()))
    }
    
    /// Decode using MCE format
    fn decode_mce(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        // MCE format for ProofMetadata - same as manual binary for now
        Err(csv_codec::CodecError::DeserializationError("ProofMetadata deserialization not yet implemented".to_string()))
    }

    /// Serialize to canonical bytes (manual implementation for L2 type)
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        
        match self.inclusion_proof_type {
            Some(t) => {
                bytes.push(1u8);
                bytes.push(t as u8);
            }
            None => bytes.push(0u8),
        }
        
        match self.finality_proof_type {
            Some(t) => {
                bytes.push(1u8);
                bytes.push(t as u8);
            }
            None => bytes.push(0u8),
        }
        
        match self.commitment_scheme {
            Some(s) => {
                bytes.push(1u8);
                bytes.push(s as u8);
            }
            None => bytes.push(0u8),
        }
        
        match self.proof_size_bytes {
            Some(size) => {
                bytes.push(1u8);
                bytes.extend_from_slice(&size.to_le_bytes());
            }
            None => bytes.push(0u8),
        }
        
        match self.confirmations {
            Some(conf) => {
                bytes.push(1u8);
                bytes.extend_from_slice(&conf.to_le_bytes());
            }
            None => bytes.push(0u8),
        }
        
        bytes.extend_from_slice(&(self.extra.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.extra);
        
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Enhanced Commitment Structure
// ---------------------------------------------------------------------------

/// Enhanced commitment with scheme and metadata tracking.
/// L1 type: proof data - uses canonical_cbor for serialization
#[derive(Debug, Clone)]
pub struct EnhancedCommitment {
    // Basic fields (same as core Commitment)
    /// Protocol version.
    pub version: u8,
    /// Unique protocol identifier.
    pub protocol_id: [u8; 32],
    /// Merkle root of the MPC tree.
    pub mpc_root: [u8; 32],
    /// Unique contract identifier.
    pub contract_id: [u8; 32],
    /// Hash of the previous commitment.
    pub previous_commitment: [u8; 32],
    /// Hash of the transition payload.
    pub transition_payload_hash: [u8; 32],
    /// Unique seal identifier.
    pub seal_id: [u8; 32],
    /// Domain separator for disambiguation.
    pub domain_separator: [u8; 32],

    // Advanced fields
    /// Commitment scheme used
    pub commitment_scheme: CommitmentScheme,
    /// Inclusion proof type
    pub inclusion_proof_type: InclusionProofType,
    /// Finality proof type
    pub finality_proof_type: FinalityProofType,
    /// Proof metadata
    pub proof_metadata: ProofMetadata,
}

impl CanonicalEncoding for EnhancedCommitment {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => self.to_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e.to_string())),
        }
    }
    
    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self> where Self: Sized {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::from_bytes(bytes).map_err(|e| csv_codec::CodecError::DeserializationError(e.to_string())),
        }
    }
}

impl EnhancedCommitment {
    /// Encode using MCE format (fixed-width byte concatenation)
    fn encode_mce(&self) -> csv_codec::CodecResult<Vec<u8>> {
        // MCE format for EnhancedCommitment - same as manual binary for now
        self.to_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e.to_string()))
    }
    
    /// Decode using MCE format
    fn decode_mce(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        // MCE format for EnhancedCommitment - same as manual binary for now
        Self::from_bytes(bytes).map_err(|e| csv_codec::CodecError::DeserializationError(e.to_string()))
    }

    /// Create a new enhanced commitment with default metadata
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8,
        protocol_id: [u8; 32],
        mpc_root: [u8; 32],
        contract_id: [u8; 32],
        previous_commitment: [u8; 32],
        transition_payload_hash: [u8; 32],
        seal_id: [u8; 32],
        domain_separator: [u8; 32],
        commitment_scheme: CommitmentScheme,
        inclusion_proof_type: InclusionProofType,
        finality_proof_type: FinalityProofType,
    ) -> Self {
        Self {
            version,
            protocol_id,
            mpc_root,
            contract_id,
            previous_commitment,
            transition_payload_hash,
            seal_id,
            domain_separator,
            commitment_scheme,
            inclusion_proof_type,
            finality_proof_type,
            proof_metadata: ProofMetadata {
                inclusion_proof_type: Some(inclusion_proof_type),
                finality_proof_type: Some(finality_proof_type),
                commitment_scheme: Some(commitment_scheme),
                proof_size_bytes: None,
                confirmations: None,
                extra: Vec::new(),
            },
        }
    }

    /// Compute the commitment hash using the configured scheme
    pub fn compute_hash(&self) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Domain separator for commitment hashing
        hasher.update(self.domain_separator);
        hasher.update([self.version]);
        hasher.update(self.protocol_id);
        hasher.update(self.mpc_root);
        hasher.update(self.contract_id);
        hasher.update(self.previous_commitment);
        hasher.update(self.transition_payload_hash);
        hasher.update(self.seal_id);

        Hash::new(hasher.finalize().into())
    }

    /// Verify the commitment scheme is supported
    pub fn is_scheme_supported(&self) -> bool {
        matches!(
            self.commitment_scheme,
            CommitmentScheme::HashBased
                | CommitmentScheme::Pedersen
                | CommitmentScheme::KZG
                | CommitmentScheme::Bulletproofs
        )
    }

    /// Check if the inclusion proof type is valid for the given chain
    pub fn is_proof_type_valid_for_chain(&self, chain: &str) -> bool {
        match self.inclusion_proof_type {
            InclusionProofType::Merkle => matches!(chain, "bitcoin"),
            InclusionProofType::MerklePatricia => matches!(chain, "ethereum"),
            InclusionProofType::ObjectProof => matches!(chain, "sui"),
            InclusionProofType::Accumulator => matches!(chain, "aptos"),
            InclusionProofType::AccountState => matches!(chain, "solana"),
            InclusionProofType::Custom => true,
        }
    }

    /// Set proof metadata with computed values
    pub fn with_proof_metadata(mut self, proof_size_bytes: u64, confirmations: u64) -> Self {
        self.proof_metadata.proof_size_bytes = Some(proof_size_bytes);
        self.proof_metadata.confirmations = Some(confirmations);
        self
    }

    /// Serialize the enhanced commitment to canonical bytes
    ///
    /// Uses manual canonical serialization to avoid serde dependency.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(&self.protocol_id);
        bytes.extend_from_slice(&self.mpc_root);
        bytes.extend_from_slice(&self.contract_id);
        bytes.extend_from_slice(&self.previous_commitment);
        bytes.extend_from_slice(&self.transition_payload_hash);
        bytes.extend_from_slice(&self.seal_id);
        bytes.extend_from_slice(&self.domain_separator);
        bytes.push(self.commitment_scheme as u8);
        bytes.push(self.inclusion_proof_type as u8);
        bytes.push(self.finality_proof_type as u8);
        
        // Serialize proof_metadata
        let metadata_bytes = self.proof_metadata.to_canonical_bytes()?;
        bytes.extend_from_slice(&(metadata_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&metadata_bytes);
        
        Ok(bytes)
    }

    /// Deserialize an enhanced commitment from canonical bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Err("EnhancedCommitment deserialization not yet implemented".into())
    }
}

/// Pedersen commitment implementation
///
/// Uses a generator point G for hiding and a second generator H for binding.
/// Commitment: C = r*G + v*H where r is the random blinding factor and v is the value.
#[derive(Debug, Clone)]
pub struct PedersenCommitment {
    /// The commitment value C = r*G + v*H
    pub commitment: Vec<u8>,
    /// The blinding factor r (kept secret)
    pub blinding_factor: Vec<u8>,
    /// The committed value
    pub value: u64,
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment
    ///
    /// # Arguments
    /// * `value` - The value to commit to
    /// * `blinding_factor` - The random blinding factor (32 bytes recommended)
    pub fn new(value: u64, blinding_factor: &[u8]) -> Self {
        // Use domain-separated hashing for the commitment to prevent
        // cross-protocol binding attacks.
        // Real Pedersen commitments would use elliptic curve: C = r*G + v*H
        // This hash-based approach is a domain-separated approximation that
        // provides binding but not the hiding property of Pedersen commitments.
        use csv_codec::to_canonical_cbor;
        use csv_hash::csv_tagged_hash;
        let payload = to_canonical_cbor(&(blinding_factor, value)).unwrap_or_else(|err| {
            format!("pedersen-commitment-serialization-error:{err}").into_bytes()
        });
        let hash = csv_tagged_hash("urn:lnp-bp:csv:pedersen-commitment:v1", &payload);

        Self {
            commitment: hash.to_vec(),
            blinding_factor: blinding_factor.to_vec(),
            value,
        }
    }

    /// Verify a Pedersen commitment
    ///
    /// Recomputes the commitment and checks it matches
    pub fn verify(&self) -> bool {
        use csv_codec::to_canonical_cbor;
        use csv_hash::csv_tagged_hash;
        let payload = to_canonical_cbor(&(self.blinding_factor.clone(), self.value))
            .unwrap_or_else(|err| {
                format!("pedersen-commitment-serialization-error:{err}").into_bytes()
            });
        let computed = csv_tagged_hash("urn:lnp-bp:csv:pedersen-commitment:v1", &payload);
        computed.as_slice() == self.commitment.as_slice()
    }

    /// Add two Pedersen commitments (homomorphic property)
    ///
    /// C1 + C2 = (r1 + r2)*G + (v1 + v2)*H
    ///
    /// # Note
    /// This is a simulated homomorphic addition using hash concatenation.
    /// A real Pedersen commitment would use elliptic curve point addition,
    /// which requires the `curve25519-dalek` or `ark-ec` crate.
    /// This hash-based approximation preserves the binding property but
    /// loses the homomorphic property. For true Pedersen commitments,
    /// enable the `zk` feature and use `zk_proof::pedersen` instead.
    pub fn add(&self, other: &PedersenCommitment) -> PedersenCommitment {
        use csv_codec::to_canonical_cbor;
        use csv_hash::csv_tagged_hash;
        let blinding_payload =
            to_canonical_cbor(&(self.blinding_factor.clone(), other.blinding_factor.clone()))
                .unwrap_or_else(|err| {
                    format!("pedersen-blinding-serialization-error:{err}").into_bytes()
                });
        let combined_blinding =
            csv_tagged_hash("urn:lnp-bp:csv:pedersen-add-blinding:v1", &blinding_payload);

        let commitment_payload =
            to_canonical_cbor(&(self.commitment.as_slice(), other.commitment.as_slice()))
                .unwrap_or_else(|err| {
                    format!("pedersen-add-serialization-error:{err}").into_bytes()
                });
        let combined_commitment = csv_tagged_hash(
            "urn:lnp-bp:csv:pedersen-add-commitment:v1",
            &commitment_payload,
        );

        PedersenCommitment {
            commitment: combined_commitment.to_vec(),
            blinding_factor: combined_blinding.to_vec(),
            value: self.value + other.value,
        }
    }
}

/// KZG polynomial commitment stub
///
/// KZG commitments are used in PLONK and other SNARK systems.
/// A commitment to a polynomial f(x) is [f(s)]_1 where s is a secret trapdoor.
#[derive(Debug, Clone)]
pub struct KZGCommitment {
    /// The commitment point [f(s)]_1 in G1
    pub commitment: Vec<u8>,
    /// The polynomial degree
    pub degree: usize,
    /// The number of points committed
    pub num_points: usize,
}

impl KZGCommitment {
    /// Create a new KZG commitment (stub - real impl requires elliptic curve crate)
    pub fn new(degree: usize, num_points: usize) -> Self {
        Self {
            commitment: Vec::new(),
            degree,
            num_points,
        }
    }

    /// Verify a KZG proof
    ///
    /// In a real implementation, this would use pairing-based verification:
    /// e([f(s)]_1, [1]_2) == e([witness]_1, [s - alpha]_2)
    pub fn verify(&self, _proof: &[u8], _public_inputs: &[u8]) -> bool {
        // Stub: real implementation requires elliptic curve pairing crate
        !self.commitment.is_empty()
    }
}

/// Bulletproofs inner product argument stub
///
/// Bulletproofs provide short range proofs without trusted setup.
/// The inner product argument proves that <a, b> = p given commitments to a and b.
#[derive(Debug, Clone)]
pub struct BulletproofCommitment {
    /// Commitment to vector a: G_a = commit(a, r_a)
    pub commitment_a: Vec<u8>,
    /// Commitment to vector b: G_b = commit(b, r_b)
    pub commitment_b: Vec<u8>,
    /// The inner product value p = <a, b>
    pub inner_product: u64,
    /// Number of bits in the proof
    pub bits: usize,
}

impl BulletproofCommitment {
    /// Create a new Bulletproof commitment (stub)
    pub fn new(bits: usize, inner_product: u64) -> Self {
        Self {
            commitment_a: Vec::new(),
            commitment_b: Vec::new(),
            inner_product,
            bits,
        }
    }

    /// Verify a Bulletproof
    ///
    /// In a real implementation, this would verify the inner product proof
    /// using the commitment generators and the proof transcript.
    pub fn verify(&self, _proof_data: &[u8]) -> bool {
        // Stub: real implementation requires elliptic curve crate
        !self.commitment_a.is_empty() && !self.commitment_b.is_empty()
    }
}
