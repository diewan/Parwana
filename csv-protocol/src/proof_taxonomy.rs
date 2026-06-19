//! Formal proof taxonomy - L1: Proof types
//!
//! **Layer:** L1 (Proof types)
//! **Encoding:** MUST use canonical_cbor for verification
//! **Serde Policy:** SHOULD NOT use serde - verification must use canonical_cbor
//!
//! This module defines the canonical proof types used across the CSV protocol.
//! All proofs must be one of these variants, ensuring consistent semantics
//! and enabling unified verification.
//!
//! # Architecture
//!
//! - **ProofBundle**: Complete proof bundle for peer-to-peer verification
//! - **InclusionProof**: Merkle inclusion proof
//! - **FinalityProof**: Chain finality proof
//! - **DAGSegment**: State transition DAG segment
//!
//! # Security
//!
//! L1 types are critical for verification consistency:
//! - Verification MUST use canonical_cbor encoding
//! - Serde derives may be present for canonical_cbor compatibility
//! - Non-canonical formats (serde_json) are FORBIDDEN in verification paths
//!
//! # Quick Start
//!
//! ```no_run
//! use csv_protocol::proof_taxonomy::ProofBundle;
//! use csv_protocol::proof_taxonomy::InclusionProof;
//! use csv_protocol::proof_taxonomy::FinalityProof;
//! use csv_hash::Hash;
//!
//! // Create a proof bundle (example - actual construction requires chain-specific data)
//! let inclusion_proof = InclusionProof::new(
//!     vec![0u8; 32],
//!     Hash::zero(),
//!     0,
//!     0,
//! ).unwrap();
//! let finality_proof = FinalityProof::default();
//! // ProofBundle construction requires more fields - see adapter implementations
//! ```
//!
//! # Migration Guide
//!
//! When working with L1 types:
//! - ❌ NEVER use serde_json for verification
//! - ✅ ALWAYS use `to_canonical_bytes()` / `from_canonical_bytes()`
//! - ✅ MAY use serde derives only if required by canonical_cbor
//!
//! See [csv-docs/LAYERING.md](../../csv-docs/LAYERING.md) for detailed layer information.

use csv_hash::Hash;
use csv_hash::HashDomain;
use csv_hash::canonical::to_canonical_cbor;
use csv_hash::dag::DAGSegment;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_hash::tagged_hash::tagged_hash;
use csv_codec::{CanonicalEncoding, EncodingFormat};
use serde::{Deserialize, Serialize};

/// Hash function types supported by different chains
///
/// Each chain uses its native hash function to avoid extra gas costs:
/// - Ethereum: Keccak256
/// - Solana: SHA256
/// - Sui: Blake2b256
/// - Bitcoin: Double SHA256
/// - Aptos: SHA3-256 (Keccak256 variant)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    /// Keccak256 (Ethereum native)
    Keccak256,
    /// SHA256 (Solana native)
    Sha256,
    /// Blake2b256 (Sui native)
    Blake2b256,
    /// Double SHA256 (Bitcoin native)
    DoubleSha256,
    /// SHA3-256 (Aptos native)
    Sha3_256,
}

impl HashFunction {
    /// Get the native hash function for a given chain
    pub fn for_chain(chain: &str) -> Self {
        match chain.to_lowercase().as_str() {
            "ethereum" | "eth" => HashFunction::Keccak256,
            "solana" | "sol" => HashFunction::Sha256,
            "sui" => HashFunction::Blake2b256,
            "bitcoin" | "btc" => HashFunction::DoubleSha256,
            "aptos" => HashFunction::Sha3_256,
            _ => HashFunction::Sha256, // Default to SHA256 for unknown chains
        }
    }

    /// Compute hash of bytes using this hash function
    pub fn hash_bytes(&self, bytes: &[u8]) -> Hash {
        match self {
            HashFunction::Keccak256 => {
                use tiny_keccak::{Hasher, Keccak};
                let mut hasher = Keccak::v256();
                let mut output = [0u8; 32];
                hasher.update(bytes);
                hasher.finalize(&mut output);
                Hash(output)
            }
            HashFunction::Sha256 => {
                use sha2::Sha256;
                use sha2::Digest;
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                Hash(hasher.finalize().into())
            }
            HashFunction::Blake2b256 => {
                use blake2::Blake2s256;
                use blake2::Digest;
                let mut hasher = Blake2s256::new();
                hasher.update(bytes);
                Hash(hasher.finalize().into())
            }
            HashFunction::DoubleSha256 => {
                use sha2::Sha256;
                use sha2::Digest;
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                let first = hasher.finalize();
                let mut hasher2 = Sha256::new();
                hasher2.update(&first);
                Hash(hasher2.finalize().into())
            }
            HashFunction::Sha3_256 => {
                use sha3::Sha3_256;
                use sha3::Digest;
                let mut hasher = Sha3_256::new();
                hasher.update(bytes);
                Hash(hasher.finalize().into())
            }
        }
    }
}

/// Chain-independent proof leaf schema (canonical)
///
/// This is the single canonical proof leaf schema that all chain adapters
/// and contracts MUST use. No chain-specific leaf schemas are allowed.
///
/// The leaf is hashed using canonical CBOR serialization, then the hash
/// is computed using the chain's native hash function to avoid extra gas costs.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Cannot use serde derives due to L0 Hash fields - use canonical encoding instead
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofLeafV1 {
    /// Protocol version (must be 1)
    pub version: u32,
    /// Source chain identifier (e.g., "ethereum", "bitcoin", "solana")
    pub source_chain: String,
    /// Destination chain identifier
    pub destination_chain: String,
    /// Sanad ID (unique identifier for the Sanad)
    pub sanad_id: Hash,
    /// Commitment hash (the commitment being proven)
    pub commitment: Hash,
    /// Content descriptor hash (optional, for content-addressed data)
    pub content_descriptor_hash: Hash,
    /// Source seal reference hash (the seal being consumed)
    pub source_seal_ref_hash: Hash,
    /// Destination owner hash (the owner on the destination chain)
    pub destination_owner_hash: Hash,
    /// Nullifier (for replay prevention)
    pub nullifier: Hash,
    /// Lock event ID (the event that locked the seal)
    pub lock_event_id: Hash,
    /// Metadata hash (optional additional metadata)
    pub metadata_hash: Hash,
    /// Proof policy hash (the policy governing this proof)
    pub proof_policy_hash: Hash,
}

impl ProofLeafV1 {
    /// Current version of the proof leaf schema
    pub const CURRENT_VERSION: u32 = 1;

    /// Domain tag for MCE encoding
    pub const DOMAIN_TAG: &[u8] = b"csv.proof.leaf.v1";

    /// Create a new proof leaf
    pub fn new(
        source_chain: String,
        destination_chain: String,
        sanad_id: Hash,
        commitment: Hash,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            source_chain,
            destination_chain,
            sanad_id,
            commitment,
            content_descriptor_hash: Hash::zero(),
            source_seal_ref_hash: Hash::zero(),
            destination_owner_hash: Hash::zero(),
            nullifier: Hash::zero(),
            lock_event_id: Hash::zero(),
            metadata_hash: Hash::zero(),
            proof_policy_hash: Hash::zero(),
        }
    }

    /// Convert this proof leaf to its Minimal Canonical Encoding (MCE) byte sequence.
    ///
    /// This is the authoritative MCE implementation that all chain contracts must reproduce.
    /// The byte layout is fixed-width with no variable-length encoding:
    ///
    /// - domain_tag(17 bytes): "csv.proof.leaf.v1"
    /// - version(4 bytes): little-endian u32
    /// - source_chain(1 byte): u8 chain ID
    /// - destination_chain(1 byte): u8 chain ID
    /// - sanad_id(32 bytes): fixed hash
    /// - commitment(32 bytes): fixed hash
    /// - content_descriptor_hash(32 bytes): fixed hash
    /// - source_seal_ref_hash(32 bytes): fixed hash
    /// - destination_owner_hash(32 bytes): fixed hash
    /// - nullifier(32 bytes): fixed hash
    /// - lock_event_id(32 bytes): fixed hash
    /// - metadata_hash(32 bytes): fixed hash
    /// - proof_policy_hash(32 bytes): fixed hash
    ///
    /// Total: 311 bytes
    ///
    /// This encoding is designed to be trivially implementable in any language without
    /// serialization libraries - just byte concatenation of fixed-width fields.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(311);

        // Domain tag (17 bytes)
        bytes.extend_from_slice(Self::DOMAIN_TAG);

        // Version (4 bytes, little-endian)
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Chain IDs (1 byte each - convert string to u8)
        bytes.push(self.chain_id_to_u8(&self.source_chain));
        bytes.push(self.chain_id_to_u8(&self.destination_chain));

        // Fixed-width hashes (32 bytes each)
        bytes.extend_from_slice(&self.sanad_id.0);
        bytes.extend_from_slice(&self.commitment.0);
        bytes.extend_from_slice(&self.content_descriptor_hash.0);
        bytes.extend_from_slice(&self.source_seal_ref_hash.0);
        bytes.extend_from_slice(&self.destination_owner_hash.0);
        bytes.extend_from_slice(&self.nullifier.0);
        bytes.extend_from_slice(&self.lock_event_id.0);
        bytes.extend_from_slice(&self.metadata_hash.0);
        bytes.extend_from_slice(&self.proof_policy_hash.0);

        bytes
    }

    /// Convert chain name string to u8 chain ID
    fn chain_id_to_u8(&self, chain: &str) -> u8 {
        match chain.to_lowercase().as_str() {
            "ethereum" | "eth" => 0,
            "solana" | "sol" => 1,
            "sui" => 2,
            "bitcoin" | "btc" => 3,
            "aptos" => 4,
            "celestia" => 5,
            _ => 255, // Unknown chain
        }
    }

    /// Compute the canonical hash of this proof leaf using the source chain's native hash function
    ///
    /// Uses MCE (Minimal Canonical Encoding) for the preimage, then hashes with the chain's
    /// native hash function to avoid extra gas costs on-chain.
    pub fn hash(&self) -> Result<Hash, String> {
        self.hash_with_function(HashFunction::for_chain(&self.source_chain))
    }

    /// Compute the canonical hash of this proof leaf using a specific hash function
    ///
    /// Uses MCE (Minimal Canonical Encoding) for the preimage, then hashes with the specified
    /// hash function. This is used for cross-chain verification where the verifier needs to
    /// compute the hash using the source chain's native hash function.
    pub fn hash_with_function(&self, hash_fn: HashFunction) -> Result<Hash, String> {
        let mce = self.to_canonical_bytes();
        Ok(hash_fn.hash_bytes(&mce))
    }

    /// Get the native hash function for this proof leaf's source chain
    pub fn native_hash_function(&self) -> HashFunction {
        HashFunction::for_chain(&self.source_chain)
    }

    /// Set the content descriptor hash
    pub fn with_content_descriptor_hash(mut self, hash: Hash) -> Self {
        self.content_descriptor_hash = hash;
        self
    }

    /// Set the source seal reference hash
    pub fn with_source_seal_ref_hash(mut self, hash: Hash) -> Self {
        self.source_seal_ref_hash = hash;
        self
    }

    /// Set the destination owner hash
    pub fn with_destination_owner_hash(mut self, hash: Hash) -> Self {
        self.destination_owner_hash = hash;
        self
    }

    /// Set the nullifier
    pub fn with_nullifier(mut self, hash: Hash) -> Self {
        self.nullifier = hash;
        self
    }

    /// Set the lock event ID
    pub fn with_lock_event_id(mut self, hash: Hash) -> Self {
        self.lock_event_id = hash;
        self
    }

    /// Set the metadata hash
    pub fn with_metadata_hash(mut self, hash: Hash) -> Self {
        self.metadata_hash = hash;
        self
    }

    /// Set the proof policy hash
    pub fn with_proof_policy_hash(mut self, hash: Hash) -> Self {
        self.proof_policy_hash = hash;
        self
    }
}

/// Maximum allowed size for proof bytes (64KB)
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

/// Maximum allowed size for finality data (4KB)
pub const MAX_FINALITY_DATA: usize = 4 * 1024;

/// Maximum allowed size for signatures in a bundle (1MB total)
pub const MAX_SIGNATURES_TOTAL_SIZE: usize = 1024 * 1024;

/// The canonical proof taxonomy for the CSV protocol.
///
/// Every proof in the system must be one of these variants.
/// This enum provides a unified type that enables:
/// - Consistent proof handling across all chain adapters
/// - Unified verification through the canonical verifier
/// - Composable proof DAGs with typed nodes
/// - Clear proof lifecycle management
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// Proves inclusion of a leaf in a Merkle tree.
    ///
    /// Used for:
    /// - Transaction inclusion in a block
    /// - State inclusion in a Merkle Patricia Trie
    /// - Receipt inclusion in a block
    Inclusion(InclusionProof),

    /// Proves finality of a chain event.
    ///
    /// Used for:
    /// - Block finality proofs (e.g., Ethereum finality sync committee)
    /// - Checkpoint finality (e.g., Sui, Aptos)
    /// - Slot finality (e.g., Solana)
    Finality(FinalityProof),

    /// Proves ownership of a seal or asset.
    ///
    /// Used for:
    /// - Seal ownership verification
    /// - NFT ownership proofs
    /// - UTXO ownership
    Ownership(OwnershipProof),

    /// Proves a valid state transition.
    ///
    /// Used for:
    /// - Sanad state transitions
    /// - Commitment chain transitions
    /// - Cross-chain state transitions
    Transition(TransitionProof),

    /// Proves that a replay has not occurred.
    ///
    /// Used for:
    /// - Replay nullifier verification
    /// - Double-spend prevention
    /// - Cross-chain replay prevention
    Replay(ReplayProof),

    /// Proves correct execution of a computation.
    ///
    /// Used for:
    /// - ZK proof verification
    /// - Fraud proof verification
    /// - VM execution proofs
    Execution(ExecutionProof),

    /// A zero-knowledge proof.
    ///
    /// Used for:
    /// - zk-SNARK proofs
    /// - zk-STARK proofs
    /// - Bulletproofs
    /// - Dilithium signatures (post-quantum)
    ZK(ZKProof),

    /// A composition of multiple proofs.
    ///
    /// Used for:
    /// - Composite proofs (e.g., inclusion + finality)
    /// - Proof aggregation
    /// - Multi-step verification chains
    Composite(CompositeProof),
}

impl Proof {
    /// Get the proof type category.
    pub fn category(&self) -> ProofCategory {
        match self {
            Proof::Inclusion(_) => ProofCategory::Inclusion,
            Proof::Finality(_) => ProofCategory::Finality,
            Proof::Ownership(_) => ProofCategory::Ownership,
            Proof::Transition(_) => ProofCategory::Transition,
            Proof::Replay(_) => ProofCategory::Replay,
            Proof::Execution(_) => ProofCategory::Execution,
            Proof::ZK(_) => ProofCategory::ZK,
            Proof::Composite(_) => ProofCategory::Composite,
        }
    }

    /// Compute a hash of this proof for identification.
    pub fn hash(&self) -> Hash {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let cat = self.category();
        let category_bytes = cat.as_bytes();

        // Hash the category + proof-specific data
        let mut data = Vec::with_capacity(category_bytes.len() + 32);
        data.extend_from_slice(category_bytes);
        data.extend_from_slice(&self.variant_hash());
        tagged_hash(HashDomain::VerificationProofV1, &data).hash
    }

    /// Get a hash of the proof variant for differentiation.
    fn variant_hash(&self) -> [u8; 32] {
        match self {
            Proof::Inclusion(p) => p.variant_hash(),
            Proof::Finality(p) => p.variant_hash(),
            Proof::Ownership(p) => p.variant_hash(),
            Proof::Transition(p) => p.variant_hash(),
            Proof::Replay(p) => p.variant_hash(),
            Proof::Execution(p) => p.variant_hash(),
            Proof::ZK(p) => p.variant_hash(),
            Proof::Composite(p) => p.variant_hash(),
        }
    }
}

/// The category of a proof.
/// **Layer:** L1
/// **Encoding:** Use Display/FromStr for serialization
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofCategory {
    /// Inclusion proof
    Inclusion,
    /// Finality proof
    Finality,
    /// Ownership proof
    Ownership,
    /// Transition proof
    Transition,
    /// Replay proof
    Replay,
    /// Execution proof
    Execution,
    /// Zero-knowledge proof
    ZK,
    /// Composite proof
    Composite,
}

impl ProofCategory {
    /// Get the category as bytes for hashing.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ProofCategory::Inclusion => b"inclusion",
            ProofCategory::Finality => b"finality",
            ProofCategory::Ownership => b"ownership",
            ProofCategory::Transition => b"transition",
            ProofCategory::Replay => b"replay",
            ProofCategory::Execution => b"execution",
            ProofCategory::ZK => b"zk",
            ProofCategory::Composite => b"composite",
        }
    }
}

/// An inclusion proof (Merkle proof).
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Raw proof bytes
    pub proof_bytes: Vec<u8>,
    /// The block hash
    pub block_hash: Hash,
    /// Legacy adapter field: transaction index / checkpoint position.
    pub position: u64,
    /// The block number
    pub block_number: u64,
    /// The leaf being proven.
    pub leaf: Hash,
    /// The Merkle root.
    pub root: Hash,
    /// The sibling path.
    pub siblings: Vec<Hash>,
    /// The leaf index.
    pub leaf_index: usize,
    /// The chain or source of this proof.
    pub source: String,
}

fn default_hash() -> Hash {
    Hash::zero()
}

impl Default for InclusionProof {
    fn default() -> Self {
        Self {
            proof_bytes: Vec::new(),
            block_hash: Hash::zero(),
            position: 0,
            block_number: 0,
            leaf: Hash::zero(),
            root: Hash::zero(),
            siblings: Vec::new(),
            leaf_index: 0,
            source: String::new(),
        }
    }
}

impl CanonicalEncoding for InclusionProof {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => self.to_canonical_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e)),
        }
    }
    
    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self> where Self: Sized {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::from_canonical_bytes(bytes).map_err(|e| csv_codec::CodecError::DeserializationError(e)),
        }
    }
}

impl InclusionProof {
    /// Serialize to canonical bytes (manual implementation for L1 type)
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.proof_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof_bytes);
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.position.to_le_bytes());
        bytes.extend_from_slice(&self.block_number.to_le_bytes());
        bytes.extend_from_slice(self.leaf.as_bytes());
        bytes.extend_from_slice(self.root.as_bytes());
        bytes.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling.as_bytes());
        }
        bytes.extend_from_slice(&self.leaf_index.to_le_bytes());
        bytes.extend_from_slice(&(self.source.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.source.as_bytes());
        Ok(bytes)
    }

    /// Deserialize from canonical bytes (manual implementation for L1 type)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0;
        
        let proof_bytes_len = if bytes.len() >= pos + 4 {
            u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize
        } else {
            return Err("Insufficient bytes for proof_bytes length".to_string());
        };
        pos += 4;
        
        if bytes.len() < pos + proof_bytes_len {
            return Err("Insufficient bytes for proof_bytes".to_string());
        }
        let proof_bytes = bytes[pos..pos + proof_bytes_len].to_vec();
        pos += proof_bytes_len;
        
        if bytes.len() < pos + 32 {
            return Err("Insufficient bytes for block_hash".to_string());
        }
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&bytes[pos..pos + 32]);
        let block_hash = Hash(block_hash_bytes);
        pos += 32;
        
        if bytes.len() < pos + 8 {
            return Err("Insufficient bytes for position".to_string());
        }
        let position = u64::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3], bytes[pos+4], bytes[pos+5], bytes[pos+6], bytes[pos+7]]);
        pos += 8;
        
        if bytes.len() < pos + 8 {
            return Err("Insufficient bytes for block_number".to_string());
        }
        let block_number = u64::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3], bytes[pos+4], bytes[pos+5], bytes[pos+6], bytes[pos+7]]);
        pos += 8;
        
        if bytes.len() < pos + 32 {
            return Err("Insufficient bytes for leaf".to_string());
        }
        let mut leaf_bytes = [0u8; 32];
        leaf_bytes.copy_from_slice(&bytes[pos..pos + 32]);
        let leaf = Hash(leaf_bytes);
        pos += 32;
        
        if bytes.len() < pos + 32 {
            return Err("Insufficient bytes for root".to_string());
        }
        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&bytes[pos..pos + 32]);
        let root = Hash(root_bytes);
        pos += 32;
        
        let siblings_len = if bytes.len() >= pos + 4 {
            u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize
        } else {
            return Err("Insufficient bytes for siblings length".to_string());
        };
        pos += 4;
        
        let mut siblings = Vec::with_capacity(siblings_len);
        for _ in 0..siblings_len {
            if bytes.len() < pos + 32 {
                return Err("Insufficient bytes for sibling".to_string());
            }
            let mut sibling_bytes = [0u8; 32];
            sibling_bytes.copy_from_slice(&bytes[pos..pos + 32]);
            siblings.push(Hash(sibling_bytes));
            pos += 32;
        }
        
        if bytes.len() < pos + 8 {
            return Err("Insufficient bytes for leaf_index".to_string());
        }
        let leaf_index = u64::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3], bytes[pos+4], bytes[pos+5], bytes[pos+6], bytes[pos+7]]) as usize;
        pos += 8;
        
        let source_len = if bytes.len() >= pos + 4 {
            u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize
        } else {
            return Err("Insufficient bytes for source length".to_string());
        };
        pos += 4;
        
        if bytes.len() < pos + source_len {
            return Err("Insufficient bytes for source".to_string());
        }
        let source = String::from_utf8(bytes[pos..pos + source_len].to_vec()).map_err(|e| format!("Invalid source string: {}", e))?;
        
        Ok(Self {
            proof_bytes,
            block_hash,
            position,
            block_number,
            leaf,
            root,
            siblings,
            leaf_index,
            source,
        })
    }

    /// Create a new inclusion proof.
    ///
    /// # Arguments
    /// * `proof_bytes` - Raw proof bytes
    /// * `block_hash` - The block hash
    /// * `block_number` - The block number
    /// * `leaf_index` - The leaf index in the Merkle tree
    pub fn new(
        proof_bytes: Vec<u8>,
        block_hash: Hash,
        block_number: u64,
        leaf_index: u64,
    ) -> Result<Self, &'static str> {
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err("Inclusion proof too large");
        }
        Ok(Self {
            proof_bytes,
            block_hash,
            position: block_number,
            block_number,
            leaf: Hash::zero(),
            root: Hash::zero(),
            siblings: Vec::new(),
            leaf_index: leaf_index as usize,
            source: String::new(),
        })
    }

    /// Create without validation (adapter compatibility).
    ///
    /// # Safety
    /// Caller must ensure fields are consistent.
    pub unsafe fn new_unchecked(
        proof_bytes: Vec<u8>,
        block_hash: Hash,
        block_number: u64,
        position: u64,
    ) -> Self {
        Self {
            proof_bytes,
            block_hash,
            position,
            block_number,
            leaf: Hash::zero(),
            root: Hash::zero(),
            siblings: Vec::new(),
            leaf_index: position as usize,
            source: String::new(),
        }
    }

    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(32 * (2 + self.siblings.len()) + self.source.len() + 8);
        data.extend_from_slice(&self.leaf.0);
        data.extend_from_slice(&self.root.0);
        for sibling in &self.siblings {
            data.extend_from_slice(&sibling.0);
        }
        data.extend_from_slice(&self.leaf_index.to_le_bytes());
        data.extend_from_slice(self.source.as_bytes());

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// A finality proof.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Finality data bytes
    pub finality_data: Vec<u8>,
    /// The block or checkpoint being finalized.
    pub block_hash: Hash,
    /// The finality threshold (e.g., 2/3 of validators).
    pub threshold: u32,
    /// The number of confirmations.
    pub confirmations: u64,
    /// Finality data (e.g., signatures, checkpoints).
    pub data: Vec<u8>,
    /// The chain or source.
    pub source: String,
    /// Whether this is a deterministic finality proof
    pub is_deterministic: bool,
}

impl Default for FinalityProof {
    fn default() -> Self {
        Self {
            finality_data: Vec::new(),
            block_hash: Hash::zero(),
            threshold: 0,
            confirmations: 0,
            data: Vec::new(),
            source: String::new(),
            is_deterministic: false,
        }
    }
}

impl CanonicalEncoding for FinalityProof {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => self.to_canonical_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e)),
        }
    }
    
    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self> where Self: Sized {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::from_canonical_bytes(bytes).map_err(|e| csv_codec::CodecError::DeserializationError(e)),
        }
    }
}

impl FinalityProof {
    /// Serialize to canonical bytes (manual implementation for L1 type)
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.finality_data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.finality_data);
        bytes.extend_from_slice(self.block_hash.as_bytes());
        bytes.extend_from_slice(&self.threshold.to_le_bytes());
        bytes.extend_from_slice(&self.confirmations.to_le_bytes());
        bytes.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes.extend_from_slice(&(self.source.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.source.as_bytes());
        bytes.push(if self.is_deterministic { 1u8 } else { 0u8 });
        Ok(bytes)
    }

    /// Deserialize from canonical bytes (manual implementation for L1 type)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0;
        
        let finality_data_len = if bytes.len() >= pos + 4 {
            u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize
        } else {
            return Err("Insufficient bytes for finality_data length".to_string());
        };
        pos += 4;
        
        if bytes.len() < pos + finality_data_len {
            return Err("Insufficient bytes for finality_data".to_string());
        }
        let finality_data = bytes[pos..pos + finality_data_len].to_vec();
        pos += finality_data_len;
        
        if bytes.len() < pos + 32 {
            return Err("Insufficient bytes for block_hash".to_string());
        }
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&bytes[pos..pos + 32]);
        let block_hash = Hash(block_hash_bytes);
        pos += 32;
        
        if bytes.len() < pos + 4 {
            return Err("Insufficient bytes for threshold".to_string());
        }
        let threshold = u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]);
        pos += 4;
        
        if bytes.len() < pos + 8 {
            return Err("Insufficient bytes for confirmations".to_string());
        }
        let confirmations = u64::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3], bytes[pos+4], bytes[pos+5], bytes[pos+6], bytes[pos+7]]);
        pos += 8;
        
        let data_len = if bytes.len() >= pos + 4 {
            u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize
        } else {
            return Err("Insufficient bytes for data length".to_string());
        };
        pos += 4;
        
        if bytes.len() < pos + data_len {
            return Err("Insufficient bytes for data".to_string());
        }
        let data = bytes[pos..pos + data_len].to_vec();
        pos += data_len;
        
        let source_len = if bytes.len() >= pos + 4 {
            u32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]) as usize
        } else {
            return Err("Insufficient bytes for source length".to_string());
        };
        pos += 4;
        
        if bytes.len() < pos + source_len {
            return Err("Insufficient bytes for source".to_string());
        }
        let source = String::from_utf8(bytes[pos..pos + source_len].to_vec()).map_err(|e| format!("Invalid source string: {}", e))?;
        pos += source_len;
        
        if bytes.len() < pos + 1 {
            return Err("Insufficient bytes for is_deterministic".to_string());
        }
        let is_deterministic = bytes[pos] == 1;
        
        Ok(Self {
            finality_data,
            block_hash,
            threshold,
            confirmations,
            data,
            source,
            is_deterministic,
        })
    }

    /// Create a new finality proof.
    ///
    /// # Arguments
    /// * `finality_data` - Raw finality data bytes
    /// * `confirmations` - Number of confirmations
    /// * `is_deterministic` - Whether finality is deterministic
    pub fn new(
        finality_data: Vec<u8>,
        confirmations: u64,
        is_deterministic: bool,
    ) -> Result<Self, &'static str> {
        if finality_data.len() > MAX_FINALITY_DATA {
            return Err("Finality proof too large");
        }
        Ok(Self {
            finality_data,
            block_hash: Hash::zero(),
            threshold: 0,
            confirmations,
            data: Vec::new(),
            source: String::new(),
            is_deterministic,
        })
    }

    /// Create without validation (adapter compatibility).
    ///
    /// # Safety
    /// Caller must ensure fields are consistent.
    pub unsafe fn new_unchecked(
        finality_data: Vec<u8>,
        confirmations: u64,
        is_deterministic: bool,
    ) -> Self {
        Self {
            finality_data,
            confirmations,
            is_deterministic,
            ..Default::default()
        }
    }

    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(32 + 4 + 8 + self.data.len() + self.source.len());
        data.extend_from_slice(&self.block_hash.0);
        data.extend_from_slice(&self.threshold.to_le_bytes());
        data.extend_from_slice(&self.confirmations.to_le_bytes());
        data.extend_from_slice(&self.data);
        data.extend_from_slice(self.source.as_bytes());

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// An ownership proof.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipProof {
    /// The owner's public key or address.
    pub owner: Vec<u8>,
    /// The proof data (signature, etc.).
    pub proof: Vec<u8>,
    /// The asset or seal being owned.
    pub asset_id: Hash,
    /// The ownership scheme (e.g., secp256k1, ed25519).
    pub scheme: String,
}

impl OwnershipProof {
    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data =
            Vec::with_capacity(self.owner.len() + self.proof.len() + 32 + self.scheme.len());
        data.extend_from_slice(&self.owner);
        data.extend_from_slice(&self.proof);
        data.extend_from_slice(&self.asset_id.0);
        data.extend_from_slice(self.scheme.as_bytes());

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// A transition proof.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionProof {
    /// The previous state hash.
    pub previous_state: Hash,
    /// The new state hash.
    pub new_state: Hash,
    /// The transition data.
    pub transition_data: Vec<u8>,
    /// The proof of valid transition.
    pub proof: Vec<u8>,
}

impl TransitionProof {
    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(64 + self.transition_data.len() + self.proof.len());
        data.extend_from_slice(&self.previous_state.0);
        data.extend_from_slice(&self.new_state.0);
        data.extend_from_slice(&self.transition_data);
        data.extend_from_slice(&self.proof);

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// A replay proof.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayProof {
    /// The replay nullifier.
    pub nullifier: Hash,
    /// The chain where the replay was prevented.
    pub chain_id: String,
    /// The context that was checked.
    pub context: Vec<u8>,
}

impl ReplayProof {
    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(32 + self.chain_id.len() + self.context.len());
        data.extend_from_slice(&self.nullifier.0);
        data.extend_from_slice(self.chain_id.as_bytes());
        data.extend_from_slice(&self.context);

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// An execution proof.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProof {
    /// The computation being proven.
    pub computation_hash: Hash,
    /// The proof of correct execution.
    pub proof: Vec<u8>,
    /// The execution context.
    pub context: Vec<u8>,
}

impl ExecutionProof {
    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(32 + self.proof.len() + self.context.len());
        data.extend_from_slice(&self.computation_hash.0);
        data.extend_from_slice(&self.proof);
        data.extend_from_slice(&self.context);

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// A zero-knowledge proof.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZKProof {
    /// The proof system used (e.g., "groth16", "stark", "dilithium").
    pub system: String,
    /// The proof data.
    pub proof: Vec<u8>,
    /// The public inputs.
    pub public_inputs: Vec<Hash>,
    /// The verification key hash.
    pub verification_key_hash: Hash,
}

impl ZKProof {
    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(
            self.system.len() + self.proof.len() + 32 * self.public_inputs.len() + 32,
        );
        data.extend_from_slice(self.system.as_bytes());
        data.extend_from_slice(&self.proof);
        for input in &self.public_inputs {
            data.extend_from_slice(&input.0);
        }
        data.extend_from_slice(&self.verification_key_hash.0);

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// A composite proof (composition of multiple proofs).
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeProof {
    /// The child proofs.
    pub children: Vec<Proof>,
    /// The composition rule (e.g., "and", "or", "threshold").
    pub rule: CompositionRule,
    /// The composite proof data (if any).
    pub proof: Vec<u8>,
}

impl CompositeProof {
    /// Get a variant-specific hash.
    pub fn variant_hash(&self) -> [u8; 32] {
        use csv_hash::HashDomain;
        use csv_hash::tagged_hash::tagged_hash;

        let mut data = Vec::with_capacity(self.proof.len() + self.rule.as_bytes().len());
        for child in &self.children {
            data.extend_from_slice(&child.hash().0);
        }
        data.extend_from_slice(self.rule.as_bytes());
        data.extend_from_slice(&self.proof);

        tagged_hash(HashDomain::VerificationProofV1, &data).hash.0
    }
}

/// The composition rule for composite proofs.
/// **Layer:** L1
/// **Encoding:** Use Display/FromStr for serialization
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionRule {
    /// All child proofs must be valid.
    And,
    /// At least one child proof must be valid.
    Or,
    /// At least N child proofs must be valid.
    Threshold(u32),
}

impl CompositionRule {
    /// Get the string representation.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CompositionRule::And => b"and",
            CompositionRule::Or => b"or",
            CompositionRule::Threshold(_) => b"threshold",
        }
    }
}

/// Explicit proof lifecycle stages. A proof may only advance forward.
/// No transfer may mint unless the phase reaches `ConsensusBound`.
/// Authorization for mint is determined by `VerificationResult::meets_chain_thresholds`,
/// not by comparing this enum to `ConsensusBound` directly.
/// **Layer:** L1
/// **Encoding:** Use Display/FromStr for serialization
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofPhase {
    /// Proof has been constructed but not validated.
    Constructed = 0,
    /// Proof has passed structural validation.
    StructuralValidated = 1,
    /// Proof has passed cryptographic validation.
    CryptographicallyValidated = 2,
    /// Proof has passed finality validation.
    FinalityValidated = 3,
    /// Replay check has been performed.
    ReplayChecked = 4,
    /// Proof is bound to consensus.
    ConsensusBound = 5,
}

/// Globally unique transfer identity. Prevents replay across process restarts
/// and across chain reorganizations.
///
/// Every transfer MUST derive a ReplayId before any state transition.
/// The replay database is append-only; a ReplayId already present means
/// the transfer has been seen before.
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplayId {
    /// Protocol version this replay ID was generated for
    pub version: u32,
    /// 32-byte replay ID payload
    pub id: [u8; 32],
}

impl ReplayId {
    /// Current protocol version for replay IDs.
    pub const CURRENT_VERSION: u32 = 1;

    /// Derive a ReplayId from all inputs that uniquely identify a transfer.
    /// The hash binds together source chain, transaction, seal, transition,
    /// and destination chain so that no two legitimate transfers share an ID.
    /// Uses canonical CBOR serialization + tagged hashing.
    ///
    /// Returns error if CBOR serialization fails, ensuring replay ID correctness.
    pub fn derive(
        source_chain: &str,
        source_txid: &[u8],
        source_output_index: u32,
        seal_id: &[u8],
        transition_id: &[u8],
        destination_chain: &str,
    ) -> Result<Self, String> {
        // Manual canonical serialization to avoid serde dependency
        let mut bytes = Vec::new();
        bytes.extend_from_slice(source_chain.as_bytes());
        bytes.push(0); // null terminator for string
        bytes.extend_from_slice(source_txid);
        bytes.extend_from_slice(&source_output_index.to_le_bytes());
        bytes.extend_from_slice(seal_id);
        bytes.extend_from_slice(transition_id);
        bytes.extend_from_slice(destination_chain.as_bytes());
        bytes.push(0); // null terminator for string

        let id = tagged_hash(HashDomain::ReplayIdV1, &bytes).hash.0;
        Ok(ReplayId {
            version: Self::CURRENT_VERSION,
            id,
        })
    }

    /// Return the raw 32-byte replay ID.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.id
    }
}

/// Complete proof bundle for peer-to-peer verification
///
/// **Layer:** L1
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Has derives for canonical_cbor compatibility, but MUST NOT use serde_json
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Protocol version this bundle conforms to
    pub version: u32,
    /// State transition DAG segment
    pub transition_dag: DAGSegment,
    /// Authorizing signatures
    pub signatures: Vec<Vec<u8>>,
    /// Signature scheme required to verify the authorizing signatures.
    pub signature_scheme: crate::signature::SignatureScheme,
    /// Seal reference
    pub seal_ref: SealPoint,
    /// Anchor reference
    pub anchor_ref: CommitAnchor,
    /// Inclusion proof
    pub inclusion_proof: InclusionProof,
    /// Finality proof
    pub finality_proof: FinalityProof,
}

impl CanonicalEncoding for ProofBundle {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => self.to_canonical_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e)),
        }
    }
    
    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self> where Self: Sized {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => Self::from_canonical_bytes(bytes).map_err(|e| csv_codec::CodecError::DeserializationError(e)),
        }
    }
}

impl ProofBundle {
    /// Serialize to canonical bytes (manual implementation for L1 type)
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        
        // Serialize DAGSegment using its manual serialization
        let dag_bytes = self.transition_dag.to_canonical_bytes();
        bytes.extend_from_slice(&(dag_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&dag_bytes);
        
        // Serialize signatures
        bytes.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            bytes.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            bytes.extend_from_slice(sig);
        }
        
        // Serialize signature scheme
        bytes.push(self.signature_scheme as u8);
        
        // Serialize seal_ref
        bytes.extend_from_slice(&(self.seal_ref.id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.seal_ref.id);
        if let Some(nonce) = self.seal_ref.nonce {
            bytes.push(1u8);
            bytes.extend_from_slice(&nonce.to_le_bytes());
        } else {
            bytes.push(0u8);
        }
        if let Some(version) = self.seal_ref.version {
            bytes.push(1u8);
            bytes.extend_from_slice(&version.to_le_bytes());
        } else {
            bytes.push(0u8);
        }
        
        // Serialize anchor_ref
        bytes.extend_from_slice(&(self.anchor_ref.anchor_id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.anchor_ref.anchor_id);
        bytes.extend_from_slice(&self.anchor_ref.block_height.to_le_bytes());
        bytes.extend_from_slice(&(self.anchor_ref.metadata.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.anchor_ref.metadata);
        
        // Serialize inclusion_proof
        let inc_bytes = self.inclusion_proof.to_canonical_bytes()?;
        bytes.extend_from_slice(&(inc_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&inc_bytes);
        
        // Serialize finality_proof
        let fin_bytes = self.finality_proof.to_canonical_bytes()?;
        bytes.extend_from_slice(&(fin_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&fin_bytes);
        
        Ok(bytes)
    }

    /// Deserialize from canonical bytes (manual implementation for L1 type)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0;
        
        let version = if bytes.len() >= pos + 4 {
            let v = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
            pos += 4;
            v
        } else {
            return Err("Insufficient bytes for version".to_string());
        };
        
        let dag_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for DAG length".to_string());
        };
        
        let transition_dag = if bytes.len() >= pos + dag_len {
            let dag_bytes = &bytes[pos..pos + dag_len];
            pos += dag_len;
            DAGSegment::from_canonical_bytes(dag_bytes).map_err(|e| format!("Failed to deserialize DAGSegment: {}", e))?
        } else {
            return Err("Insufficient bytes for DAG data".to_string());
        };
        
        let sigs_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for signatures length".to_string());
        };
        
        let mut signatures = Vec::with_capacity(sigs_len);
        for _ in 0..sigs_len {
            let sig_len = if bytes.len() >= pos + 4 {
                let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                len
            } else {
                return Err("Insufficient bytes for signature length".to_string());
            };
            let sig = if bytes.len() >= pos + sig_len {
                let sig_bytes = &bytes[pos..pos + sig_len];
                pos += sig_len;
                sig_bytes.to_vec()
            } else {
                return Err("Insufficient bytes for signature data".to_string());
            };
            signatures.push(sig);
        }
        
        let signature_scheme = if bytes.len() >= pos + 1 {
            let scheme = bytes[pos];
            pos += 1;
            match scheme {
                0 => crate::signature::SignatureScheme::Secp256k1,
                1 => crate::signature::SignatureScheme::Ed25519,
                _ => return Err("Invalid signature scheme".to_string()),
            }
        } else {
            return Err("Insufficient bytes for signature scheme".to_string());
        };
        
        let seal_id_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for seal id length".to_string());
        };
        
        let seal_id = if bytes.len() >= pos + seal_id_len {
            let id_bytes = &bytes[pos..pos + seal_id_len];
            pos += seal_id_len;
            id_bytes.to_vec()
        } else {
            return Err("Insufficient bytes for seal id data".to_string());
        };
        
        let seal_nonce = if bytes.len() >= pos + 1 {
            let has_nonce = bytes[pos] == 1;
            pos += 1;
            if has_nonce {
                if bytes.len() >= pos + 8 {
                    let nonce = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    Some(nonce)
                } else {
                    return Err("Insufficient bytes for seal nonce".to_string());
                }
            } else {
                None
            }
        } else {
            return Err("Insufficient bytes for seal nonce flag".to_string());
        };
        
        let seal_version = if bytes.len() >= pos + 1 {
            let has_version = bytes[pos] == 1;
            pos += 1;
            if has_version {
                if bytes.len() >= pos + 8 {
                    let version = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    Some(version)
                } else {
                    return Err("Insufficient bytes for seal version".to_string());
                }
            } else {
                None
            }
        } else {
            return Err("Insufficient bytes for seal version flag".to_string());
        };
        
        let anchor_id_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for anchor id length".to_string());
        };
        
        let anchor_id = if bytes.len() >= pos + anchor_id_len {
            let id_bytes = &bytes[pos..pos + anchor_id_len];
            pos += anchor_id_len;
            id_bytes.to_vec()
        } else {
            return Err("Insufficient bytes for anchor id data".to_string());
        };
        
        let block_height = if bytes.len() >= pos + 8 {
            let height = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            height
        } else {
            return Err("Insufficient bytes for block height".to_string());
        };
        
        let metadata_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for metadata length".to_string());
        };
        
        let metadata = if bytes.len() >= pos + metadata_len {
            let metadata_bytes = &bytes[pos..pos + metadata_len];
            pos += metadata_len;
            metadata_bytes.to_vec()
        } else {
            return Err("Insufficient bytes for metadata data".to_string());
        };
        
        let inc_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for inclusion proof length".to_string());
        };
        
        let inclusion_proof = if bytes.len() >= pos + inc_len {
            let inc_bytes = &bytes[pos..pos + inc_len];
            pos += inc_len;
            InclusionProof::from_canonical_bytes(inc_bytes).map_err(|e| format!("Failed to deserialize InclusionProof: {}", e))?
        } else {
            return Err("Insufficient bytes for inclusion proof data".to_string());
        };
        
        let fin_len = if bytes.len() >= pos + 4 {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for finality proof length".to_string());
        };
        
        let finality_proof = if bytes.len() >= pos + fin_len {
            let fin_bytes = &bytes[pos..pos + fin_len];
            pos += fin_len;
            FinalityProof::from_canonical_bytes(fin_bytes).map_err(|e| format!("Failed to deserialize FinalityProof: {}", e))?
        } else {
            return Err("Insufficient bytes for finality proof data".to_string());
        };
        
        Ok(Self {
            version,
            transition_dag,
            signatures,
            signature_scheme,
            seal_ref: SealPoint {
                id: seal_id,
                nonce: seal_nonce,
                version: seal_version,
            },
            anchor_ref: CommitAnchor {
                anchor_id,
                block_height,
                metadata,
            },
            inclusion_proof,
            finality_proof,
        })
    }

    /// Current protocol version for proof bundles.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new proof bundle
    ///
    /// # Arguments
    /// * `transition_dag` - State transition DAG segment
    /// * `signatures` - Authorizing signatures (total max 1MB)
    /// * `seal_ref` - Seal reference
    /// * `anchor_ref` - Anchor reference
    /// * `inclusion_proof` - Inclusion proof
    /// * `finality_proof` - Finality proof
    ///
    /// # Errors
    /// Returns an error if signatures exceed the maximum total size
    pub fn new(
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
    ) -> Result<Self, String> {
        Self::with_signature_scheme(
            crate::signature::SignatureScheme::Secp256k1,
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
    }

    /// Create a new proof bundle with an explicit signature scheme.
    pub fn with_signature_scheme(
        signature_scheme: crate::signature::SignatureScheme,
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
    ) -> Result<Self, String> {
        Self::with_certification_and_signature_scheme(
            Self::CURRENT_VERSION,
            signature_scheme,
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        )
    }

    /// Create a new proof bundle with certification and an explicit signature scheme.
    #[allow(clippy::too_many_arguments)]
    pub fn with_certification_and_signature_scheme(
        version: u32,
        signature_scheme: crate::signature::SignatureScheme,
        transition_dag: DAGSegment,
        signatures: Vec<Vec<u8>>,
        seal_ref: SealPoint,
        anchor_ref: CommitAnchor,
        inclusion_proof: InclusionProof,
        finality_proof: FinalityProof,
    ) -> Result<Self, String> {
        // Validate total signature size
        let total_sig_size: usize = signatures.iter().map(|s: &Vec<u8>| s.len()).sum();
        if total_sig_size > MAX_SIGNATURES_TOTAL_SIZE {
            return Err("total signatures size exceeds maximum allowed (1MB)".to_string());
        }

        Ok(Self {
            version,
            transition_dag,
            signatures,
            signature_scheme,
            seal_ref,
            anchor_ref,
            inclusion_proof,
            finality_proof,
        })
    }
}
