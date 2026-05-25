//! Formal proof taxonomy
//!
//! This module defines the canonical proof types used across the CSV protocol.
//! All proofs must be one of these variants, ensuring consistent semantics
//! and enabling unified verification.

use csv_hash::Hash;
use csv_hash::HashDomain;
use csv_hash::canonical::to_canonical_cbor;
use csv_hash::dag::DAGSegment;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_hash::tagged_hash::tagged_hash;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Raw proof bytes
    pub proof_bytes: Vec<u8>,
    /// The block hash
    pub block_hash: Hash,
    /// Legacy adapter field: transaction index / checkpoint position.
    #[serde(default)]
    pub position: u64,
    /// The block number
    pub block_number: u64,
    /// The leaf being proven.
    #[serde(default = "default_hash")]
    pub leaf: Hash,
    /// The Merkle root.
    #[serde(default = "default_hash")]
    pub root: Hash,
    /// The sibling path.
    #[serde(default)]
    pub siblings: Vec<Hash>,
    /// The leaf index.
    #[serde(default)]
    pub leaf_index: usize,
    /// The chain or source of this proof.
    #[serde(default)]
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

impl InclusionProof {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityProof {
    /// Finality data bytes
    pub finality_data: Vec<u8>,
    /// The block or checkpoint being finalized.
    #[serde(default = "default_hash")]
    pub block_hash: Hash,
    /// The finality threshold (e.g., 2/3 of validators).
    #[serde(default)]
    pub threshold: u32,
    /// The number of confirmations.
    pub confirmations: u64,
    /// Finality data (e.g., signatures, checkpoints).
    #[serde(default)]
    pub data: Vec<u8>,
    /// The chain or source.
    #[serde(default)]
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

impl FinalityProof {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        #[derive(Serialize)]
        struct ReplayIdInputs<'a> {
            source_chain: &'a str,
            source_txid: &'a [u8],
            source_output_index: u32,
            seal_id: &'a [u8],
            transition_id: &'a [u8],
            destination_chain: &'a str,
        }
        let inputs = ReplayIdInputs {
            source_chain,
            source_txid,
            source_output_index,
            seal_id,
            transition_id,
            destination_chain,
        };
        let cbor = to_canonical_cbor(&inputs).map_err(|e| {
            format!("Failed to serialize replay ID inputs: {}", e)
        })?;
        let id = tagged_hash(HashDomain::ReplayIdV1, &cbor).hash.0;
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

impl ProofBundle {
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
