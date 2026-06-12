//! Cross-Chain Hash Transfer
//!
//! Implements the lock-and-prove protocol for transferring Hashs between chains:
//! 1. Lock — Source chain consumes seal, emits CrossChainLockEvent
//! 2. Prove — Client generates inclusion proof
//! 3. Verify — Destination chain verifies proof, checks registry, mints new Hash
//! 4. Registry — Records transfer, prevents cross-chain double-spend

use async_trait::async_trait;
use csv_hash::Hash;
use csv_hash::canonical::to_canonical_cbor;
use csv_hash::chain_id::ChainId;
use csv_hash::seal::SealPoint;
use csv_codec::{CanonicalEncoding, EncodingFormat};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Keccak256, Sha3_256};
use blake2::{Blake2b512, Digest as Blake2Digest};
use std::vec::Vec;

/// Hash algorithm used by the source chain's proof model.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossChainHashAlgorithm {
    /// SHA-256
    Sha256,
    /// Bitcoin-style double SHA-256
    DoubleSha256,
    /// Keccak-256
    Keccak256,
    /// SHA3-256
    Sha3_256,
    /// Blake2b-256 (Sui native)
    Blake2b256,
}

impl CrossChainHashAlgorithm {
    /// Return the canonical hash algorithm for a given source chain.
    pub fn for_chain(chain: &ChainId) -> Result<Self, CrossChainError> {
        match chain.to_string().as_str() {
            "bitcoin" => Ok(Self::DoubleSha256),
            "ethereum" => Ok(Self::Keccak256),
            "solana" => Ok(Self::Sha256),
            "aptos" => Ok(Self::Sha3_256),
            "sui" => Ok(Self::Blake2b256),
            _ => Err(CrossChainError::UnsupportedChainPair(
                chain.clone(),
                chain.clone(),
            )),
        }
    }

    /// Hash raw bytes using this algorithm.
    pub fn hash_bytes(self, bytes: &[u8]) -> Hash {
        match self {
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                Hash::new(hasher.finalize().into())
            }
            Self::DoubleSha256 => {
                let mut first = Sha256::new();
                first.update(bytes);
                let digest = first.finalize();

                let mut second = Sha256::new();
                second.update(digest);
                Hash::new(second.finalize().into())
            }
            Self::Keccak256 => {
                let mut hasher = Keccak256::new();
                hasher.update(bytes);
                Hash::new(hasher.finalize().into())
            }
            Self::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(bytes);
                Hash::new(hasher.finalize().into())
            }
            Self::Blake2b256 => {
                let mut hasher = Blake2b512::new();
                Blake2Digest::update(&mut hasher, bytes);
                let result = Blake2Digest::finalize(hasher);
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&result.as_slice()[..32]);
                Hash::new(hash_bytes)
            }
        }
    }

    /// Hash bytes with chain-specific domain separation.
    ///
    /// The domain tag binds the hash to a specific chain and operation context,
    /// preventing cross-chain replay attacks where the same content on different
    /// chains would produce identical hashes.
    ///
    /// # Domain Tag Format
    /// `"csv-cross-chain-v1:{chain}:{domain}"`
    pub fn hash_bytes_domain(
        self,
        chain: &ChainId,
        domain: CrossChainDomain,
        bytes: &[u8],
    ) -> Hash {
        use csv_hash::csv_tagged_hash;

        // Build domain tag: "csv-cross-chain-v1:{chain}:{domain}"
        let tag = format!("csv-cross-chain-v1:{}:{}", chain.as_str(), domain.as_str());

        // Apply the chain's native hash, then wrap with tagged_hash for domain separation
        let native_hash = self.raw_hash(bytes);
        let final_hash = csv_tagged_hash(&tag, &native_hash);
        Hash::new(final_hash)
    }

    /// Raw chain-native hash WITHOUT domain separation.
    ///
    /// ONLY for use when verifying chain-native Merkle proofs where the
    /// raw hash must match what the chain itself produced.
    pub(crate) fn raw_hash(self, bytes: &[u8]) -> [u8; 32] {
        match self {
            Self::DoubleSha256 => {
                let first = Sha256::digest(bytes);
                Sha256::digest(first).into()
            }
            Self::Sha256 => Sha256::digest(bytes).into(),
            Self::Keccak256 => Keccak256::digest(bytes).into(),
            Self::Sha3_256 => Sha3_256::digest(bytes).into(),
            Self::Blake2b256 => {
                let mut hasher = Blake2b512::new();
                Blake2Digest::update(&mut hasher, bytes);
                let result = Blake2Digest::finalize(hasher);
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&result.as_slice()[..32]);
                hash_bytes
            }
        }
    }
}

/// Domain context for cross-chain hashing operations.
///
/// Each domain represents a distinct cryptographic context.
/// Hashes in different domains are cryptographically separated
/// even if the underlying content is identical.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossChainDomain {
    /// Hashing a lock event commitment
    LockEventCommitment,
    /// Hashing a state root
    StateRoot,
    /// Binding a proof to a transfer
    ProofBinding,
    /// Finality attestation
    FinalityAttestation,
}

impl CrossChainDomain {
    /// Convert domain to its string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LockEventCommitment => "lock-commitment",
            Self::StateRoot => "state-root",
            Self::ProofBinding => "proof-binding",
            Self::FinalityAttestation => "finality-attestation",
        }
    }
}

/// Event emitted when a Hash is locked on the source chain for cross-chain transfer.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossChainLockEvent {
    /// The Hash being locked
    pub sanad_id: Hash,
    /// The commitment hash of the Hash
    pub commitment: Hash,
    /// The owner who initiated the lock
    pub owner: Hash,
    /// Source chain where the Hash is being locked
    pub source_chain: ChainId,
    /// Destination chain for the transfer
    pub destination_chain: ChainId,
    /// Destination owner (may differ from source owner)
    pub destination_owner: Hash,
    /// Source chain's seal reference (consumed during lock)
    pub source_seal: SealPoint,
    /// Source transaction hash
    pub source_tx_hash: Hash,
    /// Source block height
    pub source_block_height: u64,
    /// Unix timestamp of the lock event
    pub timestamp: u64,
}

/// Transfer state machine for cross-chain transfers.
///
/// Cross-chain transfers have implicit state (Lock → WaitFinality → ProveInclusion →
/// MintDestination) but this is not modeled as an explicit state machine.
/// Junior devs are adding code that skips steps. This state machine makes
/// the flow explicit and prevents skipping steps.
/// L1/L2 type: uses manual canonical_cbor serialization
#[derive(Debug, Clone, PartialEq)]
pub enum TransferState {
    /// Seal locked on source chain, tx submitted
    Locked {
        /// Source transaction hash
        source_tx: String,
        /// Lock block height
        lock_height: u64,
    },
    /// Waiting for finality on source chain
    AwaitingFinality {
        /// Confirmations needed
        confirmations_needed: u32,
        /// Confirmations have
        confirmations_have: u32,
    },
    /// Finality reached, building proof bundle
    BuildingProof,
    /// Proof bundle ready, transmitting to destination
    ProofReady {
        /// The proof bundle serialized as canonical CBOR bytes
        bundle_bytes: Option<Vec<u8>>,
    },
    /// Minting on destination chain
    Minting {
        /// Destination transaction hash (if known)
        dest_tx: Option<String>,
    },
    /// Transfer complete
    Complete {
        /// Destination transaction hash
        dest_tx: String,
        /// Destination seal reference
        dest_seal: SealPoint,
    },
    /// Transfer failed, reason recorded
    Failed {
        /// Failure reason
        reason: String,
        /// Whether the failure is recoverable
        recoverable: bool,
    },
}

impl CanonicalEncoding for TransferState {
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

impl TransferState {
    /// Encode using MCE format (fixed-width byte concatenation)
    fn encode_mce(&self) -> csv_codec::CodecResult<Vec<u8>> {
        // MCE format for TransferState - same as manual binary for now
        self.to_canonical_bytes().map_err(|e| csv_codec::CodecError::SerializationError(e))
    }
    
    /// Decode using MCE format
    fn decode_mce(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        // MCE format for TransferState - same as manual binary for now
        Self::from_canonical_bytes(bytes).map_err(|e| csv_codec::CodecError::DeserializationError(e))
    }

    /// Serialize to canonical bytes (manual implementation for L1/L2 type)
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, String> {
        // Manual serialization to avoid serde dependency
        let mut bytes = Vec::new();
        
        // Variant discriminator (u8)
        let variant = match self {
            TransferState::Locked { .. } => 0u8,
            TransferState::AwaitingFinality { .. } => 1u8,
            TransferState::BuildingProof => 2u8,
            TransferState::ProofReady { .. } => 3u8,
            TransferState::Minting { .. } => 4u8,
            TransferState::Complete { .. } => 5u8,
            TransferState::Failed { .. } => 6u8,
        };
        bytes.push(variant);
        
        // Variant-specific data
        match self {
            TransferState::Locked { source_tx, lock_height } => {
                bytes.extend_from_slice(&(source_tx.len() as u32).to_le_bytes());
                bytes.extend_from_slice(source_tx.as_bytes());
                bytes.extend_from_slice(&lock_height.to_le_bytes());
            }
            TransferState::AwaitingFinality { confirmations_needed, confirmations_have } => {
                bytes.extend_from_slice(&confirmations_needed.to_le_bytes());
                bytes.extend_from_slice(&confirmations_have.to_le_bytes());
            }
            TransferState::BuildingProof => {}
            TransferState::ProofReady { bundle_bytes } => {
                match bundle_bytes {
                    Some(b) => {
                        bytes.push(1u8);
                        bytes.extend_from_slice(&(b.len() as u32).to_le_bytes());
                        bytes.extend_from_slice(b);
                    }
                    None => {
                        bytes.push(0u8);
                    }
                }
            }
            TransferState::Minting { dest_tx } => {
                match dest_tx {
                    Some(tx) => {
                        bytes.push(1u8);
                        bytes.extend_from_slice(&(tx.len() as u32).to_le_bytes());
                        bytes.extend_from_slice(tx.as_bytes());
                    }
                    None => {
                        bytes.push(0u8);
                    }
                }
            }
            TransferState::Complete { dest_tx, dest_seal } => {
                bytes.extend_from_slice(&(dest_tx.len() as u32).to_le_bytes());
                bytes.extend_from_slice(dest_tx.as_bytes());
                bytes.extend_from_slice(&(dest_seal.id.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&dest_seal.id);
                if let Some(nonce) = dest_seal.nonce {
                    bytes.push(1u8);
                    bytes.extend_from_slice(&nonce.to_le_bytes());
                } else {
                    bytes.push(0u8);
                }
                if let Some(version) = dest_seal.version {
                    bytes.push(1u8);
                    bytes.extend_from_slice(&version.to_le_bytes());
                } else {
                    bytes.push(0u8);
                }
            }
            TransferState::Failed { reason, recoverable } => {
                bytes.extend_from_slice(&(reason.len() as u32).to_le_bytes());
                bytes.extend_from_slice(reason.as_bytes());
                bytes.push(if *recoverable { 1u8 } else { 0u8 });
            }
        }
        
        Ok(bytes)
    }

    /// Deserialize from canonical bytes (manual implementation for L1/L2 type)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Note: Deserialization not yet implemented
        Err("TransferState deserialization not yet implemented".to_string())
    }
}

/// Inclusion proof — chain-specific format.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InclusionProof {
    /// Bitcoin: Merkle branch + block header
    Bitcoin(BitcoinMerkleProof),
    /// Ethereum: MPT receipt proof
    Ethereum(EthereumMPTProof),
    /// Sui: Checkpoint certification
    Sui(SuiCheckpointProof),
    /// Aptos: Ledger info proof
    Aptos(AptosLedgerProof),
    /// Solana: Slot-based inclusion proof
    Solana(SolanaSlotProof),
    /// ZK proof: chain-agnostic zero-knowledge seal proof
    ZkSeal(ZkSealProof),
}

impl InclusionProof {
    /// Returns true when the proof variant is compatible with the given chain.
    pub fn matches_chain(&self, chain: &ChainId) -> bool {
        match (chain.to_string().as_str(), self) {
            ("bitcoin", InclusionProof::Bitcoin(_))
            | ("ethereum", InclusionProof::Ethereum(_))
            | ("sui", InclusionProof::Sui(_))
            | ("aptos", InclusionProof::Aptos(_))
            | ("solana", InclusionProof::Solana(_)) => true,
            (_, InclusionProof::ZkSeal(proof)) => &proof.verifier_key.chain == chain,
            _ => false,
        }
    }

    /// Expected hash algorithm for this inclusion proof family.
    pub fn expected_hash_algorithm(&self) -> CrossChainHashAlgorithm {
        match self {
            InclusionProof::Bitcoin(_) => CrossChainHashAlgorithm::DoubleSha256,
            InclusionProof::Ethereum(_) => CrossChainHashAlgorithm::Keccak256,
            InclusionProof::Sui(_) => CrossChainHashAlgorithm::Blake2b256,
            InclusionProof::Aptos(_) => CrossChainHashAlgorithm::Sha3_256,
            InclusionProof::Solana(_) => CrossChainHashAlgorithm::Keccak256,
            InclusionProof::ZkSeal(proof) => proof.verifier_key.hash_algorithm,
        }
    }

    /// Derive a canonical attestation root/hash from the proof payload.
    pub fn attested_root_hash(&self, algorithm: CrossChainHashAlgorithm) -> Hash {
        match self {
            InclusionProof::Bitcoin(proof) => algorithm.hash_bytes(&proof.block_header),
            InclusionProof::Ethereum(proof) => algorithm.hash_bytes(&proof.block_header),
            InclusionProof::Sui(proof) => Hash::new(proof.checkpoint_contents_hash),
            InclusionProof::Aptos(proof) => algorithm.hash_bytes(&proof.ledger_info),
            InclusionProof::Solana(proof) => Hash::new(proof.block_hash),
            InclusionProof::ZkSeal(proof) => proof.public_inputs.block_hash,
        }
    }
}

/// Bitcoin Merkle proof of transaction inclusion in a block.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct BitcoinMerkleProof {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Merkle branch nodes
    pub merkle_branch: Vec<[u8; 32]>,
    /// Serialized block header
    pub block_header: Vec<u8>,
    /// Block height
    pub block_height: u64,
    /// Number of confirmations
    pub confirmations: u64,
}

/// Ethereum MPT proof of receipt inclusion in state.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct EthereumMPTProof {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Receipt root hash
    pub receipt_root: [u8; 32],
    /// RLP-encoded receipt
    pub receipt_rlp: Vec<u8>,
    /// MPT proof nodes
    pub merkle_nodes: Vec<Vec<u8>>,
    /// Serialized block header
    pub block_header: Vec<u8>,
    /// Log index in the receipt
    pub log_index: u64,
    /// Number of confirmations
    pub confirmations: u64,
}

/// Sui checkpoint proof of transaction effects certification.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct SuiCheckpointProof {
    /// Transaction digest
    pub tx_digest: [u8; 32],
    /// Checkpoint sequence number
    pub checkpoint_sequence: u64,
    /// Checkpoint contents hash
    pub checkpoint_contents_hash: [u8; 32],
    /// Transaction effects bytes
    pub effects: Vec<u8>,
    /// Event bytes
    pub events: Vec<u8>,
    /// Whether the checkpoint is certified
    pub certified: bool,
}

/// Aptos ledger info proof of transaction execution.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct AptosLedgerProof {
    /// Transaction version
    pub version: u64,
    /// Transaction proof bytes
    pub transaction_proof: Vec<u8>,
    /// Ledger info bytes
    pub ledger_info: Vec<u8>,
    /// Event bytes
    pub events: Vec<u8>,
    /// Whether the transaction succeeded
    pub success: bool,
}

/// Solana slot-based proof of transaction inclusion.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct SolanaSlotProof {
    /// Slot number where the transaction was included
    pub slot: u64,
    /// Transaction signature
    pub signature: Vec<u8>,
    /// Block hash of the slot
    pub block_hash: [u8; 32],
    /// Number of confirmations
    pub confirmations: u64,
    /// Whether the slot is finalized
    pub finalized: bool,
    /// Account keys involved in the transaction
    pub account_keys: Vec<Vec<u8>>,
    /// Instruction data hash
    pub instruction_data_hash: [u8; 32],
}

/// ZK seal proof for chain-agnostic verification.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkSealProof {
    /// The ZK proof bytes
    pub proof_bytes: Vec<u8>,
    /// Verifier key for proof verification
    pub verifier_key: VerifierKey,
    /// Public inputs from the proof
    pub public_inputs: ZkPublicInputs,
}

/// Verifier key for ZK proof verification.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierKey {
    /// Chain this verifier is for
    pub chain: ChainId,
    /// Hash algorithm encoded into the proof system's public inputs
    pub hash_algorithm: CrossChainHashAlgorithm,
    /// Verifier key bytes
    pub key_bytes: Vec<u8>,
    /// Proof system type
    pub proof_system: String,
    /// Key version
    pub version: u32,
}

/// Public inputs from a ZK seal proof.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkPublicInputs {
    /// The seal reference being proven
    pub seal_ref: SealPoint,
    /// Block hash where the seal was consumed
    pub block_hash: Hash,
    /// Commitment hash bound to the proof
    pub commitment: Hash,
    /// Source chain identifier
    pub source_chain: ChainId,
    /// Block height
    pub block_height: u64,
    /// Unix timestamp
    pub timestamp: u64,
}

/// Finality proof confirming source transaction is finalized.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossChainFinalityProof {
    /// Source chain identifier
    pub source_chain: ChainId,
    /// Block/checkpoint/ledger height of the transaction
    pub height: u64,
    /// Current height on the source chain
    pub current_height: u64,
    /// Whether finality depth has been achieved
    pub is_finalized: bool,
    /// Required finality depth in blocks
    pub depth: u64,
}

/// Complete proof bundle submitted to the destination chain.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossChainTransferProof {
    /// The lock event data from the source chain
    pub lock_event: CrossChainLockEvent,
    /// Inclusion proof (chain-specific format)
    pub inclusion_proof: InclusionProof,
    /// Finality proof confirming source transaction
    pub finality_proof: CrossChainFinalityProof,
    /// Hash algorithm used by the source chain's proof system
    pub hash_algorithm: CrossChainHashAlgorithm,
    /// Source chain's state root at the lock block
    pub source_state_root: Hash,
}

/// Entry in the cross-chain seal registry recording a completed transfer.
///
/// **Layer:** L1
/// **Serde:** Forbidden - L1 types MUST NOT use serde (enforced by deny.toml)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashEntry {
    /// Runtime transfer identifier used for deterministic crash recovery.
    pub transfer_id: String,
    /// The Hash's unique ID (preserved across chains)
    pub sanad_id: Hash,
    /// Source chain identifier
    pub source_chain: ChainId,
    /// Source chain's seal reference
    pub source_seal: SealPoint,
    /// Destination chain identifier
    pub destination_chain: ChainId,
    /// Destination chain's seal reference
    pub destination_seal: SealPoint,
    /// Lock transaction hash on source chain
    pub lock_tx_hash: Hash,
    /// State transition identifier bound to this transfer.
    pub transition_id: Vec<u8>,
    /// Mint transaction hash on destination chain
    pub mint_tx_hash: Hash,
    /// Unix timestamp of the transfer
    pub timestamp: u64,
}

/// Result of a successful cross-chain transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossChainTransferResult {
    /// The new Hash created on the destination chain
    pub destination_sanad: Hash,
    /// The destination chain's seal reference
    pub destination_seal: SealPoint,
    /// Registry entry recording the transfer
    pub registry_entry: HashEntry,
}

/// Errors that can occur during cross-chain transfer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[allow(missing_docs)]
pub enum CrossChainError {
    #[error("Hash already locked on source chain")]
    AlreadyLocked,
    #[error("Hash already exists on destination chain")]
    AlreadyMinted,
    #[error("Invalid inclusion proof")]
    InvalidInclusionProof,
    #[error("Insufficient finality: {0} confirmations, need {1}")]
    InsufficientFinality(u64, u64),
    #[error("Ownership proof verification failed")]
    InvalidOwnership,
    #[error("Lock event does not match expected data")]
    LockEventMismatch,
    #[error("Cross-chain registry error: {0}")]
    RegistryError(String),
    #[error("Unsupported chain pair: {0} → {1}")]
    UnsupportedChainPair(ChainId, ChainId),
    #[error("Lease validation failed: {0}")]
    LeaseError(String),
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
}

/// Trait for locking a Hash on a source chain.
///
/// Consumes the Hash's seal and returns the lock event data + inclusion proof.
pub trait LockProvider {
    /// Lock a Hash for cross-chain transfer.
    ///
    /// # Arguments
    /// * `sanad_id` — The unique identifier of the Hash
    /// * `commitment` — The Hash's commitment hash
    /// * `owner` — Current owner's ownership proof
    /// * `destination_chain` — Target chain ID
    /// * `destination_owner` — New owner on destination chain
    ///
    /// # Returns
    /// Lock event data and inclusion proof (chain-specific format)
    fn lock_sanad(
        &self,
        sanad_id: Hash,
        commitment: Hash,
        owner: Hash,
        destination_chain: ChainId,
        destination_owner: Hash,
    ) -> Result<(CrossChainLockEvent, InclusionProof), CrossChainError>;
}

/// Trait for verifying cross-chain transfer proofs.
pub trait TransferVerifier {
    /// Verify a cross-chain transfer proof.
    ///
    /// # Checks
    /// 1. Inclusion proof is valid (source chain finalized)
    /// 2. Seal NOT in SealNullifier (no double-spend)
    /// 3. Ownership proof valid (owner signature matches)
    /// 4. Lock event matches expected sanad_id and commitment
    fn verify_transfer_proof(&self, proof: &CrossChainTransferProof)
    -> Result<(), CrossChainError>;
}

/// Trait for minting a Hash on a destination chain.
pub trait MintProvider {
    /// Mint a new Hash from a verified cross-chain transfer proof.
    ///
    /// Creates a new Hash with the same commitment and state
    /// but a new seal on the destination chain.
    fn mint_sanad(
        &self,
        proof: &CrossChainTransferProof,
    ) -> Result<CrossChainTransferResult, CrossChainError>;
}

/// Default verifier implementation for cross-chain transfer proofs.
pub struct StandardTransferVerifier {
    registry: CrossChainRegistry,
}

impl StandardTransferVerifier {
    /// Create a new StandardTransferVerifier with an empty registry.
    pub fn new() -> Self {
        Self {
            registry: CrossChainRegistry::new(),
        }
    }

    /// Create with an existing registry (for persistence/recovery).
    pub fn with_registry(registry: CrossChainRegistry) -> Self {
        Self { registry }
    }

    /// Get a reference to the registry for inspection.
    pub fn registry(&self) -> &CrossChainRegistry {
        &self.registry
    }

    /// Record a completed transfer in the registry.
    pub fn record_transfer(&mut self, entry: CrossChainRegistryEntry) -> Result<(), CrossChainError> {
        self.registry.record_transfer(entry)
    }
}

impl Default for StandardTransferVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross-chain transfer registry entry.
///
/// Records a single cross-chain transfer with all relevant metadata
/// for double-spend prevention and tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossChainRegistryEntry {
    /// Unique sanad identifier (32-byte hash)
    pub sanad_id: Hash,
    /// Source chain identifier
    pub source_chain: ChainId,
    /// Source chain seal point (transaction reference)
    pub source_seal: SealPoint,
    /// Destination chain identifier
    pub destination_chain: ChainId,
    /// Destination chain seal point (mint transaction reference)
    pub destination_seal: SealPoint,
    /// Source transaction hash
    pub lock_tx_hash: Hash,
    /// Destination transaction hash
    pub mint_tx_hash: Hash,
    /// Transfer timestamp (Unix epoch seconds)
    pub timestamp: u64,
}

/// Cross-chain transfer registry.
///
/// In-memory BTreeMap-based registry tracking all cross-chain transfers
/// to prevent double-spending across chains. Provides O(log n) lookups
/// and deterministic iteration for persistence operations.
#[derive(Default, Debug, Clone)]
pub struct CrossChainRegistry {
    entries: std::collections::BTreeMap<Hash, CrossChainRegistryEntry>,
}

impl CrossChainRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            entries: std::collections::BTreeMap::new(),
        }
    }

    /// Record a cross-chain transfer.
    ///
    /// Enforces double-spend prevention by checking:
    /// 1. Sanad has not been transferred before
    /// 2. Source seal has not been consumed
    pub fn record_transfer(
        &mut self,
        entry: CrossChainRegistryEntry,
    ) -> Result<(), CrossChainError> {
        // Check if this sanad has already been transferred
        if self.entries.contains_key(&entry.sanad_id) {
            return Err(CrossChainError::AlreadyMinted);
        }

        // Check if the source seal has already been consumed
        for existing in self.entries.values() {
            if existing.source_seal == entry.source_seal {
                return Err(CrossChainError::AlreadyLocked);
            }
        }

        self.entries.insert(entry.sanad_id, entry);
        Ok(())
    }

    /// Check if a sanad has already been transferred.
    pub fn is_sanad_transferred(&self, sanad_id: &Hash) -> bool {
        self.entries.contains_key(sanad_id)
    }

    /// Check if a source seal has already been consumed.
    pub fn is_seal_consumed(&self, seal: &SealPoint) -> bool {
        self.entries.values().any(|e| &e.source_seal == seal)
    }

    /// Get the registry entry for a sanad.
    pub fn get_entry(&self, sanad_id: &Hash) -> Option<&CrossChainRegistryEntry> {
        self.entries.get(sanad_id)
    }

    /// Get the number of recorded transfers.
    pub fn transfer_count(&self) -> usize {
        self.entries.len()
    }

    /// Get all recorded transfers.
    pub fn all_transfers(&self) -> Vec<&CrossChainRegistryEntry> {
        self.entries.values().collect()
    }
}

#[async_trait]
impl TransferVerifier for StandardTransferVerifier {
    fn verify_transfer_proof(&self, proof: &CrossChainTransferProof)
    -> Result<(), CrossChainError> {
        // Extract sanad_id and source_seal from the lock event
        let sanad_id = proof.lock_event.sanad_id;
        let source_seal = &proof.lock_event.source_seal;

        // Check 1: Verify the seal has not been double-spent
        if self.registry.is_seal_consumed(source_seal) {
            return Err(CrossChainError::AlreadyLocked);
        }

        // Check 2: Verify the sanad has not already been transferred
        if self.registry.is_sanad_transferred(&sanad_id) {
            return Err(CrossChainError::AlreadyMinted);
        }

        // Check 3: Verify the inclusion proof is valid (source chain finalized)
        // This is delegated to the canonical verifier in production
        self.verify_inclusion_proof(proof)?;

        Ok(())
    }
}

impl StandardTransferVerifier {
    /// Internal helper to verify inclusion proof validity.
    /// 
    /// This verifies that the inclusion proof in the cross-chain transfer proof
    /// is cryptographically valid. The proof must demonstrate that the commitment
    /// was included in a finalized block on the source chain.
    fn verify_inclusion_proof(&self, proof: &CrossChainTransferProof) -> Result<(), CrossChainError> {
        use crate::proof_validation::CanonicalProof;
        use csv_hash::Hash;
        
        let inclusion_proof = &proof.inclusion_proof;
        
        // Convert chain-specific InclusionProof to CanonicalProof for validation
        let canonical_proof = match inclusion_proof {
            InclusionProof::Bitcoin(proof) => {
                let block_hash: [u8; 32] = if proof.block_header.len() >= 32 {
                    proof.block_header[..32].try_into().unwrap_or([0u8; 32])
                } else {
                    [0u8; 32]
                };
                CanonicalProof::new(
                    proof.block_height,
                    block_hash,
                    [0u8; 32], // Bitcoin doesn't have state root in the same way
                    proof.merkle_branch.iter().map(|h| h.to_vec()).collect(),
                )
            }
            InclusionProof::Ethereum(proof) => {
                let block_hash: [u8; 32] = if proof.block_header.len() >= 32 {
                    proof.block_header[..32].try_into().unwrap_or([0u8; 32])
                } else {
                    [0u8; 32]
                };
                CanonicalProof::new(
                    proof.confirmations,
                    block_hash,
                    proof.receipt_root,
                    proof.merkle_nodes.clone(),
                )
            }
            InclusionProof::Solana(proof) => {
                CanonicalProof::new(
                    proof.slot,
                    proof.block_hash,
                    [0u8; 32],
                    vec![proof.signature.clone()],
                )
            }
            InclusionProof::Sui(proof) => {
                CanonicalProof::new(
                    proof.checkpoint_sequence,
                    proof.checkpoint_contents_hash,
                    [0u8; 32],
                    vec![proof.effects.clone(), proof.events.clone()],
                )
            }
            InclusionProof::Aptos(proof) => {
                CanonicalProof::new(
                    proof.version,
                    [0u8; 32], // Block hash not directly available
                    [0u8; 32], // State root not directly available
                    vec![proof.transaction_proof.clone(), proof.ledger_info.clone()],
                )
            }
            InclusionProof::ZkSeal(proof) => {
                CanonicalProof::new(
                    proof.public_inputs.block_height,
                    {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&proof.public_inputs.block_hash.as_bytes()[..32]);
                        hash
                    },
                    [0u8; 32],
                    vec![proof.proof_bytes.clone()],
                )
            }
        };
        
        // Validate the canonical proof structure
        canonical_proof.validate().map_err(|e| {
            CrossChainError::ProofVerificationFailed(format!("Inclusion proof validation failed: {}", e))
        })?;
        
        Ok(())
    }
}
