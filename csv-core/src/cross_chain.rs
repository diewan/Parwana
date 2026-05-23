//! Cross-Chain Hash Transfer
//!
//! Implements the lock-and-prove protocol for transferring Hashs between chains:
//! 1. Lock — Source chain consumes seal, emits CrossChainLockEvent
//! 2. Prove — Client generates inclusion proof
//! 3. Verify — Destination chain verifies proof, checks registry, mints new Hash
//! 4. Registry — Records transfer, prevents cross-chain double-spend

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{Keccak256, Sha3_256};

use csv_hash::Hash;
use crate::mcp::ChainId;
// Hash is not available in csv-hash, TODO: find correct location
use csv_hash::seal::SealPoint;
use crate::signature::{Signature, SignatureScheme};

/// Hash algorithm used by the source chain's proof model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossChainHashAlgorithm {
    /// SHA-256
    Sha256,
    /// Bitcoin-style double SHA-256
    DoubleSha256,
    /// Keccak-256
    Keccak256,
    /// SHA3-256
    Sha3_256,
}

impl CrossChainHashAlgorithm {
    /// Return the canonical hash algorithm for a given source chain.
    pub fn for_chain(chain: &ChainId) -> Result<Self, CrossChainError> {
        match chain.to_string().as_str() {
            "bitcoin" => Ok(Self::DoubleSha256),
            "ethereum" => Ok(Self::Keccak256),
            "solana" => Ok(Self::Sha256),
            "aptos" => Ok(Self::Sha3_256),
            "sui" => Ok(Self::Sha256),
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
        let tag = format!(
            "csv-cross-chain-v1:{}:{}",
            chain.as_str(),
            domain.as_str()
        );

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
        }
    }
}

/// Domain context for cross-chain hashing operations.
///
/// Each domain represents a distinct cryptographic context.
/// Hashes in different domains are cryptographically separated
/// even if the underlying content is identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Return the canonical signature scheme for a given chain.
fn signature_scheme_for_chain(chain: &ChainId) -> Result<SignatureScheme, CrossChainError> {
    match chain.to_string().as_str() {
        "bitcoin" => Ok(SignatureScheme::Secp256k1),
        "ethereum" => Ok(SignatureScheme::Secp256k1),
        "solana" => Ok(SignatureScheme::Ed25519),
        "aptos" => Ok(SignatureScheme::Ed25519),
        "sui" => Ok(SignatureScheme::Ed25519),
        _ => Err(CrossChainError::UnsupportedChainPair(
            chain.clone(),
            chain.clone(),
        )),
    }
}

/// Event emitted when a Hash is locked on the source chain for cross-chain transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
        /// The proof bundle
        #[serde(skip_serializing_if = "Option::is_none")]
        bundle: Option<Box<csv_proof::proof::ProofBundle>>,
    },
    /// Minting on destination chain
    Minting {
        /// Destination transaction hash (if known)
        #[serde(skip_serializing_if = "Option::is_none")]
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

/// Inclusion proof — chain-specific format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            InclusionProof::Sui(_) => CrossChainHashAlgorithm::Sha256,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkSealProof {
    /// The ZK proof bytes
    pub proof_bytes: Vec<u8>,
    /// Verifier key for proof verification
    pub verifier_key: VerifierKey,
    /// Public inputs from the proof
    pub public_inputs: ZkPublicInputs,
}

/// Verifier key for ZK proof verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashEntry {
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
    registry: Hash, // TODO: integrate when available
}

// impl StandardTransferVerifier {
//     /// Create a verifier backed by the shared transfer registry.
//     pub fn new(_registry: Hash) -> Self {
//         Self { registry: _registry }
//     }
// 
// //     fn verify_ownership(
// //         &self,
// //         proof: &Hash,
// //         commitment: Hash,
// //         source_chain: &ChainId,
// //     ) -> Result<(), CrossChainError> {
// //         if proof.proof.is_empty() {
// //             return Err(CrossChainError::InvalidOwnership);
// //         }
// // 
// //         // Use chain-canonical signature scheme instead of proof-payload field
// //         // This prevents attackers from specifying an insecure scheme
// //         let scheme = signature_scheme_for_chain(source_chain)?;
// //         
// //         let sig = Signature::new(
// //             proof.proof.clone(),
// //             proof.owner.clone(),
// //             commitment.as_bytes().to_vec(),
// //         );
// //         
// //         sig.verify(scheme)
// //             .map_err(|e| {
// //                 eprintln!("Signature verification failed: {:?}", e);
// //                 // TODO: HashOwnershipProof not available
// //                 // eprintln!("Signature len: {}, Owner len: {}", proof.proof.len(), proof.owner.len());
// //                 CrossChainError::InvalidOwnership
// //             })?;
// // 
// //         Ok(())
// //     }
// 
//     fn verify_compatibility(&self, proof: &CrossChainTransferProof) -> Result<(), CrossChainError> {
//         if proof.lock_event.source_chain == proof.lock_event.destination_chain {
//             return Err(CrossChainError::UnsupportedChainPair(
//                 proof.lock_event.source_chain.clone(),
//                 proof.lock_event.destination_chain.clone(),
//             ));
//         }
// 
//         if !proof
//             .inclusion_proof
//             .matches_chain(&proof.lock_event.source_chain)
//         {
//             return Err(CrossChainError::InvalidInclusionProof);
//         }
// 
//         let expected_hash_algorithm =
//             CrossChainHashAlgorithm::for_chain(&proof.lock_event.source_chain)?;
//         if proof.hash_algorithm != expected_hash_algorithm
//             || proof.inclusion_proof.expected_hash_algorithm() != expected_hash_algorithm
//         {
//             return Err(CrossChainError::InvalidInclusionProof);
//         }
// 
//         let attested_root = proof
//             .inclusion_proof
//             .attested_root_hash(proof.hash_algorithm);
//         if attested_root == Hash::zero()
//             || proof.source_state_root == Hash::zero()
//             || proof.source_state_root != attested_root
//         {
//             return Err(CrossChainError::InvalidInclusionProof);
//         }
// 
//         if proof.finality_proof.source_chain != proof.lock_event.source_chain
//             || proof.finality_proof.height != proof.lock_event.source_block_height
//         {
//             return Err(CrossChainError::LockEventMismatch);
//         }
// 
//         let finalized_by_depth = proof.finality_proof.current_height
//             >= proof
//                 .finality_proof
//                 .height
//                 .saturating_add(proof.finality_proof.depth);
//         if !proof.finality_proof.is_finalized || !finalized_by_depth {
//             return Err(CrossChainError::InsufficientFinality(
//                 proof
//                     .finality_proof
//                     .current_height
//                     .saturating_sub(proof.finality_proof.height),
//                 proof.finality_proof.depth,
//             ));
//         }
// 
//         if proof.lock_event.commitment == Hash::zero()
//             || proof.lock_event.sanad_id == Hash::zero()
//             || proof.lock_event.source_tx_hash == Hash::zero()
//         {
//             return Err(CrossChainError::LockEventMismatch);
//         }
// 
// //         self.verify_ownership(&proof.lock_event.owner, proof.lock_event.commitment, &proof.lock_event.source_chain)?;
// //         self.verify_ownership(
//             &proof.lock_event.destination_owner,
//             proof.lock_event.commitment,
//             &proof.lock_event.destination_chain,
// 
//         Ok(())
//     }
// 
// impl TransferVerifier for StandardTransferVerifier<'_> {
//     fn verify_transfer_proof(
//         &self,
//         proof: &CrossChainTransferProof,
//     ) -> Result<(), CrossChainError> {
//         self.verify_compatibility(proof)?;
// 
//         if self
//             .registry
//             .is_sanad_transferred(&proof.lock_event.sanad_id)
//         {
//             return Err(CrossChainError::AlreadyMinted);
//         }
// 
//         if self
//             .registry
//             .is_seal_consumed(&proof.lock_event.source_seal)
//         {
//             return Err(CrossChainError::AlreadyLocked);
//         }
// 
//         Ok(())
//     }
// }
// 
// /// Cross-chain transfer orchestrator.
// ///
// // /// Coordinates lock → prove → verify → mint across chains.
// // pub struct CrossChainTransfer {
// //     /// The cross-chain seal registry
// //     pub registry: Hash,
// // }
// // 
// }
// // impl CrossChainTransfer {
// //     /// Create a new cross-chain transfer orchestrator.
// //     pub fn new(registry: Hash) -> Self {
// //         Self { registry }
// //     }
// // 
// //     /// Execute a full cross-chain transfer.
// //     ///
// //     /// 1. Validate lease (if provided)
//     /// 2. Lock the Hash on the source chain
//     /// 3. Build the transfer proof
//     /// 4. Verify on the destination chain
//     /// 5. Mint the new Hash
//     /// 6. Record in the registry
//     #[allow(clippy::too_many_arguments)]
//     pub fn execute(
//         &mut self,
//         locker: &dyn LockProvider,
//         verifier: &dyn TransferVerifier,
//         minter: &dyn MintProvider,
//         sanad_id: Hash,
//         commitment: Hash,
//         owner: Hash,
//         destination_chain: ChainId,
//         destination_owner: Hash,
//         current_block_height: u64,
//         finality_depth: u64,
//         lease_token: Option<Hash>,
//     ) -> Result<CrossChainTransferResult, CrossChainError> {
//         // Step 0: Validate lease if provided
//         if let Some(lease_hash) = lease_token {
//             let lease_id = crate::lease::LeaseId(lease_hash);
//             let owner_hash = Hash::new([0u8; 32]); // Placeholder - owner validation done at CLI level
//             let lease_manager = crate::lease::LeaseManager::new();
//             // Note: Full lease validation requires the lease to be in the manager's store.
//             // In production, the lease manager would be shared across the CLI and core.
//             // For now, we accept the lease token as a signal that the user has acquired one.
//             let _ = (lease_id, owner_hash, &lease_manager);
//         }
// 
//         // Step 1: Lock on source chain
//         let (lock_event, inclusion_proof) = locker.lock_sanad(
//             sanad_id,
//             commitment,
//             owner.clone(),
//             destination_chain,
//             destination_owner.clone(),
//         )?;
// 
//         // Step 2: Build transfer proof
//         let source_chain = lock_event.source_chain.clone();
//         let source_block_height = lock_event.source_block_height;
//         let lock_timestamp = lock_event.timestamp;
// 
//         let is_finalized = current_block_height >= source_block_height + finality_depth;
//         let hash_algorithm = CrossChainHashAlgorithm::for_chain(&source_chain)?;
//         let source_state_root = inclusion_proof.attested_root_hash(hash_algorithm);
// 
//         let transfer_proof = CrossChainTransferProof {
//             lock_event,
//             inclusion_proof,
//             finality_proof: CrossChainFinalityProof {
//                 source_chain: source_chain.clone(),
//                 height: source_block_height,
//                 current_height: current_block_height,
//                 is_finalized,
//                 depth: finality_depth,
//             },
//             hash_algorithm,
//             source_state_root,
//         };
// 
//         // Step 3: Verify on destination
//         verifier.verify_transfer_proof(&transfer_proof)?;
// 
//         // Step 4: Mint on destination
//         let result = minter.mint_sanad(&transfer_proof)?;
// 
//         // Step 5: Record in registry
//         let entry = HashEntry {
//             sanad_id,
//             source_chain,
//             source_seal: transfer_proof.lock_event.source_seal.clone(),
//             destination_chain: transfer_proof.lock_event.destination_chain,
//             destination_seal: result.destination_seal.clone(),
//             lock_tx_hash: transfer_proof.lock_event.source_tx_hash,
//             mint_tx_hash: Hash::new([0u8; 32]),
//             timestamp: lock_timestamp,
//         };
//         self.registry.record_transfer(entry)?;
// 
//         Ok(result)
//     }

// /// Cross-chain seal registry.
// ///
// /// Tracks all cross-chain transfers to prevent double-spends.
// #[derive(Default)]
// pub struct Hash {
//     entries: alloc::collections::BTreeMap<Hash, HashEntry>,
// }
// 
// impl Hash {
//     /// Create a new empty registry.
//     pub fn new() -> Self {
//         Self {
//             entries: alloc::collections::BTreeMap::new(),
//         }
//     }
// 
//     /// Record a cross-chain transfer.
//     pub fn record_transfer(
//         &mut self,
//         entry: HashEntry,
//     ) -> Result<(), CrossChainError> {
// }
//         // Check if this Hash has already been transferred
//         if self.entries.contains_key(&entry.sanad_id) {
//             return Err(CrossChainError::AlreadyMinted);
//         }
// 
//         // Check if the source seal has already been consumed
// //         for existing in self.entries.values() {
// // }
// //             if existing.source_seal == entry.source_seal {
// //                 return Err(CrossChainError::AlreadyLocked);
// //             }
// //         }
// // 
// //         self.entries.insert(entry.sanad_id, entry);
// //         Ok(())
// //     }
// // 
// //     /// Check if a Hash has already been transferred.
// //     pub fn is_sanad_transferred(&self, sanad_id: &Hash) -> bool {
// //         self.entries.contains_key(sanad_id)
// //     }
// // 
// //     /// Check if a source seal has already been consumed.
// //     pub fn is_seal_consumed(&self, seal: &SealPoint) -> bool {
// //         self.entries.values().any(|e| &e.source_seal == seal)
// //     }
// // 
// //     /// Get the registry entry for a Hash.
// //     pub fn get_entry(&self, sanad_id: &Hash) -> Option<&HashEntry> {
// //         self.entries.get(sanad_id)
// //     }
// // 
// //     /// Get the number of recorded transfers.
// //     pub fn transfer_count(&self) -> usize {
// //         self.entries.len()
// //     }
// // 
// //     /// Get all recorded transfers.
// //     pub fn all_transfers(&self) -> Vec<&HashEntry> {
// //         self.entries.values().collect()
// //     }
// // }
// // 
// // // Re-export for convenience
// pub use csv_hash::nullifier::SealConsumption;
// 
// /// Cross-chain seal registry for tracking transfers across all chains
// pub use csv_hash::nullifier::SealNullifier;
// 
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use csv_hash::Hash;
//     use crate::mcp::ChainId;
//     use crate::signature::SignatureScheme;
// 
//     #[test]
//     fn test_chain_id_roundtrip() {
//         for chain in [
//             ChainId::new("bitcoin"),
//             ChainId::new("sui"),
//             ChainId::new("aptos"),
//             ChainId::new("ethereum"),
//             ChainId::new("solana"),
//         ] {
//             let id_str = chain.to_string();
//             let parsed: Result<ChainId, _> = id_str.parse();
//             assert_eq!(parsed, Ok(chain));
//         }
//         assert_eq!("unknown".parse::<ChainId>().unwrap().to_string(), "unknown");
//     }
// 
//     #[test]
//     fn test_registry_prevents_double_mint() {
//         let mut registry = Hash::new();
//         let sanad_id = Hash::new([0xAB; 32]);
// 
//         let entry = HashEntry {
//             sanad_id,
//             source_chain: ChainId::new("bitcoin"),
//             source_seal: SealPoint::new(vec![0x01], None).unwrap(),
//             destination_chain: ChainId::new("sui"),
//             destination_seal: SealPoint::new(vec![0x02], None).unwrap(),
//             lock_tx_hash: Hash::new([0x03; 32]),
//             mint_tx_hash: Hash::new([0x04; 32]),
//             timestamp: 1_000_000,
//         };
// 
//         registry.record_transfer(entry.clone()).unwrap();
// 
//         // Second transfer of same Hash should fail
//         let result = registry.record_transfer(entry);
//         assert!(matches!(result, Err(CrossChainError::AlreadyMinted)));
//     }
// 
//     #[test]
//     fn test_registry_prevents_double_lock() {
//         let mut registry = Hash::new();
//         let seal = SealPoint::new(vec![0x01], None).unwrap();
// 
//         let entry1 = HashEntry {
//             sanad_id: Hash::new([0xAB; 32]),
//             source_chain: ChainId::new("bitcoin"),
//             source_seal: seal.clone(),
//             destination_chain: ChainId::new("sui"),
//             destination_seal: SealPoint::new(vec![0x02], None).unwrap(),
//             lock_tx_hash: Hash::new([0x03; 32]),
//             mint_tx_hash: Hash::new([0x04; 32]),
//             timestamp: 1_000_000,
//         };
// 
//         registry.record_transfer(entry1).unwrap();
// 
//         // Second transfer using same source seal should fail
//         let entry2 = HashEntry {
//             sanad_id: Hash::new([0xCD; 32]),
//             source_chain: ChainId::new("bitcoin"),
//             source_seal: seal.clone(),
//             destination_chain: ChainId::new("aptos"),
//             destination_seal: SealPoint::new(vec![0x05], None).unwrap(),
//             lock_tx_hash: Hash::new([0x06; 32]),
//             mint_tx_hash: Hash::new([0x07; 32]),
//             timestamp: 2_000_000,
//         };
// 
//         let result = registry.record_transfer(entry2);
//         assert!(matches!(result, Err(CrossChainError::AlreadyLocked)));
//     }
// 
//     #[test]
//     fn test_registry_tracks_transfers() {
//         let mut registry = Hash::new();
//         assert_eq!(registry.transfer_count(), 0);
// 
//         let entry = HashEntry {
//             sanad_id: Hash::new([0xAB; 32]),
//             source_chain: ChainId::new("bitcoin"),
//             source_seal: SealPoint::new(vec![0x01], None).unwrap(),
//             destination_chain: ChainId::new("sui"),
//             destination_seal: SealPoint::new(vec![0x02], None).unwrap(),
//             lock_tx_hash: Hash::new([0x03; 32]),
//             mint_tx_hash: Hash::new([0x04; 32]),
//             timestamp: 1_000_000,
//         };
// 
//         registry.record_transfer(entry).unwrap();
//         assert_eq!(registry.transfer_count(), 1);
//         assert!(registry.is_sanad_transferred(&Hash::new([0xAB; 32])));
//     }
// 
//     fn ownership_proof_for(commitment: Hash, chain: &ChainId) -> Hash {
//         match chain.to_string().as_str() {
//             "bitcoin" | "ethereum" => {
//                 use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
//                 let secp = Secp256k1::new();
//                 let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
//                 let public_key = PublicKey::from_secret_key(&secp, &secret_key)
//                     .serialize()
//                     .to_vec();
//                 let message = Message::from_digest_slice(commitment.as_bytes()).unwrap();
//                 let signature = secp
//                     .sign_ecdsa(&message, &secret_key)
//                     .serialize_compact()
//                     .to_vec();
// 
//                 Hash {
//                     proof: signature,
//                     owner: public_key,
//                     scheme: Some(SignatureScheme::Secp256k1),
//                 }
//             }
//             "solana" | "aptos" | "sui" => {
//                 use ed25519_dalek::{Signer, SigningKey};
//                 let mut csprng = rand::thread_rng();
//                 let signing_key = SigningKey::generate(&mut csprng);
// //                 let verifying_key = signing_key.verifying_key();
// //                 let message: [u8; 32] = *commitment.as_bytes();
// //                 let signature = signing_key.sign(&message);
// // 
// //                 Hash {
// //                     proof: signature.to_bytes().to_vec(),
// //                     owner: verifying_key.to_bytes().to_vec(),
// //                     scheme: Some(SignatureScheme::Ed25519),
// //                 }
// //             }
// //             _ => panic!("Unsupported chain for test"),
// //         }
// //     }
// // 
// //     fn sample_transfer_proof() -> CrossChainTransferProof {
// //         let commitment = Hash::new([0x11; 32]);
//         let block_header = vec![0x42; 80];
//         let source_chain = ChainId::new("bitcoin");
//         let hash_algorithm = CrossChainHashAlgorithm::for_chain(&source_chain).unwrap();
//         let inclusion_proof = InclusionProof::Bitcoin(BitcoinMerkleProof {
//             txid: [0xAA; 32],
//             merkle_branch: vec![[0xBB; 32]],
//             block_header: block_header.clone(),
//             block_height: 100,
//             confirmations: 6,
//         });
// 
//         CrossChainTransferProof {
//             lock_event: CrossChainLockEvent {
//                 sanad_id: Hash::new([0x01; 32]),
//                 commitment,
//                 owner: ownership_proof_for(commitment, &source_chain),
//                 source_chain: source_chain.clone(),
//                 destination_chain: ChainId::new("sui"),
//                 destination_owner: ownership_proof_for(commitment, &ChainId::new("sui")),
//                 source_seal: SealPoint::new(vec![0xAA, 0xBB], Some(42)).unwrap(),
//                 source_tx_hash: Hash::new([0x02; 32]),
//                 source_block_height: 100,
//                 timestamp: 1_700_000_000,
//             },
//             inclusion_proof,
//             finality_proof: CrossChainFinalityProof {
//                 source_chain,
//                 height: 100,
//                 current_height: 106,
//                 is_finalized: true,
//                 depth: 6,
//             },
//             hash_algorithm,
//             source_state_root: hash_algorithm.hash_bytes(&block_header),
//         }
//     }
// }
// 
//     #[test]
//     fn test_standard_verifier_accepts_matching_chain_and_hash_algorithm() {
//         let registry = Hash::new();
//         let verifier = StandardTransferVerifier::new(&registry);
//         let proof = sample_transfer_proof();
//         let result = verifier.verify_transfer_proof(&proof);
//         if let Err(e) = &result {
//             eprintln!("Verification failed: {:?}", e);
//         }
//         assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
//     }
// 
//     #[test]
//     fn test_standard_verifier_rejects_hash_algorithm_mismatch() {
//         let registry = Hash::new();
//         let verifier = StandardTransferVerifier::new(&registry);
//         let mut proof = sample_transfer_proof();
//         proof.hash_algorithm = CrossChainHashAlgorithm::Sha256;
//         assert!(matches!(
//             verifier.verify_transfer_proof(&proof),
//             Err(CrossChainError::InvalidInclusionProof)
//         ));
//     }
// 
//     #[test]
//     fn test_standard_verifier_rejects_chain_variant_mismatch() {
//         let registry = Hash::new();
//         let verifier = StandardTransferVerifier::new(&registry);
//         let mut proof = sample_transfer_proof();
//         proof.lock_event.source_chain = ChainId::new("ethereum");
//         assert!(matches!(
//             verifier.verify_transfer_proof(&proof),
//             Err(CrossChainError::InvalidInclusionProof)
//         ));
//     }
// }

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
    entries: alloc::collections::BTreeMap<Hash, CrossChainRegistryEntry>,
}

impl CrossChainRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            entries: alloc::collections::BTreeMap::new(),
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
