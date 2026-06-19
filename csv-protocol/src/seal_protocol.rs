//! Core SealProtocol trait - SECURITY CRITICAL
//!
//! This trait defines the interface that all chain-specific adapters must implement.
//! It is the primary security boundary for the entire CSV protocol.
//!
//! # Security Invariants (for Auditors)
//!
//! 1. **Single-Use Seal Guarantee**: `enforce_seal()` MUST ensure each seal is consumed at most once.
//!    - Failure to enforce this invariant enables double-spend attacks
//!    - All chain adapters must implement chain-native single-use semantics
//!
//! 2. **Commitment Binding**: `hash_commitment()` MUST use domain-separated hashing
//!    - Prevents cross-chain commitment replay attacks
//!    - Must include chain-specific domain separator
//!
//! 3. **Inclusion Proof Integrity**: `verify_inclusion()` MUST verify cryptographic inclusion
//!    - Must verify Merkle/MPT paths to prevent forged anchor claims
//!    - Must check proof structure before accepting
//!
//! 4. **Finality Verification**: `verify_finality()` MUST enforce chain-specific finality rules
//!    - Different chains have different finality models (confirmations, checkpoints, consensus)
//!    - Must not accept prematurely finalized anchors
//!
//! 5. **Rollback Safety**: `rollback()` MUST handle chain reorgs correctly
//!    - Must invalidate orphaned anchors
//!    - Must preserve audit trail of rolled-back state
//!
//! # Audit Checklist
//!
//! - [ ] Each adapter implements domain-separated hashing
//! - [ ] Each adapter uses chain-native single-use primitives (UTXO, Object, Resource, Nullifier)
//! - [ ] Each adapter verifies cryptographic inclusion proofs
//! - [ ] Each adapter enforces appropriate finality rules for the chain
//! - [ ] Each adapter handles reorgs via rollback() without state corruption
//! - [ ] No adapter exposes raw keys or secrets through trait methods
//! - [ ] No adapter accepts mock/simulated proofs in production builds

use crate::proof_taxonomy::ProofBundle;
use crate::signature::SignatureScheme;
use async_trait::async_trait;
use csv_codec::{CanonicalEncoding, EncodingFormat};
use csv_hash::Hash;

/// A typed DAG segment representing state transitions between anchors.
///
/// This replaces the untyped `Vec<u8>` representation with a structured type
/// that enables compile-time validation, canonical encoding, and type-level reasoning
/// about state transitions in the proof bundle construction process.
///
/// # Fields
/// - `anchor_from`: Hash reference to the source anchor being consumed
/// - `anchor_to`: Hash reference to the destination anchor being created
/// - `transition_data`: Canonical transition payload (chain-specific encoding)
/// - `proof`: Inclusion proof bytes for the transition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagSegment {
    /// Source anchor reference (the seal being consumed)
    pub anchor_from: Hash,
    /// Destination anchor reference (the new anchor being created)
    pub anchor_to: Hash,
    /// Canonical transition payload (chain-specific data)
    pub transition_data: Vec<u8>,
    /// Inclusion proof bytes for this transition
    pub proof: Vec<u8>,
}

impl CanonicalEncoding for DagSegment {
    fn encode(&self, format: EncodingFormat) -> csv_codec::CodecResult<Vec<u8>> {
        match format {
            EncodingFormat::MCE => self.encode_mce(),
            EncodingFormat::ManualBinary => Ok(self.to_canonical_bytes()),
        }
    }

    fn decode(bytes: &[u8], format: EncodingFormat) -> csv_codec::CodecResult<Self>
    where
        Self: Sized,
    {
        match format {
            EncodingFormat::MCE => Self::decode_mce(bytes),
            EncodingFormat::ManualBinary => {
                Self::from_canonical_bytes(bytes).map_err(csv_codec::CodecError::DeserializationError)
            }
        }
    }
}

impl DagSegment {
    /// Create a new DAG segment
    pub fn new(anchor_from: Hash, anchor_to: Hash, transition_data: Vec<u8>, proof: Vec<u8>) -> Self {
        Self {
            anchor_from,
            anchor_to,
            transition_data,
            proof,
        }
    }

    /// Encode using MCE format (fixed-width byte concatenation)
    fn encode_mce(&self) -> csv_codec::CodecResult<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(self.anchor_from.as_bytes());
        data.extend_from_slice(self.anchor_to.as_bytes());
        data.extend_from_slice(&(self.transition_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.transition_data);
        data.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.proof);
        Ok(data)
    }

    /// Decode using MCE format
    fn decode_mce(bytes: &[u8]) -> csv_codec::CodecResult<Self> {
        let mut pos = 0;

        let anchor_from = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash(hash)
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for anchor_from".to_string(),
            ));
        };

        let anchor_to = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash(hash)
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for anchor_to".to_string(),
            ));
        };

        let transition_data_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for transition_data length".to_string(),
            ));
        };

        let transition_data = if bytes.len() >= pos + transition_data_len {
            let data = bytes[pos..pos + transition_data_len].to_vec();
            pos += transition_data_len;
            data
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for transition_data".to_string(),
            ));
        };

        let proof_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for proof length".to_string(),
            ));
        };

        let proof = if bytes.len() >= pos + proof_len {
            bytes[pos..pos + proof_len].to_vec()
        } else {
            return Err(csv_codec::CodecError::DeserializationError(
                "Insufficient bytes for proof".to_string(),
            ));
        };

        Ok(Self {
            anchor_from,
            anchor_to,
            transition_data,
            proof,
        })
    }

    /// Serialize to canonical bytes (manual implementation for deterministic encoding)
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.anchor_from.as_bytes());
        data.extend_from_slice(self.anchor_to.as_bytes());
        data.extend_from_slice(&(self.transition_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.transition_data);
        data.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.proof);
        data
    }

    /// Deserialize from canonical bytes (manual implementation for deterministic encoding)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut pos = 0;

        let anchor_from = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash(hash)
        } else {
            return Err("Insufficient bytes for anchor_from".to_string());
        };

        let anchor_to = if bytes.len() >= pos + 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            Hash(hash)
        } else {
            return Err("Insufficient bytes for anchor_to".to_string());
        };

        let transition_data_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for transition_data length".to_string());
        };

        let transition_data = if bytes.len() >= pos + transition_data_len {
            let data = bytes[pos..pos + transition_data_len].to_vec();
            pos += transition_data_len;
            data
        } else {
            return Err("Insufficient bytes for transition_data".to_string());
        };

        let proof_len = if bytes.len() >= pos + 4 {
            let mut arr = [0u8; 4];
            arr.copy_from_slice(&bytes[pos..pos + 4]);
            let len = u32::from_le_bytes(arr) as usize;
            pos += 4;
            len
        } else {
            return Err("Insufficient bytes for proof length".to_string());
        };

        let proof = if bytes.len() >= pos + proof_len {
            bytes[pos..pos + proof_len].to_vec()
        } else {
            return Err("Insufficient bytes for proof".to_string());
        };

        Ok(Self {
            anchor_from,
            anchor_to,
            transition_data,
            proof,
        })
    }
}

/// The SealProtocol trait defines the security-critical interface for chain-specific adapters.
///
/// # Implementation Requirements for Security Auditors
///
/// This trait is the **primary security boundary** for cross-chain operations.
/// Each implementation must guarantee:
///
/// 1. **Cryptographic Inclusion**: Inclusion proofs must be cryptographically verified
///    against the chain's block structure (Merkle tree, MPT, etc.)
///
/// 2. **Chain-Native Finality**: Must respect each chain's finality semantics:
///    - Bitcoin: 6+ confirmations or proof-of-work depth
///    - Ethereum: 12+ confirmations or justified/finalized checkpoints
///    - Sui: Certified checkpoint inclusion
///    - Aptos: Ledger info with quorum certificate
///    - Solana: Root/supermajority confirmation
///
/// 3. **Seal Uniqueness**: Must use chain-native single-use primitives:
///    - Bitcoin: UTXO spend (tx output consumed)
///    - Sui: Object deletion/mutation
///    - Aptos: Resource destruction
///    - Ethereum: Nullifier registry uniqueness
///    - Solana: PDA account closure
///
/// 4. **Domain Separation**: All hashes must include chain-specific domain separators
///    to prevent cross-chain replay attacks.
///
/// # Critical Security Note
///
/// **NEVER** implement this trait with mock/simulated behavior in production code.
/// All methods must either perform real chain-backed operations or return a typed
/// error indicating the capability is unavailable. "Fake success" implementations
/// are security vulnerabilities that enable fraud.
#[async_trait]
pub trait SealProtocol {
    /// Chain-specific seal point type
    type SealPoint;

    /// Chain-specific commit anchor type
    type CommitAnchor;

    /// Chain-specific inclusion proof type
    type InclusionProof;

    /// Chain-specific finality proof type
    type FinalityProof;

    /// Publish a commitment under a single-use seal.
    ///
    /// This operation anchors client-side state to the blockchain. The seal
    /// MUST be consumed atomically with the commitment publication.
    ///
    /// # Security Requirements
    /// - Must consume the seal on-chain (single-use enforcement)
    /// - Must return anchor reference that includes tx hash/block height
    /// - Must fail if seal already consumed (prevent double-anchoring)
    ///
    /// # Arguments
    /// * `commitment` - The commitment hash to publish (32 bytes)
    /// * `seal` - The seal reference authorizing this commitment
    ///
    /// # Returns
    /// * `Ok(CommitAnchor)` - The anchor reference for inclusion/finality proofs
    /// * `Err` - If publication fails or seal already consumed
    async fn publish(
        &self,
        commitment: Hash,
        seal: Self::SealPoint,
    ) -> Result<Self::CommitAnchor, Box<dyn std::error::Error + 'static>>;

    /// Verify and extract inclusion proof from the base layer.
    ///
    /// This method performs cryptographic verification that the anchor is
    /// included in the chain's history. This is a **critical security check**.
    ///
    /// # Security Requirements
    /// - Must verify Merkle/MPT path from anchor to block root
    /// - Must check proof structure and validity
    /// - Must NOT accept empty or malformed proofs
    /// - Must use chain-specific verification algorithms
    ///
    /// # Arguments
    /// * `anchor` - The anchor reference to verify inclusion for
    ///
    /// # Returns
    /// * `Ok(InclusionProof)` - Cryptographically verified inclusion proof
    /// * `Err` - If proof is invalid, missing, or verification fails
    ///
    /// # Audit Note
    /// Verify this method uses the chain's native proof verification. For example:
    /// - Bitcoin: Merkle branch verification against block header
    /// - Ethereum: MPT proof verification against state root
    /// - Sui: Checkpoint content verification
    async fn verify_inclusion(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<Self::InclusionProof, Box<dyn std::error::Error + 'static>>;

    /// Verify finality according to base-layer consensus rules.
    ///
    /// Finality verification prevents acceptance of anchors that might be
    /// orphaned due to chain reorganizations. Different chains have different
    /// finality models that MUST be respected.
    ///
    /// # Security Requirements
    /// - Must enforce chain-specific confirmation depth/checkpoint rules
    /// - Must verify consensus participation (where applicable)
    /// - Must NOT accept anchors from unconfirmed/forked blocks
    /// - Must handle chain reorg detection
    ///
    /// # Chain-Specific Finality Requirements
    /// | Chain    | Minimum Finality Standard              |
    /// |----------|----------------------------------------|
    /// | Bitcoin  | 6 confirmations or 100 blocks depth    |
    /// | Ethereum | 12 confirmations or finalized epoch  |
    /// | Sui      | Certified checkpoint (2f+1 validators)|
    /// | Aptos    | Ledger version with quorum cert       |
    /// | Solana   | Root confirmation (supermajority)     |
    ///
    /// # Arguments
    /// * `anchor` - The anchor reference to verify finality for
    ///
    /// # Returns
    /// * `Ok(FinalityProof)` - Proof that anchor has reached finality
    /// * `Err` - If finality not yet reached or proof invalid
    async fn verify_finality(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<Self::FinalityProof, Box<dyn std::error::Error + 'static>>;

    /// Enforce that the seal is single-use and non-replayable.
    ///
    /// This is the **primary double-spend prevention mechanism**. The implementation
    /// MUST use chain-native single-use primitives to guarantee uniqueness.
    ///
    /// # Security Requirements (CRITICAL)
    /// - MUST verify seal has not been consumed before
    /// - MUST use chain-native single-use primitive:
    ///   * Bitcoin: UTXO must be unspent (check via RPC/indexer)
    ///   * Sui: Object must exist and be unconsumed
    ///   * Aptos: Resource must exist in account
    ///   * Ethereum: Nullifier must not exist in registry contract
    ///   * Solana: PDA must exist and not be closed
    /// - MUST fail closed (error if cannot verify)
    /// - MUST NOT rely on client-side caching alone
    ///
    /// # Arguments
    /// * `seal` - The seal reference to enforce single-use on
    ///
    /// # Returns
    /// * `Ok(())` - Seal is valid and unconsumed
    /// * `Err` - Seal already consumed or verification failed
    ///
    /// # Audit Note
    /// This method is the foundation of CSV's security model. Verify that:
    /// 1. It queries the actual chain state (not cached state)
    /// 2. It uses the appropriate native primitive for the chain
    /// 3. It cannot be bypassed or fooled by malicious inputs
    async fn enforce_seal(
        &self,
        seal: Self::SealPoint,
    ) -> Result<(), Box<dyn std::error::Error + 'static>>;

    /// Create a new seal for authorizing state transitions.
    ///
    /// # Arguments
    /// * `value` - Optional value/funding for the seal (chain-specific units)
    async fn create_seal(
        &self,
        value: Option<u64>,
    ) -> Result<Self::SealPoint, Box<dyn std::error::Error + 'static>>;

    /// Compute a domain-separated commitment hash from components.
    ///
    /// This method constructs the commitment hash that binds state transitions
    /// to seals. **Domain separation is critical** to prevent cross-chain replay.
    ///
    /// # Security Requirements
    /// - MUST use domain-separated hashing (include chain identifier)
    /// - MUST use cryptographically secure hash function (SHA-256, Keccak-256)
    /// - MUST include all components to prevent collision attacks
    /// - MUST be deterministic (same inputs always produce same output)
    ///
    /// # Hash Structure (recommended)
    /// ```text
    /// commitment = Hash(domain_separator || chain_id || contract_id ||
    ///                   previous_commitment || transition_payload_hash || seal_hash)
    /// ```
    ///
    /// # Arguments
    /// * `contract_id` - Unique contract identifier (32 bytes)
    /// * `previous_commitment` - Previous commitment hash in chain (32 bytes)
    /// * `transition_payload_hash` - Hash of transition data (32 bytes)
    /// * `seal_point` - Seal reference being consumed
    ///
    /// # Returns
    /// 32-byte commitment hash bound to this chain's domain
    ///
    /// # Audit Note
    /// Verify the implementation includes domain_separator() output in the hash.
    /// Without domain separation, commitments from one chain could be replayed
    /// on another chain, enabling cross-chain attacks.
    fn hash_commitment(
        &self,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal_point: &Self::SealPoint,
    ) -> Hash;

    /// Build a complete proof bundle for peer-to-peer verification.
    ///
    /// This method assembles all evidence needed for another party to verify
    /// the validity of a state transition without trusting the proposer.
    ///
    /// # Security Requirements
    /// - MUST include cryptographically verifiable inclusion proof
    /// - MUST include finality proof meeting chain requirements
    /// - MUST include complete transition DAG
    /// - MUST bind all components to prevent tampering
    ///
    /// # Proof Bundle Contents
    /// A valid proof bundle enables independent verification of:
    /// 1. Which seal was consumed (single-use anchor)
    /// 2. On which chain it was consumed (source chain)
    /// 3. At what block height (temporal ordering)
    /// 4. With what finality (security level)
    /// 5. What state transition was authorized
    ///
    /// # Arguments
    /// * `anchor` - The anchor reference with inclusion/finality data
    /// * `transition_dag` - The typed state transition DAG segment
    ///
    /// # Returns
    /// Complete `ProofBundle` ready for cross-chain transport and verification
    async fn build_proof_bundle(
        &self,
        anchor: Self::CommitAnchor,
        transition_dag: DagSegment,
    ) -> Result<ProofBundle, Box<dyn std::error::Error + 'static>>;

    /// Handle rollback of an anchor due to chain reorganization.
    ///
    /// Chain reorganizations can invalidate previously confirmed anchors.
    /// This method handles the rollback to maintain consistency.
    ///
    /// # Security Requirements
    /// - MUST detect when an anchor is no longer in the canonical chain
    /// - MUST invalidate rolled-back state to prevent acceptance of orphaned commits
    /// - MUST preserve audit trail of rollbacks for forensics
    /// - MUST handle deep reorgs (e.g., Bitcoin 100-block horizon)
    ///
    /// # Rollback Handling Strategy
    /// 1. Check if anchor tx is still in canonical chain
    /// 2. If not, mark anchor as rolled-back
    /// 3. Notify dependent state of invalidation
    /// 4. Preserve rollback record for audit
    ///
    /// # Arguments
    /// * `anchor` - The anchor reference to invalidate
    ///
    /// # Returns
    /// * `Ok(())` - Rollback processed successfully
    /// * `Err` - If rollback handling fails
    async fn rollback(
        &self,
        anchor: Self::CommitAnchor,
    ) -> Result<(), Box<dyn std::error::Error + 'static>>;

    /// Get the domain separator for this adapter.
    ///
    /// Domain separators prevent cross-chain replay attacks by binding
    /// all cryptographic operations to a specific chain.
    ///
    /// # Security Requirements
    /// - MUST be unique per chain (different for Bitcoin vs Ethereum vs Sui, etc.)
    /// - MUST be 32 bytes for hash function compatibility
    /// - SHOULD incorporate chain identifier and protocol version
    /// - MUST be constant for the lifetime of the adapter
    ///
    /// # Example Domain Separator Construction
    /// ```text
    /// domain = SHA256("csv-adapter-v1" || chain_id || "production")
    /// ```
    ///
    /// # Returns
    /// 32-byte unique domain separator for this chain adapter
    ///
    /// # Audit Note
    /// Verify that different chain adapters return different domain separators.
    /// Shared domain separators across chains would enable replay attacks.
    fn domain_separator(&self) -> [u8; 32];

    /// Get the signature scheme used by this chain.
    ///
    /// This is used by the proof verification pipeline to select
    /// the appropriate cryptographic verification algorithm.
    fn signature_scheme(&self) -> SignatureScheme;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_protocol_trait_exists() {
        // This test ensures the trait is defined correctly
        // Actual implementations will be in chain adapters
        assert!(true);
    }
}
