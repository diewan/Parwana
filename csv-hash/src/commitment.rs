//! Commitment type with canonical encoding (MPC-aware, multi-protocol)
//!
//! Commitments bind off-chain state transitions to the anchoring layer.
//! Each commitment is a node in a **commitment chain** — a sequence of
//! linked state transitions that clients validate independently of the blockchain.
//!
//! ## Stability Guarantee
//!
//! **Only V2 is supported.** V1 was removed to prevent silent divergence
//! between clients. All commitments must use the V2 format. This format
//! will not change without a version bump and backward-compatible migration.

use std::vec::Vec;

use crate::Hash;
use crate::commit_mux::CommitMux;
use crate::csv_tagged_hash;
use crate::seal::SealPoint;
use crate::{DomainSeparatedHash, TransferCommitmentDomain};

/// Current commitment format version.
///
/// This constant is the authoritative version number. Any commitment
/// with `version != COMMITMENT_VERSION` should be rejected.
pub const COMMITMENT_VERSION: u8 = 2;

/// A V2 commitment binding state to an anchor.
///
/// A commitment is the core data structure in CSV. It captures everything
/// needed to verify a state transition:
///
/// - **Which protocol** it belongs to (`protocol_id`)
/// - **What state** it represents (`mpc_root`, `contract_id`)
/// - **Where it came from** (`previous_commitment`)
/// - **What changed** (`transition_payload_hash`)
/// - **What seal was consumed** (`seal_id`)
/// - **Which chain context** it's valid in (`domain_separator`)
///
/// ## Commitment Chain
///
/// Commitments form a linked chain: each commitment references the hash
/// of the previous one via `previous_commitment`. Clients validate the
/// entire chain from genesis to the current state without querying the
/// blockchain for each step.
///
/// ## Collision Resistance
///
/// Each field is hashed with a unique domain tag (e.g., `"commitment-version"`,
/// `"commitment-protocol-id"`) using [`csv_tagged_hash`]. This prevents
/// cross-field collisions and ensures that different commitment versions
/// produce different hashes even if their fields are otherwise identical.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Commitment {
    /// Commitment format version (MUST be `COMMITMENT_VERSION`)
    pub version: u8,
    /// Protocol identifier (hash)
    pub protocol_id: Hash,
    /// MPC tree root (hash of all protocol commitments)
    pub mpc_root: Hash,
    /// Contract identifier (hash of contract address)
    pub contract_id: Hash,
    /// Hash of previous commitment in the chain (zero for genesis)
    pub previous_commitment: Hash,
    /// Hash of the transition payload
    pub transition_payload_hash: Hash,
    /// Hash of the seal that was consumed
    pub seal_id: Hash,
    /// Domain separator for chain context
    pub domain_separator: [u8; 32],
}

impl Commitment {
    /// Create a new commitment from its components.
    ///
    /// # Arguments
    /// * `protocol_id` - Protocol identifier (hash)
    /// * `mpc_root` - MPC tree root hash
    /// * `contract_id` - Contract identifier (hash)
    /// * `previous_commitment` - Hash of previous commitment (zero for genesis)
    /// * `transition_payload_hash` - Hash of the transition payload
    /// * `seal` - The seal that was consumed
    /// * `domain_separator` - Domain separator for chain context (32 bytes)
    ///
    /// # Returns
    /// A new commitment with the computed seal_id.
    pub fn new(
        protocol_id: Hash,
        mpc_root: Hash,
        contract_id: Hash,
        previous_commitment: Hash,
        transition_payload_hash: Hash,
        seal: &SealPoint,
        domain_separator: [u8; 32],
    ) -> Self {
        // Compute seal_id from the seal point
        let seal_id = Self::compute_seal_id(seal);

        Self {
            version: COMMITMENT_VERSION,
            protocol_id,
            mpc_root,
            contract_id,
            previous_commitment,
            transition_payload_hash,
            seal_id,
            domain_separator,
        }
    }

    /// Create a simple commitment (single-protocol, no MPC).
    ///
    /// This is a convenience method for single-protocol commitments where
    /// the MPC tree contains only one leaf (the protocol's own commitment).
    ///
    /// # Arguments
    /// * `protocol_id` - Protocol identifier (hash)
    /// * `commitment_hash` - The protocol's commitment hash
    /// * `contract_id` - Contract identifier (hash)
    /// * `seal` - The seal that was consumed
    /// * `domain_separator` - Domain separator for chain context (32 bytes)
    ///
    /// # Returns
    /// A new commitment with the computed mpc_root and seal_id.
    pub fn simple(
        protocol_id: Hash,
        commitment_hash: Hash,
        contract_id: Hash,
        seal: &SealPoint,
        domain_separator: [u8; 32],
    ) -> Self {
        // Create a single-leaf MPC tree
        let commit_mux = CommitMux::from_pairs(&[(*protocol_id.as_bytes(), commitment_hash)]);
        let mpc_root = commit_mux.root();

        Self::new(
            protocol_id,
            mpc_root,
            contract_id,
            Hash::zero(),
            commitment_hash,
            seal,
            domain_separator,
        )
    }

    /// Compute the commitment hash.
    ///
    /// This is the hash that gets committed on-chain. It includes all fields
    /// of the commitment, ensuring that any modification to the commitment
    /// results in a different on-chain commitment.
    ///
    /// # Returns
    /// The commitment hash.
    pub fn commitment_hash(&self) -> Hash {
        let domain_separator =
            DomainSeparatedHash::<TransferCommitmentDomain>::hash(&self.domain_separator);
        let commitment_hash = csv_tagged_hash("commitment-hash", &self.to_canonical_bytes());
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(domain_separator.as_bytes());
        combined.extend_from_slice(&commitment_hash);
        Hash::new(csv_tagged_hash("commitment-final", &combined))
    }

    /// Compute the commitment hash (alias for commitment_hash).
    ///
    /// # Returns
    /// The commitment hash.
    pub fn hash(&self) -> Hash {
        self.commitment_hash()
    }

    /// Compute the seal_id from a seal point.
    ///
    /// The seal_id is the hash of the canonical serialization of the seal point.
    ///
    /// # Arguments
    /// * `seal` - The seal point
    ///
    /// # Returns
    /// The seal_id hash.
    fn compute_seal_id(seal: &SealPoint) -> Hash {
        let seal_bytes = seal.to_canonical_bytes().unwrap_or_else(|err| {
            format!("seal-id-canonical-serialization-error:{err}").into_bytes()
        });
        Hash::new(csv_tagged_hash("seal-id", &seal_bytes))
    }

   /// Serialize to canonical bytes for hashing.
    ///
    /// Format: `[version][protocol_id][mpc_root][contract_id][previous_commitment][transition_payload_hash][seal_id][domain_separator]`
    ///
    /// # Returns
    /// The canonical encoding of this commitment.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + 32 * 6 + 32);
        data.push(self.version);
        data.extend_from_slice(self.protocol_id.as_bytes());
        data.extend_from_slice(self.mpc_root.as_bytes());
        data.extend_from_slice(self.contract_id.as_bytes());
        data.extend_from_slice(self.previous_commitment.as_bytes());
        data.extend_from_slice(self.transition_payload_hash.as_bytes());
        data.extend_from_slice(self.seal_id.as_bytes());
        data.extend_from_slice(&self.domain_separator);
        data
    }

    /// Check if this is a genesis commitment (no previous commitment).
    ///
    /// # Returns
    /// `true` if `previous_commitment` is zero, `false` otherwise.
    pub fn is_genesis(&self) -> bool {
        self.previous_commitment == Hash::zero()
    }

    /// Validate the commitment structure.
    ///
    /// # Returns
    /// `true` if the commitment is structurally valid, `false` otherwise.
    pub fn is_valid(&self) -> bool {
        self.version == COMMITMENT_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_commitment_commitment() -> Commitment {
        Commitment::simple(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            &SealPoint::new(vec![4u8; 16], Some(42), None).unwrap(),
            [5u8; 32],
        )
    }

    #[test]
    fn test_commitment_creation() {
        let commitment = test_commitment_commitment();
        assert_eq!(commitment.version, COMMITMENT_VERSION);
        assert!(commitment.is_valid());
    }

    #[test]
    fn test_commitment_genesis() {
        let commitment = Commitment::simple(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            &SealPoint::new(vec![4u8; 16], Some(42), None).unwrap(),
            [5u8; 32],
        );
        assert!(commitment.is_genesis());
    }

    #[test]
    fn test_commitment_non_genesis() {
        let commitment = Commitment::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
            Hash::new([5u8; 32]),
            &SealPoint::new(vec![6u8; 16], Some(42), None).unwrap(),
            [7u8; 32],
        );
        assert!(!commitment.is_genesis());
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        let commitment1 = test_commitment_commitment();
        let commitment2 = test_commitment_commitment();
        assert_eq!(commitment1.commitment_hash(), commitment2.commitment_hash());
    }

    #[test]
    fn test_commitment_invalid_version() {
        let mut commitment = test_commitment_commitment();
        commitment.version = 99;
        assert!(!commitment.is_valid());
    }
}
