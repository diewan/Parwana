//! Sanad types with payload descriptor support
//!
//! A Sanad is a verifiable, single-use digital asset that binds:
//! - A content descriptor (schema, payload hash, content root, etc.)
//! - A commitment hash
//! - An owner proof
//! - A salt for uniqueness
//!
//! The Sanad ID is derived via domain-separated tagged hashing:
//! ```text
//! SanadId = tagged_hash("csv.sanad.id.v1", descriptor_hash || commitment || salt)
//! ```
//!
//! This ensures the descriptor is cryptographically bound to the Sanad identity,
//! preventing two implementations from creating different Sanads for the same content.

pub use csv_hash::sanad::SanadId;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result};
use crate::signature::SignatureScheme;
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_hash::{Commitment, Hash};

/// Canonical payload descriptor for a Sanad.
///
/// This descriptor binds all content metadata to the Sanad identity.
/// The descriptor is serialized to canonical CBOR and hashed; the hash
/// is included in SanadId derivation.
///
/// ## Design Rationale
///
/// The descriptor is NOT stored on-chain. Only its hash is committed.
/// This keeps on-chain storage minimal while ensuring off-chain
/// implementations can verify content binding via the descriptor hash.
///
/// ## Fields
///
/// - `schema_id`: Registered schema identifier for payload structure
/// - `schema_hash`: Hash of the schema definition (for versioning)
/// - `payload_codec`: Canonical serialization codec (CBOR, etc.)
/// - `payload_hash`: Hash of the actual payload content
/// - `content_root`: Optional Merkle root over content subtrees
/// - `attachment_root`: Optional root over attachment hashes
/// - `claims_root`: Optional root over claim hashes
/// - `participants_root`: Optional root over participant hashes
/// - `disclosure_policy_hash`: Hash of the disclosure policy
/// - `proof_policy_hash`: Hash of the proof policy
/// - `resource_limits_hash`: Hash of resource limits (max size, depth, etc.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadPayloadDescriptor {
    /// Schema identifier (e.g., "csv.sanad.content.v1")
    pub schema_id: String,
    /// Hash of the schema definition for versioning
    pub schema_hash: Hash,
    /// Canonical serialization codec identifier
    pub payload_codec: u8,
    /// Hash of the payload content
    pub payload_hash: Hash,
    /// Optional Merkle root over content subtrees
    pub content_root: Option<Hash>,
    /// Optional root over attachment hashes
    pub attachment_root: Option<Hash>,
    /// Optional root over claim hashes
    pub claims_root: Option<Hash>,
    /// Optional root over participant hashes
    pub participants_root: Option<Hash>,
    /// Hash of the disclosure policy
    pub disclosure_policy_hash: Hash,
    /// Hash of the proof policy
    pub proof_policy_hash: Hash,
    /// Hash of resource limits
    pub resource_limits_hash: Hash,
}

impl SanadPayloadDescriptor {
    /// Canonical schema ID for version 1 descriptors.
    pub const SCHEMA_ID: &'static str = "csv.sanad.descriptor.v1";

    /// Create a new descriptor with default resource limits.
    pub fn new(
        schema_id: impl Into<String>,
        schema_hash: Hash,
        payload_codec: u8,
        payload_hash: Hash,
        content_root: Option<Hash>,
        disclosure_policy_hash: Hash,
        proof_policy_hash: Hash,
    ) -> Self {
        Self {
            schema_id: schema_id.into(),
            schema_hash,
            payload_codec,
            payload_hash,
            content_root,
            attachment_root: None,
            claims_root: None,
            participants_root: None,
            disclosure_policy_hash,
            proof_policy_hash,
            resource_limits_hash: Hash::new([0u8; 32]), // Default: no resource limits
        }
    }

    /// Compute the canonical descriptor hash (CBOR-serialized, then hashed).
    ///
    /// This hash is what gets bound into the SanadId derivation.
    pub fn compute_hash(&self) -> Hash {
        match to_canonical_cbor(self) {
            Ok(bytes) => Hash::sha256(&bytes),
            Err(_) => {
                // Fallback: if canonical serialization fails, use a zero hash.
                // In production, this should never happen for well-formed descriptors.
                Hash::new([0u8; 32])
            }
        }
    }

    /// Set the attachment root.
    pub fn with_attachment_root(mut self, root: Hash) -> Self {
        self.attachment_root = Some(root);
        self
    }

    /// Set the claims root.
    pub fn with_claims_root(mut self, root: Hash) -> Self {
        self.claims_root = Some(root);
        self
    }

    /// Set the participants root.
    pub fn with_participants_root(mut self, root: Hash) -> Self {
        self.participants_root = Some(root);
        self
    }

    /// Set the resource limits hash.
    pub fn with_resource_limits(mut self, hash: Hash) -> Self {
        self.resource_limits_hash = hash;
        self
    }
}

/// Ownership proof binding a Sanad to an owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipProof {
    /// Proof bytes (chain-specific or generic)
    pub proof: Vec<u8>,
    /// Owner identifier (address bytes)
    pub owner: Vec<u8>,
    /// Optional signature scheme hint
    pub scheme: Option<SignatureScheme>,
}

/// A verifiable, single-use digital Sanad (client-side state).
///
/// The Sanad binds a payload descriptor to a commitment and owner.
/// The Sanad ID is derived from the descriptor hash, commitment, and salt,
/// ensuring content metadata is cryptographically bound to the identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sanad {
    /// Unique Sanad identifier (domain-separated hash of descriptor || commitment || salt)
    pub id: SanadId,
    /// Commitment hash binding state
    pub commitment: Hash,
    /// Ownership proof
    pub owner: OwnershipProof,
    /// Salt used in ID derivation
    pub salt: Vec<u8>,
    /// Consumption nullifier when the Sanad seal has been spent
    pub nullifier: Option<Hash>,
    /// The payload descriptor hash (bound into SanadId)
    pub descriptor_hash: Hash,
}

impl Sanad {
    /// Create a new Sanad from a payload descriptor, commitment, owner proof, and salt.
    ///
    /// The Sanad ID is derived via domain-separated tagged hashing:
    /// ```text
    /// SanadId = tagged_hash("csv.sanad.id.v1", descriptor_hash || commitment || salt)
    /// ```
    ///
    /// ## Arguments
    ///
    /// * `descriptor` — The payload descriptor binding content metadata
    /// * `commitment` — The commitment hash
    /// * `owner` — The ownership proof
    /// * `salt` — Salt bytes for uniqueness
    pub fn new(
        descriptor: &SanadPayloadDescriptor,
        commitment: Hash,
        owner: OwnershipProof,
        salt: &[u8],
    ) -> Self {
        let descriptor_hash = descriptor.compute_hash();
        let id = SanadId::from_descriptor_commitment(descriptor_hash, commitment, salt);
        Self {
            id,
            commitment,
            owner,
            salt: salt.to_vec(),
            nullifier: None,
            descriptor_hash,
        }
    }

    /// Create from an existing commitment object.
    pub fn from_commitment(
        descriptor: &SanadPayloadDescriptor,
        commitment: &Commitment,
        owner: OwnershipProof,
        salt: &[u8],
    ) -> Self {
        Self::new(descriptor, commitment.commitment_hash(), owner, salt)
    }

    /// Serialize to canonical CBOR bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        to_canonical_cbor(self).map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }

    /// Deserialize from canonical CBOR bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        from_canonical_cbor(bytes).map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }
}

/// Wire-format Sanad envelope (golden corpus schema `csv.sanad.envelope.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanadEnvelope {
    /// Envelope schema version
    pub version: u8,
    /// Registered schema identifier
    pub schema_id: String,
    /// Sanad identity hash
    pub sanad_id: Hash,
    /// Payload content hash
    pub payload_hash: Hash,
    /// Optional Merkle root over content subtrees
    pub merkle_root: Option<Hash>,
    /// Descriptor hash (new in v2)
    pub descriptor_hash: Option<Hash>,
}

impl SanadEnvelope {
    /// Canonical schema id for envelopes (with descriptor).
    pub const SCHEMA_ID: &'static str = "csv.sanad.envelope.v2";

    /// Build envelope from a [`Sanad`].
    pub fn from_sanad(sanad: &Sanad) -> Self {
        Self {
            version: 2,
            schema_id: Self::SCHEMA_ID.to_string(),
            sanad_id: Hash::new(*sanad.id.as_bytes()),
            payload_hash: sanad.commitment,
            merkle_root: None,
            descriptor_hash: Some(sanad.descriptor_hash),
        }
    }
}

/// Protocol schema version constant (compatibility).
pub const SCHEMA_VERSION: u8 = 2;

/// Minimal schema descriptor for SDK consumers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub id: String,
    pub version: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_hash::Hash;

    #[test]
    fn test_descriptor_hash_is_deterministic() {
        let desc = SanadPayloadDescriptor::new(
            "test.schema",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let h1 = desc.compute_hash();
        let h2 = desc.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sanad_id_uses_descriptor() {
        let desc1 = SanadPayloadDescriptor::new(
            "schema1",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let desc2 = SanadPayloadDescriptor::new(
            "schema2",
            Hash::new([5u8; 32]),
            1,
            Hash::new([6u8; 32]),
            None,
            Hash::new([7u8; 32]),
            Hash::new([8u8; 32]),
        );
        let commitment = Hash::new([0xAAu8; 32]);
        let salt = b"test-salt";

        let id1 = SanadId::from_descriptor_commitment(desc1.compute_hash(), commitment, salt);
        let id2 = SanadId::from_descriptor_commitment(desc2.compute_hash(), commitment, salt);

        // Different descriptors produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sanad_id_uses_salt() {
        let desc = SanadPayloadDescriptor::new(
            "schema",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let commitment = Hash::new([0xAAu8; 32]);
        let salt1 = b"salt-1";
        let salt2 = b"salt-2";

        let id1 = SanadId::from_descriptor_commitment(desc.compute_hash(), commitment, salt1);
        let id2 = SanadId::from_descriptor_commitment(desc.compute_hash(), commitment, salt2);

        // Different salts produce different IDs
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sanad_new_includes_descriptor_hash() {
        let desc = SanadPayloadDescriptor::new(
            "schema",
            Hash::new([1u8; 32]),
            1,
            Hash::new([2u8; 32]),
            None,
            Hash::new([3u8; 32]),
            Hash::new([4u8; 32]),
        );
        let commitment = Hash::new([0xAAu8; 32]);
        let owner = OwnershipProof {
            proof: vec![0u8; 32],
            owner: vec![0u8; 32],
            scheme: None,
        };
        let salt = b"test-salt";

        let sanad = Sanad::new(&desc, commitment, owner, salt);
        assert_eq!(sanad.descriptor_hash, desc.compute_hash());
    }

    #[test]
    fn test_sanad_with_zero_descriptor_hash() {
        let commitment = Hash::new([0xAAu8; 32]);
        let descriptor = SanadPayloadDescriptor::new(
            SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([0u8; 32]),
            1,
            commitment,
            None,
            Hash::new([0u8; 32]),
            Hash::new([0u8; 32]),
        );
        let owner = OwnershipProof {
            proof: vec![0u8; 32],
            owner: vec![0u8; 32],
            scheme: None,
        };
        let salt = b"test-salt";

        let sanad = Sanad::new(&descriptor, commitment, owner, salt);
        // The descriptor_hash should be the hash of the descriptor, not zero
        assert_ne!(sanad.descriptor_hash, Hash::new([0u8; 32]));
        // Verify the descriptor_hash matches the descriptor's compute_hash
        assert_eq!(sanad.descriptor_hash, descriptor.compute_hash());
    }
}
