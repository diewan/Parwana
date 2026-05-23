//! Sanad and envelope types (stable API compatibility layer).

pub use csv_hash::sanad::SanadId;

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, Result};
use crate::signature::SignatureScheme;
use csv_hash::canonical::{from_canonical_cbor, to_canonical_cbor};
use csv_hash::{Commitment, Hash};

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sanad {
    /// Unique Sanad identifier
    pub id: SanadId,
    /// Commitment hash binding state
    pub commitment: Hash,
    /// Ownership proof
    pub owner: OwnershipProof,
    /// Salt used in ID derivation
    pub salt: Vec<u8>,
    /// Consumption nullifier when the Sanad seal has been spent
    pub nullifier: Option<Hash>,
}

impl Sanad {
    /// Create a new Sanad from commitment, owner proof, and salt.
    pub fn new(commitment: Hash, owner: OwnershipProof, salt: &[u8]) -> Self {
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(commitment.as_bytes());
        let id = SanadId::new(id_bytes);
        Self {
            id,
            commitment,
            owner,
            salt: salt.to_vec(),
            nullifier: None,
        }
    }

    /// Create from an existing commitment object.
    pub fn from_commitment(commitment: &Commitment, owner: OwnershipProof, salt: &[u8]) -> Self {
        Self::new(commitment.commitment_hash(), owner, salt)
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
}

impl SanadEnvelope {
    /// Canonical schema id for version 1 envelopes.
    pub const SCHEMA_ID: &'static str = "csv.sanad.envelope.v1";

    /// Build envelope from a [`Sanad`].
    pub fn from_sanad(sanad: &Sanad) -> Self {
        Self {
            version: 1,
            schema_id: Self::SCHEMA_ID.to_string(),
            sanad_id: Hash::new(*sanad.id.as_bytes()),
            payload_hash: sanad.commitment,
            merkle_root: None,
        }
    }
}

/// Protocol schema version constant (compatibility).
pub const SCHEMA_VERSION: u8 = 1;

/// Minimal schema descriptor for SDK consumers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub id: String,
    pub version: u8,
}
