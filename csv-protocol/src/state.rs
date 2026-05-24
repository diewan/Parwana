//! Typed state enums for CSV contracts
//!
//! These types define the structured state that contracts operate on.
//! Unlike opaque byte vectors, typed state enables schema validation
//! and consumer-friendly decoding.

use csv_hash::Hash;
use csv_hash::seal::SealPoint;
use serde::{Deserialize, Serialize};

/// Unique identifier for a state type within a schema
pub type StateTypeId = u16;

/// Global state: contract-wide values visible to all parties
///
/// Examples: total supply, epoch number, configuration flags.
/// Global state is not tied to any specific seal or owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GlobalState {
    /// Type identifier (defined in the schema)
    pub type_id: StateTypeId,
    /// Serialized state data (schema-defined format)
    pub data: Vec<u8>,
}

impl GlobalState {
    /// Create new global state
    pub fn new(type_id: StateTypeId, data: Vec<u8>) -> Self {
        Self { type_id, data }
    }

    /// Create global state from a single hash value
    pub fn from_hash(type_id: StateTypeId, value: Hash) -> Self {
        Self {
            type_id,
            data: value.to_vec(),
        }
    }

    /// Get the state as a hash (convenience for 32-byte states)
    pub fn as_hash(&self) -> Option<Hash> {
        if self.data.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&self.data);
            Some(Hash::new(bytes))
        } else {
            None
        }
    }
}

/// Owned state: state bound to a specific single-use seal
///
/// Examples: token ownership, NFT assignment, escrow position.
/// Only the seal owner can consume or transfer this state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnedState {
    /// Type identifier (defined in the schema)
    pub type_id: StateTypeId,
    /// The seal that owns this state
    pub seal: SealPoint,
    /// Serialized state data (schema-defined format)
    pub data: Vec<u8>,
}

impl OwnedState {
    /// Create new owned state
    pub fn new(type_id: StateTypeId, seal: SealPoint, data: Vec<u8>) -> Self {
        Self {
            type_id,
            seal,
            data,
        }
    }

    /// Create owned state from a single hash value
    pub fn from_hash(type_id: StateTypeId, seal: SealPoint, value: Hash) -> Self {
        Self {
            type_id,
            seal,
            data: value.to_vec(),
        }
    }

    /// Get the state as a hash (convenience for 32-byte states)
    pub fn as_hash(&self) -> Option<Hash> {
        if self.data.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&self.data);
            Some(Hash::new(bytes))
        } else {
            None
        }
    }
}

/// Metadata: auxiliary data attached to state transitions
///
/// Examples: timestamps, annotations, oracle feeds.
/// Metadata is not validated by the VM and is opaque to consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Metadata {
    /// Metadata key (human-readable identifier)
    pub key: String,
    /// Serialized metadata value
    pub value: Vec<u8>,
}

impl Metadata {
    /// Create new metadata
    pub fn new(key: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }

    /// Create metadata from a string value
    pub fn from_string(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into().into_bytes(),
        }
    }

    /// Try to decode value as UTF-8 string
    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.value.clone()).ok()
    }
}

/// State assignment: specifies which seal receives which state
///
/// Used in transitions to declare new owned state outputs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateAssignment {
    /// Type of state being assigned
    pub type_id: StateTypeId,
    /// Seal that will own this state
    pub seal: SealPoint,
    /// State data
    pub data: Vec<u8>,
}

impl StateAssignment {
    /// Create new state assignment
    pub fn new(type_id: StateTypeId, seal: SealPoint, data: Vec<u8>) -> Self {
        Self {
            type_id,
            seal,
            data,
        }
    }
}

/// State reference: identifies existing state to consume
///
/// Used in transitions to declare owned state inputs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateRef {
    /// Type of state being referenced
    pub type_id: StateTypeId,
    /// Commitment hash that created this state
    pub commitment: Hash,
    /// Index within the commitment's outputs
    pub output_index: u32,
}

impl StateRef {
    /// Create new state reference
    pub fn new(type_id: StateTypeId, commitment: Hash, output_index: u32) -> Self {
        Self {
            type_id,
            commitment,
            output_index,
        }
    }
}
