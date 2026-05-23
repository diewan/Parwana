//! Typed state enums for CSV contracts
//!
//! These types define the structured state that contracts operate on.
//! Unlike opaque byte vectors, typed state enables schema validation
//! and consumer-friendly decoding.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use csv_hash::Hash;
use csv_hash::seal::SealPoint;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_state_creation() {
        let state = GlobalState::new(1, vec![1, 2, 3]);
        assert_eq!(state.type_id, 1);
        assert_eq!(state.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_global_state_from_hash() {
        let hash = Hash::new([42u8; 32]);
        let state = GlobalState::from_hash(1, hash);
        assert_eq!(state.type_id, 1);
        assert_eq!(state.as_hash(), Some(hash));
    }

    #[test]
    fn test_global_state_wrong_size() {
        let state = GlobalState::new(1, vec![1, 2]); // Not 32 bytes
        assert!(state.as_hash().is_none());
    }

    #[test]
    fn test_owned_state_creation() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        let state = OwnedState::new(2, seal.clone(), vec![4, 5, 6]);
        assert_eq!(state.type_id, 2);
        assert_eq!(state.seal, seal);
        assert_eq!(state.data, vec![4, 5, 6]);
    }

    #[test]
    fn test_owned_state_from_hash() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        let hash = Hash::new([99u8; 32]);
        let state = OwnedState::from_hash(2, seal.clone(), hash);
        assert_eq!(state.seal, seal);
        assert_eq!(state.as_hash(), Some(hash));
    }

    #[test]
    fn test_metadata_creation() {
        let meta = Metadata::new("timestamp", 1700000000u64.to_le_bytes().to_vec());
        assert_eq!(meta.key, "timestamp");
    }

    #[test]
    fn test_metadata_from_string() {
        let meta = Metadata::from_string("note", "hello world");
        assert_eq!(meta.as_string(), Some("hello world".to_string()));
    }

    #[test]
    fn test_metadata_binary() {
        let meta = Metadata::new("binary", vec![0x00, 0xFF, 0x80]);
        assert!(meta.as_string().is_none()); // Not valid UTF-8
    }

    #[test]
    fn test_state_assignment() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        let assignment = StateAssignment::new(3, seal.clone(), vec![7, 8, 9]);
        assert_eq!(assignment.type_id, 3);
        assert_eq!(assignment.seal, seal);
    }

    #[test]
    fn test_state_ref() {
        let state_ref = StateRef::new(1, Hash::new([5u8; 32]), 0);
        assert_eq!(state_ref.type_id, 1);
        assert_eq!(state_ref.output_index, 0);
    }

    #[test]
    fn test_state_serialization_roundtrip() {
        let seal = SealPoint::new(vec![1, 2, 3], Some(42)).unwrap();
        let state = OwnedState::new(2, seal, vec![4, 5, 6]);
        let bytes = bincode::serialize(&state).unwrap();
        let restored: OwnedState = bincode::deserialize(&bytes).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn test_global_state_serialization_roundtrip() {
        let state = GlobalState::new(1, vec![1, 2, 3]);
        let bytes = bincode::serialize(&state).unwrap();
        let restored: GlobalState = bincode::deserialize(&bytes).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn test_metadata_serialization_roundtrip() {
        let meta = Metadata::from_string("note", "test value");
        let bytes = bincode::serialize(&meta).unwrap();
        let restored: Metadata = bincode::deserialize(&bytes).unwrap();
        assert_eq!(meta, restored);
    }
}
