//! Genesis: the initial state of a CSV contract
//!
//! Genesis represents the first instantiation of a contract. It defines
//! the global state and assigns initial owned states to their seals.
//! Every consignment chain starts from exactly one genesis.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use csv_hash::{DomainSeparatedHash, GenesisDomain};
use csv_hash::Hash;
use crate::state::{GlobalState, Metadata, OwnedState};

/// Contract genesis
///
/// The genesis is the root of every contract's state history.
/// It is referenced by the first transition and indirectly by all subsequent ones.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    /// Unique contract identifier (user-facing, e.g., "USDT-on-Bitcoin:1")
    pub contract_id: Hash,
    /// Schema identifier binding this genesis to a contract schema
    pub schema_id: Hash,
    /// Initial global state values
    pub global_state: Vec<GlobalState>,
    /// Initial owned state assignments (e.g., initial token distribution)
    pub owned_state: Vec<OwnedState>,
    /// Genesis metadata (issuance date, issuer info, etc.)
    pub metadata: Vec<Metadata>,
}

impl Genesis {
    /// Create new genesis
    pub fn new(
        contract_id: Hash,
        schema_id: Hash,
        global_state: Vec<GlobalState>,
        owned_state: Vec<OwnedState>,
        metadata: Vec<Metadata>,
    ) -> Self {
        Self {
            contract_id,
            schema_id,
            global_state,
            owned_state,
            metadata,
        }
    }

    /// Compute the genesis hash
    ///
    /// This hash serves as the root commitment for all subsequent transitions.
    pub fn hash(&self) -> Hash {
        use csv_hash::canonical::to_canonical_cbor;

        // Use canonical CBOR serialization for deterministic hashing
        let cbor_bytes = to_canonical_cbor(self)
            .expect("Genesis serialization should not fail");
        DomainSeparatedHash::<GenesisDomain>::hash(&cbor_bytes)
    }

    /// Get the total count of all state items
    pub fn state_count(&self) -> usize {
        self.global_state.len() + self.owned_state.len()
    }

    /// Find global states by type ID
    pub fn global_states_of(&self, type_id: u16) -> Vec<&GlobalState> {
        self.global_state
            .iter()
            .filter(|s| s.type_id == type_id)
            .collect()
    }

    /// Find owned states by type ID
    pub fn owned_states_of(&self, type_id: u16) -> Vec<&OwnedState> {
        self.owned_state
            .iter()
            .filter(|s| s.type_id == type_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_hash::seal::SealPoint;

    fn test_genesis() -> Genesis {
        Genesis::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            vec![
                GlobalState::new(1, vec![100, 200]), // e.g., total_supply
                GlobalState::from_hash(2, Hash::new([3u8; 32])), // e.g., config_hash
            ],
            vec![
                OwnedState::new(
                    10,
                    SealPoint::new(vec![0xAA; 16], Some(1)).unwrap(),
                    1000u64.to_le_bytes().to_vec(),
                ), // 1000 tokens to seal 1
                OwnedState::new(
                    10,
                    SealPoint::new(vec![0xBB; 16], Some(2)).unwrap(),
                    500u64.to_le_bytes().to_vec(),
                ), // 500 tokens to seal 2
            ],
            vec![
                Metadata::from_string("issuer", "test-issuer"),
                Metadata::from_string("date", "2026-04-06"),
            ],
        )
    }

    #[test]
    fn test_genesis_creation() {
        let genesis = test_genesis();
        assert_eq!(genesis.contract_id, Hash::new([1u8; 32]));
        assert_eq!(genesis.schema_id, Hash::new([2u8; 32]));
        assert_eq!(genesis.global_state.len(), 2);
        assert_eq!(genesis.owned_state.len(), 2);
        assert_eq!(genesis.metadata.len(), 2);
    }

    #[test]
    fn test_genesis_hash() {
        let genesis = test_genesis();
        let hash = genesis.hash();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let g1 = test_genesis();
        let g2 = test_genesis();
        assert_eq!(g1.hash(), g2.hash());
    }

    #[test]
    fn test_genesis_hash_differs_by_contract_id() {
        let mut g = test_genesis();
        let original_hash = g.hash();
        g.contract_id = Hash::new([99u8; 32]);
        assert_ne!(g.hash(), original_hash);
    }

    #[test]
    fn test_genesis_hash_differs_by_global_state() {
        let mut g = test_genesis();
        let original_hash = g.hash();
        g.global_state.push(GlobalState::new(99, vec![1, 2, 3]));
        assert_ne!(g.hash(), original_hash);
    }

    #[test]
    fn test_genesis_hash_differs_by_owned_state() {
        let mut g = test_genesis();
        let original_hash = g.hash();
        g.owned_state.push(OwnedState::new(
            99,
            SealPoint::new(vec![0xCC; 16], Some(3)).unwrap(),
            vec![42],
        ));
        assert_ne!(g.hash(), original_hash);
    }

    #[test]
    fn test_genesis_hash_differs_by_metadata() {
        let mut g = test_genesis();
        let original_hash = g.hash();
        g.metadata.push(Metadata::from_string("extra", "data"));
        assert_ne!(g.hash(), original_hash);
    }

    #[test]
    fn test_genesis_state_count() {
        let genesis = test_genesis();
        assert_eq!(genesis.state_count(), 4); // 2 global + 2 owned
    }

    #[test]
    fn test_genesis_global_states_of() {
        let genesis = test_genesis();
        let states = genesis.global_states_of(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].type_id, 1);

        let none = genesis.global_states_of(99);
        assert!(none.is_empty());
    }

    #[test]
    fn test_genesis_owned_states_of() {
        let genesis = test_genesis();
        let states = genesis.owned_states_of(10);
        assert_eq!(states.len(), 2);

        let none = genesis.owned_states_of(99);
        assert!(none.is_empty());
    }

    #[test]
    fn test_genesis_empty() {
        let genesis = Genesis::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            vec![],
            vec![],
            vec![],
        );
        assert_eq!(genesis.state_count(), 0);
        assert!(genesis.global_states_of(1).is_empty());
        assert!(genesis.owned_states_of(1).is_empty());

        // Still produces a valid hash
        assert_eq!(genesis.hash().as_bytes().len(), 32);
    }

    #[test]
    fn test_genesis_serialization_roundtrip() {
        let genesis = test_genesis();
        let bytes = bincode::serialize(&genesis).unwrap();
        let restored: Genesis = bincode::deserialize(&bytes).unwrap();
        assert_eq!(genesis, restored);
        assert_eq!(genesis.hash(), restored.hash());
    }
}
