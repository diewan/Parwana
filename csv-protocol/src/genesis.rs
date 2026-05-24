//! Genesis: the initial state of a CSV contract
//!
//! Genesis represents the first instantiation of a contract. It defines
//! the global state and assigns initial owned states to their seals.
//! Every consignment chain starts from exactly one genesis.

use crate::state::{GlobalState, Metadata, OwnedState};
use csv_hash::Hash;
use csv_hash::{DomainSeparatedHash, GenesisDomain};
use serde::{Deserialize, Serialize};

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
        let cbor_bytes = to_canonical_cbor(self).unwrap_or_else(|err| {
            format!("genesis-canonical-serialization-error:{err}").into_bytes()
        });
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
