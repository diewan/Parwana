//! State History Store
//!
//! Stores the full state history for contracts, enabling client-side validation.
//! The client stores:
//! - All commitments from genesis to present
//! - All state transitions
//! - All seal assignments and their lifecycle
//! - Anchors and their inclusion proofs
//!
//! This allows the client to verify the complete history without
//! re-fetching everything from the chain on every validation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use csv_hash::commitment::Commitment;
use csv_hash::Hash;
// Sanad is not available in csv-hash, TODO: find correct location
use csv_hash::seal::SealPoint;
use crate::error::ProtocolError;

/// A recorded state transition in the contract history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateTransitionRecord {
    /// The commitment that resulted from this transition
    pub commitment: Commitment,
    /// The seal that was consumed or assigned
    pub seal_ref: SealPoint,
    /// The Sanads involved in this transition
    // pub sanads: Vec<Hash>, // TODO: Sanad struct removed
    /// Block height when this was anchored on-chain
    pub block_height: u64,
    /// Whether this transition has been verified by the client
    pub verified: bool,
}

/// A contract's full state history from genesis to present.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractHistory {
    /// The contract's unique identifier
    pub contract_id: Hash,
    /// All state transitions in chronological order
    pub transitions: Vec<StateTransitionRecord>,
    /// Current active Sanads (not yet consumed)
    pub active_sanads: BTreeMap<Hash, Hash>,
    /// All consumed seals indexed by seal ID
    pub consumed_seals: BTreeMap<Vec<u8>, SealPoint>,
    /// The latest commitment hash in the chain
    pub latest_commitment_hash: Hash,
}

impl ContractHistory {
    /// Create a new contract history from genesis.
    pub fn from_genesis(genesis_commitment: Commitment) -> Self {
        let contract_id = genesis_commitment.contract_id;
        let latest_hash = genesis_commitment.hash();

        Self {
            contract_id,
            transitions: Vec::new(),
            active_sanads: BTreeMap::new(),
            consumed_seals: BTreeMap::new(),
            latest_commitment_hash: latest_hash,
        }
    }

    /// Add a state transition to the history.
    pub fn add_transition(&mut self, transition: StateTransitionRecord) -> Result<(), StoreError> {
        // Verify this transition's commitment chains from the latest
        let expected_previous = self.latest_commitment_hash;
        if transition.commitment.previous_commitment != expected_previous {
            return Err(StoreError::InvalidHistory(format!(
                "Transition commitment does not chain from latest: expected {:?}, got {:?}",
                expected_previous, transition.commitment.previous_commitment
            )));
        }

        // Update latest commitment
        self.latest_commitment_hash = transition.commitment.commitment_hash();

        // Add to transitions
        self.transitions.push(transition);

        Ok(())
    }

    /// Register a new Sanad as active.
    pub fn add_sanad(&mut self, sanad: Hash) {
        self.active_sanads.insert(sanad, sanad);
    }

    /// Mark a Sanad as consumed.
    pub fn consume_sanad(&mut self, sanad_id: &Hash) -> Option<Hash> {
        self.active_sanads.remove(sanad_id)
    }

    /// Check if a seal has been consumed.
    pub fn is_seal_consumed(&self, seal_ref: &SealPoint) -> bool {
        // Use canonical serialization for consistent indexing (PHASE 2 requirement)
        let seal_bytes = seal_ref.to_canonical_bytes()
            .expect("canonical serialization should not fail");
        self.consumed_seals.contains_key(&seal_bytes)
    }

    /// Mark a seal as consumed.
    pub fn mark_seal_consumed(&mut self, seal_ref: SealPoint) {
        // Use canonical serialization for consistent indexing (PHASE 2 requirement)
        let seal_bytes = seal_ref.to_canonical_bytes()
            .expect("canonical serialization should not fail");
        self.consumed_seals.insert(seal_bytes, seal_ref);
    }

    /// Get the number of transitions in this contract's history.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Get all active Sanads.
    pub fn get_active_sanads(&self) -> Vec<&Hash> {
        self.active_sanads.values().collect()
    }
}

/// Trait for persisting contract state history.
pub trait StateHistoryStore: Send + Sync {
    /// Save or update a contract's history.
    fn save_contract_history(
        &mut self,
        contract_id: Hash,
        history: &ContractHistory,
    ) -> Result<(), StoreError>;

    /// Load a contract's history by ID.
    fn load_contract_history(
        &self,
        contract_id: Hash,
    ) -> Result<Option<ContractHistory>, StoreError>;

    /// Get all known contract IDs.
    fn list_contracts(&self) -> Result<Vec<Hash>, StoreError>;

    /// Delete a contract's history.
    fn delete_contract(&mut self, contract_id: Hash) -> Result<(), StoreError>;
}

/// In-memory implementation of StateHistoryStore.
#[derive(Default)]
pub struct InMemoryStateStore {
    contracts: BTreeMap<Hash, ContractHistory>,
}

impl InMemoryStateStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self {
            contracts: BTreeMap::new(),
        }
    }
}

impl StateHistoryStore for InMemoryStateStore {
    fn save_contract_history(
        &mut self,
        contract_id: Hash,
        history: &ContractHistory,
    ) -> Result<(), StoreError> {
        self.contracts.insert(contract_id, history.clone());
        Ok(())
    }

    fn load_contract_history(
        &self,
        contract_id: Hash,
    ) -> Result<Option<ContractHistory>, StoreError> {
        Ok(self.contracts.get(&contract_id).cloned())
    }

    fn list_contracts(&self) -> Result<Vec<Hash>, StoreError> {
        Ok(self.contracts.keys().cloned().collect())
    }

    fn delete_contract(&mut self, contract_id: Hash) -> Result<(), StoreError> {
        self.contracts.remove(&contract_id);
        Ok(())
    }
}

/// Errors that can occur in state storage.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum StoreError {
    #[error("Contract not found: {0}")]
    ContractNotFound(Hash),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid contract history: {0}")]
    InvalidHistory(String),
    #[error("IO error: {0}")]
    IoError(String),
}

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_commitment(previous: Hash, seal_id: u8) -> Commitment {
        let domain = [0u8; 32];
        let seal = SealPoint::new(vec![seal_id], None).unwrap();
        Commitment::simple(
            Hash::new([0xAB; 32]),
            previous,
            Hash::new([0u8; 32]),
            &seal,
            domain,
        )
    }

    #[test]
    fn test_contract_history_creation() {
        let genesis = make_test_commitment(Hash::new([0u8; 32]), 0x01);
        let history = ContractHistory::from_genesis(genesis.clone());

        assert_eq!(history.contract_id, genesis.contract_id);
        assert_eq!(history.transition_count(), 0);
        assert_eq!(history.latest_commitment_hash, genesis.hash());
    }

    #[test]
    fn test_add_transition() {
        let genesis = make_test_commitment(Hash::new([0u8; 32]), 0x01);
        let mut history = ContractHistory::from_genesis(genesis.clone());

        let transition = StateTransitionRecord {
            commitment: make_test_commitment(genesis.hash(), 0x02),
            seal_ref: SealPoint::new(vec![0x02], None).unwrap(),
            sanads: Vec::new(),
            block_height: 100,
            verified: true,
        };

        history.add_transition(transition).unwrap();
        assert_eq!(history.transition_count(), 1);
    }

    #[test]
    fn test_sanad_lifecycle() {
        let genesis = make_test_commitment(Hash::new([0u8; 32]), 0x01);
        let mut history = ContractHistory::from_genesis(genesis);

        let sanad = Sanad::new(
            Hash::new([0xCD; 32]),
            crate::sanad::OwnershipProof {
                proof: vec![0x01],
                owner: vec![0xFF; 32],
                scheme: None,
            },
            &[0x42],
        );

        history.add_sanad(sanad.clone());
        assert_eq!(history.get_active_sanads().len(), 1);

        let consumed = history.consume_sanad(&sanad.id.0);
        assert!(consumed.is_some());
        assert_eq!(history.get_active_sanads().len(), 0);
    }

    #[test]
    fn test_seal_consumption_tracking() {
        let genesis = make_test_commitment(Hash::new([0u8; 32]), 0x01);
        let mut history = ContractHistory::from_genesis(genesis);

        let seal = SealPoint::new(vec![0xAB], None).unwrap();
        assert!(!history.is_seal_consumed(&seal));

        history.mark_seal_consumed(seal.clone());
        assert!(history.is_seal_consumed(&seal));
    }

    #[test]
    fn test_in_memory_store() {
        let mut store = InMemoryStateStore::new();

        let genesis = make_test_commitment(Hash::new([0u8; 32]), 0x01);
        let history = ContractHistory::from_genesis(genesis.clone());

        store
            .save_contract_history(genesis.contract_id, &history)
            .unwrap();

        let loaded = store.load_contract_history(genesis.contract_id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().contract_id, genesis.contract_id);

        let contracts = store.list_contracts().unwrap();
        assert_eq!(contracts.len(), 1);
    }
}
