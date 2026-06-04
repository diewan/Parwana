//! Transition: typed state changes in a CSV contract
//!
//! Transitions define how state changes: they consume owned state inputs,
//! produce owned state outputs, update global state, and attach metadata.
//! Each transition is validated by the VM and anchored to a seal.

use serde::{Deserialize, Serialize};

use crate::state::{GlobalState, Metadata, StateAssignment, StateRef};
use csv_hash::Hash;
use csv_hash::dag::DAGNode;
use csv_hash::seal::SealPoint;
use csv_hash::{DomainSeparatedHash, TransitionDomain};

/// A contract transition
///
/// A transition consumes existing state, executes validation logic (bytecode),
/// and produces new state. It is authorized by consuming a single-use seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// Unique transition ID (defined by the schema)
    pub transition_id: u16,
    /// Owned state inputs being consumed
    pub owned_inputs: Vec<StateRef>,
    /// Owned state outputs being created
    pub owned_outputs: Vec<StateAssignment>,
    /// Global state updates
    pub global_updates: Vec<GlobalState>,
    /// Transition metadata
    pub metadata: Vec<Metadata>,
    /// Validation bytecode (e.g., AluVM)
    pub validation_script: Vec<u8>,
    /// Authorizing signatures
    pub signatures: Vec<Vec<u8>>,
}

impl Transition {
    /// Create a new transition
    pub fn new(
        transition_id: u16,
        owned_inputs: Vec<StateRef>,
        owned_outputs: Vec<StateAssignment>,
        global_updates: Vec<GlobalState>,
        metadata: Vec<Metadata>,
        validation_script: Vec<u8>,
        signatures: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            transition_id,
            owned_inputs,
            owned_outputs,
            global_updates,
            metadata,
            validation_script,
            signatures,
        }
    }

    /// Compute the transition hash
    pub fn hash(&self) -> Hash {
        use csv_codec::canonical::to_canonical_cbor;

        // Use canonical CBOR serialization for deterministic hashing
        let cbor_bytes = to_canonical_cbor(self).unwrap_or_default();
        DomainSeparatedHash::<TransitionDomain>::hash(&cbor_bytes)
    }

    /// Get all seals consumed by this transition (from owned inputs)
    pub fn consumed_seals(&self) -> Vec<SealPoint> {
        // StateRef doesn't contain SealPoint directly — seals are resolved
        // from the parent transition that created each output.
        // This method is a basic implementation; actual resolution requires
        // walking the transition chain.
        Vec::new()
    }

    /// Get all seals that receive new state from this transition
    pub fn assigned_seals(&self) -> Vec<SealPoint> {
        self.owned_outputs.iter().map(|o| o.seal.clone()).collect()
    }

    /// Check if this transition has no inputs (genesis-like transition)
    pub fn is_genesis_like(&self) -> bool {
        self.owned_inputs.is_empty()
    }

    /// Check if this transition destroys all state (no outputs)
    pub fn is_destructive(&self) -> bool {
        self.owned_outputs.is_empty() && self.global_updates.is_empty()
    }

    /// Convert to a DAG node for backwards compatibility
    pub fn to_dag_node(&self) -> DAGNode {
        DAGNode::new(
            self.hash(),
            self.validation_script.clone(),
            self.signatures.clone(),
            self.metadata
                .iter()
                .flat_map(|m| m.value.clone())
                .collect::<Vec<_>>()
                .chunks(32)
                .map(|c: &[u8]| c.to_vec())
                .collect(),
            Vec::new(), // Parents must be set externally
        )
    }
}

/// Legal state transitions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionLegality {
    /// Locked → AwaitingFinality
    LockedToAwaitingFinality,
    /// AwaitingFinality → ProofBuilding
    AwaitingFinalityToProofBuilding,
    /// ProofBuilding → ProofValidated
    ProofBuildingToProofValidated,
    /// ProofValidated → Minting
    ProofValidatedToMinting,
    /// Minting → Completed
    MintingToCompleted,
    /// Any → RolledBack (on reorg)
    ToRolledBack,
    /// Any → Compromised (on security incident)
    ToCompromised,
}

/// Check if a transition is legal
pub fn is_legal_transition(from: State, to: State) -> bool {
    match (from, to) {
        (State::Locked, State::AwaitingFinality) => true,
        (State::AwaitingFinality, State::ProofBuilding) => true,
        (State::ProofBuilding, State::ProofValidated) => true,
        (State::ProofValidated, State::Minting) => true,
        (State::Minting, State::Completed) => true,
        (_, State::RolledBack) => true,
        (_, State::Compromised) => true,
        _ => false,
    }
}

/// Transfer states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Transfer is locked on source chain
    Locked,
    /// Awaiting finality confirmation
    AwaitingFinality,
    /// Building zero-knowledge proof
    ProofBuilding,
    /// Proof validated, ready for minting
    ProofValidated,
    /// Minting on destination chain
    Minting,
    /// Transfer successfully completed
    Completed,
    /// Transfer rolled back due to reorg
    RolledBack,
    /// Transfer compromised (security incident)
    Compromised,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_transition() -> Transition {
        Transition::new(
            1, // transition_id: e.g., "transfer"
            vec![
                StateRef::new(10, Hash::new([1u8; 32]), 0), // consume 1000 tokens from genesis output 0
            ],
            vec![
                StateAssignment::new(
                    10,
                    SealPoint::new(vec![0xAA; 16], Some(1), None).unwrap(),
                    600u64.to_le_bytes().to_vec(),
                ), // 600 to seal A
                StateAssignment::new(
                    10,
                    SealPoint::new(vec![0xBB; 16], Some(2), None).unwrap(),
                    400u64.to_le_bytes().to_vec(),
                ), // 400 to seal B (change)
            ],
            vec![
                GlobalState::new(1, vec![100, 200]), // update total supply indicator
            ],
            vec![Metadata::from_string("memo", "payment for services")],
            vec![0x01, 0x02, 0x03], // validation bytecode
            vec![vec![0xAB; 64]],   // signature
        )
    }

    #[test]
    fn test_transition_creation() {
        let t = test_transition();
        assert_eq!(t.transition_id, 1);
        assert_eq!(t.owned_inputs.len(), 1);
        assert_eq!(t.owned_outputs.len(), 2);
        assert_eq!(t.global_updates.len(), 1);
        assert_eq!(t.metadata.len(), 1);
    }

    #[test]
    fn test_transition_hash() {
        let t = test_transition();
        let hash = t.hash();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_transition_hash_deterministic() {
        let t1 = test_transition();
        let t2 = test_transition();
        assert_eq!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_transition_hash_differs_by_inputs() {
        let mut t1 = test_transition();
        let t2 = test_transition();
        t1.owned_inputs
            .push(StateRef::new(10, Hash::new([99u8; 32]), 1));
        assert_ne!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_transition_hash_differs_by_outputs() {
        let mut t1 = test_transition();
        let t2 = test_transition();
        t1.owned_outputs.push(StateAssignment::new(
            10,
            SealPoint::new(vec![0xCC; 16], Some(3), None).unwrap(),
            vec![100],
        ));
        assert_ne!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_transition_hash_differs_by_script() {
        let mut t1 = test_transition();
        let t2 = test_transition();
        t1.validation_script = vec![0xFF, 0xFF, 0xFF];
        assert_ne!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_transition_hash_differs_by_signatures() {
        let mut t1 = test_transition();
        let t2 = test_transition();
        t1.signatures.push(vec![0xCD; 64]);
        assert_ne!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_transition_hash_bytecode_order() {
        let t1 = Transition::new(
            1,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![0x01, 0x02, 0x03],
            vec![],
        );
        let t2 = Transition::new(
            1,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![0x03, 0x02, 0x01],
            vec![],
        );
        assert_ne!(t1.hash(), t2.hash());
    }

    #[test]
    fn test_assigned_seals() {
        let t = test_transition();
        let seals = t.assigned_seals();
        assert_eq!(seals.len(), 2);
        assert_eq!(seals[0].nonce, Some(1));
        assert_eq!(seals[1].nonce, Some(2));
    }

    #[test]
    fn test_is_genesis_like() {
        let genesis_like = Transition::new(
            0,
            vec![], // no inputs
            vec![StateAssignment::new(
                10,
                SealPoint::new(vec![0xAA; 16], Some(1), None).unwrap(),
                1000u64.to_le_bytes().to_vec(),
            )],
            vec![],
            vec![],
            vec![0x01],
            vec![],
        );
        assert!(genesis_like.is_genesis_like());

        let normal = test_transition();
        assert!(!normal.is_genesis_like());
    }

    #[test]
    fn test_is_destructive() {
        let destructive = Transition::new(
            2, // e.g., "burn"
            vec![StateRef::new(10, Hash::new([1u8; 32]), 0)],
            vec![], // no outputs
            vec![], // no global updates
            vec![],
            vec![0x01],
            vec![],
        );
        assert!(destructive.is_destructive());

        let normal = test_transition();
        assert!(!normal.is_destructive());
    }

    #[test]
    fn test_empty_transition() {
        let t = Transition::new(0, vec![], vec![], vec![], vec![], vec![], vec![]);
        assert!(t.is_genesis_like());
        assert!(t.is_destructive());
        assert_eq!(t.hash().as_bytes().len(), 32);
    }

    #[test]
    fn test_transition_serialization_roundtrip() {
        let t = test_transition();
        let bytes = bincode::serialize(&t).unwrap();
        let restored: Transition = bincode::deserialize(&bytes).unwrap();
        assert_eq!(t, restored);
        assert_eq!(t.hash(), restored.hash());
    }

    #[test]
    fn test_to_dag_node() {
        let t = test_transition();
        let node = t.to_dag_node();
        assert_eq!(node.node_id, t.hash());
        assert_eq!(node.bytecode, t.validation_script);
        assert_eq!(node.signatures, t.signatures);
    }
}
