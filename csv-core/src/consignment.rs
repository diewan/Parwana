//! Consignment: the wire format for CSV contract state transfer
//!
//! A consignment contains the complete provable history of a contract:
//! genesis, all transitions, seal assignments, and anchor proofs.
//! It is the unit of state transfer between peers.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use csv_protocol::genesis::Genesis;
use csv_hash::Hash;
use csv_hash::seal::CommitAnchor;
use csv_protocol::state::{Metadata, StateAssignment};
use crate::transition::Transition;

/// Consignment version for forward compatibility
pub const CONSIGNMENT_VERSION: u8 = 1;

/// Anchor proof: links a commitment to an on-chain reference
///
/// An anchor provides cryptographic proof that a commitment was
/// published to a blockchain at a specific location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Anchor reference (on-chain location of the commitment)
    pub anchor_ref: CommitAnchor,
    /// Commitment hash that was anchored
    pub commitment: Hash,
    /// Inclusion proof bytes (chain-specific)
    pub inclusion_proof: Vec<u8>,
    /// Finality proof bytes (chain-specific)
    pub finality_proof: Vec<u8>,
}

impl Anchor {
    /// Create a new anchor from its components
    pub fn new(
        anchor_ref: CommitAnchor,
        commitment: Hash,
        inclusion_proof: Vec<u8>,
        finality_proof: Vec<u8>,
    ) -> Self {
        Self {
            anchor_ref,
            commitment,
            inclusion_proof,
            finality_proof,
        }
    }
}

/// Seal assignment record in a consignment
///
/// Records which state was assigned to which seal during a transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealAssignment {
    /// Seal being assigned to
    pub seal_ref: csv_hash::seal::SealPoint,
    /// State being assigned to this seal
    pub assignment: StateAssignment,
    /// Metadata for this assignment
    pub metadata: Vec<Metadata>,
}

impl SealAssignment {
    /// Create a new seal assignment
    pub fn new(
        seal_ref: csv_hash::seal::SealPoint,
        assignment: StateAssignment,
        metadata: Vec<Metadata>,
    ) -> Self {
        Self {
            seal_ref,
            assignment,
            metadata,
        }
    }
}

/// Complete contract consignment
///
/// This is the wire format for transferring CSV contract state between peers.
/// A valid consignment contains a complete, verifiable chain from genesis
/// to the current state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consignment {
    /// Consignment version
    pub version: u8,
    /// Contract genesis
    pub genesis: Genesis,
    /// State transitions in topological order
    pub transitions: Vec<Transition>,
    /// Seal assignments (indexed by transition output)
    pub seal_assignments: Vec<SealAssignment>,
    /// Anchor proofs (on-chain commitment locations)
    pub anchors: Vec<Anchor>,
    /// Schema ID (for validation against contract rules)
    pub schema_id: Hash,
}

impl Consignment {
    /// Create a new consignment
    pub fn new(
        genesis: Genesis,
        transitions: Vec<Transition>,
        seal_assignments: Vec<SealAssignment>,
        anchors: Vec<Anchor>,
        schema_id: Hash,
    ) -> Self {
        Self {
            version: CONSIGNMENT_VERSION,
            genesis,
            transitions,
            seal_assignments,
            anchors,
            schema_id,
        }
    }

    /// Compute the consignment state root hash
    ///
    /// This hash represents the current state of the contract after all
    /// transitions have been applied.
    pub fn state_root(&self) -> Hash {
        let mut hasher = Sha256::new();

        hasher.update(b"CSV-CONSIGNMENT-v1");
        hasher.update(self.version.to_le_bytes());

        // Genesis hash
        hasher.update(self.genesis.hash().as_bytes());

        // Transition hashes in order
        hasher.update((self.transitions.len() as u64).to_le_bytes());
        for transition in &self.transitions {
            hasher.update(transition.hash().as_bytes());
        }

        // Seal assignments
        hasher.update((self.seal_assignments.len() as u64).to_le_bytes());
        for assignment in &self.seal_assignments {
            // Use canonical serialization for hashing (PHASE 2 requirement)
            let seal_ref_bytes = assignment.seal_ref.to_canonical_bytes()
                .expect("canonical serialization should not fail");
            hasher.update(seal_ref_bytes);
            let seal_bytes = assignment.assignment.seal.to_canonical_bytes()
                .expect("canonical serialization should not fail");
            hasher.update(seal_bytes);
            hasher.update(&assignment.assignment.data);
        }

        // Anchors
        hasher.update((self.anchors.len() as u64).to_le_bytes());
        for anchor in &self.anchors {
            hasher.update(anchor.commitment.as_bytes());
            // Use canonical serialization for hashing (PHASE 2 requirement)
            let anchor_ref_bytes = anchor.anchor_ref.to_canonical_bytes()
                .expect("canonical serialization should not fail");
            hasher.update(anchor_ref_bytes);
        }

        let result = hasher.finalize();
        let mut array = [0u8; 32];
        array.copy_from_slice(&result);
        Hash::new(array)
    }

    /// Get the contract ID (from genesis)
    pub fn contract_id(&self) -> Hash {
        self.genesis.contract_id
    }

    /// Get the number of transitions
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Get the number of seal assignments
    pub fn assignment_count(&self) -> usize {
        self.seal_assignments.len()
    }

    /// Get the number of anchors
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Get the latest state for a given seal
    ///
    /// Walks transitions in order to find the most recent assignment
    /// to the given seal.
    pub fn latest_state_for_seal(&self, seal: &csv_hash::seal::SealPoint) -> Option<&StateAssignment> {
        // Walk assignments in reverse to find the latest for this seal
        self.seal_assignments
            .iter()
            .rev()
            .find(|a| &a.seal_ref == seal)
            .map(|a| &a.assignment)
    }

    /// Get all current seal owners
    ///
    /// Returns the set of seals that have received state but haven't
    /// been consumed by any transition.
    pub fn current_seals(&self) -> alloc::collections::BTreeSet<Vec<u8>> {
        // Start with genesis owned state
        let mut active: alloc::collections::BTreeSet<Vec<u8>> = alloc::collections::BTreeSet::new();

        // Genesis outputs
        for owned in &self.genesis.owned_state {
            // Use canonical serialization for consistent indexing (PHASE 2 requirement)
            let seal_bytes = owned.seal.to_canonical_bytes()
                .expect("canonical serialization should not fail");
            active.insert(seal_bytes);
        }

        // Transition outputs
        for transition in &self.transitions {
            for output in &transition.owned_outputs {
                // Use canonical serialization for consistent indexing (PHASE 2 requirement)
                let seal_bytes = output.seal.to_canonical_bytes()
                    .expect("canonical serialization should not fail");
                active.insert(seal_bytes);
            }
        }

        // Note: determining which seals are actually consumed requires
        // resolving StateRef -> SealPoint mapping through the transition chain.
        // This is a simplified view; full resolution needs VM execution.
        active
    }

    /// Validate basic consignment structure
    pub fn validate_structure(&self) -> Result<(), ConsignmentError> {
        // Version check
        if self.version != CONSIGNMENT_VERSION {
            return Err(ConsignmentError::VersionMismatch {
                expected: CONSIGNMENT_VERSION,
                actual: self.version,
            });
        }

        // Schema ID consistency
        if self.genesis.schema_id != self.schema_id {
            return Err(ConsignmentError::SchemaMismatch {
                genesis_schema: self.genesis.schema_id,
                consignment_schema: self.schema_id,
            });
        }

        // Contract ID consistency
        if self.genesis.contract_id != self.contract_id() {
            return Err(ConsignmentError::ContractIdMismatch);
        }

        // Transition count vs anchor count (each transition should have an anchor)
        if self.transitions.len() != self.anchors.len() {
            return Err(ConsignmentError::AnchorCountMismatch {
                transitions: self.transitions.len(),
                anchors: self.anchors.len(),
            });
        }

        Ok(())
    }

    /// Serialize consignment to canonical bytes
    ///
    /// Uses canonical CBOR serialization for protocol-critical data.
    /// Manual bincode serialization is forbidden per AUDIT.md.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        csv_codec::to_canonical_cbor(self)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize consignment from canonical bytes with size limit (50MB max)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_SIZE: usize = 50 * 1024 * 1024; // 50MB
        if bytes.len() > MAX_SIZE {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Consignment too large: {} bytes (max {})",
                    bytes.len(),
                    MAX_SIZE
                ),
            )));
        }

        let consignment: Consignment = csv_codec::from_canonical_cbor(bytes)?;

        // Verify version before accepting
        if consignment.version != CONSIGNMENT_VERSION {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported consignment version: {}", consignment.version),
            )));
        }

        Ok(consignment)
    }

    /// Create a consignment with only genesis (no transitions yet)
    pub fn from_genesis(genesis: Genesis) -> Self {
        let schema_id = genesis.schema_id;
        Self::new(genesis, vec![], vec![], vec![], schema_id)
    }
}

/// Consignment validation errors
#[derive(Debug)]
#[allow(missing_docs)]
pub enum ConsignmentError {
    /// Version mismatch between expected and actual consignment
    VersionMismatch { expected: u8, actual: u8 },
    /// Schema ID doesn't match between genesis and consignment
    SchemaMismatch {
        genesis_schema: Hash,
        consignment_schema: Hash,
    },
    /// Contract ID inconsistency between components
    ContractIdMismatch,
    /// Transition count doesn't match anchor count
    AnchorCountMismatch { transitions: usize, anchors: usize },
}

impl core::fmt::Display for ConsignmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConsignmentError::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "Consignment version mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            ConsignmentError::SchemaMismatch {
                genesis_schema,
                consignment_schema,
            } => {
                write!(
                    f,
                    "Schema mismatch: genesis has {}, consignment has {}",
                    genesis_schema, consignment_schema
                )
            }
            ConsignmentError::ContractIdMismatch => {
                write!(f, "Contract ID inconsistency")
            }
            ConsignmentError::AnchorCountMismatch {
                transitions,
                anchors,
            } => {
                write!(
                    f,
                    "Anchor count mismatch: {} transitions but {} anchors",
                    transitions, anchors
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::Genesis;
    use csv_hash::seal::SealPoint;
    use crate::state::{GlobalState, Metadata, OwnedState};
    use crate::state::{StateAssignment, StateRef};

    fn test_consignment() -> Consignment {
        let genesis = Genesis::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            vec![
                GlobalState::new(1, 1000u64.to_le_bytes().to_vec()), // total supply
            ],
            vec![OwnedState::new(
                10,
                SealPoint::new(vec![0xAA; 16], Some(1)).unwrap(),
                1000u64.to_le_bytes().to_vec(),
            )],
            vec![Metadata::from_string("issuer", "test")],
        );

        let transition = Transition::new(
            1, // transfer
            vec![StateRef::new(10, Hash::new([1u8; 32]), 0)],
            vec![
                StateAssignment::new(
                    10,
                    SealPoint::new(vec![0xBB; 16], Some(2)).unwrap(),
                    600u64.to_le_bytes().to_vec(),
                ),
                StateAssignment::new(
                    10,
                    SealPoint::new(vec![0xAA; 16], Some(1)).unwrap(),
                    400u64.to_le_bytes().to_vec(),
                ),
            ],
            vec![],
            vec![],
            vec![0x01, 0x02],
            vec![vec![0xAB; 64]],
        );

        let seal_assignment = SealAssignment::new(
            SealPoint::new(vec![0xBB; 16], Some(2)).unwrap(),
            StateAssignment::new(
                10,
                SealPoint::new(vec![0xBB; 16], Some(2)).unwrap(),
                600u64.to_le_bytes().to_vec(),
            ),
            vec![],
        );

        let anchor = Anchor::new(
            CommitAnchor::new(vec![0xCC; 32], 100, vec![]).unwrap(),
            transition.hash(),
            vec![0xDD; 64], // inclusion proof
            vec![0xEE; 32], // finality proof
        );

        Consignment::new(
            genesis,
            vec![transition],
            vec![seal_assignment],
            vec![anchor],
            Hash::new([2u8; 32]),
        )
    }

    #[test]
    fn test_consignment_creation() {
        let c = test_consignment();
        assert_eq!(c.version, CONSIGNMENT_VERSION);
        assert_eq!(c.transition_count(), 1);
        assert_eq!(c.assignment_count(), 1);
        assert_eq!(c.anchor_count(), 1);
    }

    #[test]
    fn test_consignment_state_root() {
        let c = test_consignment();
        let root = c.state_root();
        assert_eq!(root.as_bytes().len(), 32);
    }

    #[test]
    fn test_consignment_state_root_deterministic() {
        let c1 = test_consignment();
        let c2 = test_consignment();
        assert_eq!(c1.state_root(), c2.state_root());
    }

    #[test]
    fn test_consignment_state_root_differs_by_transition() {
        let mut c1 = test_consignment();
        let c2 = test_consignment();
        // Modify transition bytecode
        c1.transitions[0].validation_script = vec![0xFF];
        assert_ne!(c1.state_root(), c2.state_root());
    }

    #[test]
    fn test_contract_id() {
        let c = test_consignment();
        assert_eq!(c.contract_id(), Hash::new([1u8; 32]));
    }

    #[test]
    fn test_latest_state_for_seal() {
        let c = test_consignment();
        let seal = SealPoint::new(vec![0xBB; 16], Some(2)).unwrap();
        let state = c.latest_state_for_seal(&seal);
        assert!(state.is_some());
        assert_eq!(state.unwrap().data, 600u64.to_le_bytes().to_vec());
    }

    #[test]
    fn test_latest_state_for_seal_not_found() {
        let c = test_consignment();
        let seal = SealPoint::new(vec![0xFF; 16], Some(99)).unwrap();
        let state = c.latest_state_for_seal(&seal);
        assert!(state.is_none());
    }

    #[test]
    fn test_validate_structure_valid() {
        let c = test_consignment();
        assert!(c.validate_structure().is_ok());
    }

    #[test]
    fn test_validate_structure_wrong_version() {
        let mut c = test_consignment();
        c.version = 99;
        assert!(c.validate_structure().is_err());
    }

    #[test]
    fn test_validate_structure_schema_mismatch() {
        let mut c = test_consignment();
        c.schema_id = Hash::new([99u8; 32]); // Different from genesis schema_id
        assert!(c.validate_structure().is_err());
    }

    #[test]
    fn test_validate_structure_anchor_count_mismatch() {
        let mut c = test_consignment();
        c.anchors.push(Anchor::new(
            CommitAnchor::new(vec![0xFF; 32], 200, vec![]).unwrap(),
            Hash::zero(),
            vec![],
            vec![],
        ));
        assert!(c.validate_structure().is_err());
    }

    #[test]
    fn test_from_genesis() {
        let genesis = Genesis::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            vec![],
            vec![],
            vec![],
        );
        let c = Consignment::from_genesis(genesis.clone());
        assert_eq!(c.version, CONSIGNMENT_VERSION);
        assert_eq!(c.transition_count(), 0);
        assert_eq!(c.assignment_count(), 0);
        assert_eq!(c.anchor_count(), 0);
        assert_eq!(c.contract_id(), Hash::new([1u8; 32]));
        assert!(c.validate_structure().is_ok());
    }

    #[test]
    fn test_consignment_serialization_roundtrip() {
        let c = test_consignment();
        let bytes = c.to_bytes().unwrap();
        let restored = Consignment::from_bytes(&bytes).unwrap();
        assert_eq!(c, restored);
        assert_eq!(c.state_root(), restored.state_root());
    }

    #[test]
    fn test_consignment_wrong_version_rejected() {
        let mut c = test_consignment();
        c.version = 99;
        let bytes = bincode::serialize(&c).unwrap();
        let result = Consignment::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_current_seals() {
        let c = test_consignment();
        let seals = c.current_seals();
        // Should include seals from genesis and transition outputs
        assert!(!seals.is_empty());
    }

    #[test]
    fn test_empty_consignment_structure() {
        let genesis = Genesis::new(
            Hash::new([1u8; 32]),
            Hash::new([2u8; 32]),
            vec![],
            vec![],
            vec![],
        );
        let c = Consignment::from_genesis(genesis);
        assert!(c.validate_structure().is_ok());
        assert_eq!(c.state_root().as_bytes().len(), 32);
    }
}
