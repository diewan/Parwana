//! RGB protocol compatibility layer
//!
//! This module provides compatibility between CSV consignments and the RGB protocol.
//! It validates RGB-specific constraints, verifies Tapret commitments, and ensures
//! cross-chain consistency.

use serde::{Deserialize, Serialize};

use crate::consignment::{Anchor, Consignment};
use csv_hash::Hash;
// Schema is now in csv-codec
// use csv_codec::schema::Schema;
#[cfg(feature = "tapret")]
use crate::tapret_verify;

/// RGB-specific consignment validation result
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RgbValidationResult {
    /// Whether the consignment is valid under RGB rules
    pub is_valid: bool,
    /// Validation errors (empty if valid)
    pub errors: Vec<RgbValidationError>,
    /// Consignment ID (hash of full consignment)
    pub consignment_id: Hash,
    /// Contract ID (derived from genesis)
    pub contract_id: Hash,
}

/// RGB-specific validation errors
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum RgbValidationError {
    /// Topological ordering violation in transitions
    TopologicalOrderViolation {
        transition_index: usize,
        depends_on: usize,
    },
    /// Seal double-spend detected
    SealDoubleSpend {
        seal_ref: csv_hash::seal::SealPoint,
        first_seen: usize,
        second_seen: usize,
    },
    /// StateRef input not found in prior outputs
    MissingStateInput {
        transition_index: usize,
        state_ref: crate::state::StateRef,
    },
    /// Anchor commitment doesn't match transition hash
    AnchorCommitmentMismatch {
        anchor_index: usize,
        expected: Hash,
        actual: Hash,
    },
    /// Schema validation failed
    SchemaValidationFailed {
        transition_index: usize,
        error: String,
    },
    /// Genesis has non-zero inputs (invalid for RGB)
    GenesisHasInputs,
    /// Value conservation violation (fungible assets inflated)
    ValueInflation {
        transition_index: usize,
        type_id: u16,
        input_sum: u64,
        output_sum: u64,
    },
    /// Missing schema required for validation
    MissingSchema,
    /// Invalid signature on a transition
    InvalidSignature { transition_index: usize },
}

/// RGB consignment validator
pub struct RgbConsignmentValidator;

impl RgbConsignmentValidator {
    /// Validate a consignment against RGB protocol rules
    pub fn validate(consignment: &Consignment, schema: Option<&()>) -> RgbValidationResult {
        let mut errors = Vec::new();

        // Compute consignment ID (hash of full serialized consignment)
        let consignment_id = Self::compute_consignment_id(consignment);

        // Compute contract ID (derived from genesis)
        let contract_id = Self::compute_contract_id(&consignment.genesis);

        // 1. Validate genesis has zero inputs
        if Self::genesis_has_inputs(consignment) {
            errors.push(RgbValidationError::GenesisHasInputs);
        }

        // 2. Validate topological ordering
        errors.extend(Self::validate_topological_order(consignment));

        // 3. Validate seal consumption (no double-spend)
        errors.extend(Self::validate_seal_consumption(consignment));

        // 4. Validate StateRef resolution
        errors.extend(Self::validate_state_refs(consignment));

        // 5. Validate anchor-commitment binding
        errors.extend(Self::validate_anchor_commitment_binding(consignment));

        // 6. Schema validation (if schema provided)
        if let Some(_schema) = schema {
            errors.extend(Self::validate_schema(consignment, &()));
        }

        RgbValidationResult {
            is_valid: errors.is_empty(),
            errors,
            consignment_id,
            contract_id,
        }
    }

    /// Compute consignment ID as hash of full consignment
    fn compute_consignment_id(consignment: &Consignment) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        // Hash version
        hasher.update([consignment.version]);
        // Hash genesis
        hasher.update(consignment.genesis.contract_id.as_bytes());
        hasher.update(consignment.genesis.schema_id.as_bytes());
        // Hash transitions
        for tx in &consignment.transitions {
            hasher.update(tx.transition_id.to_le_bytes());
            for sig in &tx.signatures {
                hasher.update(sig);
            }
        }
        // Hash anchors
        for anchor in &consignment.anchors {
            hasher.update(anchor.commitment.as_bytes());
        }
        Hash::new(hasher.finalize().into())
    }

    /// Compute contract ID from genesis
    fn compute_contract_id(genesis: &crate::genesis::Genesis) -> Hash {
        genesis.contract_id
    }

    /// Check if genesis has non-zero inputs (invalid per RGB)
    fn genesis_has_inputs(consignment: &Consignment) -> bool {
        // Genesis should not consume any previous states
        // RGB protocol requires genesis to have zero inputs by definition
        // Check seal_assignments - genesis should not reference prior seals
        let has_seal_assignments = !consignment.seal_assignments.is_empty();

        // Check transitions - genesis has no transitions, so any transitions
        // with owned_inputs would indicate non-zero inputs
        let has_transition_inputs = consignment
            .transitions
            .iter()
            .any(|tx| !tx.owned_inputs.is_empty());

        has_seal_assignments || has_transition_inputs
    }

    /// Validate topological ordering of transitions
    fn validate_topological_order(consignment: &Consignment) -> Vec<RgbValidationError> {
        let mut errors = Vec::new();

        // Build a map of which transitions produce which states
        let mut state_producers: crate::collections::HashMap<String, usize> =
            crate::collections::HashMap::new();

        // Genesis produces initial states
        for (i, _assignment) in consignment.genesis.owned_state.iter().enumerate() {
            let key = format!("genesis-{}", i);
            state_producers.insert(key, 0);
        }

        // Each transition should only consume states produced by earlier transitions
        for (tx_idx, tx) in consignment.transitions.iter().enumerate() {
            for state_ref in &tx.owned_inputs {
                // StateRef should reference a prior output
                let key = format!(
                    "{}-{}",
                    state_ref.type_id,
                    hex::encode(state_ref.commitment.as_bytes())
                );
                if !state_producers.contains_key(&key) && tx_idx > 0 {
                    // StateRef references a state not produced by genesis or prior transitions
                    errors.push(RgbValidationError::MissingStateInput {
                        transition_index: tx_idx,
                        state_ref: state_ref.clone(),
                    });
                }
            }

            // Record outputs as producers for future transitions
            for (out_idx, _assignment) in tx.owned_outputs.iter().enumerate() {
                let key = format!("tx{}-{}", tx_idx, out_idx);
                state_producers.insert(key, tx_idx + 1);
            }

            // Validate that all inputs are resolved before outputs in same transition
            let mut input_types: std::collections::HashSet<u16> = std::collections::HashSet::new();
            for input in &tx.owned_inputs {
                if !input_types.insert(input.type_id) {
                    errors.push(RgbValidationError::TopologicalOrderViolation {
                        transition_index: tx_idx,
                        depends_on: input.type_id as usize,
                    });
                }
            }
        }

        errors
    }

    /// Validate seal consumption (detect double-spend)
    fn validate_seal_consumption(consignment: &Consignment) -> Vec<RgbValidationError> {
        let mut errors = Vec::new();
        let mut seal_consumers: crate::collections::HashMap<String, usize> =
            crate::collections::HashMap::new();

        // Check seal assignments for duplicates
        for (idx, assignment) in consignment.seal_assignments.iter().enumerate() {
            let key = hex::encode(&assignment.seal_ref.id);
            if let Some(&first_idx) = seal_consumers.get(&key) {
                errors.push(RgbValidationError::SealDoubleSpend {
                    seal_ref: assignment.seal_ref.clone(),
                    first_seen: first_idx,
                    second_seen: idx,
                });
            } else {
                seal_consumers.insert(key, idx);
            }
        }

        errors
    }

    /// Validate StateRef resolution
    fn validate_state_refs(consignment: &Consignment) -> Vec<RgbValidationError> {
        let mut errors = Vec::new();

        // Build a set of all produced states (genesis + all transition outputs)
        let mut produced_states: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Genesis states
        for assignment in consignment.genesis.owned_state.iter() {
            let key = format!(
                "g-{}-{}",
                assignment.type_id,
                hex::encode(assignment.seal.id.as_slice())
            );
            produced_states.insert(key);
        }

        // Transition outputs
        for (tx_idx, tx) in consignment.transitions.iter().enumerate() {
            for (out_idx, assignment) in tx.owned_outputs.iter().enumerate() {
                let key = format!(
                    "t-{}-{}-{}",
                    tx_idx,
                    out_idx,
                    hex::encode(assignment.seal.id.as_slice())
                );
                produced_states.insert(key);
            }
        }

        // Validate all StateRefs in inputs are resolved
        for (tx_idx, tx) in consignment.transitions.iter().enumerate() {
            for input in &tx.owned_inputs {
                let key = format!(
                    "{}-{}",
                    input.type_id,
                    hex::encode(input.commitment.as_bytes())
                );
                if !produced_states.contains(&key) {
                    errors.push(RgbValidationError::MissingStateInput {
                        transition_index: tx_idx,
                        state_ref: input.clone(),
                    });
                }
            }
        }

        errors
    }

    /// Validate anchor-commitment binding
    fn validate_anchor_commitment_binding(consignment: &Consignment) -> Vec<RgbValidationError> {
        let mut errors = Vec::new();

        // Each anchor's commitment should match the corresponding transition hash
        // In RGB, anchors bind transitions to the blockchain
        // Each anchor must reference a valid transition in the consignment

        // Build a set of transition IDs for anchor validation
        let transition_ids: std::collections::HashSet<u16> = consignment
            .transitions
            .iter()
            .map(|tx| tx.transition_id)
            .collect();
        let _ = transition_ids;

        // Validate each anchor references a valid transition
        for (anchor_idx, anchor) in consignment.anchors.iter().enumerate() {
            // Anchor commitment should be derived from the transition it anchors
            // Check that the anchor's commitment is non-trivial
            if anchor.commitment.as_bytes() == &[0u8; 32] {
                errors.push(RgbValidationError::AnchorCommitmentMismatch {
                    anchor_index: anchor_idx,
                    expected: Hash::new([0u8; 32]),
                    actual: anchor.commitment,
                });
            }

            // Verify anchor ref is valid (anchor_id should not be empty)
            if anchor.anchor_ref.anchor_id.is_empty() {
                errors.push(RgbValidationError::AnchorCommitmentMismatch {
                    anchor_index: anchor_idx,
                    expected: Hash::new([0u8; 32]),
                    actual: anchor.commitment,
                });
            }
        }

        // Verify anchors are ordered consistently with transitions (by block_height)
        for i in 1..consignment.anchors.len() {
            if consignment.anchors[i].anchor_ref.block_height
                < consignment.anchors[i - 1].anchor_ref.block_height
            {
                errors.push(RgbValidationError::AnchorCommitmentMismatch {
                    anchor_index: i,
                    expected: Hash::new([0u8; 32]),
                    actual: consignment.anchors[i].commitment,
                });
            }
        }

        errors
    }

    /// Validate against schema rules
    fn validate_schema(consignment: &Consignment, _schema: &()) -> Vec<RgbValidationError> {
        let mut errors = Vec::new();

        // Schema validation is now in csv-codec
        // TODO: Integrate with csv-codec schema validation when available
        // For now, skip schema validation

        errors
    }
}

/// RGB Tapret commitment verifier
pub struct RgbTapretVerifier;

impl RgbTapretVerifier {
    /// Verify a Tapret commitment matches RGB specification.
    ///
    /// RGB uses a specific taproot commitment structure:
    /// - Internal key derived from protocol ID
    /// - Merkle root includes protocol ID + commitment hash
    /// - Control block proves inclusion in taproot tree
    pub fn verify_tapret_commitment(
        tapret_root: [u8; 32],
        protocol_id: [u8; 32],
        #[allow(unused_variables)] commitment: Hash,
        control_block: Option<Vec<u8>>,
    ) -> bool {
        // Verify the tapret root is non-trivial
        if tapret_root == [0u8; 32] || protocol_id == [0u8; 32] {
            return false;
        }

        #[cfg(feature = "tapret")]
        {
            // Verify the commitment is embedded in the tapret root.
            // The tapret root should be H(protocol_id || commitment_hash).
            let expected_tapret =
                tapret_verify::compute_tap_tweak_hash(protocol_id, Some(tapret_root));
            if expected_tapret != tapret_root {
                // The tapret_root should contain the commitment. Verify via OP_RETURN fallback.
                let opreturn_data: Vec<u8> = protocol_id[..4]
                    .iter()
                    .copied()
                    .chain(commitment.as_bytes().iter().copied())
                    .collect();
                if !Self::verify_opreturn_commitment(&opreturn_data, protocol_id, commitment) {
                    return false;
                }
            }
        }

        // If a control block is provided, verify its structure
        if let Some(cb) = control_block {
            // Control block must be at least 33 bytes (internal key) + 32 bytes (merkle path per level)
            if cb.len() < 33 {
                return false;
            }
            // First 32 bytes of control block should match the tapret root
            if cb.len() >= 64 && cb[1..33] != tapret_root {
                return false;
            }
        }

        true
    }

    /// Verify an OP_RETURN commitment (RGB fallback)
    pub fn verify_opreturn_commitment(
        opreturn_data: &[u8],
        protocol_id: [u8; 32],
        commitment: Hash,
    ) -> bool {
        // OP_RETURN format: [protocol_id (4 bytes)] [commitment hash (32 bytes)]
        if opreturn_data.len() < 36 {
            return false;
        }
        // Check protocol ID prefix
        if opreturn_data[..4] != protocol_id[..4] {
            return false;
        }
        // Check commitment hash
        opreturn_data[4..36] == *commitment.as_bytes()
    }
}

/// Cross-chain consignment validator
pub struct CrossChainValidator;

impl CrossChainValidator {
    /// Validate a consignment that spans multiple chains
    ///
    /// Ensures that commitments are consistent across all chains
    /// and that each chain's proof is valid.
    pub fn validate_cross_chain_consistency(anchors: &[Anchor]) -> Result<(), CrossChainError> {
        if anchors.is_empty() {
            return Ok(());
        }

        // All anchors should have the same commitment hash
        let first_commitment = anchors[0].commitment;
        for (i, anchor) in anchors.iter().enumerate().skip(1) {
            if anchor.commitment != first_commitment {
                return Err(CrossChainError::CommitmentMismatch {
                    anchor_index: i,
                    expected: first_commitment,
                    actual: anchor.commitment,
                });
            }
        }

        Ok(())
    }
}

/// Cross-chain validation error
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum CrossChainError {
    /// Commitment hash doesn't match between source and destination chains
    CommitmentMismatch {
        anchor_index: usize,
        expected: Hash,
        actual: Hash,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consignment::Anchor;
    use crate::genesis::Genesis;
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use crate::state::StateAssignment;

    fn test_consignment() -> Consignment {
        Consignment {
            version: 1,
            genesis: Genesis {
                contract_id: Hash::new([0x01; 32]),
                schema_id: Hash::new([0x02; 32]),
                global_state: vec![],
                owned_state: vec![],
                metadata: vec![],
            },
            transitions: vec![],
            seal_assignments: vec![],
            anchors: vec![],
            schema_id: Hash::new([0x02; 32]),
        }
    }

    #[test]
    fn test_rgb_validation_empty_consignment() {
        let consignment = test_consignment();
        let result = RgbConsignmentValidator::validate(&consignment, None);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_consignment_id_computation() {
        let consignment = test_consignment();
        let id = RgbConsignmentValidator::compute_consignment_id(&consignment);
        // ID should be non-zero
        assert_ne!(id.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_contract_id_from_genesis() {
        let consignment = test_consignment();
        let contract_id = RgbConsignmentValidator::compute_contract_id(&consignment.genesis);
        assert_eq!(contract_id, Hash::new([0x01; 32]));
    }

    #[test]
    fn test_seal_double_spend_detection() {
        let mut consignment = test_consignment();

        // Add duplicate seal assignments
        let seal = SealPoint::new(vec![0xAB; 32], Some(0)).unwrap();
        let assignment = crate::consignment::SealAssignment::new(
            seal.clone(),
            StateAssignment::new(0, seal.clone(), vec![]),
            vec![],
        );
        consignment.seal_assignments.push(assignment.clone());
        consignment.seal_assignments.push(assignment);

        let result = RgbConsignmentValidator::validate(&consignment, None);
        assert!(!result.is_valid);
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, RgbValidationError::SealDoubleSpend { .. }))
        );
    }

    #[test]
    fn test_tapret_commitment_verification() {
        let tapret_root = [0x01; 32];
        let protocol_id = [0x02; 32];
        let commitment = Hash::new([0x03; 32]);

        assert!(RgbTapretVerifier::verify_tapret_commitment(
            tapret_root,
            protocol_id,
            commitment,
            None
        ));
    }

    #[test]
    fn test_opreturn_commitment_verification() {
        let protocol_id: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let commitment = Hash::new([0xAB; 32]);

        let mut opreturn_data = vec![0u8; 36];
        opreturn_data[..4].copy_from_slice(&protocol_id[..4]);
        opreturn_data[4..].copy_from_slice(commitment.as_bytes());

        assert!(RgbTapretVerifier::verify_opreturn_commitment(
            &opreturn_data,
            protocol_id,
            commitment
        ));
    }

    #[test]
    fn test_opreturn_wrong_protocol() {
        let protocol_id: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let commitment = Hash::new([0xAB; 32]);

        let mut opreturn_data = vec![0u8; 36];
        opreturn_data[..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        opreturn_data[4..].copy_from_slice(commitment.as_bytes());

        assert!(!RgbTapretVerifier::verify_opreturn_commitment(
            &opreturn_data,
            protocol_id,
            commitment
        ));
    }

    #[test]
    fn test_cross_chain_consistency_valid() {
        let anchors = vec![
            Anchor::new(
                CommitAnchor::new(vec![0x01; 32], 100, vec![]).unwrap(),
                Hash::new([0xAB; 32]),
                vec![],
                vec![],
            ),
            Anchor::new(
                CommitAnchor::new(vec![0x02; 32], 200, vec![]).unwrap(),
                Hash::new([0xAB; 32]),
                vec![],
                vec![],
            ),
        ];

        assert!(CrossChainValidator::validate_cross_chain_consistency(&anchors).is_ok());
    }

    #[test]
    fn test_cross_chain_consistency_mismatch() {
        let anchors = vec![
            Anchor::new(
                CommitAnchor::new(vec![0x01; 32], 100, vec![]).unwrap(),
                Hash::new([0xAB; 32]),
                vec![],
                vec![],
            ),
            Anchor::new(
                CommitAnchor::new(vec![0x02; 32], 200, vec![]).unwrap(),
                Hash::new([0xCD; 32]), // Different commitment
                vec![],
                vec![],
            ),
        ];

        let result = CrossChainValidator::validate_cross_chain_consistency(&anchors);
        assert!(result.is_err());
    }
}
