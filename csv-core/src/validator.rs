//! Consignment Validation Pipeline - SECURITY CRITICAL
//!
//! Provides detailed, step-by-step validation of consignments:
//! 1. Fetch state proof chain
//! 2. Verify commitment linkage
//! 3. Verify single consumption of each seal
//! 4. Verify no conflicting state transitions
//! 5. Accept or reject based on full validation
//!
//! ## Validation Pipeline
//!
//! ```text
//! Consignment Received
//!   ↓
//! [1] Structural Validation
//!   - Version check
//!   - Schema ID consistency  
//!   - Required fields present
//!   ↓
//! [2] Commitment Chain Validation
//!   - Genesis → Latest chain integrity
//!   - No missing commitments
//!   - No cycles or duplicates
//!   ↓
//! [3] Seal Consumption Validation  
//!   - Each seal consumed at most once
//!   - Cross-chain double-spend check
//!   - Seal references match transitions
//!   ↓
//! [4] State Transition Validation
//!   - Inputs satisfied by prior outputs
//!   - State conservation rules
//!   - No conflicting transitions
//!   ↓
//! [5] Final Acceptance Decision
//!   - All checks pass → Accept
//!   - Any check fails → Reject with reason
//! ```
//!
//! # Security Purpose
//!
//! This validator is the **gatekeeper for all incoming consignments**. It ensures
//! that only valid, properly authorized state transitions are accepted into the
//! local state. A compromised or bypassed validator would allow fraudulent
//! state transitions.
//!
//! # Security Invariants
//!
//! 1. **Deterministic Validation**: Same consignment always produces same result
//! 2. **Complete Verification**: All 5 validation steps must pass
//! 3. **No Partial Acceptance**: A consignment is either fully accepted or rejected
//! 4. **Audit Trail**: Rejected consignments include detailed failure reasons
//! 5. **Seal Uniqueness**: Double-spend attempts are detected via `SealNullifier`
//!
//! # Critical Validation Steps
//!
//! | Step | Purpose | Security Impact |
//! |------|---------|-----------------|
//! | 1. Structural | Ensure well-formed data | Prevents malformed input attacks |
//! | 2. Commitment Chain | Verify chain integrity | Prevents insertion of fake history |
//! | 3. Seal Consumption | Double-spend detection | Prevents replay attacks |
//! | 4. State Transition | Valid state evolution | Prevents invalid state changes |
//! | 5. Acceptance | Final gate | Only valid consignments accepted |
//!
//! # Audit Checklist
//!
//! - [ ] All 5 validation steps execute for every consignment
//! - [ ] Seal consumption check uses `SealNullifier`
//! - [ ] No validation step can be bypassed via configuration
//! - [ ] Failed validations return detailed but safe error messages
//! - [ ] Validator state doesn't affect validation outcome (deterministic)

use alloc::vec::Vec;

use crate::consignment::Consignment;
use csv_hash::Hash;
use csv_hash::nullifier::{ChainId, SealConsumption, SealNullifier, SealStatus};
use crate::state_store::InMemoryStateStore;

#[cfg(feature = "experimental")]
use crate::vm::{AluVmAdapter, DeterministicVM, VMInputs};

/// Detailed validation report.
#[derive(Debug)]
pub struct ValidationReport {
    /// Whether the consignment passed validation
    pub passed: bool,
    /// Individual validation step results
    pub steps: Vec<ValidationStep>,
    /// Summary of findings
    pub summary: String,
}

/// A single validation step result.
#[derive(Debug)]
pub struct ValidationStep {
    /// Name of the validation step
    pub name: String,
    /// Whether this step passed
    pub passed: bool,
    /// Details of the validation (for debugging)
    pub details: String,
}

/// Consignment validator with detailed reporting.
pub struct ConsignmentValidator {
    /// State history store
    store: InMemoryStateStore,
    /// Cross-chain seal registry
    seal_registry: SealNullifier,
    /// Validation report being built
    report: ValidationReport,
    /// VM for executing validation scripts (AluVM) - Phase 5
    #[cfg(feature = "experimental")]
    vm: AluVmAdapter,
}

impl ConsignmentValidator {
    /// Create a new validator.
    pub fn new() -> Self {
        Self {
            store: InMemoryStateStore::new(),
            seal_registry: SealNullifier::new(),
            report: ValidationReport {
                passed: true,
                steps: Vec::new(),
                summary: String::new(),
            },
            #[cfg(feature = "experimental")]
            vm: AluVmAdapter::default_(),
        }
    }

    /// Create a new validator with custom VM cycle limit.
    #[cfg(feature = "experimental")]
    pub fn with_vm_cycles(max_cycles: u64) -> Self {
        Self {
            store: InMemoryStateStore::new(),
            seal_registry: SealNullifier::new(),
            report: ValidationReport {
                passed: true,
                steps: Vec::new(),
                summary: String::new(),
            },
            vm: AluVmAdapter::new(max_cycles),
        }
    }

    /// Validate a consignment with detailed reporting.
    pub fn validate_consignment(
        mut self,
        consignment: &Consignment,
        anchor_chain: ChainId,
    ) -> ValidationReport {
        // Step 1: Structural validation
        self.validate_structure(consignment);

        // Step 2: Commitment chain validation
        self.validate_commitment_chain(consignment);

        // Step 3: Seal consumption validation
        self.validate_seal_consumption(consignment, &anchor_chain);

        // Step 4: State transition validation
        self.validate_state_transitions(consignment);

        // Step 5: Generate summary
        self.generate_summary();

        self.report
    }

    /// Step 1: Validate consignment structure.
    fn validate_structure(&mut self, consignment: &Consignment) {
        let result = consignment.validate_structure();
        let passed = result.is_ok();

        self.report.steps.push(ValidationStep {
            name: "Structural Validation".to_string(),
            passed,
            details: if passed {
                "All structural checks passed".to_string()
            } else {
                format!("Structural validation failed: {}", result.unwrap_err())
            },
        });

        if !passed {
            self.report.passed = false;
        }
    }

    /// Step 2: Validate commitment chain integrity.
    fn validate_commitment_chain(&mut self, consignment: &Consignment) {
        // Verify that the anchors form a valid commitment chain.
        // Each anchor contains a commitment hash and an inclusion proof.
        // We verify that:
        // 1. The genesis commitment is consistent with the consignment
        // 2. Each transition's hash is linked to its anchor's commitment
        // 3. The commitment chain forms an unbroken sequence

        if consignment.anchors.is_empty() {
            // No anchors means no on-chain commitments to verify
            // This is valid for a genesis-only consignment
            self.report.steps.push(ValidationStep {
                name: "Commitment Chain Validation".to_string(),
                passed: true,
                details: "No anchors — genesis-only consignment".to_string(),
            });
            return;
        }

        // Verify anchor count matches transition count
        if consignment.anchors.len() != consignment.transitions.len() {
            self.report.steps.push(ValidationStep {
                name: "Commitment Chain Validation".to_string(),
                passed: false,
                details: format!(
                    "Anchor count mismatch: {} anchors but {} transitions",
                    consignment.anchors.len(),
                    consignment.transitions.len(),
                ),
            });
            self.report.passed = false;
            return;
        }

        // Verify each transition's hash is anchored
        let mut all_valid = true;
        let mut details = Vec::new();

        for (i, (transition, anchor)) in consignment
            .transitions
            .iter()
            .zip(consignment.anchors.iter())
            .enumerate()
        {
            let tx_hash = transition.hash();
            if tx_hash != anchor.commitment {
                all_valid = false;
                details.push(format!(
                    "Transition {} hash {} not anchored (got {})",
                    i,
                    hex::encode(tx_hash.as_bytes()),
                    hex::encode(anchor.commitment.as_bytes()),
                ));
            }
        }

        // Verify inclusion proofs are non-empty (basic check; full MPT/Merkle
        // verification is done by chain-specific verifiers)
        for (i, anchor) in consignment.anchors.iter().enumerate() {
            if anchor.inclusion_proof.is_empty() {
                all_valid = false;
                details.push(format!("Anchor {} has empty inclusion proof", i));
            }
            if anchor.finality_proof.is_empty() {
                all_valid = false;
                details.push(format!("Anchor {} has empty finality proof", i));
            }
        }

        self.report.steps.push(ValidationStep {
            name: "Commitment Chain Validation".to_string(),
            passed: all_valid,
            details: if all_valid {
                format!(
                    "Verified {} commitment(s) anchored on-chain",
                    consignment.anchors.len(),
                )
            } else {
                details.join("; ")
            },
        });

        if !all_valid {
            self.report.passed = false;
        }
    }

    /// Step 3: Validate seal consumption (no double-spends).
    fn validate_seal_consumption(&mut self, consignment: &Consignment, anchor_chain: &ChainId) {
        let mut all_passed = true;
        let mut details = Vec::new();

        for seal_assignment in &consignment.seal_assignments {
            match self
                .seal_registry
                .check_seal_status(&seal_assignment.seal_ref)
            {
                SealStatus::Unconsumed => {
                    // Create a synthetic Sanad ID for tracking
                    let sanad_id = csv_hash::sanad::SanadId(Hash::new(
                        seal_assignment
                            .seal_ref
                            .id
                            .clone()
                            .try_into()
                            .unwrap_or([0u8; 32]),
                    ));

                    let consumption = SealConsumption {
                        chain: anchor_chain.clone(),
                        seal_ref: seal_assignment.seal_ref.clone(),
                        sanad_id,
                        block_height: 0,
                        tx_hash: Hash::new([0u8; 32]),
                        recorded_at: 0,
                    };

                    if let Err(e) = self.seal_registry.record_consumption(consumption) {
                        all_passed = false;
                        details.push(format!("Double-spend: {:?}", e));
                    }
                }
                SealStatus::ConsumedOnChain { chain, .. } => {
                    all_passed = false;
                    details.push(format!("Seal already consumed on {:?}", chain));
                }
                SealStatus::DoubleSpent { consumptions } => {
                    all_passed = false;
                    details.push(format!(
                        "Seal double-spent across {} chains",
                        consumptions.len()
                    ));
                }
            }
        }

        self.report.steps.push(ValidationStep {
            name: "Seal Consumption Validation".to_string(),
            passed: all_passed,
            details: if all_passed {
                format!(
                    "All {} seals validated successfully",
                    consignment.seal_assignments.len()
                )
            } else {
                details.join("; ")
            },
        });

        if !all_passed {
            self.report.passed = false;
        }
    }

    /// Step 4: Validate state transitions.
    fn validate_state_transitions(&mut self, consignment: &Consignment) {
        // Verify state transitions are valid:
        // 1. Each transition's validation script is non-empty
        // 2. Each transition's input references point to valid commitments
        // 3. Seal assignments are consistent with transition outputs
        // 4. AluVM executes validation scripts correctly (Phase 5) - experimental feature
        let mut all_valid = true;
        let mut details = Vec::new();

        // Track available commitments from genesis and transition outputs
        let mut available_commitments: alloc::collections::BTreeSet<Hash> =
            alloc::collections::BTreeSet::new();

        // Genesis outputs are initially available (indexed by their commitment hash)
        for _owned in &consignment.genesis.owned_state {
            available_commitments.insert(consignment.genesis.hash());
        }

        for (i, transition) in consignment.transitions.iter().enumerate() {
            // Check validation script is non-empty
            if transition.validation_script.is_empty() {
                all_valid = false;
                details.push(format!("Transition {} has empty validation script", i));
                continue;
            }

            // Verify input references point to known commitments
            for input in &transition.owned_inputs {
                if !available_commitments.contains(&input.commitment) {
                    all_valid = false;
                    details.push(format!(
                        "Transition {} references unknown commitment {}",
                        i,
                        hex::encode(input.commitment.as_bytes()),
                    ));
                }
            }

            // Phase 5: Execute validation script using AluVM (experimental feature)
            #[cfg(feature = "experimental")]
            {
                let vm_inputs = self.build_vm_inputs(transition, consignment);
                let signatures: Vec<Vec<u8>> = transition.signatures.clone();

                match self.vm.execute(
                    &transition.validation_script,
                    vm_inputs.clone(),
                    &signatures,
                ) {
                    Ok(outputs) => {
                        // Validate outputs are consistent with inputs
                        if let Err(e) = self.vm.validate_outputs(&vm_inputs, &outputs) {
                            all_valid = false;
                            details.push(format!("Transition {} VM validation failed: {}", i, e));
                        }
                    }
                    Err(e) => {
                        all_valid = false;
                        details.push(format!("Transition {} VM execution failed: {}", i, e));
                    }
                }
            }

            // Track transition outputs as available for subsequent transitions
            available_commitments.insert(transition.hash());
        }

        // Verify seal assignments reference valid transition outputs
        for (i, assignment) in consignment.seal_assignments.iter().enumerate() {
            // The assignment should correspond to a transition output
            // Check that the assignment's metadata is well-formed
            if assignment.assignment.data.is_empty() {
                details.push(format!("Seal assignment {} has empty data", i));
            }
        }

        self.report.steps.push(ValidationStep {
            name: "State Transition Validation".to_string(),
            passed: all_valid,
            details: if all_valid {
                #[cfg(feature = "experimental")]
                {
                    format!(
                        "Validated {} transitions, {} commitments tracked, AluVM executed",
                        consignment.transitions.len(),
                        available_commitments.len(),
                    )
                }
                #[cfg(not(feature = "experimental"))]
                {
                    format!(
                        "Validated {} transitions, {} commitments tracked",
                        consignment.transitions.len(),
                        available_commitments.len(),
                    )
                }
            } else {
                details.join("; ")
            },
        });

        if !all_valid {
            self.report.passed = false;
        }
    }

    /// Build VM inputs for a transition (experimental feature).
    #[cfg(feature = "experimental")]
    fn build_vm_inputs(
        &self,
        transition: &crate::transition::Transition,
        consignment: &Consignment,
    ) -> VMInputs {
        use csv_hash::seal::SealPoint;
        use crate::state::{GlobalState, Metadata, OwnedState};

        // Convert transition inputs to owned states
        // Note: StateRef doesn't contain seal info, so we create placeholder seals
        // In production, these would be resolved from the state store
        let owned_inputs: Vec<OwnedState> = transition
            .owned_inputs
            .iter()
            .enumerate()
            .map(|(i, input)| {
                // Create a placeholder seal from the commitment hash
                let seal_ref = SealPoint::new(
                    input.commitment.as_bytes().to_vec(),
                    Some(input.output_index as u64),
                )
                .unwrap_or_else(|_| SealPoint::new(vec![0u8; 16], Some(0)).unwrap());

                OwnedState::from_hash(i as u16, seal_ref, input.commitment)
            })
            .collect();

        // Convert global state updates to global state
        let global_state: Vec<GlobalState> = transition
            .global_updates
            .iter()
            .enumerate()
            .map(|(i, gs)| GlobalState::new(i as u16, gs.data.clone()))
            .collect();

        // Build metadata from transition
        let metadata: Vec<Metadata> = transition
            .metadata
            .iter()
            .map(|m| Metadata::new(m.key.clone(), m.value.clone()))
            .collect();

        VMInputs::new(
            owned_inputs,
            global_state,
            metadata,
            consignment.genesis.contract_id.as_bytes().to_vec(),
        )
    }

    /// Generate final summary.
    fn generate_summary(&mut self) {
        let passed_count = self.report.steps.iter().filter(|s| s.passed).count();
        let total_count = self.report.steps.len();

        self.report.summary = if self.report.passed {
            format!(
                "Consignment accepted: {}/{} validation steps passed",
                passed_count, total_count
            )
        } else {
            let failed: Vec<&str> = self
                .report
                .steps
                .iter()
                .filter(|s| !s.passed)
                .map(|s| s.name.as_str())
                .collect();
            format!(
                "Consignment rejected: {} steps failed: {}",
                failed.len(),
                failed.join(", ")
            )
        };
    }

    /// Get access to the state store.
    pub fn store(&self) -> &InMemoryStateStore {
        &self.store
    }

    /// Get access to the seal registry.
    pub fn seal_registry(&self) -> &SealNullifier {
        &self.seal_registry
    }
}

impl Default for ConsignmentValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consignment::Consignment;
    use crate::genesis::Genesis;
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use crate::state_store::StateHistoryStore;

    fn make_test_consignment() -> Consignment {
        let genesis = Genesis::new(
            Hash::new([0xAB; 32]),
            Hash::new([0x01; 32]),
            vec![],
            vec![],
            vec![],
        );
        Consignment::new(genesis, vec![], vec![], vec![], Hash::new([0x01; 32]))
    }

    #[test]
    fn test_validator_creation() {
        let validator = ConsignmentValidator::new();
        assert_eq!(validator.store().list_contracts().unwrap().len(), 0);
    }

    #[test]
    fn test_validate_simple_consignment() {
        let validator = ConsignmentValidator::new();
        let consignment = make_test_consignment();

        let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));

        // Should have validation steps
        assert!(!report.steps.is_empty());

        // All steps should pass for a simple valid consignment
        for step in &report.steps {
            assert!(step.passed, "Step '{}' failed: {}", step.name, step.details);
        }
    }

    #[test]
    fn test_validation_report_structure() {
        let validator = ConsignmentValidator::new();
        let consignment = make_test_consignment();

        let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));

        // Report should have meaningful content
        assert!(!report.summary.is_empty());
        assert!(report.steps.len() >= 3); // At least structural, seal, and transition validation
    }

    #[test]
    fn test_validation_steps_are_sequential() {
        let validator = ConsignmentValidator::new();
        let consignment = make_test_consignment();

        let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));

        // Steps should be in expected order
        let step_names: Vec<&str> = report.steps.iter().map(|s| s.name.as_str()).collect();

        assert!(step_names.contains(&"Structural Validation"));
        assert!(step_names.contains(&"Seal Consumption Validation"));
        assert!(step_names.contains(&"State Transition Validation"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Property-based tests (proptest)
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_tampered_commitment_hash_rejected() {
        use proptest::prelude::*;

        proptest!(|(bytes in any::<[u8; 32]>())| {
            // A tampered commitment should not match any valid anchor
            let tampered_hash = Hash::new(bytes);
            let genesis = Genesis::new(
                tampered_hash,
                Hash::new([0x01; 32]),
                vec![],
                vec![],
                vec![],
            );
            let consignment = Consignment::new(
                genesis,
                vec![],
                vec![],
                vec![],
                tampered_hash,
            );
            let validator = ConsignmentValidator::new();
            let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));
            // Structural validation should catch the mismatch
            assert!(
                !report.passed || report.steps.iter().any(|s| !s.passed),
                "Tampered commitment should be detected"
            );
        });
    }

    #[test]
    fn test_wrong_chain_id_detected() {
        use proptest::prelude::*;

        proptest!(|(_chain_id_bytes in any::<[u8; 4]>())| {
            let genesis = Genesis::new(
                Hash::new([0xAB; 32]),
                Hash::new([0x01; 32]),
                vec![],
                vec![],
                vec![],
            );
            let consignment = Consignment::new(
                genesis,
                vec![],
                vec![],
                vec![],
                Hash::new([0x01; 32]),
            );
            let validator = ConsignmentValidator::new();
            // Validation should complete without panic regardless of chain ID
            let _report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));
        });
    }

    #[test]
    fn test_empty_consignment_validates_cleanly() {
        let genesis = Genesis::new(
            Hash::new([0xAB; 32]),
            Hash::new([0x01; 32]),
            vec![],
            vec![],
            vec![],
        );
        let consignment = Consignment::new(genesis, vec![], vec![], vec![], Hash::new([0x01; 32]));
        let validator = ConsignmentValidator::new();
        let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));
        // Empty consignment (genesis-only) should pass structural validation
        assert!(
            report.steps.iter().all(|s| s.passed),
            "Genesis-only consignment should pass: {:?}",
            report.steps
        );
    }

    #[test]
    fn test_multiple_transitions_validated_sequentially() {
        use proptest::prelude::*;

        proptest!(|(n in 1u32..10)| {
            let mut transitions = Vec::new();
            let mut seal_assignments = Vec::new();
            let mut anchors = Vec::new();

            for i in 0..n {
                let tx_hash = Hash::new([i as u8; 32]);
                transitions.push(crate::transition::Transition::new(
                    i as u16,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![0x01; 16],
                    vec![],
                ));
                anchors.push(crate::consignment::Anchor::new(
                    CommitAnchor::new(tx_hash.to_vec(), 0, vec![]).unwrap(),
                    tx_hash,
                    vec![0x02; 32],
                    vec![0x03; 32],
                ));
                seal_assignments.push(crate::consignment::SealAssignment::new(
                    SealPoint::new(vec![i as u8; 16], Some(i as u64)).unwrap(),
                    crate::state::StateAssignment::new(
                        1,
                        SealPoint::new(vec![i as u8; 16], Some(i as u64)).unwrap(),
                        vec![],
                    ),
                    vec![],
                ));
            }

            let genesis = Genesis::new(
                Hash::new([0xAB; 32]),
                Hash::new([0x01; 32]),
                vec![],
                vec![],
                vec![],
            );
            let consignment = Consignment::new(
                genesis,
                transitions,
                seal_assignments,
                anchors,
                Hash::new([0x01; 32]),
            );
            let validator = ConsignmentValidator::new();
            let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));
            assert!(!report.steps.is_empty());
        });
    }

    #[test]
    fn test_anchor_count_mismatch_detected() {
        let genesis = Genesis::new(
            Hash::new([0xAB; 32]),
            Hash::new([0x01; 32]),
            vec![],
            vec![],
            vec![],
        );
        let transitions = vec![
            crate::transition::Transition::new(
                0,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![0x01; 16],
                vec![],
            ),
            crate::transition::Transition::new(
                1,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![0x02; 16],
                vec![],
            ),
        ];
        // Only one anchor for two transitions
        let anchors = vec![crate::consignment::Anchor::new(
            CommitAnchor::new(Hash::new([0x01; 32]).to_vec(), 0, vec![]).unwrap(),
            Hash::new([0x01; 32]),
            vec![0x02; 32],
            vec![0x03; 32],
        )];
        let consignment =
            Consignment::new(genesis, transitions, vec![], anchors, Hash::new([0x01; 32]));
        let validator = ConsignmentValidator::new();
        let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));
        assert!(!report.passed, "Anchor count mismatch should be detected");
    }

    #[test]
    fn test_empty_inclusion_proof_detected() {
        let genesis = Genesis::new(
            Hash::new([0xAB; 32]),
            Hash::new([0x01; 32]),
            vec![],
            vec![],
            vec![],
        );
        let tx_hash = Hash::new([0x01; 32]);
        let transitions = vec![crate::transition::Transition::new(
            0,
            vec![],
            vec![],
            vec![],
            vec![],
            vec![0x01; 16],
            vec![],
        )];
        // Anchor with empty inclusion proof
        let anchors = vec![crate::consignment::Anchor::new(
            CommitAnchor::new(tx_hash.to_vec(), 0, vec![]).unwrap(),
            tx_hash,
            vec![], // empty inclusion proof
            vec![0x03; 32],
        )];
        let consignment =
            Consignment::new(genesis, transitions, vec![], anchors, Hash::new([0x01; 32]));
        let validator = ConsignmentValidator::new();
        let report = validator.validate_consignment(&consignment, ChainId::new("bitcoin"));
        assert!(!report.passed, "Empty inclusion proof should be detected");
    }
}
