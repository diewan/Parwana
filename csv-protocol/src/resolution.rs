//! Resolution and validation of consumed state (PAR-STATE-003).
//!
//! A transition's consumed references are claims. This module turns each claim
//! into exactly one verified parent output, or into a named failure — and binds
//! the resolved inputs together with the created outputs into the transition
//! commitment, so neither can be changed without changing the commitment.
//!
//! This implements RFC-0014 §3.1 P4–P5 and is a prerequisite for the source
//! closure dimension: closure decides which successor of a state wins, but only
//! after resolution has established *which* state a successor consumes.
//!
//! # Separate checks, separate errors
//!
//! Existence, index, state type, schema agreement, content commitment, and
//! authorization are checked independently and report distinct
//! [`ResolutionError`] variants. Collapsing them into "input invalid" would make
//! a mutated parent indistinguishable from a wrong index, and neither
//! diagnosable by a recipient.
//!
//! # What this layer does not do
//!
//! - It does not execute VM bytecode. `validation_script` is carried into the
//!   commitment so it cannot be swapped, but running it belongs to the VM.
//!   [`ResolvedTransition::validate_rules`] checks the rules that are decidable
//!   here and says so, rather than implying a program was run.
//! - It does not verify signatures cryptographically. It checks that a
//!   presented signer is one the parent output authorizes; whether the
//!   signature is valid is a separate assurance dimension owned by
//!   `csv-verifier` (PAR-VERIFY-001).
//! - It does not establish source closure. Resolution succeeding means the
//!   successor is *well-formed*, never that it is the unique successor.

use std::collections::BTreeSet;

use crate::exclusivity::{
    ConsumptionMode, ExclusivityClass, ExclusivityError, OutputUseBinding, StateUseSchema,
};
use crate::reference::ConsumedStateRef;
use crate::state::{StateAssignment, StateRef, StateTypeId};
use crate::transition::Transition;
use csv_hash::seal::SealPoint;
use csv_hash::{Hash, csv_tagged_hash};
use serde::{Deserialize, Serialize};

/// Domain tag for a parent output's content commitment.
pub const PARENT_OUTPUT_TAG: &str = "parent-output-v2";
/// Domain tag for a created output's commitment.
pub const CREATED_OUTPUT_TAG: &str = "created-output-v2";
/// Domain tag for a resolved transition's commitment.
pub const RESOLVED_TRANSITION_TAG: &str = "resolved-transition-v2";

/// One output created by an accepted transition, available to be consumed.
///
/// The `recorded_commitment` is what the creating transition committed to. It
/// is checked against a recomputation from the content below, so a parent whose
/// stored state was mutated after the fact does not resolve.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentOutput {
    /// Transition that created this output.
    pub transition_id: Hash,
    /// Index of this output within that transition.
    pub output_index: u32,
    /// State type of this output.
    pub state_type: StateTypeId,
    /// Use semantics fixed when this output was created (PAR-STATE-002).
    pub use_binding: OutputUseBinding,
    /// Seal that owns this output.
    pub seal: SealPoint,
    /// Output payload.
    pub data: Vec<u8>,
    /// The commitment the creating transition recorded for this output.
    pub recorded_commitment: Hash,
    /// Signer keys permitted to consume this output.
    pub authorized_consumers: Vec<Vec<u8>>,
}

impl ParentOutput {
    /// Commitment recomputed from this output's content.
    ///
    /// Binds identity, state type, use semantics, seal, payload, and the
    /// authorized-consumer list. Mutating any of them changes this value, which
    /// is what makes a tampered parent visible against its
    /// `recorded_commitment`.
    pub fn content_commitment(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(self.transition_id.as_bytes());
        data.extend_from_slice(&self.output_index.to_le_bytes());
        data.extend_from_slice(&self.state_type.to_le_bytes());
        let binding = self.use_binding.to_canonical_bytes();
        data.extend_from_slice(&(binding.len() as u32).to_le_bytes());
        data.extend_from_slice(&binding);
        data.extend_from_slice(&(self.seal.id.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.seal.id);
        data.extend_from_slice(&self.seal.nonce.unwrap_or_default().to_le_bytes());
        data.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.data);
        data.extend_from_slice(&(self.authorized_consumers.len() as u32).to_le_bytes());
        for consumer in &self.authorized_consumers {
            data.extend_from_slice(&(consumer.len() as u32).to_le_bytes());
            data.extend_from_slice(consumer);
        }
        Hash::new(csv_tagged_hash(PARENT_OUTPUT_TAG, &data))
    }

    /// Build an output whose recorded commitment is its content commitment.
    ///
    /// The honest constructor: there is no way to record a commitment that does
    /// not describe the content.
    pub fn sealed(
        transition_id: Hash,
        output_index: u32,
        use_binding: OutputUseBinding,
        seal: SealPoint,
        data: Vec<u8>,
        authorized_consumers: Vec<Vec<u8>>,
    ) -> Self {
        let mut output = Self {
            transition_id,
            output_index,
            state_type: use_binding.state_type(),
            use_binding,
            seal,
            data,
            recorded_commitment: Hash::zero(),
            authorized_consumers,
        };
        output.recorded_commitment = output.content_commitment();
        output
    }

    /// The reference that consumes this output.
    pub fn reference(&self) -> ConsumedStateRef {
        ConsumedStateRef::new(self.transition_id, self.output_index, self.state_type)
    }
}

/// Where resolution looks up parent outputs.
///
/// Implemented by the runtime's accepted-state store. An empty result is a
/// statement that this resolver has no such output — never that no such output
/// exists anywhere, which no local store can know.
pub trait ParentStateSource {
    /// Every output at `output_index` of `transition_id` known to this source.
    ///
    /// A well-formed source returns zero or one value. Returning all matches
    /// lets resolution reject ambiguous history instead of silently selecting
    /// whichever duplicate happened to be stored first.
    fn outputs(&self, transition_id: Hash, output_index: u32) -> Vec<&ParentOutput>;

    /// Whether this source knows any output created by `transition_id`.
    ///
    /// This distinguishes a missing transition from a known transition with a
    /// missing output index, including sparse histories without output zero.
    fn contains_transition(&self, transition_id: Hash) -> bool;
}

impl ParentStateSource for Vec<ParentOutput> {
    fn outputs(&self, transition_id: Hash, output_index: u32) -> Vec<&ParentOutput> {
        self.iter()
            .filter(|output| {
                output.transition_id == transition_id && output.output_index == output_index
            })
            .collect()
    }

    fn contains_transition(&self, transition_id: Hash) -> bool {
        self.iter()
            .any(|output| output.transition_id == transition_id)
    }
}

/// Why a consumed reference did not resolve to exactly one verified parent.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionError {
    /// No output exists for the referenced transition.
    #[error("no output of transition {transition_id} is available")]
    MissingParent {
        /// The transition the reference names.
        transition_id: Hash,
    },
    /// The transition exists but has no output at that index.
    #[error("transition {transition_id} has no output at index {output_index}")]
    WrongOutputIndex {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
    },
    /// More than one parent occupies the referenced coordinate, so the supplied
    /// history is internally equivocal.
    #[error(
        "source contains {matches} outputs at index {output_index} of transition {transition_id}"
    )]
    AmbiguousParent {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
        /// Number of conflicting candidates supplied.
        matches: usize,
    },
    /// The referenced output exists but is of a different state type.
    #[error(
        "output {output_index} of transition {transition_id} is state type {actual}, \
         not the referenced {referenced}"
    )]
    StateTypeMismatch {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
        /// State type the reference asserts.
        referenced: StateTypeId,
        /// State type the output actually has.
        actual: StateTypeId,
    },
    /// The schema disagrees with the output's recorded use semantics, or the
    /// requested consumption mode is not one the output permits.
    #[error("state-use check failed: {0}")]
    Schema(#[from] ExclusivityError),
    /// The parent output's content does not reproduce its recorded commitment.
    /// This is what a mutated parent state looks like.
    #[error(
        "output {output_index} of transition {transition_id} records commitment {recorded} \
         but its content produces {recomputed}"
    )]
    CommitmentMismatch {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
        /// The commitment the output records.
        recorded: Hash,
        /// The commitment its content produces.
        recomputed: Hash,
    },
    /// No presented signer is authorized to consume this output.
    #[error(
        "no presented signer is authorized to consume output {output_index} of transition {transition_id}"
    )]
    Unauthorized {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
    },
    /// The parent output authorizes nobody, so it can never be consumed.
    /// Reported separately from `Unauthorized` because the fault is in the
    /// parent, not the presenter.
    #[error("output {output_index} of transition {transition_id} authorizes no consumer")]
    NoAuthorizedConsumer {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
    },
    /// One transition consumes the same output twice.
    #[error(
        "output {output_index} of transition {transition_id} is consumed twice by one transition"
    )]
    DuplicateConsumption {
        /// The transition the reference names.
        transition_id: Hash,
        /// The index the reference names.
        output_index: u32,
    },
    /// A created output names a state type the schema does not bind, so it has
    /// no use semantics and cannot be created.
    #[error("created output {index} names unbound state type {state_type}")]
    UnboundCreatedOutput {
        /// Index of the created output.
        index: usize,
        /// The unbound state type.
        state_type: StateTypeId,
    },
    /// A declared input could not be decoded into a consumption reference.
    /// Fails closed rather than resolving to a zero-filled reference.
    #[error("declared input {index} is not a well-formed consumption reference: {reason}")]
    MalformedReference {
        /// Index of the declared input.
        index: usize,
        /// Why decoding failed.
        reason: String,
    },
}

/// One consumed reference, resolved to exactly one verified parent output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedInput {
    /// The reference that was resolved.
    pub reference: ConsumedStateRef,
    /// The parent output it resolved to.
    pub parent: ParentOutput,
    /// The consumption mode the parent's use binding authorized. Determined by
    /// the output, never by the consuming transition.
    pub mode: ConsumptionMode,
}

impl ResolvedInput {
    /// Digest binding the reference to the parent it resolved to.
    ///
    /// Includes the parent's content commitment, so this changes if the parent
    /// changes even when the reference does not.
    pub fn digest(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.reference.to_canonical_bytes());
        data.extend_from_slice(self.parent.content_commitment().as_bytes());
        data.push(self.mode as u8);
        Hash::new(csv_tagged_hash(PARENT_OUTPUT_TAG, &data))
    }
}

/// A transition whose every consumed reference resolved, with the commitment
/// that binds those inputs to its created outputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTransition {
    /// Schema-defined transition identifier.
    pub transition_id: u16,
    /// Resolved consumed inputs, in the transition's declared order.
    pub inputs: Vec<ResolvedInput>,
    /// Created outputs, in the transition's declared order.
    pub outputs: Vec<StateAssignment>,
    /// Validation bytecode carried into the commitment so it cannot be swapped.
    pub validation_script: Vec<u8>,
}

impl ResolvedTransition {
    /// The seals consumed by this transition, taken from resolved parent state.
    ///
    /// This replaces `Transition::consumed_seals()`, which could only ever
    /// return an empty placeholder: a `StateRef` names a parent output, and the
    /// seal that owns it lives on the parent. Resolution is what makes the
    /// question answerable, so the method lives here.
    pub fn consumed_seals(&self) -> Vec<SealPoint> {
        self.inputs
            .iter()
            .map(|input| input.parent.seal.clone())
            .collect()
    }

    /// The exclusively-consumed inputs — those requiring source closure.
    pub fn exclusive_inputs(&self) -> Vec<&ResolvedInput> {
        self.inputs
            .iter()
            .filter(|input| input.mode == ConsumptionMode::Exclusive)
            .collect()
    }

    /// Commitment binding the resolved inputs and the created outputs.
    ///
    /// Changing a consumed input — its reference, its parent's content, or the
    /// mode it was consumed under — changes this value. So does changing any
    /// created output, the transition id, or the validation script.
    pub fn commitment(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.transition_id.to_le_bytes());

        data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            data.extend_from_slice(input.digest().as_bytes());
        }

        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for (index, output) in self.outputs.iter().enumerate() {
            data.extend_from_slice(created_output_digest(index, output).as_bytes());
        }

        data.extend_from_slice(&(self.validation_script.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.validation_script);

        Hash::new(csv_tagged_hash(RESOLVED_TRANSITION_TAG, &data))
    }

    /// Check the transition rules decidable at this layer.
    ///
    /// This is rule validation, not program execution: it does not run
    /// `validation_script`. It checks that created outputs have use semantics
    /// under `schema`, and that a transition consuming exclusive state is not
    /// silently treated as genesis-like.
    pub fn validate_rules(&self, schema: &StateUseSchema) -> Result<(), ResolutionError> {
        for (index, output) in self.outputs.iter().enumerate() {
            if schema.class_of(output.type_id).is_none() {
                return Err(ResolutionError::UnboundCreatedOutput {
                    index,
                    state_type: output.type_id,
                });
            }
        }
        for input in &self.inputs {
            schema.reconcile(&input.parent.use_binding)?;
        }
        Ok(())
    }
}

/// Digest of one created output at its declared position.
fn created_output_digest(index: usize, output: &StateAssignment) -> Hash {
    let mut data = Vec::new();
    data.extend_from_slice(&(index as u32).to_le_bytes());
    data.extend_from_slice(&output.type_id.to_le_bytes());
    // `SealPointWire::id` is the hex encoding; commit to its bytes as declared
    // so a re-encoding cannot silently change the digest.
    let seal_id = output.seal.id.as_bytes();
    data.extend_from_slice(&(seal_id.len() as u32).to_le_bytes());
    data.extend_from_slice(seal_id);
    data.extend_from_slice(&output.seal.nonce.unwrap_or_default().to_le_bytes());
    data.extend_from_slice(&(output.data.len() as u32).to_le_bytes());
    data.extend_from_slice(&output.data);
    Hash::new(csv_tagged_hash(CREATED_OUTPUT_TAG, &data))
}

/// Resolve one consumed reference to exactly one verified parent output.
///
/// Each check is independent and reports its own error. `presented_signers` are
/// the signer keys the consuming party presents; membership in the parent's
/// authorized set is checked here, and the cryptographic validity of their
/// signatures is a separate dimension.
pub fn resolve_input(
    reference: &ConsumedStateRef,
    source: &impl ParentStateSource,
    schema: &StateUseSchema,
    presented_signers: &[Vec<u8>],
) -> Result<ResolvedInput, ResolutionError> {
    // 1. Existence, distinguishing "no such transition" from "no such index".
    let candidates = source.outputs(reference.transition_id, reference.output_index);
    let parent = match candidates.as_slice() {
        [parent] => *parent,
        [] if source.contains_transition(reference.transition_id) => {
            return Err(ResolutionError::WrongOutputIndex {
                transition_id: reference.transition_id,
                output_index: reference.output_index,
            });
        }
        [] => {
            return Err(ResolutionError::MissingParent {
                transition_id: reference.transition_id,
            });
        }
        _ => {
            return Err(ResolutionError::AmbiguousParent {
                transition_id: reference.transition_id,
                output_index: reference.output_index,
                matches: candidates.len(),
            });
        }
    };

    // 2. State type asserted by the reference must be the one the output has.
    if parent.state_type != reference.state_type {
        return Err(ResolutionError::StateTypeMismatch {
            transition_id: reference.transition_id,
            output_index: reference.output_index,
            referenced: reference.state_type,
            actual: parent.state_type,
        });
    }

    // 3. The schema must still agree with the semantics the output recorded.
    schema.reconcile(&parent.use_binding)?;

    // 4. The output's content must reproduce the commitment it records.
    let recomputed = parent.content_commitment();
    if parent.recorded_commitment != recomputed {
        return Err(ResolutionError::CommitmentMismatch {
            transition_id: reference.transition_id,
            output_index: reference.output_index,
            recorded: parent.recorded_commitment,
            recomputed,
        });
    }

    // 5. Authorization: the parent decides who may consume it.
    if parent.authorized_consumers.is_empty() {
        return Err(ResolutionError::NoAuthorizedConsumer {
            transition_id: reference.transition_id,
            output_index: reference.output_index,
        });
    }
    if !presented_signers
        .iter()
        .any(|signer| parent.authorized_consumers.contains(signer))
    {
        return Err(ResolutionError::Unauthorized {
            transition_id: reference.transition_id,
            output_index: reference.output_index,
        });
    }

    // 6. The output — not the transition — decides the consumption mode.
    let mode = parent
        .use_binding
        .authorize(parent.use_binding.class().required_mode())?;

    Ok(ResolvedInput {
        reference: *reference,
        parent: parent.clone(),
        mode,
    })
}

/// Resolve every consumed reference of `transition` (PAR-STATE-003).
///
/// This is the production path that exercises `Transition::owned_inputs`: every
/// declared input is converted to a [`ConsumedStateRef`] and resolved, and the
/// result binds those inputs and the created outputs into one commitment.
pub fn resolve_transition(
    transition: &Transition,
    source: &impl ParentStateSource,
    schema: &StateUseSchema,
    presented_signers: &[Vec<u8>],
) -> Result<ResolvedTransition, ResolutionError> {
    let mut inputs = Vec::with_capacity(transition.owned_inputs.len());
    let mut seen = BTreeSet::new();

    for reference in consumed_state_refs(&transition.owned_inputs)? {
        if !seen.insert((reference.transition_id, reference.output_index)) {
            return Err(ResolutionError::DuplicateConsumption {
                transition_id: reference.transition_id,
                output_index: reference.output_index,
            });
        }
        inputs.push(resolve_input(
            &reference,
            source,
            schema,
            presented_signers,
        )?);
    }

    let resolved = ResolvedTransition {
        transition_id: transition.transition_id,
        inputs,
        outputs: transition.owned_outputs.clone(),
        validation_script: transition.validation_script.clone(),
    };
    resolved.validate_rules(schema)?;
    Ok(resolved)
}

/// The V2 consumption references a transition's declared inputs stand for.
///
/// `StateRef` is the V1 shape; its `commitment` field names the transition that
/// created the output, which is exactly `ConsumedStateRef::transition_id`.
///
/// Decoding fails closed on a malformed commitment rather than substituting a
/// zero hash: two distinct malformed inputs would otherwise collapse to the
/// same reference (`DECODE-ZEROFILL-FAILCLOSED-001`).
pub fn consumed_state_refs(inputs: &[StateRef]) -> Result<Vec<ConsumedStateRef>, ResolutionError> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let transition_id = input.commitment.to_hash().map_err(|reason| {
                ResolutionError::MalformedReference {
                    index,
                    reason: reason.to_string(),
                }
            })?;
            Ok(ConsumedStateRef::new(
                transition_id,
                input.output_index,
                input.type_id,
            ))
        })
        .collect()
}

/// Whether a resolved transition consumes any exclusive state.
///
/// A transition that does is not genesis-like however few inputs it has, and
/// its acceptance requires source closure.
pub fn requires_source_closure(resolved: &ResolvedTransition) -> bool {
    resolved
        .inputs
        .iter()
        .any(|input| input.parent.use_binding.class() == ExclusivityClass::Exclusive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateAssignment;

    const TOKEN: StateTypeId = 10;
    const NOTE: StateTypeId = 11;
    const PARENT: [u8; 32] = [1u8; 32];

    fn schema() -> StateUseSchema {
        let mut schema = StateUseSchema::new();
        schema.bind(TOKEN, ExclusivityClass::Exclusive).unwrap();
        schema.bind(NOTE, ExclusivityClass::Citable).unwrap();
        schema
    }

    fn owner() -> Vec<u8> {
        vec![0xAAu8; 33]
    }

    fn seal(tag: u8) -> SealPoint {
        SealPoint::new(vec![tag; 16], Some(1), None).unwrap()
    }

    fn parent_output(index: u32, state_type: StateTypeId) -> ParentOutput {
        ParentOutput::sealed(
            Hash::new(PARENT),
            index,
            schema().bind_output(state_type).unwrap(),
            seal(0xAA),
            vec![index as u8; 8],
            vec![owner()],
        )
    }

    fn source() -> Vec<ParentOutput> {
        vec![parent_output(0, TOKEN), parent_output(1, NOTE)]
    }

    fn transition_consuming(reference: ConsumedStateRef) -> Transition {
        Transition::new(
            7,
            vec![StateRef::new(
                reference.state_type,
                reference.transition_id,
                reference.output_index,
            )],
            vec![StateAssignment::new(TOKEN, seal(0xBB), vec![0x01, 0x02])],
            vec![],
            vec![],
            vec![0x01],
            vec![],
        )
    }

    // ── Happy path ──────────────────────────────────────────────────────────

    #[test]
    fn a_reference_resolves_to_exactly_one_parent_output() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let resolved = resolve_input(&reference, &source(), &schema(), &[owner()]).unwrap();
        assert_eq!(resolved.parent.output_index, 0);
        assert_eq!(resolved.parent.state_type, TOKEN);
        assert_eq!(resolved.mode, ConsumptionMode::Exclusive);
    }

    #[test]
    fn owned_inputs_are_exercised_by_resolution() {
        // The type carries `owned_inputs`; this is the production path that
        // actually walks them.
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let transition = transition_consuming(reference);
        assert_eq!(transition.owned_inputs.len(), 1);

        let resolved = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();
        assert_eq!(resolved.inputs.len(), 1);
        assert_eq!(resolved.inputs[0].reference, reference);
    }

    // ── Each failure is separate ────────────────────────────────────────────

    #[test]
    fn a_missing_parent_fails_on_its_own() {
        let absent = Hash::new([9u8; 32]);
        let reference = ConsumedStateRef::new(absent, 0, TOKEN);
        assert_eq!(
            resolve_input(&reference, &source(), &schema(), &[owner()]),
            Err(ResolutionError::MissingParent {
                transition_id: absent
            })
        );
    }

    #[test]
    fn a_wrong_index_fails_on_its_own() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 7, TOKEN);
        assert_eq!(
            resolve_input(&reference, &source(), &schema(), &[owner()]),
            Err(ResolutionError::WrongOutputIndex {
                transition_id: Hash::new(PARENT),
                output_index: 7,
            })
        );
    }

    #[test]
    fn a_sparse_history_still_reports_a_wrong_index() {
        let outputs = vec![parent_output(3, TOKEN)];
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 7, TOKEN);
        assert_eq!(
            resolve_input(&reference, &outputs, &schema(), &[owner()]),
            Err(ResolutionError::WrongOutputIndex {
                transition_id: Hash::new(PARENT),
                output_index: 7,
            })
        );
    }

    #[test]
    fn duplicate_parent_coordinates_fail_as_ambiguous() {
        let parent = parent_output(0, TOKEN);
        let outputs = vec![parent.clone(), parent];
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        assert_eq!(
            resolve_input(&reference, &outputs, &schema(), &[owner()]),
            Err(ResolutionError::AmbiguousParent {
                transition_id: Hash::new(PARENT),
                output_index: 0,
                matches: 2,
            })
        );
    }

    #[test]
    fn a_wrong_state_type_fails_on_its_own() {
        // Output 1 is a NOTE; the reference claims it is a TOKEN.
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 1, TOKEN);
        assert_eq!(
            resolve_input(&reference, &source(), &schema(), &[owner()]),
            Err(ResolutionError::StateTypeMismatch {
                transition_id: Hash::new(PARENT),
                output_index: 1,
                referenced: TOKEN,
                actual: NOTE,
            })
        );
    }

    #[test]
    fn a_mutated_parent_fails_on_its_own() {
        let mut outputs = source();
        // Tamper with the payload but leave the recorded commitment alone —
        // the shape a rewritten local store has.
        outputs[0].data = vec![0xFF; 8];

        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let failure = resolve_input(&reference, &outputs, &schema(), &[owner()]).unwrap_err();
        assert!(
            matches!(failure, ResolutionError::CommitmentMismatch { .. }),
            "unexpected failure: {failure}"
        );
    }

    #[test]
    fn an_unauthorized_consumer_fails_on_its_own() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        assert_eq!(
            resolve_input(&reference, &source(), &schema(), &[vec![0xBBu8; 33]]),
            Err(ResolutionError::Unauthorized {
                transition_id: Hash::new(PARENT),
                output_index: 0,
            })
        );
    }

    #[test]
    fn a_rewritten_authorization_list_fails_as_mutated_parent() {
        let mut outputs = source();
        let attacker = vec![0xBBu8; 33];
        outputs[0].authorized_consumers = vec![attacker.clone()];

        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let failure = resolve_input(&reference, &outputs, &schema(), &[attacker]).unwrap_err();
        assert!(
            matches!(failure, ResolutionError::CommitmentMismatch { .. }),
            "unexpected failure: {failure}"
        );
    }

    #[test]
    fn an_output_authorizing_nobody_fails_distinctly() {
        let mut outputs = source();
        outputs[0].authorized_consumers.clear();
        outputs[0].recorded_commitment = outputs[0].content_commitment();

        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        assert_eq!(
            resolve_input(&reference, &outputs, &schema(), &[owner()]),
            Err(ResolutionError::NoAuthorizedConsumer {
                transition_id: Hash::new(PARENT),
                output_index: 0,
            })
        );
    }

    #[test]
    fn a_schema_that_reinterprets_the_parent_fails_on_its_own() {
        // A revised schema that would weaken an existing exclusive output.
        let mut revised = StateUseSchema::new();
        revised.bind(TOKEN, ExclusivityClass::Citable).unwrap();
        revised.bind(NOTE, ExclusivityClass::Citable).unwrap();

        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let failure = resolve_input(&reference, &source(), &revised, &[owner()]).unwrap_err();
        assert!(
            matches!(
                failure,
                ResolutionError::Schema(ExclusivityError::SchemaReinterpretation { .. })
            ),
            "unexpected failure: {failure}"
        );
    }

    #[test]
    fn consuming_the_same_output_twice_in_one_transition_fails() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let mut transition = transition_consuming(reference);
        transition
            .owned_inputs
            .push(StateRef::new(TOKEN, Hash::new(PARENT), 0));

        assert_eq!(
            resolve_transition(&transition, &source(), &schema(), &[owner()]),
            Err(ResolutionError::DuplicateConsumption {
                transition_id: Hash::new(PARENT),
                output_index: 0,
            })
        );
    }

    #[test]
    fn every_failure_reports_a_distinct_reason() {
        let messages: BTreeSet<String> = [
            ResolutionError::MissingParent {
                transition_id: Hash::new(PARENT),
            },
            ResolutionError::WrongOutputIndex {
                transition_id: Hash::new(PARENT),
                output_index: 7,
            },
            ResolutionError::StateTypeMismatch {
                transition_id: Hash::new(PARENT),
                output_index: 1,
                referenced: TOKEN,
                actual: NOTE,
            },
            ResolutionError::CommitmentMismatch {
                transition_id: Hash::new(PARENT),
                output_index: 0,
                recorded: Hash::zero(),
                recomputed: Hash::new([2u8; 32]),
            },
            ResolutionError::Unauthorized {
                transition_id: Hash::new(PARENT),
                output_index: 0,
            },
        ]
        .iter()
        .map(|error| error.to_string())
        .collect();
        assert_eq!(messages.len(), 5);
    }

    // ── consumed_seals comes from resolved state ────────────────────────────

    #[test]
    fn consumed_seals_are_taken_from_the_resolved_parents() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let transition = transition_consuming(reference);
        let resolved = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();

        let seals = resolved.consumed_seals();
        assert_eq!(seals.len(), 1, "not an empty placeholder");
        assert_eq!(seals[0], seal(0xAA));
    }

    #[test]
    fn exclusive_inputs_are_identified_for_closure() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN);
        let transition = transition_consuming(reference);
        let resolved = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();

        assert_eq!(resolved.exclusive_inputs().len(), 1);
        assert!(requires_source_closure(&resolved));
    }

    #[test]
    fn a_citable_input_does_not_require_source_closure() {
        let reference = ConsumedStateRef::new(Hash::new(PARENT), 1, NOTE);
        let mut transition = transition_consuming(reference);
        transition.owned_inputs = vec![StateRef::new(NOTE, Hash::new(PARENT), 1)];

        let resolved = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();
        assert_eq!(resolved.inputs[0].mode, ConsumptionMode::Observational);
        assert!(!requires_source_closure(&resolved));
    }

    // ── The commitment binds inputs and outputs ─────────────────────────────

    #[test]
    fn changing_a_consumed_input_changes_the_commitment() {
        let base = resolve_transition(
            &transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN)),
            &source(),
            &schema(),
            &[owner()],
        )
        .unwrap();

        let mut other = transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 1, NOTE));
        other.owned_inputs = vec![StateRef::new(NOTE, Hash::new(PARENT), 1)];
        let switched = resolve_transition(&other, &source(), &schema(), &[owner()]).unwrap();

        assert_ne!(base.commitment(), switched.commitment());
    }

    #[test]
    fn mutating_a_resolved_parent_changes_the_commitment() {
        let mut resolved = resolve_transition(
            &transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN)),
            &source(),
            &schema(),
            &[owner()],
        )
        .unwrap();
        let before = resolved.commitment();

        // The reference is untouched; only the parent's content changes.
        resolved.inputs[0].parent.data = vec![0xFF; 8];
        assert_ne!(before, resolved.commitment());
    }

    #[test]
    fn changing_a_created_output_changes_the_commitment() {
        let transition = transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN));
        let base = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();

        let mut changed = transition.clone();
        changed.owned_outputs = vec![StateAssignment::new(TOKEN, seal(0xBB), vec![0x09])];
        let after = resolve_transition(&changed, &source(), &schema(), &[owner()]).unwrap();

        assert_ne!(base.commitment(), after.commitment());
    }

    #[test]
    fn reordering_created_outputs_changes_the_commitment() {
        let transition = transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN));

        let mut forward = transition.clone();
        forward.owned_outputs = vec![
            StateAssignment::new(TOKEN, seal(0xBB), vec![0x01]),
            StateAssignment::new(TOKEN, seal(0xCC), vec![0x02]),
        ];
        let mut reversed = forward.clone();
        reversed.owned_outputs.reverse();

        let a = resolve_transition(&forward, &source(), &schema(), &[owner()]).unwrap();
        let b = resolve_transition(&reversed, &source(), &schema(), &[owner()]).unwrap();
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn changing_the_validation_script_changes_the_commitment() {
        let transition = transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN));
        let base = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();

        let mut changed = transition.clone();
        changed.validation_script = vec![0xFF, 0xFE];
        let after = resolve_transition(&changed, &source(), &schema(), &[owner()]).unwrap();

        assert_ne!(base.commitment(), after.commitment());
    }

    #[test]
    fn the_commitment_is_deterministic() {
        let transition = transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN));
        let a = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();
        let b = resolve_transition(&transition, &source(), &schema(), &[owner()]).unwrap();
        assert_eq!(a.commitment(), b.commitment());
    }

    // ── Rule validation ─────────────────────────────────────────────────────

    #[test]
    fn a_created_output_of_an_unbound_state_type_is_refused() {
        let mut transition =
            transition_consuming(ConsumedStateRef::new(Hash::new(PARENT), 0, TOKEN));
        transition.owned_outputs = vec![StateAssignment::new(99, seal(0xBB), vec![0x01])];

        assert_eq!(
            resolve_transition(&transition, &source(), &schema(), &[owner()]),
            Err(ResolutionError::UnboundCreatedOutput {
                index: 0,
                state_type: 99,
            })
        );
    }
}
