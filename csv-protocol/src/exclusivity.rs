//! State-use semantics bound at output creation (PAR-STATE-002).
//!
//! Whether an output may be consumed once or cited repeatedly is fixed by its
//! state type **when the output is created**, and is non-downgradable. No later
//! transition, schema revision, profile, or decoding path may weaken it.
//!
//! This is constitutional rule 2 of
//! `development/PARWANA_PORTABLE_NON_EQUIVOCATION_PLAN.md`, RFC-0014 §1.8, and
//! rule `NE-R-EXCLUSIVITY-BOUND` under threat T-NE-08.
//!
//! # Why there is no `ClosureMode`
//!
//! A transition-selected closure mode is deliberately deferred (plan §7) and
//! must not be introduced as a convenience. If a successor could name the
//! strength with which it consumes its input, an attacker would simply name the
//! weakest one and consume an exclusive output observationally — the exact
//! downgrade this module exists to prevent.
//!
//! So [`OutputUseBinding::authorize`] takes the mode a transition *requests*
//! and returns the mode the **output** permits, or an error. It never returns a
//! weaker mode than the output's class requires, and there is no other way to
//! reach a consumption mode. The request is an assertion to be checked, not a
//! setting to be honoured.
//!
//! # Why the output carries its own binding
//!
//! The schema is the authority at creation time. Afterwards the *output* is,
//! because a schema can be revised and an already-created output cannot be
//! renegotiated. [`StateUseSchema::reconcile`] therefore reports a disagreement
//! between a revised schema and an existing output as an error; it never lets
//! the schema reinterpret the output.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::state::StateTypeId;

/// Version of the state-use semantics encoding.
///
/// Recorded in every [`OutputUseBinding`] so an output decoded later is read
/// under the semantics it was created with, not the reader's current ones.
pub const STATE_USE_SEMANTICS_VERSION: u16 = 2;

/// Whether an output may be consumed once, or cited repeatedly.
///
/// Fixed at output creation. There is no ordering on this type and no
/// conversion that weakens it: `Exclusive` never becomes `Citable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExclusivityClass {
    /// May be referenced any number of times as evidence. Consuming it is not
    /// a defined operation.
    Citable = 1,
    /// At most one successor transition may consume it, ever. Requires closure
    /// evidence in the source state's closure domain.
    Exclusive = 2,
}

impl ExclusivityClass {
    /// Canonical discriminant used in encodings and digest preimages.
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    /// Decode a canonical discriminant. Unknown values fail closed: an output
    /// whose class this build does not understand is never read as `Citable`.
    pub const fn from_discriminant(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Citable),
            2 => Some(Self::Exclusive),
            _ => None,
        }
    }

    /// The consumption mode this class requires. Not a preference — the only
    /// mode the output permits.
    pub const fn required_mode(self) -> ConsumptionMode {
        match self {
            Self::Citable => ConsumptionMode::Observational,
            Self::Exclusive => ConsumptionMode::Exclusive,
        }
    }
}

/// How a transition proposes to use a parent output.
///
/// This is a *request*, checked against the output's class. It is never a
/// setting the transition gets to choose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConsumptionMode {
    /// Read without consuming. Permitted only for citable state.
    Observational = 1,
    /// Consume, asserting a unique successor. Requires closure evidence.
    Exclusive = 2,
}

/// Why a state-use check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExclusivityError {
    /// A transition asked to use an exclusive output observationally. This is
    /// the downgrade attack, reported by its own name.
    #[error(
        "state type {state_type} is exclusive and cannot be consumed observationally; \
         exclusivity is bound at output creation and is not downgradable"
    )]
    ObservationalUseOfExclusiveState {
        /// The state type whose output was targeted.
        state_type: StateTypeId,
    },
    /// A transition asked to exclusively consume citable state. Citable state
    /// has no consumption semantics to invoke.
    #[error("state type {state_type} is citable; exclusive consumption is not defined for it")]
    ExclusiveUseOfCitableState {
        /// The state type whose output was targeted.
        state_type: StateTypeId,
    },
    /// A schema tried to bind a state type it had already bound differently.
    #[error(
        "state type {state_type} is already bound as {existing:?} and cannot be rebound as {proposed:?}"
    )]
    RebindingRefused {
        /// The state type being rebound.
        state_type: StateTypeId,
        /// The binding already in force.
        existing: ExclusivityClass,
        /// The binding that was refused.
        proposed: ExclusivityClass,
    },
    /// A revised schema disagrees with an existing output's recorded binding.
    /// The output wins; the disagreement is surfaced, never resolved silently.
    #[error(
        "schema now binds state type {state_type} as {schema:?}, but an existing output records \
         {output:?}; a schema revision cannot reinterpret an output that already exists"
    )]
    SchemaReinterpretation {
        /// The state type in dispute.
        state_type: StateTypeId,
        /// What the current schema says.
        schema: ExclusivityClass,
        /// What the existing output recorded at creation.
        output: ExclusivityClass,
    },
    /// The schema has no binding for this state type. An unbound type has no
    /// use semantics, so it cannot be created or consumed.
    #[error("schema has no state-use binding for state type {state_type}")]
    UnboundStateType {
        /// The unbound state type.
        state_type: StateTypeId,
    },
    /// The recorded class discriminant is not one this build defines.
    #[error("unknown exclusivity class {0}")]
    UnknownClass(u8),
    /// The recorded semantics version is newer than this build understands.
    /// Reading it under current semantics could silently change its meaning.
    #[error("state-use semantics version {found} is newer than the supported {supported}")]
    UnsupportedSemanticsVersion {
        /// Version recorded in the output.
        found: u16,
        /// Newest version this build understands.
        supported: u16,
    },
}

impl ExclusivityError {
    /// Stable registry identifier for this state-use rejection.
    ///
    /// Derived from the variant, not from the diagnostic message, so a reworded
    /// `Display` string cannot change what a consumer matches on.
    pub const fn registry_id(&self) -> &'static str {
        match self {
            Self::ObservationalUseOfExclusiveState { .. } => {
                "PROTOCOL.EXCLUSIVITY.OBSERVATIONAL_USE_OF_EXCLUSIVE_STATE"
            }
            Self::ExclusiveUseOfCitableState { .. } => {
                "PROTOCOL.EXCLUSIVITY.EXCLUSIVE_USE_OF_CITABLE_STATE"
            }
            Self::RebindingRefused { .. } => "PROTOCOL.EXCLUSIVITY.REBINDING_REFUSED",
            Self::SchemaReinterpretation { .. } => "PROTOCOL.EXCLUSIVITY.SCHEMA_REINTERPRETATION",
            Self::UnboundStateType { .. } => "PROTOCOL.EXCLUSIVITY.UNBOUND_STATE_TYPE",
            Self::UnknownClass(_) => "PROTOCOL.EXCLUSIVITY.UNKNOWN_CLASS",
            Self::UnsupportedSemanticsVersion { .. } => {
                "PROTOCOL.EXCLUSIVITY.UNSUPPORTED_SEMANTICS_VERSION"
            }
        }
    }

    /// Every identifier this error family can carry, in stable published order.
    pub const ALL_REGISTRY_IDS: &'static [&'static str] = &[
        "PROTOCOL.EXCLUSIVITY.OBSERVATIONAL_USE_OF_EXCLUSIVE_STATE",
        "PROTOCOL.EXCLUSIVITY.EXCLUSIVE_USE_OF_CITABLE_STATE",
        "PROTOCOL.EXCLUSIVITY.REBINDING_REFUSED",
        "PROTOCOL.EXCLUSIVITY.SCHEMA_REINTERPRETATION",
        "PROTOCOL.EXCLUSIVITY.UNBOUND_STATE_TYPE",
        "PROTOCOL.EXCLUSIVITY.UNKNOWN_CLASS",
        "PROTOCOL.EXCLUSIVITY.UNSUPPORTED_SEMANTICS_VERSION",
    ];
}

/// The immutable use semantics recorded on one created output.
///
/// Created only by [`StateUseSchema::bind_output`], so an output's class always
/// comes from the schema that was in force when it was created. There are no
/// setters: the fields are readable and fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputUseBinding {
    /// Semantics version in force when the output was created.
    semantics_version: u16,
    /// The output's state type.
    state_type: StateTypeId,
    /// The class fixed at creation.
    class: ExclusivityClass,
}

impl OutputUseBinding {
    /// Semantics version this output was created under.
    pub const fn semantics_version(&self) -> u16 {
        self.semantics_version
    }

    /// The output's state type.
    pub const fn state_type(&self) -> StateTypeId {
        self.state_type
    }

    /// The class fixed at creation. Read-only by construction.
    pub const fn class(&self) -> ExclusivityClass {
        self.class
    }

    /// Check a transition's proposed use against what this output permits.
    ///
    /// Returns the mode the output requires, which for an exclusive output is
    /// always [`ConsumptionMode::Exclusive`]. A request for a weaker mode is an
    /// error, not a negotiation.
    pub fn authorize(
        &self,
        requested: ConsumptionMode,
    ) -> Result<ConsumptionMode, ExclusivityError> {
        match (self.class, requested) {
            (ExclusivityClass::Exclusive, ConsumptionMode::Observational) => {
                Err(ExclusivityError::ObservationalUseOfExclusiveState {
                    state_type: self.state_type,
                })
            }
            (ExclusivityClass::Citable, ConsumptionMode::Exclusive) => {
                Err(ExclusivityError::ExclusiveUseOfCitableState {
                    state_type: self.state_type,
                })
            }
            _ => Ok(self.class.required_mode()),
        }
    }

    /// Canonical bytes: `[version:u16 LE][state_type:u16 LE][class:u8]`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(5);
        data.extend_from_slice(&self.semantics_version.to_le_bytes());
        data.extend_from_slice(&self.state_type.to_le_bytes());
        data.push(self.class.discriminant());
        data
    }

    /// Decode a binding, preserving the semantics it was created under.
    ///
    /// A version newer than this build understands fails closed rather than
    /// being read under current semantics.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ExclusivityError> {
        if bytes.len() != 5 {
            return Err(ExclusivityError::UnknownClass(0));
        }
        let semantics_version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if semantics_version > STATE_USE_SEMANTICS_VERSION {
            return Err(ExclusivityError::UnsupportedSemanticsVersion {
                found: semantics_version,
                supported: STATE_USE_SEMANTICS_VERSION,
            });
        }
        let state_type = StateTypeId::from_le_bytes([bytes[2], bytes[3]]);
        let class = ExclusivityClass::from_discriminant(bytes[4])
            .ok_or(ExclusivityError::UnknownClass(bytes[4]))?;
        Ok(Self {
            semantics_version,
            state_type,
            class,
        })
    }
}

/// The schema's binding of state types to use semantics.
///
/// Insert-only: a state type may be bound once. Rebinding it differently is
/// refused, so a schema revision cannot redefine what an existing type means.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateUseSchema {
    version: u16,
    bindings: BTreeMap<StateTypeId, ExclusivityClass>,
}

impl StateUseSchema {
    /// An empty schema at the current semantics version.
    pub fn new() -> Self {
        Self {
            version: STATE_USE_SEMANTICS_VERSION,
            bindings: BTreeMap::new(),
        }
    }

    /// The semantics version outputs created under this schema will record.
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Bind a state type's use semantics.
    ///
    /// Binding the same type to the same class again is accepted (idempotent);
    /// binding it to a different class is refused.
    pub fn bind(
        &mut self,
        state_type: StateTypeId,
        class: ExclusivityClass,
    ) -> Result<(), ExclusivityError> {
        match self.bindings.get(&state_type) {
            Some(existing) if *existing != class => Err(ExclusivityError::RebindingRefused {
                state_type,
                existing: *existing,
                proposed: class,
            }),
            Some(_) => Ok(()),
            None => {
                self.bindings.insert(state_type, class);
                Ok(())
            }
        }
    }

    /// The class this schema binds to `state_type`, if any.
    pub fn class_of(&self, state_type: StateTypeId) -> Option<ExclusivityClass> {
        self.bindings.get(&state_type).copied()
    }

    /// Create the immutable binding an output records at creation.
    ///
    /// This is the only constructor for [`OutputUseBinding`], which is why an
    /// output's class always originates in a schema rather than in a
    /// transition.
    pub fn bind_output(
        &self,
        state_type: StateTypeId,
    ) -> Result<OutputUseBinding, ExclusivityError> {
        let class = self
            .class_of(state_type)
            .ok_or(ExclusivityError::UnboundStateType { state_type })?;
        Ok(OutputUseBinding {
            semantics_version: self.version,
            state_type,
            class,
        })
    }

    /// Check an existing output's recorded binding against this schema.
    ///
    /// Used when a revised schema meets an output created under an earlier one.
    /// A disagreement is an error: the output keeps the semantics it was
    /// created with, and the conflict is reported rather than resolved.
    pub fn reconcile(&self, binding: &OutputUseBinding) -> Result<(), ExclusivityError> {
        match self.class_of(binding.state_type()) {
            None => Err(ExclusivityError::UnboundStateType {
                state_type: binding.state_type(),
            }),
            Some(class) if class != binding.class() => {
                Err(ExclusivityError::SchemaReinterpretation {
                    state_type: binding.state_type(),
                    schema: class,
                    output: binding.class(),
                })
            }
            Some(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: StateTypeId = 10;
    const NOTE: StateTypeId = 11;

    #[test]
    fn every_state_use_error_publishes_one_distinct_registry_identifier() {
        let variants = [
            ExclusivityError::ObservationalUseOfExclusiveState { state_type: TOKEN },
            ExclusivityError::ExclusiveUseOfCitableState { state_type: TOKEN },
            ExclusivityError::RebindingRefused {
                state_type: TOKEN,
                existing: ExclusivityClass::Exclusive,
                proposed: ExclusivityClass::Citable,
            },
            ExclusivityError::SchemaReinterpretation {
                state_type: TOKEN,
                schema: ExclusivityClass::Citable,
                output: ExclusivityClass::Exclusive,
            },
            ExclusivityError::UnboundStateType { state_type: TOKEN },
            ExclusivityError::UnknownClass(0xff),
            ExclusivityError::UnsupportedSemanticsVersion {
                found: 9,
                supported: 2,
            },
        ];
        let ids: Vec<&'static str> = variants.iter().map(ExclusivityError::registry_id).collect();
        assert_eq!(ids, ExclusivityError::ALL_REGISTRY_IDS);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "two variants share an identifier");
    }

    fn schema() -> StateUseSchema {
        let mut schema = StateUseSchema::new();
        schema.bind(TOKEN, ExclusivityClass::Exclusive).unwrap();
        schema.bind(NOTE, ExclusivityClass::Citable).unwrap();
        schema
    }

    // ── Exclusivity is fixed at creation ────────────────────────────────────

    #[test]
    fn an_output_records_the_class_its_schema_bound() {
        let binding = schema().bind_output(TOKEN).unwrap();
        assert_eq!(binding.class(), ExclusivityClass::Exclusive);
        assert_eq!(binding.state_type(), TOKEN);
        assert_eq!(binding.semantics_version(), STATE_USE_SEMANTICS_VERSION);
    }

    #[test]
    fn an_unbound_state_type_cannot_create_an_output() {
        assert_eq!(
            schema().bind_output(99),
            Err(ExclusivityError::UnboundStateType { state_type: 99 })
        );
    }

    // ── Non-downgradability ─────────────────────────────────────────────────

    #[test]
    fn an_exclusive_output_cannot_be_consumed_observationally() {
        let binding = schema().bind_output(TOKEN).unwrap();
        assert_eq!(
            binding.authorize(ConsumptionMode::Observational),
            Err(ExclusivityError::ObservationalUseOfExclusiveState { state_type: TOKEN })
        );
    }

    #[test]
    fn an_exclusive_output_always_authorizes_exclusive_use() {
        let binding = schema().bind_output(TOKEN).unwrap();
        assert_eq!(
            binding.authorize(ConsumptionMode::Exclusive),
            Ok(ConsumptionMode::Exclusive)
        );
    }

    #[test]
    fn authorize_returns_the_outputs_mode_not_the_requested_one() {
        // The property that makes a transition-selected closure mode
        // impossible: whatever is requested, an exclusive output yields
        // exclusive use or an error — never something weaker.
        let binding = schema().bind_output(TOKEN).unwrap();
        for requested in [ConsumptionMode::Exclusive, ConsumptionMode::Observational] {
            match binding.authorize(requested) {
                Ok(mode) => assert_eq!(mode, ConsumptionMode::Exclusive),
                Err(error) => assert_eq!(
                    error,
                    ExclusivityError::ObservationalUseOfExclusiveState { state_type: TOKEN }
                ),
            }
        }
    }

    #[test]
    fn citable_state_has_no_exclusive_consumption() {
        let binding = schema().bind_output(NOTE).unwrap();
        assert_eq!(
            binding.authorize(ConsumptionMode::Exclusive),
            Err(ExclusivityError::ExclusiveUseOfCitableState { state_type: NOTE })
        );
        assert_eq!(
            binding.authorize(ConsumptionMode::Observational),
            Ok(ConsumptionMode::Observational)
        );
    }

    // ── Schema revisions cannot reinterpret existing outputs ────────────────

    #[test]
    fn a_schema_cannot_rebind_a_state_type_to_a_different_class() {
        let mut schema = schema();
        assert_eq!(
            schema.bind(TOKEN, ExclusivityClass::Citable),
            Err(ExclusivityError::RebindingRefused {
                state_type: TOKEN,
                existing: ExclusivityClass::Exclusive,
                proposed: ExclusivityClass::Citable,
            })
        );
        // The original binding survives the attempt.
        assert_eq!(schema.class_of(TOKEN), Some(ExclusivityClass::Exclusive));
    }

    #[test]
    fn rebinding_to_the_same_class_is_idempotent() {
        let mut schema = schema();
        assert_eq!(schema.bind(TOKEN, ExclusivityClass::Exclusive), Ok(()));
    }

    #[test]
    fn a_revised_schema_cannot_reinterpret_an_existing_exclusive_output() {
        let existing = schema().bind_output(TOKEN).unwrap();

        // A fresh schema that binds the same type as citable — a revision that
        // would weaken an already-created output.
        let mut revised = StateUseSchema::new();
        revised.bind(TOKEN, ExclusivityClass::Citable).unwrap();

        assert_eq!(
            revised.reconcile(&existing),
            Err(ExclusivityError::SchemaReinterpretation {
                state_type: TOKEN,
                schema: ExclusivityClass::Citable,
                output: ExclusivityClass::Exclusive,
            })
        );
        // And the output still authorizes only exclusive use.
        assert_eq!(
            existing.authorize(ConsumptionMode::Observational),
            Err(ExclusivityError::ObservationalUseOfExclusiveState { state_type: TOKEN })
        );
    }

    #[test]
    fn an_agreeing_schema_reconciles() {
        let existing = schema().bind_output(TOKEN).unwrap();
        assert_eq!(schema().reconcile(&existing), Ok(()));
    }

    #[test]
    fn a_schema_that_dropped_a_binding_fails_closed() {
        let existing = schema().bind_output(TOKEN).unwrap();
        assert_eq!(
            StateUseSchema::new().reconcile(&existing),
            Err(ExclusivityError::UnboundStateType { state_type: TOKEN })
        );
    }

    // ── Versioned decoding preserves original semantics ─────────────────────

    #[test]
    fn a_binding_round_trips_with_its_original_semantics() {
        let binding = schema().bind_output(TOKEN).unwrap();
        let decoded =
            OutputUseBinding::from_canonical_bytes(&binding.to_canonical_bytes()).unwrap();
        assert_eq!(decoded, binding);
        assert_eq!(decoded.class(), ExclusivityClass::Exclusive);
    }

    #[test]
    fn an_older_output_keeps_the_semantics_version_it_was_created_under() {
        // Hand-build a v1 output: the reader must not restamp it as v2.
        let bytes = {
            let mut data = Vec::new();
            data.extend_from_slice(&1u16.to_le_bytes());
            data.extend_from_slice(&TOKEN.to_le_bytes());
            data.push(ExclusivityClass::Exclusive.discriminant());
            data
        };
        let decoded = OutputUseBinding::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.semantics_version(), 1);
        assert_eq!(decoded.class(), ExclusivityClass::Exclusive);
        assert_eq!(
            decoded.authorize(ConsumptionMode::Observational),
            Err(ExclusivityError::ObservationalUseOfExclusiveState { state_type: TOKEN }),
            "an older exclusive output is still exclusive"
        );
    }

    #[test]
    fn a_newer_semantics_version_fails_closed() {
        let bytes = {
            let mut data = Vec::new();
            data.extend_from_slice(&(STATE_USE_SEMANTICS_VERSION + 1).to_le_bytes());
            data.extend_from_slice(&TOKEN.to_le_bytes());
            data.push(ExclusivityClass::Exclusive.discriminant());
            data
        };
        assert_eq!(
            OutputUseBinding::from_canonical_bytes(&bytes),
            Err(ExclusivityError::UnsupportedSemanticsVersion {
                found: STATE_USE_SEMANTICS_VERSION + 1,
                supported: STATE_USE_SEMANTICS_VERSION,
            })
        );
    }

    #[test]
    fn an_unknown_class_fails_closed_rather_than_defaulting_to_citable() {
        let bytes = {
            let mut data = Vec::new();
            data.extend_from_slice(&STATE_USE_SEMANTICS_VERSION.to_le_bytes());
            data.extend_from_slice(&TOKEN.to_le_bytes());
            data.push(0xFF);
            data
        };
        assert_eq!(
            OutputUseBinding::from_canonical_bytes(&bytes),
            Err(ExclusivityError::UnknownClass(0xFF))
        );
    }

    #[test]
    fn class_discriminants_are_distinct_and_stable() {
        assert_eq!(ExclusivityClass::Citable.discriminant(), 1);
        assert_eq!(ExclusivityClass::Exclusive.discriminant(), 2);
        for class in [ExclusivityClass::Citable, ExclusivityClass::Exclusive] {
            assert_eq!(
                ExclusivityClass::from_discriminant(class.discriminant()),
                Some(class)
            );
        }
    }
}
