//! Supported accountability protocol facade.
//!
//! Semantic validation and canonical serialization remain owned by
//! `csv-accountability`. This module provides stable SDK imports and transport
//! helpers without copying protocol logic.

pub use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionIntent, ActionMandate,
    AssuranceDimension, AssuranceProfile, ContextBoundOutput, DimensionResult, DimensionStatus,
    DisputeBundle, EvidenceKind, EvidenceNode, EvidenceNodeId, ExecutionAttempt, ExecutionReceipt,
    GateProfileId, GitHubDeploymentIntentV1, IntentError, MandateSignatureEnvelope, ObjectVersion,
    ProtocolVersion, RequiredContexts, SourceLocator, VerificationContext, VerificationContextId,
};
pub use csv_wire::{
    AccountabilityObjectKind, ActionIntentWire, CanonicalAccountabilityObjectWire,
    GitHubDeploymentIntentV1Wire, RequiredContextsWire,
};

/// Encodes an action intent using the sole canonical serializer in the semantic crate.
pub fn encode_action_intent(
    intent: &ActionIntent,
) -> Result<CanonicalAccountabilityObjectWire, csv_accountability::IntentError> {
    let bytes = intent.canonical_bytes()?;
    let id = intent.id()?.into_bytes();
    CanonicalAccountabilityObjectWire::new(AccountabilityObjectKind::ActionIntent, id, &bytes)
        .map_err(|_| csv_accountability::IntentError::EmptyField("canonical_bytes"))
}

/// Decodes and validates the public JSON wire representation of an action intent.
pub fn action_intent_from_wire(
    wire: ActionIntentWire,
) -> Result<ActionIntent, csv_accountability::IntentError> {
    wire.try_into()
}
