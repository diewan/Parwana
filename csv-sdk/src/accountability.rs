//! Supported accountability protocol facade.
//!
//! Semantic validation and canonical serialization remain owned by
//! `csv-accountability`. This module provides stable SDK imports and transport
//! helpers without copying protocol logic.

pub use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionIntent, ActionMandate,
    AssuranceDimension, AssuranceProfile, AuthorityAuthenticity, AuthorityConclusion,
    AuthorityError, AuthorityEvaluation, AuthorityLink, AuthorityReason, AuthorityReconstruction,
    AuthorityReconstructionId, AuthoritySourceCompleteness, BoxedProfileCodec, ContextBoundOutput,
    DB_MIGRATION_ACTION_TYPE, DB_MIGRATION_PARAMETERS_MEDIA_TYPE, DB_MIGRATION_PROFILE_ID,
    DbMigrationCodec, DbMigrationIntentV1, DimensionResult, DimensionStatus, DisputeBundle,
    EVIDENCE_DB_MIGRATION_APPLIED_RECORD, EvidenceKind, EvidenceNode, EvidenceNodeId,
    EvidenceSourceClass, EvidenceSourceDecl, EvidenceSourceId, ExecutionAttempt, ExecutionReceipt,
    GateProfileId, GitHubDeploymentCodec, GitHubDeploymentIntentV1, IntentError,
    MandateSignatureEnvelope, MigrationDirection, ObjectVersion, ProfileCodec, ProfileDescriptor,
    ProfileId, ProfileRegistry, ProtocolVersion, QuarantineReleaseRule, RequiredContexts,
    SourceLocator, VerificationContext, VerificationContextId, db_migration_descriptor,
    default_registry, github_deployment_descriptor,
};
pub use csv_accountability::{
    AnchorError, AnchorFinality, AnchorObservation, AnchorReconciliation, CHAIN_ANCHOR_DOMAIN_TAG,
    CHAIN_COMMITMENT_ANCHOR_MEDIA_TYPE, CSV_SEAL_COMMITMENT_ANCHOR_MEDIA_TYPE,
    CSV_SEAL_CONSUMPTION_MEDIA_TYPE, ChainAnchor, ChainAnchorAssessment, CommitmentAnchorRecord,
    EVIDENCE_CHAIN_COMMITMENT_ANCHOR, EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR,
    EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD, SealConsumptionRecord, SingleUseAnchorAssessment,
    reconcile_anchor,
};
pub use csv_accountability_verify::evaluate_authority_reconstruction;
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

/// Encodes a reconstruction with its distinct non-mandate transport kind.
pub fn encode_authority_reconstruction(
    reconstruction: &AuthorityReconstruction,
) -> Result<CanonicalAccountabilityObjectWire, AuthorityError> {
    let bytes = reconstruction.canonical_bytes()?;
    let id = reconstruction.id()?.into_bytes();
    CanonicalAccountabilityObjectWire::new(
        AccountabilityObjectKind::AuthorityReconstruction,
        id,
        &bytes,
    )
    .map_err(|_| AuthorityError::InvalidEncoding)
}
