//! Pure accountability protocol semantics.
//!
//! This crate defines canonical accountability objects and validation rules.
//! It owns no storage, network, runtime, chain, UI, or application authority.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod anchor;
pub mod assurance;
pub mod bundle;
pub mod context;
pub mod dispute;
pub mod evidence;
pub mod execution;
pub mod id;
pub mod intent;
pub mod mandate;
pub mod profile;
pub mod receipt;
pub mod registry;
pub mod state;
pub mod verification;

pub use anchor::{
    AnchorError, CSV_SEAL_COMMITMENT_ANCHOR_MEDIA_TYPE, CSV_SEAL_CONSUMPTION_MEDIA_TYPE,
    CommitmentAnchorRecord, EVIDENCE_CSV_SEAL_COMMITMENT_ANCHOR,
    EVIDENCE_CSV_SEAL_CONSUMPTION_RECORD, MAX_ANCHOR_FIELD_BYTES, SealConsumptionRecord,
    SingleUseAnchorAssessment,
};
pub use assurance::{
    ASSURANCE_DIMENSIONS, AssuranceDimension, AssuranceError, AssuranceProfile, DimensionGateRule,
    DimensionResult, DimensionStatus, GateDisposition, GateOutcome, GateProfile, GateResult,
    MAX_ASSURANCE_ITEMS, MAX_ASSURANCE_TEXT_BYTES,
};
pub use bundle::{
    BundleError, DisclosedObject, DisputeBundle, MAX_BUNDLE_OBJECT_BYTES, MAX_BUNDLE_OBJECTS,
    MAX_BUNDLE_TEXT_BYTES, MAX_BUNDLE_TOTAL_BYTES, WithheldObject, bundle_object_digest,
};
pub use context::{
    ContextBoundOutput, ContextError, ContextExtension, MAX_CONTEXT_EXTENSION_ID_BYTES,
    MAX_CONTEXT_EXTENSIONS, VerificationContext,
};
pub use evidence::{
    ATTESTATION_REGISTRY_ID, AuthenticityMaterial, CLAIM_REGISTRY_ID, EVIDENCE_GAP_REGISTRY_ID,
    EvidenceError, EvidenceKind, EvidenceNode, MAX_EVIDENCE_DEPTH, MAX_EVIDENCE_NODES,
    MAX_EVIDENCE_RELATIONSHIPS, OBSERVATION_REGISTRY_ID, RESERVED_EVIDENCE_REGISTRY_IDS,
    SourceLocator, validate_evidence_graph,
};
pub use execution::{
    ExecutionAttempt, ExecutionError, MAX_CORRELATION_KEY_BYTES, MAX_EXECUTION_IDENTITY_BYTES,
};
pub use id::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, AssuranceProfileId, AttemptId,
    BundleId, EvidenceNodeId, GateProfileId, IntentId, MandateId, ObjectVersion, ProtocolVersion,
    ReceiptId, VerificationContextId, VersionError,
};
pub use intent::{
    ActionIntent, EVIDENCE_EXECUTOR_ATTEMPT_RECORD, EVIDENCE_GITHUB_DEPLOYMENT_RECORD,
    EVIDENCE_GITHUB_ENVIRONMENT_CONFIGURATION, EVIDENCE_GITHUB_WEBHOOK_DELIVERY,
    GITHUB_DEPLOYMENT_ACTION_TYPE, GITHUB_DEPLOYMENT_PARAMETERS_DOMAIN_TAG,
    GITHUB_DEPLOYMENT_PROFILE_ID, GITHUB_DEPLOYMENT_TASK_V1, GitHubDeploymentCodec,
    GitHubDeploymentIntentV1, IntentError, MAX_CONTEXT_COMMITMENTS, MAX_DISPLAY_BYTES,
    MAX_IDENTITY_BYTES, MAX_REQUIRED_CONTEXTS, PARAMETERS_MEDIA_TYPE_V1, RequiredContexts,
    github_deployment_descriptor,
};
pub use mandate::{
    ActionMandate, ED25519_SIGNATURE_ALGORITHM, ExecutionPolicy, MandateError, MandateRequirement,
    MandateSignatureEnvelope, MandateSubject, SignatureRequirements,
};
pub use profile::{
    BoxedProfileCodec, EvidenceSourceClass, EvidenceSourceDecl, EvidenceSourceId,
    MAX_PROFILE_ID_BYTES, ProfileCodec, ProfileDescriptor, ProfileId, QuarantineReleaseRule,
};
pub use receipt::{
    ConsumptionRecord, EvidenceRequirementStatus, ExecutionOutcome, ExecutionReceipt,
    MAX_RECEIPT_EVIDENCE_ITEMS, MAX_RECEIPT_REGISTRY_ID_BYTES, MAX_RECEIPT_SIGNATURE_BYTES,
    ReceiptError,
};
pub use registry::{ProfileRegistry, default_registry};
pub use state::{
    CasReservation, DispatchCertainty, ExecutionAttemptState, MandateJournalEntry, MandateState,
    NonAcceptanceEvidence, QuarantineReleasePolicy, ReservationError, ReservationSnapshot,
    TransitionContext, TransitionError, mandate_transition_edges, validate_journal,
    validate_mandate_transition, validate_reservation_cas,
};
