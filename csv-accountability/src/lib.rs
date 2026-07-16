//! Pure accountability protocol semantics.
//!
//! This crate defines canonical accountability objects and validation rules.
//! It owns no storage, network, runtime, chain, UI, or application authority.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod assurance;
pub mod bundle;
pub mod context;
pub mod dispute;
pub mod evidence;
pub mod execution;
pub mod id;
pub mod intent;
pub mod mandate;
pub mod receipt;
pub mod state;
pub mod verification;

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
    ActionIntent, GITHUB_DEPLOYMENT_TASK_V1, GitHubDeploymentIntentV1, IntentError,
    MAX_CONTEXT_COMMITMENTS, MAX_DISPLAY_BYTES, MAX_IDENTITY_BYTES, MAX_REQUIRED_CONTEXTS,
    PARAMETERS_MEDIA_TYPE_V1, ProfileEvidenceSource, ProfileValidator, RequiredContexts,
    validate_profile,
};
pub use mandate::{
    ActionMandate, ED25519_SIGNATURE_ALGORITHM, ExecutionPolicy, MandateError, MandateRequirement,
    MandateSignatureEnvelope, MandateSubject, SignatureRequirements,
};
pub use receipt::{
    ConsumptionRecord, EvidenceRequirementStatus, ExecutionOutcome, ExecutionReceipt,
    MAX_RECEIPT_EVIDENCE_ITEMS, MAX_RECEIPT_REGISTRY_ID_BYTES, MAX_RECEIPT_SIGNATURE_BYTES,
    ReceiptError,
};
pub use state::{
    CasReservation, DispatchCertainty, ExecutionAttemptState, MandateJournalEntry, MandateState,
    NonAcceptanceEvidence, QuarantineReleasePolicy, ReservationError, ReservationSnapshot,
    TransitionContext, TransitionError, mandate_transition_edges, validate_journal,
    validate_mandate_transition, validate_reservation_cas,
};
