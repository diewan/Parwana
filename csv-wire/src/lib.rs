//! Wire encoding and transport layer.
//!
//! This crate owns ALL serde, ALL transport encoding, and ALL RPC wire format conversions.
//! It depends on csv-algebra. The inverse is forbidden by deny.toml.

#[cfg(feature = "accountability")]
pub mod accountability;
pub mod app;
pub mod canonical;
pub mod consignment;
pub mod hexbytes;
pub mod invoice;
pub mod primitives;
pub mod proof;
pub mod remote;
pub mod rpc;
pub mod seal;
pub mod transfer;
pub mod transfer_state;

#[cfg(feature = "accountability")]
pub use accountability::{
    AccountabilityObjectKind, ActionIntentWire, CanonicalAccountabilityObjectWire,
    GitHubDeploymentIntentV1Wire, RequiredContextsWire,
};
pub use app::{
    APP_CONTRACT_SCHEMA_VERSION, ArtifactKind, ContractArtifact, ContractError, ContractHeader,
    FinalityEvidence, NextAction, RecoveryPlan, RecoveryReason, RuntimeHealthReport, SigningIntent,
    TransferEvent, TransferMode, TransferPhase, TransferReceipt, VerificationAssuranceWire,
};
pub use canonical::CanonicalProofWire;
pub use consignment::{CONSIGNMENT_VERSION, Consignment};
pub use invoice::{INVOICE_VERSION, Invoice};
pub use primitives::{CommitmentWire, HashWire, SanadIdWire};
pub use proof::ProofBundleWire;
pub use remote::{
    REMOTE_DISPATCH_VERSION, RemoteError, RemoteLockResult, RemoteMaterialization,
    RemoteMintResult, RemoteRequest, RemoteRequestPayload, RemoteResponse, RemoteResponsePayload,
    RemoteSealRegistryStatus, RemoteSettlementResult, RemoteTransfer, RemoteTxFinality,
};
pub use seal::{SealDefinition, SealPointWire};
pub use transfer::TransferWire;
pub use transfer_state::{
    AwaitingFinalityWire, LockedWire, ProofBuildingWire, ProofValidatedWire, TransferDataWire,
};
