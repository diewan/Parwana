//! Supported consumer facade for portable V2 consignments.
//!
//! Inspection is structural only. Verification is always performed as part of
//! atomic acceptance against recipient-owned context, checkpoint, trust, and
//! proof-provider inputs.

use csv_chain_ports::ClosureProofVerifier;
use csv_codec::from_canonical_cbor;
use csv_storage::AcceptedStateStore;

/// Version of the embedded hostile-conformance fixture package.
pub const CONFORMANCE_PACKAGE_VERSION: &str = "stage4-v1";

/// SHA-256 of the exact embedded conformance manifest bytes.
pub const CONFORMANCE_MANIFEST_SHA256: &str =
    "1ff11779fb94334d24af10428996215af5b0bba30d9c754ebaee44ac11e83f0e";

/// Return the exact, versioned Stage 4 conformance manifest.
///
/// Consumers should verify [`CONFORMANCE_MANIFEST_SHA256`] before executing
/// cases. The returned bytes are identical on native and WASM targets.
pub const fn conformance_manifest() -> &'static [u8] {
    include_bytes!("../../csv-testkit/corpus/v2/manifest.json")
}

pub use csv_protocol::closure::{
    ClosureProof, ClosureProofKind, ClosureTrustMode, FinalizedCheckpoint,
};
pub use csv_protocol::resolution::{
    ParentOutput, ResolvedInput, ResolvedTransition, resolve_transition,
};
pub use csv_protocol::transition::Transition;
pub use csv_protocol::{ConsumedStateRef, SignatureScheme, StateUseSchema};
pub use csv_runtime::{
    AcceptanceContext, AcceptanceError, AcceptanceErrorCode, AcceptanceResult, AuthorizedSigner,
    Consignment, ConsignmentEmissionError, ConsignmentEmissionJournal, ConsignmentV2Authorizer,
    ConsignmentV2EmissionRequest, InMemoryConsignmentEmissionJournal, VerifiedConsignment,
};
pub use csv_verifier::{
    DimensionAssurance, DimensionStatus, ProofKind, ProofProvider, ProtocolAssuranceDimension,
    ProtocolAssuranceReport, ProtocolReasonCode,
};
pub use csv_wire::{
    ConsignmentAuthorization, ConsignmentProofRequirements, ConsignmentV2, ConsignmentV2Error,
    ConsignmentV2ErrorCode, ConsignmentV2Payload, Invoice, SealDefinition,
};

/// Stable SDK capability identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Decode and structurally inspect canonical V2 consignments.
    Inspection,
    /// Construct and emit V2 consignments with a supplied proof provider.
    Emission,
    /// Verify and atomically accept with a supplied proof provider and store.
    AtomicAcceptance,
    /// Use filesystem-backed durable journals and stores.
    NativePersistence,
}

/// An explicitly unsupported SDK capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("SDK.V2.UNSUPPORTED_CAPABILITY: {capability:?} is unavailable on {platform}")]
pub struct UnsupportedCapability {
    /// Capability that was requested.
    pub capability: Capability,
    /// Stable platform name.
    pub platform: &'static str,
}

/// Check a V2 capability without silently degrading to a weaker operation.
pub const fn require_capability(capability: Capability) -> Result<(), UnsupportedCapability> {
    if cfg!(target_arch = "wasm32") && matches!(capability, Capability::NativePersistence) {
        Err(UnsupportedCapability {
            capability,
            platform: "wasm32",
        })
    } else {
        Ok(())
    }
}

/// Decode and validate a canonical V2 consignment for structural inspection.
///
/// A successful result establishes neither signature validity nor source
/// closure. Call [`accept`] for cryptographic verification and atomic commit.
pub fn inspect(bytes: &[u8]) -> Result<ConsignmentV2, ConsignmentV2Error> {
    ConsignmentV2::decode_v2(bytes)
}

/// Construct, verify, authorize, and durably emit a canonical V2 consignment.
pub async fn emit(
    request: &ConsignmentV2EmissionRequest,
    source_closure: ClosureProof,
    closure_verifier: &dyn ClosureProofVerifier,
    authorizer: &dyn ConsignmentV2Authorizer,
    journal: &dyn ConsignmentEmissionJournal,
) -> Result<Consignment, ConsignmentEmissionError> {
    csv_runtime::emit_consignment_v2(
        request,
        source_closure,
        closure_verifier,
        authorizer,
        journal,
    )
    .await
}

/// Verify against explicit recipient inputs and atomically accept.
///
/// There is intentionally no proof-validation boolean: the supplied provider
/// must verify the proof material and the store owns conflict detection.
pub async fn accept(
    bytes: &[u8],
    context: &AcceptanceContext<'_>,
    closure_verifier: &dyn ClosureProofVerifier,
    store: &dyn AcceptedStateStore,
) -> Result<AcceptanceResult, AcceptanceError> {
    csv_runtime::accept_consignment_v2(bytes, context, closure_verifier, store).await
}

/// Verify against explicit recipient context and checkpoint without accepting.
pub async fn verify(
    bytes: &[u8],
    context: &AcceptanceContext<'_>,
    closure_verifier: &dyn ClosureProofVerifier,
) -> Result<VerifiedConsignment, AcceptanceError> {
    csv_runtime::verify_consignment_v2(bytes, context, closure_verifier).await
}

/// Decode a canonical typed assurance report.
///
/// Report fields remain private in `csv-verifier`; consumers cannot construct
/// or mutate them to upgrade assurance.
pub fn decode_verification_report(
    bytes: &[u8],
) -> Result<VerificationReport, VerificationReportDecodeError> {
    from_canonical_cbor(bytes).map_err(|error| VerificationReportDecodeError {
        detail: error.to_string(),
    })
}

/// Immutable transport view of a verifier-produced assurance report.
///
/// The SDK deliberately does not convert this view back into
/// [`ProtocolAssuranceReport`], whose constructor remains verifier-owned.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub struct VerificationReport {
    verification_context_digest: String,
    assurance_report_digest: String,
    dimensions: Vec<VerificationDimension>,
    errors: Vec<serde_json::Value>,
    foundational_shortfalls: Vec<String>,
}

impl VerificationReport {
    /// Digest of the exact verification context used by the producer.
    pub fn verification_context_digest(&self) -> &str {
        &self.verification_context_digest
    }

    /// Producer-computed digest of the complete report.
    pub fn assurance_report_digest(&self) -> &str {
        &self.assurance_report_digest
    }

    /// Complete typed dimension payloads, preserved without an aggregate verdict.
    pub fn dimensions(&self) -> &[VerificationDimension] {
        &self.dimensions
    }

    /// Typed verifier failures; these are never downgraded to warnings.
    pub fn errors(&self) -> &[serde_json::Value] {
        &self.errors
    }

    /// Foundational dimension registry IDs that were not satisfied.
    pub fn foundational_shortfalls(&self) -> &[String] {
        &self.foundational_shortfalls
    }
}

/// Immutable, registry-coded assurance reading decoded from a report.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct VerificationDimension {
    /// Stable assurance-dimension registry ID.
    pub dimension: String,
    /// Four-valued status registry ID.
    pub status: String,
    /// Stable reason-code registry IDs.
    pub reason_codes: Vec<String>,
    /// Proof provider identity.
    pub provider: String,
    /// Provider trust-mode registry ID.
    pub trust_mode: String,
    /// Explicit limits on what this reading establishes.
    pub limitations: Vec<String>,
}

/// Stable report decoding failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("SDK.V2.REPORT_DECODE: {detail}")]
pub struct VerificationReportDecodeError {
    /// Non-authoritative decoding detail.
    pub detail: String,
}
