//! Typed, multi-dimensional protocol assurance (PAR-VERIFY-001).
//!
//! # Why this exists
//!
//! The verifier used to answer with `is_valid: bool` plus a single
//! `VerificationLevel` label. Both are inflated readings: a structural check
//! that never touched a chain could reach `FullyVerified`, and a caller-supplied
//! `native_proof_validated: bool` could carry an entire bundle across the trust
//! boundary without naming who verified what.
//!
//! This module replaces that with a [`ProtocolAssuranceReport`]: one independent
//! reading per dimension, each naming the [`ProofProvider`] that established it,
//! all bound to the digest of the effective verification context. There is no
//! aggregate "verified" label and no authoritative boolean on the result. A
//! caller decides acceptance by declaring a named [`AssuranceRequirement`] and
//! reading the shortfalls and accepted limitations it produces.
//!
//! # Governing rules
//!
//! - *Integrity levels are explicit* (plan rule 3): structural, authenticated,
//!   anchored, finalized and closure-verified are separate dimensions. A
//!   structural check can never produce a full-verification claim.
//! - *No authoritative booleans cross a trust boundary* (plan rule 4): a flag may
//!   cache a result internally, but the boundary carries typed readings whose
//!   verifier and inputs are named.
//! - *Plurality stays above integrity* (plan rule 7): a contextual reading — one
//!   asserted by an external provider rather than recomputed here — is reported
//!   as [`TrustMode::ProviderAttested`] and never becomes a cryptographic fact.

use std::collections::BTreeSet;

pub use csv_accountability::DimensionStatus;

use csv_accountability::{AssuranceDimension, AssuranceProfile};
use csv_hash::{
    DomainSeparatedHash, Hash, ProtocolAssuranceReportDomain, ProtocolVerificationContextDomain,
};
use csv_protocol::verification_levels::VerificationLevel;

use crate::verifier::VerificationError;

/// An independently reported verification dimension.
///
/// Declaration order is canonical: it fixes the order of readings in a report,
/// of rules in an [`AssuranceRequirement`], and of fields in a report digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolAssuranceDimension {
    /// Canonical encoding, size bounds, DAG identity, and reference integrity.
    CanonicalStructure,
    /// The asserted transition resolves against the history it claims to consume.
    TransitionSemantics,
    /// Signatures verify and bind to an approved signer set.
    Authorization,
    /// The anchor is included in the source chain.
    AnchorInclusion,
    /// The including block reached the required confirmation depth or checkpoint.
    FinalityCheckpoint,
    /// The source state's unique successor is externally grounded (non-equivocation).
    SourceClosure,
    /// The anchor is recent enough under the configured age bound.
    Freshness,
}

/// Complete canonical dimension list. Every report carries exactly these, in order.
pub const PROTOCOL_ASSURANCE_DIMENSIONS: [ProtocolAssuranceDimension; 7] = [
    ProtocolAssuranceDimension::CanonicalStructure,
    ProtocolAssuranceDimension::TransitionSemantics,
    ProtocolAssuranceDimension::Authorization,
    ProtocolAssuranceDimension::AnchorInclusion,
    ProtocolAssuranceDimension::FinalityCheckpoint,
    ProtocolAssuranceDimension::SourceClosure,
    ProtocolAssuranceDimension::Freshness,
];

impl ProtocolAssuranceDimension {
    /// Stable registry identifier for machine output and UI display.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::CanonicalStructure => "PROTOCOL.DIMENSION.CANONICAL_STRUCTURE",
            Self::TransitionSemantics => "PROTOCOL.DIMENSION.TRANSITION_SEMANTICS",
            Self::Authorization => "PROTOCOL.DIMENSION.AUTHORIZATION",
            Self::AnchorInclusion => "PROTOCOL.DIMENSION.ANCHOR_INCLUSION",
            Self::FinalityCheckpoint => "PROTOCOL.DIMENSION.FINALITY_CHECKPOINT",
            Self::SourceClosure => "PROTOCOL.DIMENSION.SOURCE_CLOSURE",
            Self::Freshness => "PROTOCOL.DIMENSION.FRESHNESS",
        }
    }

    /// Whether a failed or unavailable reading here invalidates any cryptographic
    /// claim about the bundle.
    ///
    /// Freshness is the one contextual dimension: it bounds how old the anchor may
    /// be relative to an observed tip, which an offline verifier may legitimately
    /// be unable to establish. It is still always reported and never hidden.
    pub const fn is_foundational(self) -> bool {
        !matches!(self, Self::Freshness)
    }

    /// Position of this dimension in [`PROTOCOL_ASSURANCE_DIMENSIONS`].
    ///
    /// Exhaustive by construction, which is what lets reports and policies index
    /// their fixed-length dimension arrays without a fallible lookup.
    pub const fn index(self) -> usize {
        match self {
            Self::CanonicalStructure => 0,
            Self::TransitionSemantics => 1,
            Self::Authorization => 2,
            Self::AnchorInclusion => 3,
            Self::FinalityCheckpoint => 4,
            Self::SourceClosure => 5,
            Self::Freshness => 6,
        }
    }

    /// Canonical byte tag used in digests. Explicit so reordering the enum cannot
    /// silently change a digest.
    const fn tag(self) -> u8 {
        match self {
            Self::CanonicalStructure => 1,
            Self::TransitionSemantics => 2,
            Self::Authorization => 3,
            Self::AnchorInclusion => 4,
            Self::FinalityCheckpoint => 5,
            Self::SourceClosure => 6,
            Self::Freshness => 7,
        }
    }

    /// The accountability dimension this protocol reading folds into.
    ///
    /// The mapping is deliberately conservative and many-to-one; folding uses
    /// [`weaken`], so a protocol reading can fill in or weaken an accountability
    /// dimension but never upgrade one.
    pub const fn accountability_dimension(self) -> AssuranceDimension {
        match self {
            // Canonical encoding and transition well-formedness are both
            // structural statements about the object under evaluation.
            Self::CanonicalStructure | Self::TransitionSemantics => AssuranceDimension::Structural,
            // Signature verification and approved-signer binding.
            Self::Authorization => AssuranceDimension::Cryptographic,
            // Both are corroboration by something outside the reporting executor.
            Self::AnchorInclusion | Self::FinalityCheckpoint => {
                AssuranceDimension::ExternalCorroboration
            }
            // Source closure is exactly the single-use / non-equivocation question.
            Self::SourceClosure => AssuranceDimension::SingleUse,
            Self::Freshness => AssuranceDimension::Temporal,
        }
    }
}

/// Machine-readable reason for a dimension reading.
///
/// Codes are stable: consumers route on them. A reading always carries at least
/// one, including when it is `Satisfied`, so a report never states a conclusion
/// without stating why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolReasonCode {
    // Canonical structure
    /// Canonical structural rules were recomputed and hold.
    StructureValidated,
    /// The bundle exceeds the configured size bound.
    BundleTooLarge,
    /// The transition DAG is empty, cyclic, or otherwise malformed.
    DagStructureInvalid,
    /// The anchor reference does not bind the inclusion proof it travels with.
    AnchorReferenceInvalid,
    /// Node identifiers and the segment root were supplied, not recomputed.
    DagIdentityNotRecomputed,
    /// The seal reference is absent or empty.
    SealReferenceMissing,

    // Transition semantics
    /// The bundle is bound to the transfer and chain the context names.
    TransitionBindingVerified,
    /// The bundle was built for a different Sanad, chain, or destination.
    DomainBindingMismatch,
    /// Consumed-state resolution is not implemented, so semantics cannot be concluded.
    ConsumedStateResolutionUnavailable,

    // Authorization
    /// Every signature verified against a key in the approved verifier set.
    SignaturesVerified,
    /// A signature failed cryptographic verification or is malformed.
    SignatureInvalid,
    /// The bundle carries no signatures.
    SignaturesAbsent,
    /// Signatures verified, but no approved verifier set was supplied to bind them to.
    SignerSetUnbound,

    // Anchor inclusion
    /// A named provider attested chain-native inclusion.
    InclusionAttestedByProvider,
    /// A named provider evaluated the inclusion material and rejected it.
    InclusionRejectedByProvider,
    /// The inclusion proof is empty, oversized, or carries a zero block hash.
    InclusionProofMalformed,
    /// The inclusion proof is structurally well formed but was not verified against a chain.
    InclusionNotCryptographicallyVerified,

    // Finality / checkpoint
    /// A named provider attested the checkpoint or confirmation depth.
    CheckpointAttestedByProvider,
    /// A named provider evaluated the finality material and rejected it.
    CheckpointRejectedByProvider,
    /// The finality proof is empty, oversized, or below the minimum confirmation floor.
    FinalityProofMalformed,
    /// The observed depth is below the required confirmations.
    ConfirmationDepthNotMet,
    /// No observed source-chain tip was supplied, so depth cannot be established.
    CheckpointUnobserved,

    // Source closure
    /// The supplied replay registry reports the source seal as unconsumed.
    ReplayRegistryClean,
    /// The source seal is already consumed — a replay or double-spend attempt.
    ReplayDetected,
    /// No replay registry was supplied, so local replay safety is unknown.
    ReplayRegistryAbsent,
    /// Closure is not grounded on an external shared ordering.
    SourceClosureNotExternallyGrounded,
    /// Chain-native verification established closure for the named successor.
    SourceClosureCryptographicallyVerified,
    /// Chain-native verification rejected closure for the named successor.
    SourceClosureRejected,

    // Freshness
    /// The anchor is within the configured maximum age below the observed tip.
    WithinMaxAnchorAge,
    /// The anchor is buried deeper than the configured maximum age.
    AnchorStale,
    /// No freshness bound was configured, so staleness cannot be excluded.
    FreshnessBoundNotConfigured,
    /// Freshness inputs were supplied incompletely or inconsistently.
    FreshnessContextIncomplete,
    /// The chain reports instant finality, so anchor age is not measured in blocks.
    FreshnessNotMeasuredInBlocks,

    /// The pipeline stopped before this dimension could be evaluated.
    NotEvaluated,
}

impl ProtocolReasonCode {
    /// Stable registry identifier for machine output and UI display.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::StructureValidated => "PROTOCOL.STRUCTURE.VALIDATED",
            Self::BundleTooLarge => "PROTOCOL.STRUCTURE.BUNDLE_TOO_LARGE",
            Self::DagStructureInvalid => "PROTOCOL.STRUCTURE.DAG_INVALID",
            Self::AnchorReferenceInvalid => "PROTOCOL.STRUCTURE.ANCHOR_REFERENCE_INVALID",
            Self::DagIdentityNotRecomputed => "PROTOCOL.STRUCTURE.DAG_IDENTITY_NOT_RECOMPUTED",
            Self::SealReferenceMissing => "PROTOCOL.STRUCTURE.SEAL_REFERENCE_MISSING",
            Self::TransitionBindingVerified => "PROTOCOL.TRANSITION.BINDING_VERIFIED",
            Self::DomainBindingMismatch => "PROTOCOL.TRANSITION.DOMAIN_BINDING_MISMATCH",
            Self::ConsumedStateResolutionUnavailable => {
                "PROTOCOL.TRANSITION.CONSUMED_STATE_RESOLUTION_UNAVAILABLE"
            }
            Self::SignaturesVerified => "PROTOCOL.AUTHORIZATION.SIGNATURES_VERIFIED",
            Self::SignatureInvalid => "PROTOCOL.AUTHORIZATION.SIGNATURE_INVALID",
            Self::SignaturesAbsent => "PROTOCOL.AUTHORIZATION.SIGNATURES_ABSENT",
            Self::SignerSetUnbound => "PROTOCOL.AUTHORIZATION.SIGNER_SET_UNBOUND",
            Self::InclusionAttestedByProvider => "PROTOCOL.INCLUSION.ATTESTED_BY_PROVIDER",
            Self::InclusionRejectedByProvider => "PROTOCOL.INCLUSION.REJECTED_BY_PROVIDER",
            Self::InclusionProofMalformed => "PROTOCOL.INCLUSION.PROOF_MALFORMED",
            Self::InclusionNotCryptographicallyVerified => {
                "PROTOCOL.INCLUSION.NOT_CRYPTOGRAPHICALLY_VERIFIED"
            }
            Self::CheckpointAttestedByProvider => "PROTOCOL.FINALITY.ATTESTED_BY_PROVIDER",
            Self::CheckpointRejectedByProvider => "PROTOCOL.FINALITY.REJECTED_BY_PROVIDER",
            Self::FinalityProofMalformed => "PROTOCOL.FINALITY.PROOF_MALFORMED",
            Self::ConfirmationDepthNotMet => "PROTOCOL.FINALITY.CONFIRMATION_DEPTH_NOT_MET",
            Self::CheckpointUnobserved => "PROTOCOL.FINALITY.CHECKPOINT_UNOBSERVED",
            Self::ReplayRegistryClean => "PROTOCOL.SOURCE_CLOSURE.REPLAY_REGISTRY_CLEAN",
            Self::ReplayDetected => "PROTOCOL.SOURCE_CLOSURE.REPLAY_DETECTED",
            Self::ReplayRegistryAbsent => "PROTOCOL.SOURCE_CLOSURE.REPLAY_REGISTRY_ABSENT",
            Self::SourceClosureNotExternallyGrounded => {
                "PROTOCOL.SOURCE_CLOSURE.NOT_EXTERNALLY_GROUNDED"
            }
            Self::SourceClosureCryptographicallyVerified => {
                "PROTOCOL.SOURCE_CLOSURE.CRYPTOGRAPHICALLY_VERIFIED"
            }
            Self::SourceClosureRejected => "PROTOCOL.SOURCE_CLOSURE.REJECTED",
            Self::WithinMaxAnchorAge => "PROTOCOL.FRESHNESS.WITHIN_MAX_ANCHOR_AGE",
            Self::AnchorStale => "PROTOCOL.FRESHNESS.ANCHOR_STALE",
            Self::FreshnessBoundNotConfigured => "PROTOCOL.FRESHNESS.BOUND_NOT_CONFIGURED",
            Self::FreshnessContextIncomplete => "PROTOCOL.FRESHNESS.CONTEXT_INCOMPLETE",
            Self::FreshnessNotMeasuredInBlocks => "PROTOCOL.FRESHNESS.NOT_MEASURED_IN_BLOCKS",
            Self::NotEvaluated => "PROTOCOL.DIMENSION.NOT_EVALUATED",
        }
    }
}

/// What kind of proof material established a dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofKind {
    /// Deterministic protocol rules applied to the supplied bytes.
    CanonicalRules,
    /// Digital signature verification.
    DigitalSignature,
    /// Merkle or state-trie inclusion against a block root.
    MerkleInclusion,
    /// Confirmation depth or checkpoint finality.
    ConfirmationDepth,
    /// Consumption of the source seal under a shared ordering.
    SourceSealClosure,
    /// A replay/nullifier registry lookup.
    ReplayRegistry,
    /// An observed source-chain tip height.
    ObservedChainTip,
}

impl ProofKind {
    /// Stable registry identifier.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::CanonicalRules => "canonical-rules",
            Self::DigitalSignature => "digital-signature",
            Self::MerkleInclusion => "merkle-inclusion",
            Self::ConfirmationDepth => "confirmation-depth",
            Self::SourceSealClosure => "source-seal-closure",
            Self::ReplayRegistry => "replay-registry",
            Self::ObservedChainTip => "observed-chain-tip",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::CanonicalRules => 1,
            Self::DigitalSignature => 2,
            Self::MerkleInclusion => 3,
            Self::ConfirmationDepth => 4,
            Self::SourceSealClosure => 5,
            Self::ReplayRegistry => 6,
            Self::ObservedChainTip => 7,
        }
    }
}

/// How much of a dimension's conclusion this verifier actually computed.
///
/// A provider assertion is reported as exactly that — an assertion — and is
/// never presented as a conclusion the pure verifier recomputed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustMode {
    /// Recomputed here from the supplied material alone.
    LocalRecomputation,
    /// Asserted by the named external provider; not recomputed here.
    ProviderAttested,
    /// Verified against a locally validated full-node chain view.
    FullNode,
    /// Verified from a pinned light-client checkpoint.
    LightClient,
    /// Established by agreement from a named RPC quorum.
    RpcQuorum,
    /// Asserted by a signed registry; not locally recomputed.
    AttestedRegistry,
    /// Nothing established this dimension.
    Unverified,
}

impl TrustMode {
    /// Stable registry identifier.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::LocalRecomputation => "local-recomputation",
            Self::ProviderAttested => "provider-attested",
            Self::FullNode => "full-node",
            Self::LightClient => "light-client",
            Self::RpcQuorum => "rpc-quorum",
            Self::AttestedRegistry => "attested-registry",
            Self::Unverified => "unverified",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::LocalRecomputation => 1,
            Self::ProviderAttested => 2,
            Self::FullNode => 3,
            Self::LightClient => 4,
            Self::RpcQuorum => 5,
            Self::AttestedRegistry => 6,
            Self::Unverified => 7,
        }
    }
}

impl From<csv_protocol::ClosureTrustMode> for TrustMode {
    fn from(value: csv_protocol::ClosureTrustMode) -> Self {
        match value {
            csv_protocol::ClosureTrustMode::FullNode => Self::FullNode,
            csv_protocol::ClosureTrustMode::LightClient => Self::LightClient,
            csv_protocol::ClosureTrustMode::RpcQuorum => Self::RpcQuorum,
            csv_protocol::ClosureTrustMode::AttestedRegistry => Self::AttestedRegistry,
        }
    }
}

/// Who established a dimension, over what material, and how far to trust it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofProvider {
    /// Stable identifier of the component that produced the conclusion.
    pub provider_id: String,
    /// Chain the conclusion is about, when it is chain-specific.
    pub chain_id: Option<String>,
    /// Kind of proof material consumed.
    pub proof_kind: ProofKind,
    /// How much of the conclusion this verifier computed itself.
    pub trust_mode: TrustMode,
}

/// Identifier the pure verifier reports for conclusions it recomputed itself.
pub const CANONICAL_VERIFIER_PROVIDER_ID: &str = "parwana.csv-verifier.canonical.v1";

impl ProofProvider {
    /// A conclusion the canonical verifier recomputed from supplied material.
    pub fn local(proof_kind: ProofKind) -> Self {
        Self {
            provider_id: CANONICAL_VERIFIER_PROVIDER_ID.to_string(),
            chain_id: None,
            proof_kind,
            trust_mode: TrustMode::LocalRecomputation,
        }
    }

    /// A conclusion asserted by a named external provider.
    pub fn attested(
        provider_id: impl Into<String>,
        chain_id: Option<String>,
        proof_kind: ProofKind,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            chain_id,
            proof_kind,
            trust_mode: TrustMode::ProviderAttested,
        }
    }

    /// No provider established the dimension.
    pub fn unverified(proof_kind: ProofKind) -> Self {
        Self {
            provider_id: "none".to_string(),
            chain_id: None,
            proof_kind,
            trust_mode: TrustMode::Unverified,
        }
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        push_text(out, &self.provider_id);
        match &self.chain_id {
            Some(chain) => {
                out.push(1);
                push_text(out, chain);
            }
            None => out.push(0),
        }
        out.push(self.proof_kind.tag());
        out.push(self.trust_mode.tag());
    }

    /// Human-readable provenance, e.g. `bitcoin-adapter (bitcoin, merkle-inclusion,
    /// provider-attested)`.
    pub fn describe(&self) -> String {
        match &self.chain_id {
            Some(chain) => format!(
                "{} ({}, {}, {})",
                self.provider_id,
                chain,
                self.proof_kind.registry_id(),
                self.trust_mode.registry_id()
            ),
            None => format!(
                "{} ({}, {})",
                self.provider_id,
                self.proof_kind.registry_id(),
                self.trust_mode.registry_id()
            ),
        }
    }
}

/// One thing a chain-native provider states it established.
///
/// Claims are enumerated rather than folded into a single flag so a provider
/// cannot raise every dimension at once: each dimension consults only its own
/// claim, and a claim the provider did not make is never assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainNativeClaim {
    /// The anchor is included in the source chain.
    AnchorInclusion,
    /// The including block met the provider's confirmation or checkpoint policy.
    CheckpointFinality,
    /// The proof binds the transfer the context names.
    TransferBinding,
}

impl ChainNativeClaim {
    /// Stable registry identifier.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::AnchorInclusion => "anchor-inclusion",
            Self::CheckpointFinality => "checkpoint-finality",
            Self::TransferBinding => "transfer-binding",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::AnchorInclusion => 1,
            Self::CheckpointFinality => 2,
            Self::TransferBinding => 3,
        }
    }
}

/// What a named chain-native provider states about a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainNativeProofAttestation {
    /// Stable identifier of the component that performed the chain-native checks.
    pub provider_id: String,
    /// Chain the checks were performed against.
    pub chain_id: String,
    /// Exactly what the provider states it established, canonically sorted.
    pub claims: Vec<ChainNativeClaim>,
    /// Optional provider-supplied detail, carried into reports verbatim.
    pub detail: Option<String>,
}

impl ChainNativeProofAttestation {
    /// Build an attestation, canonically sorting and deduplicating its claims.
    pub fn new(
        provider_id: impl Into<String>,
        chain_id: impl Into<String>,
        claims: impl IntoIterator<Item = ChainNativeClaim>,
    ) -> Self {
        let claims: BTreeSet<ChainNativeClaim> = claims.into_iter().collect();
        Self {
            provider_id: provider_id.into(),
            chain_id: chain_id.into(),
            claims: claims.into_iter().collect(),
            detail: None,
        }
    }

    /// Attach provider-supplied detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The provider named as the source of a dimension reading.
    pub fn provider(&self, proof_kind: ProofKind) -> ProofProvider {
        ProofProvider::attested(
            self.provider_id.clone(),
            Some(self.chain_id.clone()),
            proof_kind,
        )
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        push_text(out, &self.provider_id);
        push_text(out, &self.chain_id);
        push_u32(out, self.claims.len() as u32);
        for claim in &self.claims {
            out.push(claim.tag());
        }
        match &self.detail {
            Some(detail) => {
                out.push(1);
                push_text(out, detail);
            }
            None => out.push(0),
        }
    }
}

/// Chain-native verification supplied to the verifier by an external provider.
///
/// This replaces the former `native_proof_validated: bool` on the verification
/// context. A bare flag could carry a bundle across the trust boundary without
/// naming who verified what, and could not distinguish "no provider looked" from
/// "a provider looked and rejected it" (plan rule 4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ChainNativeProofAssessment {
    /// No chain-native provider evaluated the bundle.
    #[default]
    NotSupplied,
    /// A named provider states it established the listed claims.
    Attested(ChainNativeProofAttestation),
    /// A named provider evaluated the material and rejected it.
    Rejected(ChainNativeProofAttestation),
}

/// How a chain-native provider addressed one claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainNativeClaimReading<'a> {
    /// The provider states it established the claim.
    Attested(&'a ChainNativeProofAttestation),
    /// The provider evaluated the material and rejected it.
    Rejected(&'a ChainNativeProofAttestation),
    /// No provider addressed the claim.
    Absent,
}

impl ChainNativeProofAssessment {
    /// How this assessment addresses one claim.
    ///
    /// A rejection covers every claim the provider evaluated; an attestation
    /// covers only the claims it actually lists.
    pub fn reading(&self, claim: ChainNativeClaim) -> ChainNativeClaimReading<'_> {
        match self {
            Self::NotSupplied => ChainNativeClaimReading::Absent,
            Self::Rejected(attestation) => ChainNativeClaimReading::Rejected(attestation),
            Self::Attested(attestation) if attestation.claims.contains(&claim) => {
                ChainNativeClaimReading::Attested(attestation)
            }
            Self::Attested(_) => ChainNativeClaimReading::Absent,
        }
    }

    /// Commit the assessment to a verification-context digest.
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::NotSupplied => out.push(0),
            Self::Attested(attestation) => {
                out.push(1);
                attestation.write_canonical(out);
            }
            Self::Rejected(attestation) => {
                out.push(2);
                attestation.write_canonical(out);
            }
        }
    }
}

/// One independent dimension reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionAssurance {
    /// Dimension this reading is about.
    pub dimension: ProtocolAssuranceDimension,
    /// Four-valued conclusion, shared with the accountability assurance model.
    pub status: DimensionStatus,
    /// Stable reasons, canonically sorted and deduplicated. Never empty.
    pub reason_codes: Vec<ProtocolReasonCode>,
    /// Who established the reading and how far to trust it.
    pub provider: ProofProvider,
    /// Explicit bounds on what the reading proves.
    pub limitations: Vec<String>,
}

impl DimensionAssurance {
    /// Build a reading, sorting and deduplicating its reason codes.
    pub fn new(
        dimension: ProtocolAssuranceDimension,
        status: DimensionStatus,
        reason_codes: impl IntoIterator<Item = ProtocolReasonCode>,
        provider: ProofProvider,
        limitations: impl IntoIterator<Item = String>,
    ) -> Self {
        let codes: BTreeSet<ProtocolReasonCode> = reason_codes.into_iter().collect();
        let mut limitations: Vec<String> = limitations.into_iter().collect();
        limitations.sort();
        limitations.dedup();
        Self {
            dimension,
            status,
            reason_codes: if codes.is_empty() {
                vec![ProtocolReasonCode::NotEvaluated]
            } else {
                codes.into_iter().collect()
            },
            provider,
            limitations,
        }
    }

    /// The fail-closed default for a dimension the pipeline never reached.
    pub fn not_evaluated(dimension: ProtocolAssuranceDimension, proof_kind: ProofKind) -> Self {
        Self::new(
            dimension,
            DimensionStatus::Indeterminate,
            [ProtocolReasonCode::NotEvaluated],
            ProofProvider::unverified(proof_kind),
            ["Verification stopped before this dimension was evaluated".to_string()],
        )
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.push(self.dimension.tag());
        out.push(status_tag(self.status));
        push_u32(out, self.reason_codes.len() as u32);
        for code in &self.reason_codes {
            push_text(out, code.registry_id());
        }
        self.provider.write_canonical(out);
        push_u32(out, self.limitations.len() as u32);
        for limitation in &self.limitations {
            push_text(out, limitation);
        }
    }
}

/// A dimensioned verification result bound to the context that produced it.
///
/// The report carries no aggregate verdict and no boolean. Callers evaluate it
/// against a named [`AssuranceRequirement`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolAssuranceReport {
    verification_context_digest: Hash,
    dimensions: Vec<DimensionAssurance>,
    errors: Vec<VerificationError>,
}

impl ProtocolAssuranceReport {
    /// Digest of the effective verification context this report was produced under.
    ///
    /// Two verifiers that echo the same digest evaluated the same rules and inputs.
    pub fn verification_context_digest(&self) -> Hash {
        self.verification_context_digest
    }

    /// Every reading, in canonical dimension order.
    pub fn dimensions(&self) -> &[DimensionAssurance] {
        &self.dimensions
    }

    /// The reading for one dimension. Always present.
    ///
    /// [`ProtocolAssuranceReportBuilder::build`] is the only constructor and always
    /// emits every dimension in canonical order, so the positional lookup is total.
    pub fn reading(&self, dimension: ProtocolAssuranceDimension) -> &DimensionAssurance {
        &self.dimensions[dimension.index()]
    }

    /// Typed failures encountered during verification. Never downgraded to warnings.
    pub fn errors(&self) -> &[VerificationError] {
        &self.errors
    }

    /// Foundational dimensions that are not `Satisfied`.
    ///
    /// This is what stops an aggregate label from hiding a failed or unavailable
    /// foundational dimension: the list is derived from the readings themselves and
    /// cannot be suppressed.
    pub fn foundational_shortfalls(&self) -> Vec<&DimensionAssurance> {
        self.dimensions
            .iter()
            .filter(|reading| {
                reading.dimension.is_foundational() && reading.status != DimensionStatus::Satisfied
            })
            .collect()
    }

    /// Digest over the full dimensioned report and its context digest.
    pub fn digest(&self) -> Hash {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.verification_context_digest.as_bytes());
        push_u32(&mut bytes, self.dimensions.len() as u32);
        for reading in &self.dimensions {
            reading.write_canonical(&mut bytes);
        }
        DomainSeparatedHash::<ProtocolAssuranceReportDomain>::hash(&bytes)
    }

    /// Non-authoritative coarse label, for display and legacy transport only.
    ///
    /// It exists so surfaces that still carry a [`VerificationLevel`] cannot invent
    /// their own mapping. It is a lossy projection: it can never report
    /// `FullyVerified` or `ConsensusVerified` while any foundational dimension is
    /// unsatisfied, so nonempty proof bytes alone cannot produce a full-verification
    /// claim. Never gate on it — gate on an [`AssuranceRequirement`].
    pub fn display_level(&self) -> VerificationLevel {
        let satisfied = |dimension: ProtocolAssuranceDimension| {
            self.reading(dimension).status == DimensionStatus::Satisfied
        };
        if !self.foundational_shortfalls().is_empty() {
            return if satisfied(ProtocolAssuranceDimension::AnchorInclusion) {
                VerificationLevel::MerkleVerified
            } else {
                VerificationLevel::StructuralOnly
            };
        }
        if satisfied(ProtocolAssuranceDimension::Freshness) {
            VerificationLevel::ConsensusVerified
        } else {
            VerificationLevel::FullyVerified
        }
    }

    /// Fold this report into an accountability assurance profile.
    ///
    /// Each protocol reading is combined into its
    /// [`accountability_dimension`](ProtocolAssuranceDimension::accountability_dimension)
    /// with [`weaken`], which can fill in a dimension the accountability profile
    /// left unevaluated or weaken one, but never strengthen one. Every folded
    /// dimension gains the protocol reason codes and a limitation naming the proof
    /// provider and trust mode, so a provider-attested contextual reading stays
    /// visibly contextual instead of collapsing into a cryptographic fact.
    ///
    /// Returns the profile unchanged if it does not validate, so an invalid profile
    /// is never silently rewritten.
    pub fn incorporate_into(&self, profile: &mut AssuranceProfile) {
        if profile.validate().is_err() {
            return;
        }
        for reading in &self.dimensions {
            let target = reading.dimension.accountability_dimension();
            let Some(result) = profile
                .dimensions
                .iter_mut()
                .find(|candidate| candidate.dimension == target)
            else {
                continue;
            };
            result.status = weaken(result.status, reading.status);
            for code in &reading.reason_codes {
                result.reason_codes.push(code.registry_id().to_string());
            }
            result.limitations.push(format!(
                "{}: {} established by {}",
                reading.dimension.registry_id(),
                status_registry_id(reading.status),
                reading.provider.describe()
            ));
            for limitation in &reading.limitations {
                result.limitations.push(limitation.clone());
            }
            result.reason_codes.sort();
            result.reason_codes.dedup();
            result.limitations.sort();
            result.limitations.dedup();
        }
    }
}

/// Serializes the whole dimensioned report.
///
/// Hand-written because the four-valued status comes from `csv-accountability`,
/// which is serde-free by policy. Every dimension is emitted, so a transport can
/// not drop a shortfall on the way out.
impl serde::Serialize for ProtocolAssuranceReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeSeq, SerializeStruct};

        struct Readings<'a>(&'a [DimensionAssurance]);
        impl serde::Serialize for Readings<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for reading in self.0 {
                    seq.serialize_element(reading)?;
                }
                seq.end()
            }
        }

        let mut state = serializer.serialize_struct("ProtocolAssuranceReport", 5)?;
        state.serialize_field(
            "verification_context_digest",
            &self.verification_context_digest.to_hex(),
        )?;
        state.serialize_field("assurance_report_digest", &self.digest().to_hex())?;
        state.serialize_field("dimensions", &Readings(&self.dimensions))?;
        state.serialize_field("errors", &self.errors)?;
        state.serialize_field(
            "foundational_shortfalls",
            &self
                .foundational_shortfalls()
                .iter()
                .map(|reading| reading.dimension.registry_id())
                .collect::<Vec<_>>(),
        )?;
        state.end()
    }
}

impl serde::Serialize for DimensionAssurance {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DimensionAssurance", 6)?;
        state.serialize_field("dimension", self.dimension.registry_id())?;
        state.serialize_field("status", status_registry_id(self.status))?;
        state.serialize_field(
            "reason_codes",
            &self
                .reason_codes
                .iter()
                .map(|code| code.registry_id())
                .collect::<Vec<_>>(),
        )?;
        state.serialize_field("provider", &self.provider.provider_id)?;
        state.serialize_field("trust_mode", self.provider.trust_mode.registry_id())?;
        state.serialize_field("limitations", &self.limitations)?;
        state.end()
    }
}

/// Combine an existing conclusion with an incoming one without ever strengthening it.
///
/// `NotApplicable` is the identity: a dimension nothing has evaluated takes the
/// incoming reading. Otherwise `NotSatisfied` dominates, then `Indeterminate`.
pub fn weaken(current: DimensionStatus, incoming: DimensionStatus) -> DimensionStatus {
    match (current, incoming) {
        (DimensionStatus::NotSatisfied, _) | (_, DimensionStatus::NotSatisfied) => {
            DimensionStatus::NotSatisfied
        }
        (DimensionStatus::NotApplicable, other) | (other, DimensionStatus::NotApplicable) => other,
        (DimensionStatus::Indeterminate, _) | (_, DimensionStatus::Indeterminate) => {
            DimensionStatus::Indeterminate
        }
        (DimensionStatus::Satisfied, DimensionStatus::Satisfied) => DimensionStatus::Satisfied,
    }
}

/// Stable registry identifier for a four-valued conclusion.
pub const fn status_registry_id(status: DimensionStatus) -> &'static str {
    match status {
        DimensionStatus::Satisfied => "satisfied",
        DimensionStatus::NotSatisfied => "not-satisfied",
        DimensionStatus::Indeterminate => "indeterminate",
        DimensionStatus::NotApplicable => "not-applicable",
    }
}

/// Accumulates readings during a verification run.
///
/// Any dimension the pipeline never records is filled in as
/// [`DimensionAssurance::not_evaluated`], so an unreached dimension is reported as
/// unknown rather than omitted or assumed.
#[derive(Debug)]
pub struct ProtocolAssuranceReportBuilder {
    verification_context_digest: Hash,
    readings: Vec<DimensionAssurance>,
    errors: Vec<VerificationError>,
}

impl ProtocolAssuranceReportBuilder {
    /// Start a report bound to an effective verification context digest.
    pub fn new(verification_context_digest: Hash) -> Self {
        Self {
            verification_context_digest,
            readings: Vec::with_capacity(PROTOCOL_ASSURANCE_DIMENSIONS.len()),
            errors: Vec::new(),
        }
    }

    /// Record a reading. The last reading for a dimension wins.
    pub fn record(&mut self, reading: DimensionAssurance) -> &mut Self {
        self.readings
            .retain(|existing| existing.dimension != reading.dimension);
        self.readings.push(reading);
        self
    }

    /// Record the four independent readings produced by chain-native closure verification.
    pub fn record_closure_result(
        &mut self,
        result: &csv_protocol::ClosureVerificationResult,
    ) -> &mut Self {
        let entries = [
            (
                ProtocolAssuranceDimension::AnchorInclusion,
                result.proof_validity,
                ProtocolReasonCode::InclusionAttestedByProvider,
                ProtocolReasonCode::InclusionRejectedByProvider,
                ProofKind::MerkleInclusion,
            ),
            (
                ProtocolAssuranceDimension::FinalityCheckpoint,
                result.checkpoint_finality,
                ProtocolReasonCode::CheckpointAttestedByProvider,
                ProtocolReasonCode::CheckpointRejectedByProvider,
                ProofKind::ConfirmationDepth,
            ),
            (
                ProtocolAssuranceDimension::Freshness,
                result.checkpoint_freshness,
                ProtocolReasonCode::WithinMaxAnchorAge,
                ProtocolReasonCode::AnchorStale,
                ProofKind::ObservedChainTip,
            ),
            (
                ProtocolAssuranceDimension::SourceClosure,
                result.source_closure,
                ProtocolReasonCode::SourceClosureCryptographicallyVerified,
                ProtocolReasonCode::SourceClosureRejected,
                ProofKind::SourceSealClosure,
            ),
        ];
        for (dimension, status, success, failure, proof_kind) in entries {
            let (status, reason) = match status {
                csv_protocol::ClosureDimensionStatus::Satisfied => {
                    (DimensionStatus::Satisfied, success)
                }
                csv_protocol::ClosureDimensionStatus::Failed => {
                    (DimensionStatus::NotSatisfied, failure)
                }
                csv_protocol::ClosureDimensionStatus::Indeterminate => (
                    DimensionStatus::Indeterminate,
                    ProtocolReasonCode::NotEvaluated,
                ),
            };
            self.record(DimensionAssurance::new(
                dimension,
                status,
                [reason],
                ProofProvider {
                    provider_id: result.verifier_id.clone(),
                    chain_id: Some(result.chain_id.clone()),
                    proof_kind,
                    trust_mode: result.trust_mode.into(),
                },
                [format!(
                    "proof material from {}; checkpoint {}:{}",
                    result.proof_provider_id,
                    result.checkpoint.network_id,
                    result.checkpoint.block_height
                )],
            ));
        }
        self
    }

    /// Record a typed failure alongside the reading that reports it.
    pub fn record_error(&mut self, error: VerificationError) -> &mut Self {
        self.errors.push(error);
        self
    }

    /// Whether a dimension already has a reading.
    pub fn has(&self, dimension: ProtocolAssuranceDimension) -> bool {
        self.readings
            .iter()
            .any(|reading| reading.dimension == dimension)
    }

    /// Finish the report, filling unrecorded dimensions with the fail-closed default.
    pub fn build(self) -> ProtocolAssuranceReport {
        let Self {
            verification_context_digest,
            readings,
            errors,
        } = self;
        let dimensions = PROTOCOL_ASSURANCE_DIMENSIONS
            .iter()
            .map(|dimension| {
                readings
                    .iter()
                    .find(|reading| reading.dimension == *dimension)
                    .cloned()
                    .unwrap_or_else(|| {
                        DimensionAssurance::not_evaluated(
                            *dimension,
                            default_proof_kind(*dimension),
                        )
                    })
            })
            .collect();
        ProtocolAssuranceReport {
            verification_context_digest,
            dimensions,
            errors,
        }
    }
}

const fn default_proof_kind(dimension: ProtocolAssuranceDimension) -> ProofKind {
    match dimension {
        ProtocolAssuranceDimension::CanonicalStructure
        | ProtocolAssuranceDimension::TransitionSemantics => ProofKind::CanonicalRules,
        ProtocolAssuranceDimension::Authorization => ProofKind::DigitalSignature,
        ProtocolAssuranceDimension::AnchorInclusion => ProofKind::MerkleInclusion,
        ProtocolAssuranceDimension::FinalityCheckpoint => ProofKind::ConfirmationDepth,
        ProtocolAssuranceDimension::SourceClosure => ProofKind::SourceSealClosure,
        ProtocolAssuranceDimension::Freshness => ProofKind::ObservedChainTip,
    }
}

/// What a named policy demands of one dimension.
///
/// No variant accepts `NotSatisfied`: a dimension whose evidence establishes
/// failure is always a shortfall, so a failed dimension can never be waived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DimensionRequirement {
    /// Only `Satisfied` is acceptable.
    MustBeSatisfied,
    /// `Satisfied`, `Indeterminate` or `NotApplicable` are acceptable; anything
    /// short of `Satisfied` is reported as an accepted limitation the caller must
    /// surface.
    MayBeIndeterminate,
    /// This policy makes no demand of the dimension; it is still reported.
    NotRequired,
}

/// A named acceptance policy over a [`ProtocolAssuranceReport`].
///
/// This is the replacement for `is_valid: bool`. Acceptance is a caller policy
/// decision, stated up front and identified by name, applied to typed readings —
/// not a verdict the verifier hands down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssuranceRequirement {
    /// Stable policy identifier, echoed in the outcome.
    pub policy_id: &'static str,
    /// One rule per dimension, in canonical dimension order.
    pub rules: [DimensionRequirement; PROTOCOL_ASSURANCE_DIMENSIONS.len()],
}

impl AssuranceRequirement {
    /// Every dimension must be `Satisfied`.
    ///
    /// Nothing can meet this today: source closure is not externally grounded until
    /// Stage 2 and consumed-state resolution lands with PAR-STATE-003. It is the
    /// honest statement of the end state, and a regression test target.
    pub const COMPLETE: Self = Self {
        policy_id: "parwana.assurance.complete.v1",
        rules: [DimensionRequirement::MustBeSatisfied; PROTOCOL_ASSURANCE_DIMENSIONS.len()],
    };

    /// Runtime source-proof policy.
    ///
    /// Inclusion and finality must be `Satisfied` via a named chain-native
    /// provider — those are the readings this path exists to obtain.
    ///
    /// Canonical structure is allowed to be `Indeterminate` because the runtime's
    /// chain adapters still supply node identifiers and the segment root instead of
    /// deriving them (PAR-DAG-001, PAR-DAG-002). A malformed size, seal reference
    /// or anchor binding is still `NotSatisfied` and still blocks.
    ///
    /// Authorization is allowed to be `Indeterminate` on this path and only this
    /// path: destination materialization is authorized by the on-chain §9.2
    /// verifier-attested mint, not by the proof bundle's DAG-signature binding
    /// (VERIFY-SIGNER-BINDING-001), so the runtime supplies no approved verifier
    /// set. That is a tolerance, not a pass — it comes back in
    /// [`RequirementOutcome::accepted_limitations`] and travels on the receipt.
    /// A `NotSatisfied` signature is still a shortfall.
    ///
    /// Transition semantics, source closure and freshness may likewise be
    /// `Indeterminate` and are returned as accepted limitations.
    pub const RUNTIME_SOURCE_PROOF: Self = Self {
        policy_id: "parwana.assurance.runtime-source-proof.v1",
        rules: [
            DimensionRequirement::MayBeIndeterminate, // CanonicalStructure
            DimensionRequirement::MayBeIndeterminate, // TransitionSemantics
            DimensionRequirement::MayBeIndeterminate, // Authorization
            DimensionRequirement::MustBeSatisfied,    // AnchorInclusion
            DimensionRequirement::MustBeSatisfied,    // FinalityCheckpoint
            DimensionRequirement::MayBeIndeterminate, // SourceClosure
            DimensionRequirement::MayBeIndeterminate, // Freshness
        ],
    };

    /// Offline recipient policy.
    ///
    /// An offline recipient holds no chain connection, so inclusion, finality and
    /// closure cannot be recomputed and are accepted as limitations. Canonical
    /// structure and authorization must still be `Satisfied` — those it can and
    /// must establish from the bundle itself.
    pub const OFFLINE_RECIPIENT: Self = Self {
        policy_id: "parwana.assurance.offline-recipient.v1",
        rules: [
            DimensionRequirement::MustBeSatisfied,    // CanonicalStructure
            DimensionRequirement::MayBeIndeterminate, // TransitionSemantics
            DimensionRequirement::MustBeSatisfied,    // Authorization
            DimensionRequirement::MayBeIndeterminate, // AnchorInclusion
            DimensionRequirement::MayBeIndeterminate, // FinalityCheckpoint
            DimensionRequirement::MayBeIndeterminate, // SourceClosure
            DimensionRequirement::MayBeIndeterminate, // Freshness
        ],
    };

    /// The rule this policy applies to one dimension.
    pub fn rule(&self, dimension: ProtocolAssuranceDimension) -> DimensionRequirement {
        self.rules[dimension.index()]
    }

    /// Apply the policy without mutating or hiding any reading.
    pub fn evaluate(&self, report: &ProtocolAssuranceReport) -> RequirementOutcome {
        let mut shortfalls = Vec::new();
        let mut accepted_limitations = Vec::new();
        for reading in report.dimensions() {
            let required = self.rule(reading.dimension);
            let entry = RequirementShortfall {
                dimension: reading.dimension,
                status: reading.status,
                required,
                reason_codes: reading.reason_codes.clone(),
                provider: reading.provider.clone(),
            };
            match (required, reading.status) {
                (_, DimensionStatus::NotSatisfied) => shortfalls.push(entry),
                (DimensionRequirement::MustBeSatisfied, DimensionStatus::Satisfied) => {}
                (DimensionRequirement::MustBeSatisfied, _) => shortfalls.push(entry),
                (_, DimensionStatus::Satisfied) => {}
                (DimensionRequirement::MayBeIndeterminate, _) => accepted_limitations.push(entry),
                (DimensionRequirement::NotRequired, _) => {}
            }
        }
        RequirementOutcome {
            policy_id: self.policy_id,
            verification_context_digest: report.verification_context_digest(),
            shortfalls,
            accepted_limitations,
        }
    }
}

/// One dimension a policy could not accept, or accepted only as a limitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequirementShortfall {
    /// Dimension in question.
    pub dimension: ProtocolAssuranceDimension,
    /// Observed conclusion.
    pub status: DimensionStatus,
    /// What the policy demanded.
    pub required: DimensionRequirement,
    /// Reasons carried by the reading.
    pub reason_codes: Vec<ProtocolReasonCode>,
    /// Who established the reading.
    pub provider: ProofProvider,
}

impl std::fmt::Display for RequirementShortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} is {} [{}] via {}",
            self.dimension.registry_id(),
            status_registry_id(self.status),
            self.reason_codes
                .iter()
                .map(|code| code.registry_id())
                .collect::<Vec<_>>()
                .join(", "),
            self.provider.describe()
        )
    }
}

/// The result of applying a named policy to a report.
///
/// It names the policy and the effective verification context, lists every
/// blocking shortfall, and lists every dimension the policy accepted while short
/// of `Satisfied`. The accepted limitations are part of the outcome precisely so
/// they cannot be dropped on the way to a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequirementOutcome {
    /// Policy that was applied.
    pub policy_id: &'static str,
    /// Effective verification context the report was produced under.
    pub verification_context_digest: Hash,
    /// Dimensions the policy could not accept.
    pub shortfalls: Vec<RequirementShortfall>,
    /// Dimensions accepted despite not being `Satisfied`.
    pub accepted_limitations: Vec<RequirementShortfall>,
}

impl RequirementOutcome {
    /// Whether the policy's demands were met.
    ///
    /// This is a derived policy conclusion over typed readings, not a verdict the
    /// verifier produced: it names its policy and context digest, and it never
    /// stands in for the report. Callers that accept must still surface
    /// [`accepted_limitations`](Self::accepted_limitations).
    pub fn is_met(&self) -> bool {
        self.shortfalls.is_empty()
    }

    /// Single-line summary of every blocking shortfall.
    pub fn shortfall_summary(&self) -> String {
        self.shortfalls
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Single-line summary of every accepted limitation.
    pub fn limitation_summary(&self) -> String {
        self.accepted_limitations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Builds the canonical byte string a verification-context digest is taken over.
///
/// Every field is length-prefixed and named, so no two different contexts can
/// serialize to the same bytes and no field can be silently dropped.
#[derive(Debug)]
pub struct ContextDigestWriter {
    buffer: Vec<u8>,
}

impl ContextDigestWriter {
    /// Start a digest for a named verification profile (which pipeline ran).
    pub fn new(profile_id: &str) -> Self {
        let mut buffer = Vec::new();
        push_text(&mut buffer, "profile");
        push_text(&mut buffer, profile_id);
        Self { buffer }
    }

    /// Commit a named byte field.
    pub fn bytes(&mut self, name: &str, value: &[u8]) -> &mut Self {
        push_text(&mut self.buffer, name);
        push_u32(&mut self.buffer, value.len() as u32);
        self.buffer.extend_from_slice(value);
        self
    }

    /// Commit a named text field.
    pub fn text(&mut self, name: &str, value: &str) -> &mut Self {
        self.bytes(name, value.as_bytes())
    }

    /// Commit a named integer field.
    pub fn u64(&mut self, name: &str, value: u64) -> &mut Self {
        self.bytes(name, &value.to_be_bytes())
    }

    /// Commit a named optional integer field, distinguishing absence from zero.
    pub fn opt_u64(&mut self, name: &str, value: Option<u64>) -> &mut Self {
        match value {
            Some(value) => {
                self.bytes(name, &[1]);
                self.u64(name, value)
            }
            None => self.bytes(name, &[0]),
        }
    }

    /// Commit a named optional byte field, distinguishing absence from empty.
    pub fn opt_bytes(&mut self, name: &str, value: Option<&[u8]>) -> &mut Self {
        match value {
            Some(value) => {
                self.bytes(name, &[1]);
                self.bytes(name, value)
            }
            None => self.bytes(name, &[0]),
        }
    }

    /// Commit a named presence marker for an input that cannot itself be hashed
    /// (a callback, for instance). Presence changes the verdict, so it is committed.
    pub fn presence(&mut self, name: &str, present: bool) -> &mut Self {
        self.bytes(name, &[u8::from(present)])
    }

    /// Commit a named chain-native provider assessment.
    pub fn chain_native_proof(
        &mut self,
        name: &str,
        assessment: &ChainNativeProofAssessment,
    ) -> &mut Self {
        let mut encoded = Vec::new();
        assessment.write_canonical(&mut encoded);
        self.bytes(name, &encoded)
    }

    /// Commit a named, order-preserving list of byte strings.
    pub fn byte_list(&mut self, name: &str, values: &[Vec<u8>]) -> &mut Self {
        push_text(&mut self.buffer, name);
        push_u32(&mut self.buffer, values.len() as u32);
        for value in values {
            push_u32(&mut self.buffer, value.len() as u32);
            self.buffer.extend_from_slice(value);
        }
        self
    }

    /// Finish and hash under the protocol verification-context domain.
    pub fn finish(&self) -> Hash {
        DomainSeparatedHash::<ProtocolVerificationContextDomain>::hash(&self.buffer)
    }
}

const fn status_tag(status: DimensionStatus) -> u8 {
    match status {
        DimensionStatus::Satisfied => 0,
        DimensionStatus::NotSatisfied => 1,
        DimensionStatus::Indeterminate => 2,
        DimensionStatus::NotApplicable => 3,
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv_accountability::{AssuranceDimension, DimensionResult};

    fn digest() -> Hash {
        ContextDigestWriter::new("test").finish()
    }

    fn satisfied(dimension: ProtocolAssuranceDimension) -> DimensionAssurance {
        DimensionAssurance::new(
            dimension,
            DimensionStatus::Satisfied,
            [ProtocolReasonCode::StructureValidated],
            ProofProvider::local(ProofKind::CanonicalRules),
            [],
        )
    }

    #[test]
    fn unrecorded_dimensions_default_to_indeterminate() {
        let report = ProtocolAssuranceReportBuilder::new(digest()).build();
        assert_eq!(
            report.dimensions().len(),
            PROTOCOL_ASSURANCE_DIMENSIONS.len()
        );
        for reading in report.dimensions() {
            assert_eq!(reading.status, DimensionStatus::Indeterminate);
            assert_eq!(reading.provider.trust_mode, TrustMode::Unverified);
            assert_eq!(
                reading.reason_codes,
                vec![ProtocolReasonCode::NotEvaluated],
                "an unreached dimension must say so"
            );
        }
    }

    #[test]
    fn report_dimensions_are_in_canonical_order() {
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(satisfied(ProtocolAssuranceDimension::Freshness));
        builder.record(satisfied(ProtocolAssuranceDimension::CanonicalStructure));
        let report = builder.build();
        let order: Vec<_> = report
            .dimensions()
            .iter()
            .map(|reading| reading.dimension)
            .collect();
        assert_eq!(order, PROTOCOL_ASSURANCE_DIMENSIONS.to_vec());
    }

    #[test]
    fn display_level_never_reaches_full_verification_with_a_shortfall() {
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        for dimension in PROTOCOL_ASSURANCE_DIMENSIONS {
            if dimension != ProtocolAssuranceDimension::SourceClosure {
                builder.record(satisfied(dimension));
            }
        }
        let report = builder.build();
        assert!(matches!(
            report.display_level(),
            VerificationLevel::StructuralOnly | VerificationLevel::MerkleVerified
        ));
    }

    #[test]
    fn a_failed_dimension_is_always_a_shortfall_even_when_not_required() {
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(DimensionAssurance::new(
            ProtocolAssuranceDimension::SourceClosure,
            DimensionStatus::NotSatisfied,
            [ProtocolReasonCode::ReplayDetected],
            ProofProvider::local(ProofKind::ReplayRegistry),
            [],
        ));
        let report = builder.build();
        let permissive = AssuranceRequirement {
            policy_id: "test.permissive",
            rules: [DimensionRequirement::NotRequired; PROTOCOL_ASSURANCE_DIMENSIONS.len()],
        };
        let outcome = permissive.evaluate(&report);
        assert!(!outcome.is_met());
        assert_eq!(outcome.shortfalls.len(), 1);
        assert_eq!(
            outcome.shortfalls[0].dimension,
            ProtocolAssuranceDimension::SourceClosure
        );
    }

    #[test]
    fn accepted_limitations_are_reported_separately_from_shortfalls() {
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(satisfied(ProtocolAssuranceDimension::CanonicalStructure));
        builder.record(satisfied(ProtocolAssuranceDimension::Authorization));
        builder.record(satisfied(ProtocolAssuranceDimension::AnchorInclusion));
        builder.record(satisfied(ProtocolAssuranceDimension::FinalityCheckpoint));
        let report = builder.build();
        let outcome = AssuranceRequirement::RUNTIME_SOURCE_PROOF.evaluate(&report);
        assert!(outcome.is_met());
        let limited: Vec<_> = outcome
            .accepted_limitations
            .iter()
            .map(|entry| entry.dimension)
            .collect();
        assert_eq!(
            limited,
            vec![
                ProtocolAssuranceDimension::TransitionSemantics,
                ProtocolAssuranceDimension::SourceClosure,
                ProtocolAssuranceDimension::Freshness,
            ]
        );
    }

    #[test]
    fn weakening_never_upgrades_a_conclusion() {
        assert_eq!(
            weaken(DimensionStatus::Satisfied, DimensionStatus::Indeterminate),
            DimensionStatus::Indeterminate
        );
        assert_eq!(
            weaken(DimensionStatus::Indeterminate, DimensionStatus::Satisfied),
            DimensionStatus::Indeterminate
        );
        assert_eq!(
            weaken(DimensionStatus::NotApplicable, DimensionStatus::Satisfied),
            DimensionStatus::Satisfied
        );
        assert_eq!(
            weaken(DimensionStatus::NotSatisfied, DimensionStatus::Satisfied),
            DimensionStatus::NotSatisfied
        );
    }

    fn empty_profile() -> AssuranceProfile {
        AssuranceProfile {
            verification_context_id: csv_accountability::VerificationContextId::from_digest(
                [0u8; 32],
            ),
            dimensions: csv_accountability::ASSURANCE_DIMENSIONS
                .iter()
                .map(|dimension| DimensionResult {
                    dimension: *dimension,
                    status: DimensionStatus::NotApplicable,
                    assurance_level: None,
                    reason_codes: Vec::new(),
                    supporting_evidence_refs: Vec::new(),
                    limitations: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn incorporating_a_report_names_the_provider_and_keeps_the_profile_valid() {
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(DimensionAssurance::new(
            ProtocolAssuranceDimension::AnchorInclusion,
            DimensionStatus::Satisfied,
            [ProtocolReasonCode::InclusionAttestedByProvider],
            ProofProvider::attested(
                "bitcoin-adapter",
                Some("bitcoin".to_string()),
                ProofKind::MerkleInclusion,
            ),
            [],
        ));
        let report = builder.build();

        let mut profile = empty_profile();
        report.incorporate_into(&mut profile);
        profile
            .validate()
            .expect("folding must leave the profile canonical");

        let corroboration = profile
            .dimensions
            .iter()
            .find(|result| result.dimension == AssuranceDimension::ExternalCorroboration)
            .expect("every dimension is present");
        assert!(
            corroboration
                .limitations
                .iter()
                .any(|limitation| limitation.contains("provider-attested")),
            "a provider-attested reading must stay visibly contextual: {:?}",
            corroboration.limitations
        );
        // AnchorInclusion (Satisfied) folds with FinalityCheckpoint (Indeterminate,
        // never evaluated) into the same accountability dimension, and weakening
        // keeps the pair honest.
        assert_eq!(corroboration.status, DimensionStatus::Indeterminate);
    }

    #[test]
    fn incorporating_cannot_upgrade_an_accountability_dimension() {
        let mut profile = empty_profile();
        for result in &mut profile.dimensions {
            if result.dimension == AssuranceDimension::Cryptographic {
                result.status = DimensionStatus::Satisfied;
            }
        }
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(DimensionAssurance::new(
            ProtocolAssuranceDimension::Authorization,
            DimensionStatus::NotSatisfied,
            [ProtocolReasonCode::SignatureInvalid],
            ProofProvider::local(ProofKind::DigitalSignature),
            [],
        ));
        builder.build().incorporate_into(&mut profile);

        let cryptographic = profile
            .dimensions
            .iter()
            .find(|result| result.dimension == AssuranceDimension::Cryptographic)
            .expect("every dimension is present");
        assert_eq!(cryptographic.status, DimensionStatus::NotSatisfied);
    }

    #[test]
    fn context_digest_separates_every_committed_field() {
        let mut a = ContextDigestWriter::new("p");
        a.text("chain", "bitcoin").u64("confirmations", 6);
        let mut b = ContextDigestWriter::new("p");
        b.text("chain", "bitcoin").u64("confirmations", 7);
        let mut c = ContextDigestWriter::new("p");
        c.text("chain", "bitcoi").u64("confirmations", 6);
        assert_ne!(a.finish(), b.finish());
        assert_ne!(a.finish(), c.finish());

        let mut absent = ContextDigestWriter::new("p");
        absent.opt_u64("tip", None);
        let mut zero = ContextDigestWriter::new("p");
        zero.opt_u64("tip", Some(0));
        assert_ne!(
            absent.finish(),
            zero.finish(),
            "absence must not digest as zero"
        );
    }

    #[test]
    fn report_digest_changes_with_any_reading() {
        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(satisfied(ProtocolAssuranceDimension::CanonicalStructure));
        let first = builder.build();

        let mut builder = ProtocolAssuranceReportBuilder::new(digest());
        builder.record(DimensionAssurance::new(
            ProtocolAssuranceDimension::CanonicalStructure,
            DimensionStatus::Indeterminate,
            [ProtocolReasonCode::NotEvaluated],
            ProofProvider::local(ProofKind::CanonicalRules),
            [],
        ));
        let second = builder.build();

        assert_ne!(first.digest(), second.digest());
    }
}
