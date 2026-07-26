//! Proof Verification Pipeline - SECURITY CRITICAL
//!
//! This module provides the core verification logic for proof bundles.
//! It is the cryptographic gatekeeper that ensures only valid proofs are accepted.
//!
//! # Security Purpose
//!
//! This verifier ensures that:
//! 1. **Authenticity**: Signatures are valid and from authorized keys
//! 2. **Integrity**: The proof bundle hasn't been tampered with
//! 3. **Uniqueness**: Seals haven't been used before (replay protection)
//! 4. **Finality**: The anchor has reached required confirmation depth
//!
//! # Verification Steps
//!
//! The pipeline enforces a strict order of validation:
//! 1. **DAG Structure** - Verify the transition graph is well-formed
//! 2. **Signatures** - Cryptographically verify all authorizing signatures
//! 3. **Seal Replay** - Check seal hasn't been consumed before
//! 4. **Inclusion** - Verify anchor is in the chain's history
//! 5. **Finality** - Confirm anchor has reached required confirmations
//!
//! # Security Invariants
//!
//! - All signatures must be valid (no partial signature acceptance)
//! - Seal replay check uses provided registry callback
//! - Empty inclusion proofs are rejected
//! - Zero confirmations fails finality check
//! - Verification is deterministic (same input = same result)
//!
//! # Audit Checklist
//!
//! - [ ] Signature verification uses appropriate scheme (Secp256k1/Ed25519)
//! - [ ] Seal registry callback properly checks for replays
//! - [ ] Empty proofs are rejected at each validation step
//! - [ ] Signature format parsing is robust against malformed input
//! - [ ] Verification failures provide specific error types (not just generic)
//!
//! # Critical Security Note
//!
//! **NEVER** bypass or weaken these checks in production. Any shortcut
//! here could allow fraudulent proofs to be accepted, leading to
//! unauthorized state transitions or double-spends.

use csv_accountability::DimensionStatus;
use csv_hash::Hash;
use csv_protocol::error::ProtocolError;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::proof_taxonomy::ProofLeafV1;
use csv_protocol::signature::{Signature, SignatureScheme, verify_signatures};
use serde::Serialize;

use crate::assurance::{
    ChainNativeClaim, ChainNativeClaimReading, ChainNativeProofAssessment, ContextDigestWriter,
    DimensionAssurance, ProofKind, ProofProvider, ProtocolAssuranceDimension,
    ProtocolAssuranceReport, ProtocolAssuranceReportBuilder, ProtocolReasonCode,
};

type Result<T> = std::result::Result<T, ProtocolError>;

/// Machine-readable error code for verification failures.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum VerificationErrorCode {
    /// Seal was already consumed — replay attempt
    SealReplay,
    /// Signature verification failed
    SignatureInvalid,
    /// Inclusion proof verification failed
    InclusionProofInvalid,
    /// Finality requirements not met
    FinalityNotReached,
    /// Domain mismatch between proof and expected chain
    DomainMismatch,
    /// Proof structure is malformed
    MalformedProof,
    /// Proof exceeds maximum allowed size
    ProofTooLarge,
    /// Anchor reference is invalid
    AnchorInvalid,
    /// Internal verification error
    InternalError,
}

impl std::fmt::Display for VerificationErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SealReplay => write!(f, "SEAL_REPLAY"),
            Self::SignatureInvalid => write!(f, "SIGNATURE_INVALID"),
            Self::InclusionProofInvalid => write!(f, "INCLUSION_PROOF_INVALID"),
            Self::FinalityNotReached => write!(f, "FINALITY_NOT_REACHED"),
            Self::DomainMismatch => write!(f, "DOMAIN_MISMATCH"),
            Self::MalformedProof => write!(f, "MALFORMED_PROOF"),
            Self::ProofTooLarge => write!(f, "PROOF_TOO_LARGE"),
            Self::AnchorInvalid => write!(f, "ANCHOR_INVALID"),
            Self::InternalError => write!(f, "INTERNAL_ERROR"),
        }
    }
}

/// Typed verification error with retryability semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationError {
    /// Machine-readable error code for routing.
    pub code: VerificationErrorCode,
    /// Human-readable description.
    pub message: String,
    /// Whether retrying may succeed (transient vs permanent).
    pub retryable: bool,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl VerificationError {
    /// Create a seal replay error (permanent — never retry).
    pub fn seal_replay(seal_id: &[u8]) -> Self {
        Self {
            code: VerificationErrorCode::SealReplay,
            message: format!("Seal {:?} already consumed — replay attempt", seal_id),
            retryable: false,
        }
    }

    /// Create a signature invalid error (permanent — never retry).
    pub fn signature_invalid() -> Self {
        Self {
            code: VerificationErrorCode::SignatureInvalid,
            message: "Signature verification failed".to_string(),
            retryable: false,
        }
    }

    /// Create an inclusion proof invalid error (permanent — never retry).
    pub fn inclusion_proof_invalid(reason: &str) -> Self {
        Self {
            code: VerificationErrorCode::InclusionProofInvalid,
            message: format!("Inclusion proof invalid: {}", reason),
            retryable: false,
        }
    }

    /// Create a finality not reached error (transient — retry after more confirmations).
    pub fn finality_not_reached(confirmations: u64, required: u64) -> Self {
        Self {
            code: VerificationErrorCode::FinalityNotReached,
            message: format!("{} confirmations, need {}", confirmations, required),
            retryable: true,
        }
    }

    /// Create a domain mismatch error (permanent — never retry).
    pub fn domain_mismatch(expected: &str, found: &str) -> Self {
        Self {
            code: VerificationErrorCode::DomainMismatch,
            message: format!("Domain mismatch: expected {}, found {}", expected, found),
            retryable: false,
        }
    }

    /// Create a malformed proof error (permanent — never retry).
    pub fn malformed_proof(reason: &str) -> Self {
        Self {
            code: VerificationErrorCode::MalformedProof,
            message: format!("Malformed proof: {}", reason),
            retryable: false,
        }
    }

    /// Create a proof too large error (permanent — never retry).
    pub fn proof_too_large(actual: usize, max: usize) -> Self {
        Self {
            code: VerificationErrorCode::ProofTooLarge,
            message: format!("Proof too large: {} bytes (max {})", actual, max),
            retryable: false,
        }
    }

    /// Create an anchor invalid error (permanent — never retry).
    pub fn anchor_invalid(reason: &str) -> Self {
        Self {
            code: VerificationErrorCode::AnchorInvalid,
            message: format!("Anchor invalid: {}", reason),
            retryable: false,
        }
    }

    /// Create an internal error (transient — may retry).
    pub fn internal(reason: &str) -> Self {
        Self {
            code: VerificationErrorCode::InternalError,
            message: format!("Internal error: {}", reason),
            retryable: true,
        }
    }
}

/// Maximum proof bundle size in bytes (1MB)
const MAX_PROOF_BUNDLE_SIZE: usize = 1024 * 1024;

/// Minimum required confirmations for finality
const MIN_REQUIRED_CONFIRMATIONS: u64 = 6;

// ============================================================================
// Canonical Verifier Interface (PHASE 5.4)
// ============================================================================

/// Canonical verifier trait for all proof verification (PHASE 5.4).
///
/// This trait defines the single source of truth for proof verification.
/// All components (runtime, adapters, SDKs) MUST delegate verification
/// to implementations of this trait to ensure consistent verification
/// semantics across the protocol.
///
/// # Security Invariants
///
/// - All verification paths MUST go through this interface
/// - No component may implement its own verification logic
/// - Verification MUST be deterministic (same input = same result)
/// - All verification failures MUST be typed and explicit
///
/// # Result shape (PAR-VERIFY-001)
///
/// Verification answers with a
/// [`ProtocolAssuranceReport`](crate::assurance::ProtocolAssuranceReport): one
/// reading per dimension, each naming its proof provider, all bound to the digest
/// of the effective verification context. There is no boolean and no aggregate
/// label. Acceptance is a caller decision, taken by evaluating the report against
/// a named [`AssuranceRequirement`](crate::assurance::AssuranceRequirement).
///
/// Verification is pure, so it does not fail: material that cannot be verified
/// produces a `NotSatisfied` or `Indeterminate` reading with a stable reason
/// code, never an opaque error that a caller might discard.
///
/// # Implementation Notes
///
/// The canonical implementation is provided by `CanonicalVerifier` in this module.
/// Chain adapters should implement this trait for chain-specific verification
/// (inclusion proofs, finality checks) but MUST delegate to the canonical
/// verifier for protocol-level checks (signatures, replay, DAG structure).
pub trait CanonicalVerifier: Send + Sync {
    /// Verify a proof bundle according to the CSV verification pipeline.
    ///
    /// This is the primary verification entry point. It reports, per dimension,
    /// exactly what the supplied material established.
    ///
    /// # Arguments
    /// * `bundle` - The proof bundle to verify
    /// * `context` - Verification context containing chain-specific data
    fn verify_proof_bundle(
        &self,
        bundle: &ProofBundle,
        context: &VerificationContext,
    ) -> ProtocolAssuranceReport;

    /// Report the anchor-inclusion dimension for a bundle.
    ///
    /// The pure verifier can only recompute structure; cryptographic inclusion
    /// comes from the context's chain-native provider, and its absence is reported
    /// as `Indeterminate` rather than assumed either way.
    fn verify_inclusion_proof(
        &self,
        bundle: &ProofBundle,
        context: &VerificationContext,
    ) -> DimensionAssurance;

    /// Report the finality/checkpoint dimension for an anchor height.
    ///
    /// Takes the finality proof explicitly: a reading about material the caller
    /// did not supply would be a reading about nothing.
    fn verify_finality(
        &self,
        finality_proof: &csv_protocol::proof_taxonomy::FinalityProof,
        anchor_height: u64,
        context: &VerificationContext,
    ) -> DimensionAssurance;

    /// Verify seal registry status (check if seal has been consumed).
    ///
    /// # Arguments
    /// * `seal_id` - The seal identifier to check
    /// * `context` - Verification context containing replay registry
    ///
    /// # Returns
    /// Seal registry status (available or consumed).
    fn verify_seal_registry(
        &self,
        seal_id: &[u8],
        context: &VerificationContext,
    ) -> Result<SealRegistryStatus>;

    /// Verify a ProofLeafV1 using the source chain's native hash function.
    ///
    /// This method computes the leaf hash using the chain's native hash function
    /// and verifies it matches the expected hash. This is critical for cross-chain
    /// verification where each chain uses its native hash to avoid gas costs.
    ///
    /// # Arguments
    /// * `leaf` - The proof leaf to verify
    /// * `expected_hash` - The expected hash value
    ///
    /// # Returns
    /// The canonical-structure reading for the leaf: `Satisfied` when the
    /// recomputed native hash matches, `NotSatisfied` when it does not.
    fn verify_proof_leaf(
        &self,
        leaf: &ProofLeafV1,
        expected_hash: &csv_hash::Hash,
    ) -> DimensionAssurance;
}

/// Status of a seal in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SealRegistryStatus {
    /// Seal is available for use.
    Available,
    /// Seal has been consumed (replay attempt).
    Consumed,
    /// Registry check failed (transient error).
    CheckFailed(String),
}

/// Verification context containing chain-specific and protocol data.
///
/// This context is passed to all verification methods to provide the
/// necessary data for verification without requiring chain-specific
/// knowledge in the canonical verifier.
pub struct VerificationContext {
    /// Chain identifier for this verification.
    pub chain_id: String,
    /// Signature scheme to use for verification.
    pub signature_scheme: SignatureScheme,
    /// Required confirmations for finality.
    pub required_confirmations: u64,
    /// Current block height (for finality checks).
    pub current_block_height: Option<u64>,
    /// Replay registry callback (returns true if seal is consumed).
    pub seal_registry: Option<Box<dyn Fn(&[u8]) -> bool + Send + Sync>>,
    /// Chain-specific verification data (inclusion proofs, headers, etc.).
    pub chain_data: Option<ChainVerificationData>,
    /// What a named chain-native provider states it established about this bundle
    /// (PAR-VERIFY-001).
    ///
    /// This replaces the former `native_proof_validated: bool`. A bare flag could
    /// carry an entire bundle to a full-verification claim without naming who
    /// verified what, and conflated "no provider looked" with "a provider rejected
    /// it". Each claim raises only its own dimension, and every dimension it raises
    /// is reported as
    /// [`TrustMode::ProviderAttested`](crate::assurance::TrustMode::ProviderAttested)
    /// — never as something this verifier recomputed.
    pub chain_native_proof: ChainNativeProofAssessment,
    /// Sanad ID that the proof must bind to.
    pub sanad_id: Option<csv_hash::SanadId>,
    /// Lock transaction hash bytes (source chain lock tx).
    pub lock_tx: Option<Vec<u8>>,
    /// Lock output index on the source chain.
    pub lock_output_index: Option<u32>,
    /// Transition ID for the transfer being verified.
    pub transition_id: Option<Vec<u8>>,
    /// Destination chain identifier for cross-chain binding.
    pub destination_chain: Option<String>,
    /// Approved verifier public keys (RFC-0012 §9 verifier set) a proof-bundle
    /// signature MUST recover to (VERIFY-SIGNER-BINDING-001).
    ///
    /// Without this binding, `verify_bundle_signatures` would only prove that
    /// "whoever chose the embedded public key also signed with its private key" —
    /// a tautology any sender satisfies. When non-empty, every proof-bundle
    /// signature's public key must be a member of this set or verification fails
    /// closed. Keys are raw public-key bytes as they appear in the signature
    /// blob; secp256k1 keys are compared in canonical compressed form.
    ///
    /// Leaving this empty no longer silently passes: the authorization dimension
    /// is then reported as `Indeterminate` with
    /// `PROTOCOL.AUTHORIZATION.SIGNER_SET_UNBOUND`, which every shipped
    /// [`AssuranceRequirement`](crate::assurance::AssuranceRequirement) treats as a
    /// blocking shortfall. Both the runtime path and the offline recipient accept
    /// path must populate it from trusted configuration.
    pub authorized_signers: Vec<Vec<u8>>,
}

/// Chain-specific verification data.
#[derive(Clone, Debug)]
pub struct ChainVerificationData {
    /// Block header for inclusion verification.
    pub block_header: Option<Vec<u8>>,
    /// Merkle proof data.
    pub merkle_proof: Option<Vec<u8>>,
    /// Finality proof data.
    pub finality_proof: Option<Vec<u8>>,
    /// Additional chain-specific data.
    pub additional: Option<Vec<u8>>,
}

/// Canonical verifier implementation (PHASE 5.4).
///
/// This is the single source of truth for proof verification in the Parwana.
/// All other components MUST delegate to this verifier for protocol-level checks.
pub struct CanonicalVerifierImpl {
    /// Verification configuration.
    config: VerifierConfig,
}

/// Configuration for the canonical verifier.
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// Maximum proof bundle size in bytes.
    pub max_proof_bundle_size: usize,
    /// Minimum required confirmations for finality.
    pub min_required_confirmations: u64,
    /// Maximum age of a proof's anchor, in blocks below the observed source-chain
    /// tip, before the proof is rejected as stale (VERIFY-PROOF-FRESHNESS-001).
    ///
    /// This is a height-based freshness bound rather than a wall-clock one: a
    /// `ProofBundle` carries no trusted timestamp, but its `anchor_ref.block_height`
    /// plus the context's observed tip give a real, deterministic age in blocks.
    /// It is the *upper* bound on the same `tip - anchor_height` quantity that
    /// finality lower-bounds. `None` disables the check (the default), because a
    /// meaningful bound is deployment/chain-specific. Production constructors
    /// must set it from source-chain configuration; `None` is reserved for
    /// tests and explicit deployments that disable freshness. The `u64::MAX`
    /// "instant-final" confirmation sentinel used by chains without a depth
    /// model remains exempt when the bound is set.
    pub max_anchor_age_blocks: Option<u64>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_proof_bundle_size: MAX_PROOF_BUNDLE_SIZE,
            min_required_confirmations: MIN_REQUIRED_CONFIRMATIONS,
            max_anchor_age_blocks: None,
        }
    }
}

impl Default for CanonicalVerifierImpl {
    fn default() -> Self {
        Self::new(VerifierConfig::default())
    }
}

impl CanonicalVerifierImpl {
    /// Create a new canonical verifier with the given configuration.
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Get the verifier configuration.
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }
}

impl CanonicalVerifier for CanonicalVerifierImpl {
    fn verify_proof_bundle(
        &self,
        bundle: &ProofBundle,
        context: &VerificationContext,
    ) -> ProtocolAssuranceReport {
        let mut builder = ProtocolAssuranceReportBuilder::new(self.runtime_context_digest(context));

        // Dimension 1 — canonical structure. Size bound, DAG identity and
        // anchor-reference integrity are recomputed here from the bundle alone
        // (VERIFY-VALIDATIONS-DISABLED-001).
        // The runtime rebuilds its bundle from live chain state through an adapter
        // that still selects node identifiers and the segment root itself, so
        // canonical DAG identity cannot be recomputed here yet. PAR-DAG-001 and
        // PAR-DAG-002 own closing that gap; until then this path reports it rather
        // than claiming a check it did not run.
        let structure = structure_reading(
            bundle,
            self.config.max_proof_bundle_size,
            DagIdentityRule::Deferred,
        );
        record_dimension_error(&mut builder, &structure);
        builder.record(structure);

        // Dimension 2 — transition semantics. Binding the bundle to the transfer
        // the context authorizes stops a proof built for one chain/Sanad being
        // replayed under a context for another (VERIFY-DOMAIN-SEPARATION-001).
        // Full semantics also need consumed-state resolution, which PAR-STATE-003
        // owns, so a verified binding is still only an Indeterminate reading.
        let semantics = transition_semantics_reading(
            validate_context_binding(bundle, context),
            context
                .chain_native_proof
                .reading(ChainNativeClaim::TransferBinding),
        );
        record_dimension_error(&mut builder, &semantics);
        builder.record(semantics);

        // Dimension 3 — authorization.
        let authorization = authorization_reading(
            bundle,
            context.signature_scheme,
            &context.authorized_signers,
        );
        record_dimension_error(&mut builder, &authorization);
        builder.record(authorization);

        // Dimension 4 — anchor inclusion.
        let inclusion = self.verify_inclusion_proof(bundle, context);
        record_dimension_error(&mut builder, &inclusion);
        builder.record(inclusion);

        // Dimension 5 — finality / checkpoint.
        let finality = finality_reading(
            &bundle.finality_proof,
            bundle.anchor_ref.block_height,
            context.required_confirmations,
            context.current_block_height,
            &context.chain_native_proof,
        );
        record_dimension_error(&mut builder, &finality);
        builder.record(finality);

        // Dimension 6 — source closure. The replay registry is a *local* defence;
        // it is never portable non-equivocation, so this dimension cannot be
        // Satisfied until source closure is grounded on a shared ordering
        // (Stage 2, PAR-BTC-002).
        let closure = source_closure_reading(self.seal_replay_reading(bundle, context));
        record_dimension_error(&mut builder, &closure);
        builder.record(closure);

        // Dimension 7 — freshness (VERIFY-PROOF-FRESHNESS-001).
        let freshness = freshness_reading(
            bundle.anchor_ref.block_height,
            context.current_block_height,
            self.config.max_anchor_age_blocks,
        );
        record_dimension_error(&mut builder, &freshness);
        builder.record(freshness);

        builder.build()
    }

    fn verify_inclusion_proof(
        &self,
        bundle: &ProofBundle,
        context: &VerificationContext,
    ) -> DimensionAssurance {
        inclusion_reading(
            &bundle.inclusion_proof,
            &bundle.anchor_ref,
            &context.chain_native_proof,
        )
    }

    fn verify_finality(
        &self,
        finality_proof: &csv_protocol::proof_taxonomy::FinalityProof,
        anchor_height: u64,
        context: &VerificationContext,
    ) -> DimensionAssurance {
        finality_reading(
            finality_proof,
            anchor_height,
            context.required_confirmations,
            context.current_block_height,
            &context.chain_native_proof,
        )
    }

    fn verify_seal_registry(
        &self,
        seal_id: &[u8],
        context: &VerificationContext,
    ) -> Result<SealRegistryStatus> {
        if let Some(registry) = &context.seal_registry {
            if registry(seal_id) {
                return Ok(SealRegistryStatus::Consumed);
            }
            return Ok(SealRegistryStatus::Available);
        }
        Ok(SealRegistryStatus::CheckFailed(
            "no replay registry supplied".to_string(),
        ))
    }

    fn verify_proof_leaf(
        &self,
        leaf: &ProofLeafV1,
        expected_hash: &csv_hash::Hash,
    ) -> DimensionAssurance {
        let hash_fn = leaf.native_hash_function();
        let computed = match leaf.hash_with_function(hash_fn) {
            Ok(computed) => computed,
            Err(e) => {
                return not_satisfied(
                    ProtocolAssuranceDimension::CanonicalStructure,
                    ProtocolReasonCode::InclusionProofMalformed,
                    ProofKind::CanonicalRules,
                    format!("proof leaf hash could not be computed: {e}"),
                );
            }
        };
        if computed == *expected_hash {
            DimensionAssurance::new(
                ProtocolAssuranceDimension::CanonicalStructure,
                DimensionStatus::Satisfied,
                [ProtocolReasonCode::StructureValidated],
                ProofProvider::local(ProofKind::CanonicalRules),
                [format!(
                    "Recomputed with the source chain's native hash function ({hash_fn:?}); \
                     leaf identity only, not inclusion"
                )],
            )
        } else {
            not_satisfied(
                ProtocolAssuranceDimension::CanonicalStructure,
                ProtocolReasonCode::InclusionProofMalformed,
                ProofKind::CanonicalRules,
                format!(
                    "proof leaf hash mismatch: computed {computed:?}, expected {expected_hash:?} \
                     (using {hash_fn:?})"
                ),
            )
        }
    }
}

impl CanonicalVerifierImpl {
    /// Digest of everything in the runtime context that can change a verdict.
    ///
    /// The verifier configuration is part of the effective context: the same
    /// bundle under a different confirmation floor or freshness bound is a
    /// different evaluation, and the digest must say so.
    fn runtime_context_digest(&self, context: &VerificationContext) -> Hash {
        let mut writer = ContextDigestWriter::new(RUNTIME_VERIFICATION_PROFILE_ID);
        writer
            .text("chain_id", &context.chain_id)
            .u64(
                "signature_scheme",
                signature_scheme_tag(context.signature_scheme),
            )
            .u64("required_confirmations", context.required_confirmations)
            .opt_u64("current_block_height", context.current_block_height)
            .presence("seal_registry", context.seal_registry.is_some())
            .chain_native_proof("chain_native_proof", &context.chain_native_proof)
            .opt_bytes(
                "sanad_id",
                context.sanad_id.as_ref().map(|id| id.as_bytes().as_slice()),
            )
            .opt_bytes("lock_tx", context.lock_tx.as_deref())
            .opt_u64(
                "lock_output_index",
                context.lock_output_index.map(u64::from),
            )
            .opt_bytes("transition_id", context.transition_id.as_deref())
            .opt_bytes(
                "destination_chain",
                context.destination_chain.as_deref().map(str::as_bytes),
            )
            .byte_list("authorized_signers", &context.authorized_signers)
            .u64(
                "config.max_proof_bundle_size",
                self.config.max_proof_bundle_size as u64,
            )
            .u64(
                "config.min_required_confirmations",
                self.config.min_required_confirmations,
            )
            .opt_u64(
                "config.max_anchor_age_blocks",
                self.config.max_anchor_age_blocks,
            );
        if let Some(chain_data) = &context.chain_data {
            writer
                .presence("chain_data", true)
                .opt_bytes(
                    "chain_data.block_header",
                    chain_data.block_header.as_deref(),
                )
                .opt_bytes(
                    "chain_data.merkle_proof",
                    chain_data.merkle_proof.as_deref(),
                )
                .opt_bytes(
                    "chain_data.finality_proof",
                    chain_data.finality_proof.as_deref(),
                )
                .opt_bytes("chain_data.additional", chain_data.additional.as_deref());
        } else {
            writer.presence("chain_data", false);
        }
        writer.finish()
    }

    /// Local replay-registry reading for the bundle's source seal.
    ///
    /// `None` means no registry was supplied, which is not the same as "unconsumed".
    fn seal_replay_reading(
        &self,
        bundle: &ProofBundle,
        context: &VerificationContext,
    ) -> Option<bool> {
        match self.verify_seal_registry(&bundle.seal_ref.id, context) {
            Ok(SealRegistryStatus::Consumed) => Some(true),
            Ok(SealRegistryStatus::Available) => Some(false),
            Ok(SealRegistryStatus::CheckFailed(_)) | Err(_) => None,
        }
    }
}

/// Stable name of the runtime verification pipeline, committed to every digest.
const RUNTIME_VERIFICATION_PROFILE_ID: &str = "parwana.csv-verifier.proof-bundle.v1";

/// Stable name of the offline bound-verification pipeline.
const OFFLINE_VERIFICATION_PROFILE_ID: &str = "parwana.csv-verifier.proof-bound.v1";

const fn signature_scheme_tag(scheme: SignatureScheme) -> u64 {
    match scheme {
        SignatureScheme::Secp256k1 => 1,
        SignatureScheme::Ed25519 => 2,
        SignatureScheme::MlDsa65 => 3,
    }
}

/// A `NotSatisfied` reading carrying one reason and one explanatory limitation.
fn not_satisfied(
    dimension: ProtocolAssuranceDimension,
    reason: ProtocolReasonCode,
    proof_kind: ProofKind,
    detail: String,
) -> DimensionAssurance {
    DimensionAssurance::new(
        dimension,
        DimensionStatus::NotSatisfied,
        [reason],
        ProofProvider::local(proof_kind),
        [detail],
    )
}

/// Mirror an unsatisfied reading into the report's typed error list.
///
/// Errors are a routing convenience over the same readings; they never soften
/// one. A `NotSatisfied` dimension stays `NotSatisfied` whether or not a caller
/// reads the error list.
fn record_dimension_error(
    builder: &mut ProtocolAssuranceReportBuilder,
    reading: &DimensionAssurance,
) {
    if reading.status != DimensionStatus::NotSatisfied {
        return;
    }
    let message = format!(
        "{} [{}]{}",
        reading.dimension.registry_id(),
        reading
            .reason_codes
            .iter()
            .map(|code| code.registry_id())
            .collect::<Vec<_>>()
            .join(", "),
        if reading.limitations.is_empty() {
            String::new()
        } else {
            format!(": {}", reading.limitations.join("; "))
        }
    );
    let code = match reading.dimension {
        ProtocolAssuranceDimension::CanonicalStructure
        | ProtocolAssuranceDimension::TransitionSemantics => VerificationErrorCode::MalformedProof,
        ProtocolAssuranceDimension::Authorization => VerificationErrorCode::SignatureInvalid,
        ProtocolAssuranceDimension::AnchorInclusion => VerificationErrorCode::InclusionProofInvalid,
        ProtocolAssuranceDimension::FinalityCheckpoint | ProtocolAssuranceDimension::Freshness => {
            VerificationErrorCode::FinalityNotReached
        }
        ProtocolAssuranceDimension::SourceClosure => VerificationErrorCode::SealReplay,
    };
    builder.record_error(VerificationError {
        code,
        message,
        // Only an insufficient confirmation depth can change with time.
        retryable: reading
            .reason_codes
            .contains(&ProtocolReasonCode::ConfirmationDepthNotMet),
    });
}

/// Canonical-structure reading: everything recomputable from the bundle alone.
fn structure_reading(
    bundle: &ProofBundle,
    max_bundle_size: usize,
    dag_rule: DagIdentityRule,
) -> DimensionAssurance {
    if let Err(e) = validate_proof_bundle_size_with(bundle, max_bundle_size) {
        return not_satisfied(
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::BundleTooLarge,
            ProofKind::CanonicalRules,
            e.to_string(),
        );
    }
    // The relation rules read declared identifiers only, so they run on every
    // path — including the one that cannot yet recompute identity. A cycle, a
    // duplicate identifier or an unresolvable parent is a structural failure
    // wherever the identifiers came from, and must not be reported as merely
    // unknown (PAR-DAG-002; ARCHITECTURE.md §8: no security error downgraded to
    // a best-effort result).
    if let Err(e) = bundle.transition_dag.validate_relations() {
        return not_satisfied(
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::DagStructureInvalid,
            ProofKind::CanonicalRules,
            format!("invalid DAG structure: {e}"),
        );
    }
    if dag_rule == DagIdentityRule::Recompute
        && let Err(e) = bundle.transition_dag.validate_structure()
    {
        return not_satisfied(
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::DagStructureInvalid,
            ProofKind::CanonicalRules,
            format!("invalid DAG structure: {e}"),
        );
    }
    if bundle.seal_ref.id.is_empty() {
        return not_satisfied(
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::SealReferenceMissing,
            ProofKind::CanonicalRules,
            "seal reference is empty".to_string(),
        );
    }
    if let Err(e) = validate_anchor_reference(bundle) {
        return not_satisfied(
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::AnchorReferenceInvalid,
            ProofKind::CanonicalRules,
            e.to_string(),
        );
    }
    match dag_rule {
        DagIdentityRule::Recompute => DimensionAssurance::new(
            ProtocolAssuranceDimension::CanonicalStructure,
            DimensionStatus::Satisfied,
            [ProtocolReasonCode::StructureValidated],
            ProofProvider::local(ProofKind::CanonicalRules),
            [
                "Structural validity says nothing about whether the asserted facts are true"
                    .to_string(),
            ],
        ),
        // The size, relation, seal and anchor rules held, but node identity and
        // the segment root were taken as given. That is not a passing
        // canonical-structure check, so the reading stops short of Satisfied and
        // names exactly which rules did not run.
        DagIdentityRule::Deferred => DimensionAssurance::new(
            ProtocolAssuranceDimension::CanonicalStructure,
            DimensionStatus::Indeterminate,
            [
                ProtocolReasonCode::StructureValidated,
                ProtocolReasonCode::DagIdentityNotRecomputed,
            ],
            ProofProvider::local(ProofKind::CanonicalRules),
            [
                "Size, DAG relation (uniqueness, acyclicity, parent resolution, roots), \
                 seal-reference and anchor-binding rules hold, but node identifiers and \
                 the segment root were supplied rather than recomputed from contents, so \
                 canonical order and root commitment were not checked \
                 (PAR-DAG-001, PAR-DAG-002)"
                    .to_string(),
            ],
        ),
    }
}

/// Whether canonical DAG identity is recomputed for a structure reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DagIdentityRule {
    /// Recompute node identifiers and the segment root from node contents.
    Recompute,
    /// Take them as supplied and report the gap.
    ///
    /// The runtime's chain adapters still choose node identifiers and the segment
    /// root when they build a bundle from live chain state, so recomputing on that
    /// path would reject every real transfer. PAR-DAG-001 and PAR-DAG-002 own
    /// making it recomputable; this variant exists so the report states the gap
    /// instead of papering over it.
    Deferred,
}

/// Transition-semantics reading.
///
/// A verified domain binding is real but partial: resolving each consumed state
/// reference against its parent output is PAR-STATE-003's work and is not
/// implemented, so this dimension stops at `Indeterminate` no matter what a
/// provider asserts. That is the point — no caller-supplied attestation can
/// upgrade a dimension whose evidence does not exist yet.
fn transition_semantics_reading(
    binding: Result<()>,
    transfer_binding: ChainNativeClaimReading<'_>,
) -> DimensionAssurance {
    if let Err(e) = binding {
        return not_satisfied(
            ProtocolAssuranceDimension::TransitionSemantics,
            ProtocolReasonCode::DomainBindingMismatch,
            ProofKind::CanonicalRules,
            e.to_string(),
        );
    }
    if let ChainNativeClaimReading::Rejected(attestation) = transfer_binding {
        return DimensionAssurance::new(
            ProtocolAssuranceDimension::TransitionSemantics,
            DimensionStatus::NotSatisfied,
            [ProtocolReasonCode::DomainBindingMismatch],
            attestation.provider(ProofKind::CanonicalRules),
            [format!(
                "{} rejected the proof's binding to the transfer{}",
                attestation.provider_id,
                attestation
                    .detail
                    .as_ref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            )],
        );
    }
    let provider = match transfer_binding {
        ChainNativeClaimReading::Attested(attestation) => {
            attestation.provider(ProofKind::CanonicalRules)
        }
        _ => ProofProvider::local(ProofKind::CanonicalRules),
    };
    DimensionAssurance::new(
        ProtocolAssuranceDimension::TransitionSemantics,
        DimensionStatus::Indeterminate,
        [
            ProtocolReasonCode::TransitionBindingVerified,
            ProtocolReasonCode::ConsumedStateResolutionUnavailable,
        ],
        provider,
        [
            "The bundle is bound to the transfer the context names, and consumed-state \
             resolution is implemented, but this V1 bundle supplies no parent-output \
             history to resolve against, so transition semantics remain undecided"
                .to_string(),
        ],
    )
}

/// Authorization reading.
///
/// Signatures that verify only against sender-chosen keys prove a tautology:
/// whoever picked the embedded public key also signed with its private key. That
/// is `Indeterminate`, not `Satisfied` — binding to an approved verifier set is
/// what makes the dimension conclusive (VERIFY-SIGNER-BINDING-001).
fn authorization_reading(
    bundle: &ProofBundle,
    scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
) -> DimensionAssurance {
    if bundle.signatures.is_empty() {
        return not_satisfied(
            ProtocolAssuranceDimension::Authorization,
            ProtocolReasonCode::SignaturesAbsent,
            ProofKind::DigitalSignature,
            "proof bundle carries no signatures".to_string(),
        );
    }
    if let Err(e) = verify_bundle_signatures(bundle, scheme, authorized_signers) {
        return not_satisfied(
            ProtocolAssuranceDimension::Authorization,
            ProtocolReasonCode::SignatureInvalid,
            ProofKind::DigitalSignature,
            e.to_string(),
        );
    }
    if authorized_signers.is_empty() {
        return DimensionAssurance::new(
            ProtocolAssuranceDimension::Authorization,
            DimensionStatus::Indeterminate,
            [
                ProtocolReasonCode::SignaturesVerified,
                ProtocolReasonCode::SignerSetUnbound,
            ],
            ProofProvider::local(ProofKind::DigitalSignature),
            [
                "Signatures verify against keys the sender chose; no approved verifier set \
                 was supplied to bind them to an authorized signer"
                    .to_string(),
            ],
        );
    }
    DimensionAssurance::new(
        ProtocolAssuranceDimension::Authorization,
        DimensionStatus::Satisfied,
        [ProtocolReasonCode::SignaturesVerified],
        ProofProvider::local(ProofKind::DigitalSignature),
        [format!(
            "Every signature verified against one of {} approved verifier keys",
            authorized_signers.len()
        )],
    )
}

/// Anchor-inclusion reading.
///
/// Nonempty, well-formed proof bytes are structure, not inclusion. Without a
/// named chain-native provider this dimension is `Indeterminate`, which is what
/// stops proof bytes alone from reaching a full-verification claim.
fn inclusion_reading(
    proof: &csv_protocol::proof_taxonomy::InclusionProof,
    anchor_ref: &csv_hash::seal::CommitAnchor,
    assessment: &ChainNativeProofAssessment,
) -> DimensionAssurance {
    if anchor_ref.anchor_id.is_empty() {
        return not_satisfied(
            ProtocolAssuranceDimension::AnchorInclusion,
            ProtocolReasonCode::InclusionProofMalformed,
            ProofKind::MerkleInclusion,
            "anchor_id is empty".to_string(),
        );
    }
    if let Err(e) = validate_inclusion_proof(proof) {
        return not_satisfied(
            ProtocolAssuranceDimension::AnchorInclusion,
            ProtocolReasonCode::InclusionProofMalformed,
            ProofKind::MerkleInclusion,
            e.to_string(),
        );
    }
    match assessment.reading(ChainNativeClaim::AnchorInclusion) {
        ChainNativeClaimReading::Rejected(attestation) => DimensionAssurance::new(
            ProtocolAssuranceDimension::AnchorInclusion,
            DimensionStatus::NotSatisfied,
            [ProtocolReasonCode::InclusionRejectedByProvider],
            attestation.provider(ProofKind::MerkleInclusion),
            [format!(
                "{} rejected the inclusion material{}",
                attestation.provider_id,
                attestation
                    .detail
                    .as_ref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            )],
        ),
        ChainNativeClaimReading::Attested(attestation) => DimensionAssurance::new(
            ProtocolAssuranceDimension::AnchorInclusion,
            DimensionStatus::Satisfied,
            [ProtocolReasonCode::InclusionAttestedByProvider],
            attestation.provider(ProofKind::MerkleInclusion),
            [format!(
                "Inclusion was asserted by {} against {}; the pure verifier did not \
                 recompute it and cannot, having no chain access",
                attestation.provider_id, attestation.chain_id
            )],
        ),
        ChainNativeClaimReading::Absent => DimensionAssurance::new(
            ProtocolAssuranceDimension::AnchorInclusion,
            DimensionStatus::Indeterminate,
            [ProtocolReasonCode::InclusionNotCryptographicallyVerified],
            ProofProvider::unverified(ProofKind::MerkleInclusion),
            [
                "The inclusion proof is well formed, which is not evidence that the anchor \
                 is in the chain; no chain-native provider verified it"
                    .to_string(),
            ],
        ),
    }
}

/// Finality/checkpoint reading.
fn finality_reading(
    proof: &csv_protocol::proof_taxonomy::FinalityProof,
    anchor_height: u64,
    required_confirmations: u64,
    observed_tip: Option<u64>,
    assessment: &ChainNativeProofAssessment,
) -> DimensionAssurance {
    if let Err(e) = validate_finality_proof(proof) {
        return not_satisfied(
            ProtocolAssuranceDimension::FinalityCheckpoint,
            ProtocolReasonCode::FinalityProofMalformed,
            ProofKind::ConfirmationDepth,
            e.to_string(),
        );
    }
    if let ChainNativeClaimReading::Rejected(attestation) =
        assessment.reading(ChainNativeClaim::CheckpointFinality)
    {
        return DimensionAssurance::new(
            ProtocolAssuranceDimension::FinalityCheckpoint,
            DimensionStatus::NotSatisfied,
            [ProtocolReasonCode::CheckpointRejectedByProvider],
            attestation.provider(ProofKind::ConfirmationDepth),
            [format!(
                "{} rejected the finality material{}",
                attestation.provider_id,
                attestation
                    .detail
                    .as_ref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            )],
        );
    }
    if let Some(tip) = observed_tip {
        let confirmations = tip.saturating_sub(anchor_height);
        if confirmations < required_confirmations {
            return not_satisfied(
                ProtocolAssuranceDimension::FinalityCheckpoint,
                ProtocolReasonCode::ConfirmationDepthNotMet,
                ProofKind::ConfirmationDepth,
                format!("{confirmations} confirmations, need {required_confirmations}"),
            );
        }
    }
    match (
        assessment.reading(ChainNativeClaim::CheckpointFinality),
        observed_tip,
    ) {
        (ChainNativeClaimReading::Attested(attestation), _) => DimensionAssurance::new(
            ProtocolAssuranceDimension::FinalityCheckpoint,
            DimensionStatus::Satisfied,
            [ProtocolReasonCode::CheckpointAttestedByProvider],
            attestation.provider(ProofKind::ConfirmationDepth),
            [format!(
                "Checkpoint finality was asserted by {} against {}; trust in this reading \
                 is trust in that provider's chain view",
                attestation.provider_id, attestation.chain_id
            )],
        ),
        (_, Some(tip)) => DimensionAssurance::new(
            ProtocolAssuranceDimension::FinalityCheckpoint,
            DimensionStatus::Satisfied,
            [ProtocolReasonCode::CheckpointAttestedByProvider],
            ProofProvider::attested(OBSERVED_TIP_PROVIDER_ID, None, ProofKind::ConfirmationDepth),
            [format!(
                "Depth was recomputed against a context-supplied observed tip ({tip}); the \
                 tip itself is an input this verifier cannot check"
            )],
        ),
        (_, None) => DimensionAssurance::new(
            ProtocolAssuranceDimension::FinalityCheckpoint,
            DimensionStatus::Indeterminate,
            [ProtocolReasonCode::CheckpointUnobserved],
            ProofProvider::unverified(ProofKind::ConfirmationDepth),
            [
                "No observed source-chain tip and no provider checkpoint, so confirmation \
                 depth could not be established"
                    .to_string(),
            ],
        ),
    }
}

/// Identifier reported when a reading rests on a context-supplied chain observation.
const OBSERVED_TIP_PROVIDER_ID: &str = "context.observed-source-tip";

/// Source-closure reading.
///
/// A local replay database answers "did *I* already see this seal spent?", which
/// is strictly weaker than "does a shared ordering make this successor unique?".
/// Conflating the two is the inflation this ticket exists to remove, so a clean
/// registry is `Indeterminate` with the gap stated, never `Satisfied`. Stage 2
/// (PAR-BTC-002) grounds closure on Bitcoin and can raise it.
fn source_closure_reading(replay: Option<bool>) -> DimensionAssurance {
    match replay {
        Some(true) => DimensionAssurance::new(
            ProtocolAssuranceDimension::SourceClosure,
            DimensionStatus::NotSatisfied,
            [ProtocolReasonCode::ReplayDetected],
            ProofProvider::local(ProofKind::ReplayRegistry),
            ["The source seal is already recorded as consumed".to_string()],
        ),
        Some(false) => DimensionAssurance::new(
            ProtocolAssuranceDimension::SourceClosure,
            DimensionStatus::Indeterminate,
            [
                ProtocolReasonCode::ReplayRegistryClean,
                ProtocolReasonCode::SourceClosureNotExternallyGrounded,
            ],
            ProofProvider::local(ProofKind::ReplayRegistry),
            [
                "A local replay registry is not a shared ordering: it shows this holder has \
                 not seen a conflicting spend, not that none exists (PAR-BTC-002)"
                    .to_string(),
            ],
        ),
        None => DimensionAssurance::new(
            ProtocolAssuranceDimension::SourceClosure,
            DimensionStatus::Indeterminate,
            [
                ProtocolReasonCode::ReplayRegistryAbsent,
                ProtocolReasonCode::SourceClosureNotExternallyGrounded,
            ],
            ProofProvider::unverified(ProofKind::SourceSealClosure),
            [
                "No replay registry was supplied and closure is not grounded on a shared \
                 ordering, so uniqueness of this successor is unknown (PAR-BTC-002)"
                    .to_string(),
            ],
        ),
    }
}

/// Freshness reading (VERIFY-PROOF-FRESHNESS-001).
///
/// Height-based, not wall-clock: a bundle carries no trusted timestamp, but an
/// anchor height plus an observed tip give a deterministic age in blocks.
fn freshness_reading(
    anchor_height: u64,
    observed_tip: Option<u64>,
    max_anchor_age_blocks: Option<u64>,
) -> DimensionAssurance {
    match (observed_tip, max_anchor_age_blocks) {
        (Some(tip), Some(max_age)) => {
            if tip == u64::MAX {
                return DimensionAssurance::new(
                    ProtocolAssuranceDimension::Freshness,
                    DimensionStatus::NotApplicable,
                    [ProtocolReasonCode::FreshnessNotMeasuredInBlocks],
                    ProofProvider::attested(
                        OBSERVED_TIP_PROVIDER_ID,
                        None,
                        ProofKind::ObservedChainTip,
                    ),
                    [
                        "The chain reports instant finality, so anchor age is not measured \
                         in blocks and no staleness bound applies"
                            .to_string(),
                    ],
                );
            }
            let Some(age) = tip.checked_sub(anchor_height) else {
                return not_satisfied(
                    ProtocolAssuranceDimension::Freshness,
                    ProtocolReasonCode::FreshnessContextIncomplete,
                    ProofKind::ObservedChainTip,
                    format!("observed source tip {tip} is below anchor height {anchor_height}"),
                );
            };
            if age > max_age {
                return not_satisfied(
                    ProtocolAssuranceDimension::Freshness,
                    ProtocolReasonCode::AnchorStale,
                    ProofKind::ObservedChainTip,
                    format!("anchor is {age} blocks below tip, exceeds max age {max_age}"),
                );
            }
            DimensionAssurance::new(
                ProtocolAssuranceDimension::Freshness,
                DimensionStatus::Satisfied,
                [ProtocolReasonCode::WithinMaxAnchorAge],
                ProofProvider::attested(
                    OBSERVED_TIP_PROVIDER_ID,
                    None,
                    ProofKind::ObservedChainTip,
                ),
                [format!(
                    "Anchor is {age} blocks below a context-supplied tip, within the \
                     configured bound of {max_age}"
                )],
            )
        }
        // A bound with nothing to measure against, or a tip with no bound to
        // measure it by, is an unknown — not a pass. The scalar pipeline treated a
        // half-supplied pair as a hard error and a missing bound as silent success;
        // both told the caller less than this reading does.
        (None, Some(_)) => DimensionAssurance::new(
            ProtocolAssuranceDimension::Freshness,
            DimensionStatus::Indeterminate,
            [ProtocolReasonCode::FreshnessContextIncomplete],
            ProofProvider::unverified(ProofKind::ObservedChainTip),
            [
                "A maximum anchor age is configured but no source-chain tip was observed, \
                 so the anchor's age is unknown"
                    .to_string(),
            ],
        ),
        (_, None) => DimensionAssurance::new(
            ProtocolAssuranceDimension::Freshness,
            DimensionStatus::Indeterminate,
            [ProtocolReasonCode::FreshnessBoundNotConfigured],
            ProofProvider::unverified(ProofKind::ObservedChainTip),
            [
                "No freshness bound is configured, so replay of an old but otherwise valid \
                 proof cannot be excluded"
                    .to_string(),
            ],
        ),
    }
}

/// Verify a proof bundle offline, reporting what the bundle alone establishes.
///
/// This is the **primary entry point for offline proof verification**. It applies
/// every check that is possible without chain access and reports each dimension
/// separately.
///
/// # What an offline verifier can and cannot establish
///
/// It recomputes canonical structure, signature validity, approved-signer binding
/// and — when the caller supplies an observed tip — freshness. It cannot
/// recompute anchor inclusion, checkpoint finality, or source closure: those need
/// a chain view it does not have, and they are reported as `Indeterminate` rather
/// than assumed. Evaluate the report against
/// [`AssuranceRequirement::OFFLINE_RECIPIENT`](crate::assurance::AssuranceRequirement::OFFLINE_RECIPIENT)
/// and surface its accepted limitations to whoever is deciding to accept.
///
/// # Security requirements preserved from the scalar pipeline
///
/// 1. **All signatures must be valid** — an invalid signature is `NotSatisfied`.
/// 2. **Signatures must bind to an approved verifier set** — an empty set leaves
///    authorization `Indeterminate`, which every shipped policy rejects.
/// 3. **Empty inclusion/finality proofs are rejected**.
/// 4. **Insufficient confirmations are rejected**.
/// 5. **A stale anchor is rejected** when the caller supplies freshness inputs.
/// 6. **Oversized bundles are rejected** before any further work.
/// 7. **Domain separation is enforced** against the caller's expected domain.
pub fn verify_proof(
    bundle: &ProofBundle,
    seal_registry: impl Fn(&[u8]) -> bool,
    signature_scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
) -> ProtocolAssuranceReport {
    // No expected-domain binding for callers that only inspect a proof. The
    // authoritative offline accept path uses `verify_proof_bound` below.
    verify_proof_bound(
        bundle,
        seal_registry,
        signature_scheme,
        authorized_signers,
        &ExpectedDomain::default(),
    )
}

/// Offline proof verification with explicit expected-domain binding
/// (VERIFY-DOMAIN-SEPARATION-001) and optional caller-supplied freshness data.
///
/// Identical to [`verify_proof`] but additionally binds the bundle to the caller's
/// trusted `ExpectedDomain` (Sanad id and/or source chain). The recipient accept
/// path builds `expected` from the invoice/consignment it trusts and thereby
/// rejects a bundle that does not match the transfer it intends to accept.
///
/// Offline verification cannot discover a live source-chain tip by itself. When
/// `expected.observed_source_tip` and `expected.max_anchor_age_blocks` are both
/// populated, the freshness dimension is decided against them; otherwise it is
/// reported as `Indeterminate` and the caller is told so.
pub fn verify_proof_bound(
    bundle: &ProofBundle,
    seal_registry: impl Fn(&[u8]) -> bool,
    signature_scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
    expected: &ExpectedDomain,
) -> ProtocolAssuranceReport {
    let mut builder = ProtocolAssuranceReportBuilder::new(offline_context_digest(
        signature_scheme,
        authorized_signers,
        expected,
    ));

    let structure = structure_reading(bundle, MAX_PROOF_BUNDLE_SIZE, DagIdentityRule::Recompute);
    record_dimension_error(&mut builder, &structure);
    builder.record(structure);

    let semantics = transition_semantics_reading(
        validate_expected_domain(bundle, expected),
        ChainNativeClaimReading::Absent,
    );
    record_dimension_error(&mut builder, &semantics);
    builder.record(semantics);

    let authorization = authorization_reading(bundle, signature_scheme, authorized_signers);
    record_dimension_error(&mut builder, &authorization);
    builder.record(authorization);

    // Offline: no chain-native provider exists, so inclusion and finality report
    // exactly what the bundle's own bytes support and no more.
    let inclusion = inclusion_reading(
        &bundle.inclusion_proof,
        &bundle.anchor_ref,
        &ChainNativeProofAssessment::NotSupplied,
    );
    record_dimension_error(&mut builder, &inclusion);
    builder.record(inclusion);

    let finality = finality_reading(
        &bundle.finality_proof,
        bundle.anchor_ref.block_height,
        MIN_REQUIRED_CONFIRMATIONS,
        expected.observed_source_tip,
        &ChainNativeProofAssessment::NotSupplied,
    );
    record_dimension_error(&mut builder, &finality);
    builder.record(finality);

    let closure = source_closure_reading(Some(seal_registry(bundle.seal_ref.id.as_ref())));
    record_dimension_error(&mut builder, &closure);
    builder.record(closure);

    let freshness = freshness_reading(
        bundle.anchor_ref.block_height,
        expected.observed_source_tip,
        expected.max_anchor_age_blocks,
    );
    record_dimension_error(&mut builder, &freshness);
    builder.record(freshness);

    builder.build()
}

/// Digest of everything the offline path treats as its effective context.
fn offline_context_digest(
    signature_scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
    expected: &ExpectedDomain,
) -> Hash {
    ContextDigestWriter::new(OFFLINE_VERIFICATION_PROFILE_ID)
        .u64("signature_scheme", signature_scheme_tag(signature_scheme))
        .byte_list("authorized_signers", authorized_signers)
        .opt_bytes(
            "expected.sanad_id",
            expected.sanad_id.as_ref().map(|id| id.as_slice()),
        )
        .opt_bytes(
            "expected.source_chain",
            expected.source_chain.as_deref().map(str::as_bytes),
        )
        .opt_u64("expected.observed_source_tip", expected.observed_source_tip)
        .opt_u64(
            "expected.max_anchor_age_blocks",
            expected.max_anchor_age_blocks,
        )
        .u64("config.max_proof_bundle_size", MAX_PROOF_BUNDLE_SIZE as u64)
        .u64(
            "config.min_required_confirmations",
            MIN_REQUIRED_CONFIRMATIONS,
        )
        .finish()
}

/// Bind a bundle to the caller's trusted expected domain.
fn validate_expected_domain(bundle: &ProofBundle, expected: &ExpectedDomain) -> Result<()> {
    if let Some(expected_sanad) = &expected.sanad_id
        && bundle.anchor_ref.anchor_id.as_slice() != expected_sanad.as_slice()
    {
        return Err(ProtocolError::Generic(
            "Domain binding failed: proof anchor does not match the expected Sanad".to_string(),
        ));
    }
    if let Some(expected_source) = &expected.source_chain
        && !bundle.inclusion_proof.source.is_empty()
        && &bundle.inclusion_proof.source != expected_source
    {
        return Err(ProtocolError::Generic(format!(
            "Domain binding failed: proof source chain '{}' does not match expected '{}'",
            bundle.inclusion_proof.source, expected_source
        )));
    }
    Ok(())
}

/// Validate proof bundle size against a configured bound (VERIFY-VALIDATIONS-DISABLED-001).
///
/// # Security
/// - Prevents memory exhaustion from oversized proofs
/// - Limits network bandwidth consumption
fn validate_proof_bundle_size_with(bundle: &ProofBundle, max_bundle_size: usize) -> Result<()> {
    // Estimate size by summing all components
    let mut total_size: usize = 0;

    // DAG segment size
    total_size += bundle.transition_dag.root_commitment.as_bytes().len();
    for node in &bundle.transition_dag.nodes {
        total_size += node.node_id.as_bytes().len();
        total_size += node.bytecode.len();
        total_size += node.witnesses.len();
        for sig in &node.signatures {
            total_size += sig.len();
        }
        for parent in &node.parents {
            total_size += parent.as_bytes().len();
        }
    }

    // Signatures size
    for sig in &bundle.signatures {
        total_size += sig.len();
    }

    // Seal and anchor references
    total_size += bundle.seal_ref.id.len();
    total_size += bundle.anchor_ref.anchor_id.len();
    total_size += bundle.anchor_ref.metadata.len();

    // Proof data
    total_size += bundle.inclusion_proof.proof_bytes.len();
    total_size += bundle.finality_proof.finality_data.len();

    if total_size > max_bundle_size {
        return Err(ProtocolError::Generic(format!(
            "Proof bundle too large: {} bytes (max {})",
            total_size, max_bundle_size
        )));
    }

    Ok(())
}

/// Expected chain/transfer identifiers a proof bundle must be bound to, for the
/// offline accept path (VERIFY-DOMAIN-SEPARATION-001).
///
/// The runtime path uses the full [`VerificationContext`]; offline callers build
/// this smaller struct from the invoice/consignment they already trust. `None`
/// fields are not enforced, but the accept path must supply at least the Sanad
/// binding and fail closed if it cannot.
#[derive(Debug, Clone, Default)]
pub struct ExpectedDomain {
    /// Expected Sanad id (bound to the bundle's `anchor_ref.anchor_id`).
    pub sanad_id: Option<[u8; 32]>,
    /// Expected source-chain tag (compared to the bundle's proof `source` when set).
    pub source_chain: Option<String>,
    /// Caller-supplied observed source-chain tip for offline freshness checks.
    pub observed_source_tip: Option<u64>,
    /// Maximum allowed anchor age, in blocks below `observed_source_tip`.
    pub max_anchor_age_blocks: Option<u64>,
}

/// Bind a proof bundle to the transfer/domain it is being verified for
/// (VERIFY-DOMAIN-SEPARATION-001).
///
/// Prevents cross-domain replay: a bundle built for one transfer (Sanad / source
/// chain) must not verify under a context for another. Uses identifiers the
/// production adapters bind reliably and unambiguously:
///
/// - `anchor_ref.anchor_id == sanad_id` — the primary binding. Both the context
///   value and the adapter-set `anchor_id` derive from the same `transfer.sanad_id`
///   (see the Bitcoin adapter's `build_inclusion_proof`), so there is no
///   encoding/byte-order ambiguity.
/// - `inclusion_proof.source == chain_id` — defense in depth, enforced only when
///   the bundle carries a non-empty source tag (not yet mandatory in every adapter
///   build path, so an empty tag is not treated as a mismatch).
///
/// The `seal_ref` lock-outpoint binding is intentionally NOT enforced here: the
/// lock txid crosses a display/internal byte-order boundary between the transfer
/// record and the seal reference, so a naive equality check would reject valid
/// bundles. That binding is a follow-up once the byte order is normalized.
fn validate_context_binding(bundle: &ProofBundle, context: &VerificationContext) -> Result<()> {
    if let Some(sanad_id) = &context.sanad_id
        && bundle.anchor_ref.anchor_id.as_slice() != sanad_id.as_bytes()
    {
        return Err(ProtocolError::Generic(
            "Domain binding failed: proof anchor does not match the expected Sanad".to_string(),
        ));
    }

    if !bundle.inclusion_proof.source.is_empty()
        && !context.chain_id.is_empty()
        && bundle.inclusion_proof.source != context.chain_id
    {
        return Err(ProtocolError::Generic(format!(
            "Domain binding failed: proof source chain '{}' does not match expected '{}'",
            bundle.inclusion_proof.source, context.chain_id
        )));
    }

    Ok(())
}

/// Validate inclusion proof structure.
///
/// # Security
/// - Rejects empty proofs
/// - Validates proof structure before chain-specific verification
fn validate_inclusion_proof(proof: &csv_protocol::proof_taxonomy::InclusionProof) -> Result<()> {
    // Check for empty proof
    if proof.proof_bytes.is_empty() {
        return Err(ProtocolError::InclusionProofFailed(
            "Empty inclusion proof".to_string(),
        ));
    }

    // Validate proof size (prevent DoS via oversized proofs)
    if proof.proof_bytes.len() > csv_protocol::proof_taxonomy::MAX_PROOF_BYTES {
        return Err(ProtocolError::InclusionProofFailed(format!(
            "Inclusion proof too large: {} bytes (max {})",
            proof.proof_bytes.len(),
            csv_protocol::proof_taxonomy::MAX_PROOF_BYTES
        )));
    }

    // Validate block hash is not zero (indicates malformed proof)
    if proof.block_hash == csv_hash::Hash::zero() {
        return Err(ProtocolError::InclusionProofFailed(
            "Invalid inclusion proof: block hash is zero".to_string(),
        ));
    }

    Ok(())
}

/// Validate finality proof structure.
///
/// # Security
/// - Enforces minimum confirmation count
/// - Validates finality data is present
fn validate_finality_proof(proof: &csv_protocol::proof_taxonomy::FinalityProof) -> Result<()> {
    // Enforce minimum confirmation count
    if proof.confirmations < MIN_REQUIRED_CONFIRMATIONS {
        return Err(ProtocolError::FinalityNotReached(format!(
            "Insufficient confirmations: {} (minimum required: {})",
            proof.confirmations, MIN_REQUIRED_CONFIRMATIONS
        )));
    }

    // Validate finality data is present (non-empty for security)
    if proof.finality_data.is_empty() {
        return Err(ProtocolError::FinalityNotReached(
            "Empty finality proof".to_string(),
        ));
    }

    // Validate finality data size
    if proof.finality_data.len() > csv_protocol::proof_taxonomy::MAX_FINALITY_DATA {
        return Err(ProtocolError::FinalityNotReached(format!(
            "Finality proof too large: {} bytes (max {})",
            proof.finality_data.len(),
            csv_protocol::proof_taxonomy::MAX_FINALITY_DATA
        )));
    }

    Ok(())
}

/// Validate anchor reference integrity.
///
/// # Security
/// - Ensures anchor data integrity
/// - Validates consistency between seal and anchor
fn validate_anchor_reference(bundle: &ProofBundle) -> Result<()> {
    // Verify anchor block height is reasonable (not 0, not absurdly high)
    if bundle.anchor_ref.block_height == 0 {
        return Err(ProtocolError::Generic(
            "Invalid anchor: block height is 0".to_string(),
        ));
    }

    if bundle.anchor_ref.block_height != bundle.inclusion_proof.block_number {
        return Err(ProtocolError::InclusionProofFailed(
            "anchor height does not match inclusion proof block".to_string(),
        ));
    }

    if bundle.anchor_ref.metadata.is_empty()
        || bundle.anchor_ref.metadata != bundle.inclusion_proof.proof_bytes
    {
        return Err(ProtocolError::InclusionProofFailed(
            "anchor metadata does not bind the inclusion proof".to_string(),
        ));
    }

    Ok(())
}

/// Verify all signatures in a proof bundle.
///
/// This function performs **cryptographic signature verification** on all
/// signatures in the bundle. It is a critical security check that ensures
/// the proof was authorized by the sanadful owner(s).
///
/// # Signature Format
///
/// Each signature is encoded as:
/// ```text
/// [public_key_length: 4 bytes LE] [public_key: pk_len bytes] [signature: remaining bytes]
/// ```
///
/// The signed message is the DAG root commitment hash.
///
/// # Security Requirements
/// - MUST verify all signatures (not just first one)
/// - MUST use correct signature scheme for the chain
/// - MUST fail if any signature is invalid
/// - MUST parse signature format robustly
///
/// # Arguments
/// * `bundle` - The proof bundle containing signatures to verify
/// * `scheme` - The signature scheme (Secp256k1 or Ed25519)
///
/// # Returns
/// - `Ok(())` - All signatures are valid
/// - `Err(ProtocolError::SignatureVerificationFailed)` - If any signature invalid
///
/// # Audit Note
///
/// Verify that:
/// 1. The signature parsing correctly handles variable-length public keys
/// 2. The message being verified is the correct DAG root commitment
/// 3. No signature is skipped during verification
/// 4. The scheme matches the chain's expected signature type
fn verify_bundle_signatures(
    bundle: &ProofBundle,
    scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
) -> Result<()> {
    // Check we have signatures
    if bundle.signatures.is_empty() {
        return Err(ProtocolError::SignatureVerificationFailed(
            "No signatures in proof bundle".to_string(),
        ));
    }

    // For each signature in the bundle, verify it
    //
    // The signature format is:
    // [public_key_length (4 bytes LE)] [public_key] [signature_bytes]
    // The message is the DAG root commitment hash.
    //
    // VERIFY-SIGNER-BINDING-001: the public key embedded in the blob is chosen by
    // the sender and proves nothing about authorization on its own. When
    // `authorized_signers` is non-empty we additionally require every embedded key
    // to be a member of the approved verifier set (RFC-0012 §9) and fail closed
    // otherwise, so a bundle signed by an attacker-chosen key cannot verify.
    let authorized_canonical: Vec<Vec<u8>> = authorized_signers
        .iter()
        .map(|k| canonical_public_key(k, scheme))
        .collect();

    let mut signatures = Vec::with_capacity(bundle.signatures.len());

    for (i, sig_bytes) in bundle.signatures.iter().enumerate() {
        // Parse signature format: [pk_len (4)] [public_key] [signature]
        let sig_bytes: &[u8] = sig_bytes;
        if sig_bytes.len() < 4 {
            return Err(ProtocolError::SignatureVerificationFailed(format!(
                "Signature {} too short for header",
                i
            )));
        }

        // Extract public key length (little-endian u32)
        let pk_len =
            u32::from_le_bytes([sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3]]) as usize;

        if sig_bytes.len() < 4 + pk_len {
            return Err(ProtocolError::SignatureVerificationFailed(format!(
                "Signature {} too short for public key",
                i
            )));
        }

        let public_key = sig_bytes[4..4 + pk_len].to_vec();
        let signature = sig_bytes[4 + pk_len..].to_vec();

        // Fail closed if the recovered key is not in the approved verifier set.
        // Compare in canonical form so compressed/uncompressed secp256k1 encodings
        // of the same key still match.
        if !authorized_canonical.is_empty() {
            let candidate = canonical_public_key(&public_key, scheme);
            if !authorized_canonical.iter().any(|k| k == &candidate) {
                return Err(ProtocolError::SignatureVerificationFailed(format!(
                    "Signature {} public key is not in the approved verifier set",
                    i
                )));
            }
        }

        // The signed message is the DAG root commitment
        let message = bundle.transition_dag.root_commitment.as_bytes().to_vec();

        signatures.push(Signature::new(signature, public_key, message));
    }

    // Verify all signatures
    verify_signatures(&signatures, scheme)
}

/// Reduce a public key to a canonical byte form for set-membership comparison.
///
/// secp256k1 keys are normalized to their 33-byte compressed serialization so a
/// compressed and uncompressed encoding of the same key compare equal; any bytes
/// that do not parse as a valid key (and all other schemes, e.g. ed25519) are
/// returned unchanged for an exact byte comparison.
fn canonical_public_key(key: &[u8], scheme: SignatureScheme) -> Vec<u8> {
    match scheme {
        SignatureScheme::Secp256k1 => match secp256k1::PublicKey::from_slice(key) {
            Ok(pk) => pk.serialize().to_vec(),
            Err(_) => key.to_vec(),
        },
        _ => key.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assurance::{
        AssuranceRequirement, ChainNativeProofAttestation, DimensionRequirement, TrustMode,
    };
    use csv_hash::Hash;
    use csv_hash::dag::{DAGNode, DAGSegment};
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};
    use csv_protocol::signature::SignatureScheme;
    use csv_protocol::verification_levels::VerificationLevel;

    // Deterministic key so tests can build the approved-signer set now required
    // by verify_bundle_signatures (VERIFY-SIGNER-BINDING-001).
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Approved verifier set matching `make_ed25519_signature_bytes`'s signer.
    fn authorized() -> Vec<Vec<u8>> {
        vec![test_signing_key().verifying_key().to_bytes().to_vec()]
    }

    /// Status of one dimension in a report.
    fn status(
        report: &ProtocolAssuranceReport,
        dimension: ProtocolAssuranceDimension,
    ) -> DimensionStatus {
        report.reading(dimension).status
    }

    /// Whether a report carries a reason code on a dimension.
    fn has_reason(
        report: &ProtocolAssuranceReport,
        dimension: ProtocolAssuranceDimension,
        code: ProtocolReasonCode,
    ) -> bool {
        report.reading(dimension).reason_codes.contains(&code)
    }

    /// Does the offline recipient policy accept this report?
    fn offline_accepts(report: &ProtocolAssuranceReport) -> bool {
        AssuranceRequirement::OFFLINE_RECIPIENT
            .evaluate(report)
            .is_met()
    }

    fn make_ed25519_signature_bytes(message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(message);
        // Format: [pk_len (4 bytes LE)] [public_key] [signature]
        let mut encoded = Vec::with_capacity(4 + 32 + 64);
        encoded.extend_from_slice(&32u32.to_le_bytes());
        encoded.extend_from_slice(&verifying_key.to_bytes());
        encoded.extend_from_slice(&signature.to_bytes());
        encoded
    }

    /// A signature blob from a fresh, unauthorized key (the exploit shape).
    fn make_unauthorized_signature_bytes(message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(message);
        let mut encoded = Vec::with_capacity(4 + 32 + 64);
        encoded.extend_from_slice(&32u32.to_le_bytes());
        encoded.extend_from_slice(&verifying_key.to_bytes());
        encoded.extend_from_slice(&signature.to_bytes());
        encoded
    }

    /// A canonical single-node segment (PAR-DAG-001).
    ///
    /// Node identity and segment root are derived from contents, so the root
    /// cannot be chosen and must be sealed before it can be signed. The node
    /// carries no signature of its own: signing the root that commits to the
    /// node holding the signature would be circular, and bundle-level
    /// signatures are what the verifier checks against the root.
    fn canonical_segment() -> DAGSegment {
        DAGSegment::sealed(vec![DAGNode::sealed(
            vec![0x01, 0x02],
            vec![],
            vec![],
            vec![],
        )])
        .expect("canonical single-node segment")
    }

    fn test_bundle_with_signatures() -> Result<ProofBundle> {
        // The message signed is the DAG root commitment.
        let transition_dag = canonical_segment();
        let signature = make_ed25519_signature_bytes(transition_dag.root_commitment.as_bytes());

        let seal_id = vec![1u8, 2, 3];
        let bundle = ProofBundle::new(
            transition_dag,
            vec![signature],
            SealPoint::new(seal_id.clone(), Some(42), None)
                .map_err(|e| ProtocolError::Generic(e.to_string()))?,
            CommitAnchor::new(seal_id, 100, vec![0xCD; 32])
                .map_err(|e| ProtocolError::Generic(e.to_string()))?,
            InclusionProof::new(vec![0xCD; 32], Hash::new([2u8; 32]), 100, 0)
                .map_err(|e| ProtocolError::Generic(e.to_string()))?,
            {
                let mut fp = FinalityProof::new(vec![0xAB; 16], 6, false)
                    .map_err(|e| ProtocolError::Generic(e.to_string()))?;
                fp.block_hash = Hash::new([3u8; 32]); // Set non-zero block hash
                fp
            },
        )
        .map_err(|e| ProtocolError::Generic(e.to_string()))?;
        Ok(bundle)
    }

    /// A runtime context with a named chain-native provider attesting inclusion,
    /// finality and transfer binding — the shape the transfer coordinator builds.
    fn attested_runtime_context() -> VerificationContext {
        VerificationContext {
            chain_id: "bitcoin".to_string(),
            signature_scheme: SignatureScheme::Ed25519,
            required_confirmations: 1,
            current_block_height: Some(200),
            seal_registry: None,
            chain_data: None,
            chain_native_proof: ChainNativeProofAssessment::Attested(
                ChainNativeProofAttestation::new(
                    "test-adapter",
                    "bitcoin",
                    [
                        ChainNativeClaim::AnchorInclusion,
                        ChainNativeClaim::CheckpointFinality,
                        ChainNativeClaim::TransferBinding,
                    ],
                ),
            ),
            sanad_id: None,
            lock_tx: None,
            lock_output_index: None,
            transition_id: None,
            destination_chain: None,
            authorized_signers: authorized(),
        }
    }

    // ==================================================================
    // PAR-VERIFY-001 acceptance criteria
    // ==================================================================

    #[test]
    fn nonempty_proof_bytes_alone_cannot_produce_full_verification() {
        // AC1. A structurally perfect bundle with nonempty inclusion and finality
        // bytes, correctly signed, verified offline. Nothing checked those bytes
        // against a chain, so inclusion, finality and closure must all stay short
        // of Satisfied and no aggregate label may claim full verification.
        let bundle = test_bundle_with_signatures().unwrap();
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());

        assert!(!bundle.inclusion_proof.proof_bytes.is_empty());
        assert!(!bundle.finality_proof.finality_data.is_empty());

        assert_eq!(
            status(&report, ProtocolAssuranceDimension::CanonicalStructure),
            DimensionStatus::Satisfied
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::AnchorInclusion),
            DimensionStatus::Indeterminate,
            "well-formed proof bytes are structure, not inclusion"
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::AnchorInclusion,
            ProtocolReasonCode::InclusionNotCryptographicallyVerified
        ));
        assert_ne!(report.display_level(), VerificationLevel::FullyVerified);
        assert_ne!(report.display_level(), VerificationLevel::ConsensusVerified);
        assert!(
            !AssuranceRequirement::COMPLETE.evaluate(&report).is_met(),
            "no bundle can meet the complete policy while closure is ungrounded"
        );
    }

    #[test]
    fn a_caller_supplied_attestation_cannot_upgrade_every_dimension() {
        // AC2. The old `native_proof_validated: bool` raised the whole bundle to
        // FullyVerified. Its typed replacement raises only the dimensions it names,
        // and cannot reach dimensions whose evidence does not exist yet.
        let bundle = test_bundle_with_signatures().unwrap();
        let report = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());

        assert_eq!(
            status(&report, ProtocolAssuranceDimension::AnchorInclusion),
            DimensionStatus::Satisfied
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::FinalityCheckpoint),
            DimensionStatus::Satisfied
        );
        // Even a provider claiming transfer binding cannot conclude transition
        // semantics (PAR-STATE-003) or source closure (PAR-BTC-002).
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::TransitionSemantics),
            DimensionStatus::Indeterminate
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::SourceClosure),
            DimensionStatus::Indeterminate
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::SourceClosure,
            ProtocolReasonCode::SourceClosureNotExternallyGrounded
        ));
        assert_ne!(report.display_level(), VerificationLevel::FullyVerified);
    }

    #[test]
    fn provider_attested_dimensions_are_never_reported_as_locally_recomputed() {
        // AC2/AC3. A dimension the verifier could not recompute must say who
        // asserted it, so a contextual reading stays visibly contextual.
        let bundle = test_bundle_with_signatures().unwrap();
        let report = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());

        let inclusion = report.reading(ProtocolAssuranceDimension::AnchorInclusion);
        assert_eq!(inclusion.provider.trust_mode, TrustMode::ProviderAttested);
        assert_eq!(inclusion.provider.provider_id, "test-adapter");
        assert_eq!(inclusion.provider.chain_id.as_deref(), Some("bitcoin"));

        let structure = report.reading(ProtocolAssuranceDimension::CanonicalStructure);
        assert_eq!(structure.provider.trust_mode, TrustMode::LocalRecomputation);
        assert_eq!(
            structure.provider.provider_id,
            crate::assurance::CANONICAL_VERIFIER_PROVIDER_ID
        );
    }

    #[test]
    fn every_report_names_its_verification_context_and_a_provider_per_dimension() {
        // AC3.
        let bundle = test_bundle_with_signatures().unwrap();
        let runtime = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());
        let offline = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());

        for report in [&runtime, &offline] {
            assert_ne!(report.verification_context_digest(), Hash::zero());
            assert_eq!(
                report.dimensions().len(),
                crate::assurance::PROTOCOL_ASSURANCE_DIMENSIONS.len()
            );
            for reading in report.dimensions() {
                assert!(
                    !reading.provider.provider_id.is_empty(),
                    "{} has no named provider",
                    reading.dimension.registry_id()
                );
                assert!(
                    !reading.reason_codes.is_empty(),
                    "{} states a conclusion with no reason",
                    reading.dimension.registry_id()
                );
            }
        }
        assert_ne!(
            runtime.verification_context_digest(),
            offline.verification_context_digest(),
            "different pipelines and inputs must not share a context digest"
        );
    }

    #[test]
    fn the_context_digest_changes_when_an_input_changes() {
        // AC3: the digest is only useful if it actually binds the inputs.
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::default();

        let baseline = verifier.verify_proof_bundle(&bundle, &attested_runtime_context());

        let mut deeper = attested_runtime_context();
        deeper.required_confirmations += 1;
        let deeper = verifier.verify_proof_bundle(&bundle, &deeper);

        let mut unattested = attested_runtime_context();
        unattested.chain_native_proof = ChainNativeProofAssessment::NotSupplied;
        let unattested = verifier.verify_proof_bundle(&bundle, &unattested);

        assert_ne!(
            baseline.verification_context_digest(),
            deeper.verification_context_digest()
        );
        assert_ne!(
            baseline.verification_context_digest(),
            unattested.verification_context_digest()
        );
    }

    #[test]
    fn a_failed_foundational_dimension_cannot_be_hidden_behind_an_aggregate() {
        // AC4. A rejected inclusion attestation must show up in the readings, in
        // the foundational shortfalls, in the policy outcome and in the coarse
        // display label — there is nowhere for it to hide.
        let bundle = test_bundle_with_signatures().unwrap();
        let mut context = attested_runtime_context();
        context.chain_native_proof = ChainNativeProofAssessment::Rejected(
            ChainNativeProofAttestation::new("test-adapter", "bitcoin", [])
                .with_detail("merkle path does not reach the block root"),
        );
        let report = CanonicalVerifierImpl::default().verify_proof_bundle(&bundle, &context);

        assert_eq!(
            status(&report, ProtocolAssuranceDimension::AnchorInclusion),
            DimensionStatus::NotSatisfied
        );
        assert!(
            report
                .foundational_shortfalls()
                .iter()
                .any(|reading| reading.dimension == ProtocolAssuranceDimension::AnchorInclusion)
        );
        let outcome = AssuranceRequirement::RUNTIME_SOURCE_PROOF.evaluate(&report);
        assert!(!outcome.is_met());
        assert!(outcome.shortfall_summary().contains("ANCHOR_INCLUSION"));
        assert_eq!(report.display_level(), VerificationLevel::StructuralOnly);
    }

    #[test]
    fn an_unavailable_foundational_dimension_blocks_the_runtime_policy() {
        // AC4, the "unavailable" half: no provider at all is not the same as a
        // provider that succeeded, and the runtime policy must not accept it.
        let bundle = test_bundle_with_signatures().unwrap();
        let mut context = attested_runtime_context();
        context.chain_native_proof = ChainNativeProofAssessment::NotSupplied;
        context.current_block_height = None;
        let report = CanonicalVerifierImpl::default().verify_proof_bundle(&bundle, &context);

        assert_eq!(
            status(&report, ProtocolAssuranceDimension::AnchorInclusion),
            DimensionStatus::Indeterminate
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::FinalityCheckpoint),
            DimensionStatus::Indeterminate
        );
        let outcome = AssuranceRequirement::RUNTIME_SOURCE_PROOF.evaluate(&report);
        assert!(!outcome.is_met());
        let blocked: Vec<_> = outcome
            .shortfalls
            .iter()
            .map(|entry| entry.dimension)
            .collect();
        assert!(blocked.contains(&ProtocolAssuranceDimension::AnchorInclusion));
        assert!(blocked.contains(&ProtocolAssuranceDimension::FinalityCheckpoint));
    }

    #[test]
    fn accepted_limitations_are_carried_out_of_every_successful_runtime_verification() {
        // AC4. A met policy still hands back what it chose to tolerate, so a caller
        // physically cannot report success without the caveats.
        let bundle = test_bundle_with_signatures().unwrap();
        let report = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());
        let outcome = AssuranceRequirement::RUNTIME_SOURCE_PROOF.evaluate(&report);

        assert!(outcome.is_met(), "{}", outcome.shortfall_summary());
        assert!(
            outcome
                .accepted_limitations
                .iter()
                .any(|entry| entry.dimension == ProtocolAssuranceDimension::SourceClosure),
            "source closure must be surfaced as an accepted limitation"
        );
        assert_eq!(
            outcome.verification_context_digest,
            report.verification_context_digest()
        );
    }

    #[test]
    fn the_runtime_path_reports_that_dag_identity_was_not_recomputed() {
        // The runtime's adapters still supply node identifiers and the segment
        // root (PAR-DAG-001/PAR-DAG-002). That gap is stated on the reading rather
        // than absorbed into a passing structural check.
        let bundle = test_bundle_with_signatures().unwrap();
        let report = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::CanonicalStructure),
            DimensionStatus::Indeterminate
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::DagIdentityNotRecomputed
        ));
        // The offline path does recompute it, and says so.
        let offline = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert_eq!(
            status(&offline, ProtocolAssuranceDimension::CanonicalStructure),
            DimensionStatus::Satisfied
        );
    }

    #[test]
    fn a_malformed_bundle_still_fails_structurally_on_the_runtime_path() {
        // Deferring DAG identity must not defer the rules that do run.
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.transition_dag.nodes.clear();
        let report = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::CanonicalStructure),
            DimensionStatus::NotSatisfied
        );
        assert!(
            !AssuranceRequirement::RUNTIME_SOURCE_PROOF
                .evaluate(&report)
                .is_met()
        );
    }

    #[test]
    fn a_hostile_graph_fails_structurally_even_where_identity_is_deferred() {
        // PAR-DAG-002. The runtime path cannot recompute node identity yet, but
        // a cycle, a self-parenting node, a duplicate identifier and an
        // unresolvable parent are defects in the declared graph itself. Each
        // must come back NotSatisfied — not the Indeterminate that "identity was
        // supplied" earns — or a structural failure would be downgraded to an
        // uncertainty on the one path real transfers take.
        let a = Hash::new([1u8; 32]);
        let b = Hash::new([2u8; 32]);
        let node = |id: Hash, parents: Vec<Hash>| {
            DAGNode::new(id, vec![0x01], vec![vec![0xAB; 8]], vec![], parents)
        };

        let hostile_graphs = [
            ("cycle", vec![node(a, vec![b]), node(b, vec![a])]),
            ("self-parent", vec![node(a, vec![a])]),
            (
                "duplicate identifier",
                vec![node(a, vec![]), node(a, vec![])],
            ),
            ("missing parent", vec![node(a, vec![Hash::new([9u8; 32])])]),
        ];

        for (shape, nodes) in hostile_graphs {
            let mut bundle = test_bundle_with_signatures().unwrap();
            bundle.transition_dag = DAGSegment::new(nodes, bundle.transition_dag.root_commitment);
            let report = CanonicalVerifierImpl::default()
                .verify_proof_bundle(&bundle, &attested_runtime_context());
            assert_eq!(
                status(&report, ProtocolAssuranceDimension::CanonicalStructure),
                DimensionStatus::NotSatisfied,
                "{shape} was not reported as a structural failure"
            );
            assert!(
                !AssuranceRequirement::RUNTIME_SOURCE_PROOF
                    .evaluate(&report)
                    .is_met(),
                "{shape} still met the runtime acceptance policy"
            );
        }
    }

    #[test]
    fn an_adapter_shaped_segment_still_passes_the_relation_rules() {
        // The counterweight to the test above: every chain adapter builds a
        // single parentless node with an adapter-chosen identifier and root.
        // Enforcing the relation rules on the deferred path must not reject it —
        // it stays Indeterminate for the identity it genuinely cannot recompute.
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.transition_dag = DAGSegment::new(
            vec![DAGNode::new(
                Hash::new([7u8; 32]),
                vec![0x01, 0x02],
                vec![vec![0xAB; 8]],
                vec![vec![0xCD; 4]],
                vec![],
            )],
            Hash::new([7u8; 32]),
        );
        let report = CanonicalVerifierImpl::default()
            .verify_proof_bundle(&bundle, &attested_runtime_context());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::CanonicalStructure),
            DimensionStatus::Indeterminate
        );
    }

    #[test]
    fn source_closure_reports_that_it_is_not_externally_grounded() {
        // Stage 1 exit gate: Parwana validates a transition from supplied history
        // while explicitly reporting that closure is not yet externally grounded.
        let bundle = test_bundle_with_signatures().unwrap();
        for report in [
            verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized()),
            CanonicalVerifierImpl::default()
                .verify_proof_bundle(&bundle, &attested_runtime_context()),
        ] {
            assert_ne!(
                status(&report, ProtocolAssuranceDimension::SourceClosure),
                DimensionStatus::Satisfied
            );
            assert!(has_reason(
                &report,
                ProtocolAssuranceDimension::SourceClosure,
                ProtocolReasonCode::SourceClosureNotExternallyGrounded
            ));
        }
    }

    // ==================================================================
    // Behaviour preserved from the scalar pipeline
    // ==================================================================

    #[test]
    fn test_verify_proof_valid() {
        let bundle = test_bundle_with_signatures().unwrap();
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        let outcome = AssuranceRequirement::OFFLINE_RECIPIENT.evaluate(&report);
        assert!(outcome.is_met(), "{}", outcome.shortfall_summary());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Authorization),
            DimensionStatus::Satisfied
        );
    }

    #[test]
    fn verify_proof_rejects_unauthorized_signer() {
        // VERIFY-SIGNER-BINDING-001 exploit regression: a bundle signed by a
        // fresh, attacker-chosen keypair over the DAG root must be REJECTED even
        // though the signature is cryptographically valid for its embedded key,
        // because that key is not in the approved verifier set.
        let message = [0u8; 32];
        let forged = make_unauthorized_signature_bytes(&message);
        let seal_id = vec![1u8, 2, 3];
        let bundle = ProofBundle::new(
            DAGSegment::new(
                vec![DAGNode::new(
                    Hash::new([1u8; 32]),
                    vec![0x01, 0x02],
                    vec![forged.clone()],
                    vec![],
                    vec![],
                )],
                Hash::zero(),
            ),
            vec![forged],
            SealPoint::new(seal_id.clone(), Some(42), None)
                .map_err(|e| ProtocolError::Generic(e.to_string()))
                .unwrap(),
            CommitAnchor::new(seal_id, 100, vec![0xCD; 32])
                .map_err(|e| ProtocolError::Generic(e.to_string()))
                .unwrap(),
            InclusionProof::new(vec![0xCD; 32], Hash::new([2u8; 32]), 100, 0)
                .map_err(|e| ProtocolError::Generic(e.to_string()))
                .unwrap(),
            {
                let mut fp = FinalityProof::new(vec![0xAB; 16], 6, false)
                    .map_err(|e| ProtocolError::Generic(e.to_string()))
                    .unwrap();
                fp.block_hash = Hash::new([3u8; 32]);
                fp
            },
        )
        .map_err(|e| ProtocolError::Generic(e.to_string()))
        .unwrap();
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Authorization),
            DimensionStatus::NotSatisfied,
            "a bundle signed by an unauthorized key must not authorize"
        );
        assert!(!offline_accepts(&report));
    }

    #[test]
    fn verify_proof_rejects_oversized_bundle() {
        // VERIFY-VALIDATIONS-DISABLED-001 regression: the size bound must reject a
        // bundle larger than MAX_PROOF_BUNDLE_SIZE (DoS protection).
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.signatures.push(vec![0u8; MAX_PROOF_BUNDLE_SIZE + 1]);
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::CanonicalStructure),
            DimensionStatus::NotSatisfied
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::CanonicalStructure,
            ProtocolReasonCode::BundleTooLarge
        ));
        assert!(!offline_accepts(&report));
    }

    #[test]
    fn verify_proof_bound_rejects_wrong_expected_sanad() {
        // VERIFY-DOMAIN-SEPARATION-001: a bundle whose anchor binds Sanad A must
        // be rejected when the caller expects Sanad B (cross-domain replay).
        let bundle = test_bundle_with_signatures().unwrap();

        // The test bundle's anchor_id is the seal_id (vec![1,2,3]); an expected
        // Sanad that differs must be rejected.
        let expected = ExpectedDomain {
            sanad_id: Some([0xABu8; 32]),
            source_chain: None,
            observed_source_tip: None,
            max_anchor_age_blocks: None,
        };
        let report = verify_proof_bound(
            &bundle,
            |_| false,
            SignatureScheme::Ed25519,
            &authorized(),
            &expected,
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::TransitionSemantics),
            DimensionStatus::NotSatisfied,
            "a bundle bound to a different Sanad must not verify"
        );
        assert!(!offline_accepts(&report));
    }

    #[test]
    fn trait_path_rejects_bundle_bound_to_other_sanad() {
        // VERIFY-DOMAIN-SEPARATION-001 on the CanonicalVerifierImpl (runtime) path:
        // a context expecting a different Sanad than the bundle's anchor must fail.
        let bundle = test_bundle_with_signatures().unwrap();
        let mut ctx = attested_runtime_context();
        // Anchor id in the test bundle is vec![1,2,3]; a 32-byte mismatch here
        // must be rejected by the context binding step.
        ctx.sanad_id = Some(csv_hash::SanadId(Hash::new([0x11u8; 32])));
        ctx.destination_chain = Some("sui".to_string());
        let report = CanonicalVerifierImpl::default().verify_proof_bundle(&bundle, &ctx);
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::TransitionSemantics),
            DimensionStatus::NotSatisfied,
            "runtime path must reject a bundle whose anchor does not match the context Sanad"
        );
        assert!(
            !AssuranceRequirement::RUNTIME_SOURCE_PROOF
                .evaluate(&report)
                .is_met()
        );
    }

    fn freshness_context(current_height: u64) -> VerificationContext {
        let mut context = attested_runtime_context();
        context.current_block_height = Some(current_height);
        context
    }

    #[test]
    fn stale_anchor_beyond_max_age_is_reported_as_not_fresh() {
        // VERIFY-PROOF-FRESHNESS-001: with a freshness bound configured, an anchor
        // buried more than max_anchor_age_blocks below the observed tip is stale.
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        // tip is 250 blocks above the anchor -> age 250 > 100 -> stale.
        let ctx = freshness_context(bundle.anchor_ref.block_height + 250);
        let report = verifier.verify_proof_bundle(&bundle, &ctx);
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::NotSatisfied
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::Freshness,
            ProtocolReasonCode::AnchorStale
        ));
        assert!(
            !AssuranceRequirement::RUNTIME_SOURCE_PROOF
                .evaluate(&report)
                .is_met(),
            "a NotSatisfied dimension is a shortfall even where the policy tolerates \
             indeterminacy"
        );
    }

    #[test]
    fn fresh_anchor_within_max_age_satisfies_freshness() {
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        // 50 blocks deep: within both the finality floor (1) and freshness cap (100).
        let ctx = freshness_context(bundle.anchor_ref.block_height + 50);
        let report = verifier.verify_proof_bundle(&bundle, &ctx);
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::Satisfied
        );
    }

    #[test]
    fn anchor_exactly_at_max_age_satisfies_freshness() {
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        let ctx = freshness_context(bundle.anchor_ref.block_height + 100);
        let report = verifier.verify_proof_bundle(&bundle, &ctx);
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::Satisfied
        );
    }

    #[test]
    fn freshness_exempts_the_instant_final_sentinel() {
        // u64::MAX confirmations is the "instant-final" sentinel; its age is not
        // measured in blocks, so the dimension is inapplicable rather than stale.
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        let report = verifier.verify_proof_bundle(&bundle, &freshness_context(u64::MAX));
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::NotApplicable
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::Freshness,
            ProtocolReasonCode::FreshnessNotMeasuredInBlocks
        ));
    }

    #[test]
    fn an_unconfigured_freshness_bound_is_reported_as_unknown_not_as_fresh() {
        // The default config leaves freshness off. Under the scalar pipeline that
        // silently passed; now it is an explicit unknown that the report carries.
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::default();
        let report = verifier.verify_proof_bundle(&bundle, &freshness_context(1_000_000));
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::Indeterminate
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::Freshness,
            ProtocolReasonCode::FreshnessBoundNotConfigured
        ));
    }

    #[test]
    fn verify_proof_bound_rejects_stale_anchor_beyond_expected_max_age() {
        let bundle = test_bundle_with_signatures().unwrap();
        let expected = ExpectedDomain {
            observed_source_tip: Some(bundle.anchor_ref.block_height + 101),
            max_anchor_age_blocks: Some(100),
            ..ExpectedDomain::default()
        };

        let report = verify_proof_bound(
            &bundle,
            |_| false,
            SignatureScheme::Ed25519,
            &authorized(),
            &expected,
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::NotSatisfied,
            "offline bound verification must reject anchors older than the configured max age"
        );
        assert!(!offline_accepts(&report));
        assert!(
            report
                .errors()
                .iter()
                .any(|e| e.message.contains("exceeds max age")),
            "stale anchor must surface a typed error, got {:?}",
            report.errors()
        );
    }

    #[test]
    fn verify_proof_bound_accepts_anchor_exactly_at_expected_max_age() {
        let bundle = test_bundle_with_signatures().unwrap();
        let expected = ExpectedDomain {
            observed_source_tip: Some(bundle.anchor_ref.block_height + 100),
            max_anchor_age_blocks: Some(100),
            ..ExpectedDomain::default()
        };

        let report = verify_proof_bound(
            &bundle,
            |_| false,
            SignatureScheme::Ed25519,
            &authorized(),
            &expected,
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::Satisfied
        );
        assert!(offline_accepts(&report));
    }

    #[test]
    fn verify_proof_bound_freshness_exempts_instant_final_sentinel() {
        let bundle = test_bundle_with_signatures().unwrap();
        let expected = ExpectedDomain {
            observed_source_tip: Some(u64::MAX),
            max_anchor_age_blocks: Some(100),
            ..ExpectedDomain::default()
        };

        let report = verify_proof_bound(
            &bundle,
            |_| false,
            SignatureScheme::Ed25519,
            &authorized(),
            &expected,
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Freshness),
            DimensionStatus::NotApplicable
        );
        assert!(offline_accepts(&report));
    }

    #[test]
    fn verify_proof_fails_closed_without_authorized_set() {
        // Signatures that verify only against sender-chosen keys are a tautology.
        // The dimension says so, and every shipped policy refuses it.
        let bundle = test_bundle_with_signatures().unwrap();
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &[]);
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Authorization),
            DimensionStatus::Indeterminate,
            "empty approved verifier set must fail closed"
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::Authorization,
            ProtocolReasonCode::SignerSetUnbound
        ));
        assert!(!offline_accepts(&report));
        assert!(
            !AssuranceRequirement::RUNTIME_SOURCE_PROOF
                .evaluate(&report)
                .is_met()
        );
    }

    #[test]
    fn test_verify_proof_accepts_distinct_seal_and_anchor_ids() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.anchor_ref = CommitAnchor::new(vec![9u8; 32], 100, vec![0xCD; 32])
            .map_err(|e| ProtocolError::Generic(e.to_string()))
            .unwrap();

        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert!(offline_accepts(&report));
    }

    #[test]
    fn test_verify_proof_seal_replay() {
        let bundle = test_bundle_with_signatures().unwrap();
        let report = verify_proof(
            &bundle,
            |seal_id| seal_id == [1, 2, 3],
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::SourceClosure),
            DimensionStatus::NotSatisfied
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::SourceClosure,
            ProtocolReasonCode::ReplayDetected
        ));
        assert!(!offline_accepts(&report));
        assert!(!report.errors().is_empty());
    }

    #[test]
    fn test_verify_proof_no_signatures() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.signatures.clear();
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Authorization),
            DimensionStatus::NotSatisfied
        );
        assert!(has_reason(
            &report,
            ProtocolAssuranceDimension::Authorization,
            ProtocolReasonCode::SignaturesAbsent
        ));
        assert!(!offline_accepts(&report));
    }

    #[test]
    fn test_verify_proof_no_confirmations() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.finality_proof.confirmations = 0;
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::FinalityCheckpoint),
            DimensionStatus::NotSatisfied
        );
        assert!(!offline_accepts(&report));
        assert!(!report.errors().is_empty());
    }

    #[test]
    fn test_verify_proof_invalid_signature_format() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        // Corrupt signature format
        bundle.signatures[0] = vec![0x00, 0x00]; // Too short
        let report = verify_proof(&bundle, |_| false, SignatureScheme::Ed25519, &authorized());
        assert_eq!(
            status(&report, ProtocolAssuranceDimension::Authorization),
            DimensionStatus::NotSatisfied
        );
        assert!(!offline_accepts(&report));
        assert!(!report.errors().is_empty());
    }

    #[test]
    fn test_seal_double_spend_regression() {
        // Regression test for double-spend vulnerability: the same seal must not
        // be usable in a second proof bundle.
        let seal_id = vec![1u8, 2, 3];
        let bundle1 = test_bundle_with_signatures().unwrap();

        let mut consumed_seals = std::collections::HashSet::new();
        let report1 = verify_proof(
            &bundle1,
            |candidate: &[u8]| consumed_seals.contains(candidate),
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(offline_accepts(&report1));

        consumed_seals.insert(seal_id.clone());

        let bundle2 = test_bundle_with_signatures().unwrap();
        let report2 = verify_proof(
            &bundle2,
            |candidate: &[u8]| consumed_seals.contains(candidate),
            SignatureScheme::Ed25519,
            &authorized(),
        );

        assert!(
            !offline_accepts(&report2),
            "Double-spend attempt should be rejected"
        );
        assert!(has_reason(
            &report2,
            ProtocolAssuranceDimension::SourceClosure,
            ProtocolReasonCode::ReplayDetected
        ));
    }

    #[test]
    fn verification_is_deterministic_for_the_same_inputs() {
        // Same evidence, same rules, same verdict — including the same digests.
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::default();
        let first = verifier.verify_proof_bundle(&bundle, &attested_runtime_context());
        let second = verifier.verify_proof_bundle(&bundle, &attested_runtime_context());
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn no_shipped_policy_can_waive_a_failed_dimension() {
        // Structural guard on the policy vocabulary itself: whatever a policy
        // tolerates, NotSatisfied is never acceptable.
        for policy in [
            AssuranceRequirement::COMPLETE,
            AssuranceRequirement::RUNTIME_SOURCE_PROOF,
            AssuranceRequirement::OFFLINE_RECIPIENT,
        ] {
            for dimension in crate::assurance::PROTOCOL_ASSURANCE_DIMENSIONS {
                assert!(matches!(
                    policy.rule(dimension),
                    DimensionRequirement::MustBeSatisfied
                        | DimensionRequirement::MayBeIndeterminate
                        | DimensionRequirement::NotRequired
                ));
            }
        }
        // And the offline policy must still demand the two things an offline
        // recipient can actually establish.
        assert_eq!(
            AssuranceRequirement::OFFLINE_RECIPIENT
                .rule(ProtocolAssuranceDimension::CanonicalStructure),
            DimensionRequirement::MustBeSatisfied
        );
        assert_eq!(
            AssuranceRequirement::OFFLINE_RECIPIENT.rule(ProtocolAssuranceDimension::Authorization),
            DimensionRequirement::MustBeSatisfied
        );
    }
}
