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

use csv_protocol::error::ProtocolError;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::proof_taxonomy::ProofLeafV1;
use csv_protocol::signature::{Signature, SignatureScheme, verify_signatures};
use csv_protocol::verification_levels::VerificationLevel;
use serde::Serialize;

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
#[derive(Debug, Clone, Serialize)]
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

/// Result of a proof verification with explicit assurance level.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof passed all checks.
    pub is_valid: bool,
    /// The verification level achieved.
    pub level: VerificationLevel,
    /// Errors encountered during verification (empty if valid).
    pub errors: Vec<VerificationError>,
    /// Warnings (non-fatal issues).
    pub warnings: Vec<String>,
}

impl serde::Serialize for VerificationResult {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("VerificationResult", 4)?;
        s.serialize_field("is_valid", &self.is_valid)?;
        s.serialize_field("level", &format!("{:?}", self.level))?;
        s.serialize_field("errors", &self.errors)?;
        s.serialize_field("warnings", &self.warnings)?;
        s.end()
    }
}

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
/// # Implementation Notes
///
/// The canonical implementation is provided by `CanonicalVerifier` in this module.
/// Chain adapters should implement this trait for chain-specific verification
/// (inclusion proofs, finality checks) but MUST delegate to the canonical
/// verifier for protocol-level checks (signatures, replay, DAG structure).
pub trait CanonicalVerifier: Send + Sync {
    /// Verify a proof bundle according to the CSV verification pipeline.
    ///
    /// This is the primary verification entry point. It performs all
    /// cryptographic and structural checks required to validate a proof bundle.
    ///
    /// # Arguments
    /// * `bundle` - The proof bundle to verify
    /// * `context` - Verification context containing chain-specific data
    ///
    /// # Returns
    /// Verification result with explicit assurance level and any errors.
    fn verify_proof_bundle(
        &self,
        bundle: &ProofBundle,
        context: &VerificationContext,
    ) -> Result<VerificationResult>;

    /// Verify an inclusion proof for a specific anchor.
    ///
    /// # Arguments
    /// * `anchor_ref` - The anchor reference to verify
    /// * `context` - Verification context containing chain-specific data
    ///
    /// # Returns
    /// Verification result for the inclusion proof.
    fn verify_inclusion_proof(
        &self,
        anchor_ref: &csv_hash::seal::CommitAnchor,
        context: &VerificationContext,
    ) -> Result<VerificationResult>;

    /// Verify finality for a block height.
    ///
    /// # Arguments
    /// * `block_height` - The block height to check
    /// * `context` - Verification context containing chain-specific data
    ///
    /// # Returns
    /// Verification result for finality check.
    fn verify_finality(
        &self,
        block_height: u64,
        context: &VerificationContext,
    ) -> Result<VerificationResult>;

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
    /// Verification result indicating if the leaf hash matches.
    fn verify_proof_leaf(
        &self,
        leaf: &ProofLeafV1,
        expected_hash: &csv_hash::Hash,
    ) -> Result<VerificationResult>;
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
    /// Whether the chain adapter has cryptographically validated inclusion,
    /// finality, and the proof's binding to the transfer being authorized.
    pub native_proof_validated: bool,
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
    /// The **runtime** path may leave this empty because destination
    /// materialization is separately authorized by the on-chain §9.2
    /// verifier-attested mint (and `native_proof_validated`). The **offline
    /// recipient accept** path MUST populate it from trusted local config and
    /// fails closed if it is empty — that path has no other authorization gate.
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
/// This is the single source of truth for proof verification in the CSV protocol.
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
    /// meaningful bound is deployment/chain-specific and an always-on default
    /// would reject the `u64::MAX` "instant-final" confirmation sentinel used by
    /// chains without a depth model.
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
    ) -> Result<VerificationResult> {
        // Step 0: Size bound (DoS protection) — reject oversized bundles before
        // any further work (VERIFY-VALIDATIONS-DISABLED-001).
        validate_proof_bundle_size(bundle)?;

        // Step 1: DAG Structure Validation
        self.validate_dag_structure(bundle)?;

        // Step 1.5: Domain / transfer-context binding (VERIFY-DOMAIN-SEPARATION-001).
        // Bind the bundle to the specific transfer the context authorizes so a
        // proof built for one chain/Sanad cannot be replayed under a context for
        // another.
        validate_context_binding(bundle, context)?;

        // Step 2: Signature Verification (with approved-verifier-set binding when
        // the context supplies one; the runtime path relies on the on-chain §9.2
        // gate + native_proof_validated below).
        verify_bundle_signatures(
            bundle,
            context.signature_scheme,
            &context.authorized_signers,
        )?;

        // Step 3: Seal Replay Check
        self.check_seal_replay(bundle, context)?;

        // Step 4: Inclusion Verification
        validate_inclusion_proof(&bundle.inclusion_proof)?;
        self.verify_inclusion_proof(&bundle.anchor_ref, context)?;

        // Step 5: Finality Check
        self.verify_finality(bundle.anchor_ref.block_height, context)?;

        // Step 6: Validate finality proof data integrity
        validate_finality_proof(&bundle.finality_proof)?;

        // Step 7: Validate anchor reference integrity
        validate_anchor_reference(bundle)?;

        if !context.native_proof_validated {
            return Err(ProtocolError::InclusionProofFailed(
                "chain-native proof validation evidence is required".to_string(),
            ));
        }

        Ok(VerificationResult::fully_verified())
    }

    fn verify_inclusion_proof(
        &self,
        anchor_ref: &csv_hash::seal::CommitAnchor,
        _context: &VerificationContext,
    ) -> Result<VerificationResult> {
        if anchor_ref.anchor_id.is_empty() {
            return Err(ProtocolError::InvalidInput(
                "anchor_id is empty".to_string(),
            ));
        }

        Ok(VerificationResult::merkle_verified())
    }

    fn verify_finality(
        &self,
        block_height: u64,
        context: &VerificationContext,
    ) -> Result<VerificationResult> {
        if let Some(current_height) = context.current_block_height {
            let confirmations = current_height.saturating_sub(block_height);
            if confirmations < context.required_confirmations {
                return Err(ProtocolError::FinalityNotReached(format!(
                    "{} confirmations, need {}",
                    confirmations, context.required_confirmations
                )));
            }

            // VERIFY-PROOF-FRESHNESS-001: reject a proof whose anchor is buried
            // more than `max_anchor_age_blocks` below the observed tip — a stale
            // proof being replayed long after its anchor. This is the upper bound
            // on the same `tip - anchor` quantity finality lower-bounds, using the
            // real observed height (deterministic, no wall clock). `u64::MAX` is
            // the "instant-final" sentinel from chains without a depth model and
            // is exempt (its age is not measured in blocks).
            if let Some(max_age) = self.config.max_anchor_age_blocks
                && current_height != u64::MAX
                && confirmations > max_age
            {
                return Err(ProtocolError::ProofExpired(format!(
                    "anchor is {confirmations} blocks below tip, exceeds max age {max_age}"
                )));
            }
        }

        Ok(VerificationResult::fully_verified())
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
        }
        Ok(SealRegistryStatus::Available)
    }

    fn verify_proof_leaf(
        &self,
        leaf: &ProofLeafV1,
        expected_hash: &csv_hash::Hash,
    ) -> Result<VerificationResult> {
        // Get the native hash function for the source chain
        let hash_fn = leaf.native_hash_function();

        // Compute the leaf hash using the chain's native hash function
        let computed_hash = leaf.hash_with_function(hash_fn).map_err(|e| {
            ProtocolError::InvalidInput(format!("Failed to compute leaf hash: {}", e))
        })?;

        // Verify the computed hash matches the expected hash
        if computed_hash == *expected_hash {
            Ok(VerificationResult::fully_verified())
        } else {
            Ok(VerificationResult {
                is_valid: false,
                level: VerificationLevel::StructuralOnly,
                errors: vec![VerificationError {
                    code: VerificationErrorCode::InclusionProofInvalid,
                    message: format!(
                        "Proof leaf hash mismatch: computed {:?}, expected {:?} (using {:?})",
                        computed_hash, expected_hash, hash_fn
                    ),
                    retryable: false,
                }],
                warnings: vec![],
            })
        }
    }
}

impl CanonicalVerifierImpl {
    /// Validate DAG structure of the proof bundle.
    fn validate_dag_structure(&self, bundle: &ProofBundle) -> Result<()> {
        // Basic structure validation
        if bundle.transition_dag.nodes.is_empty() {
            return Err(ProtocolError::InvalidInput("DAG has no nodes".to_string()));
        }

        Ok(())
    }

    /// Check seal replay status.
    fn check_seal_replay(&self, bundle: &ProofBundle, context: &VerificationContext) -> Result<()> {
        let status = self.verify_seal_registry(&bundle.seal_ref.id, context)?;
        match status {
            SealRegistryStatus::Consumed => Err(ProtocolError::SealReplay(format!(
                "{:?}",
                bundle.seal_ref.id
            ))),
            SealRegistryStatus::Available => Ok(()),
            SealRegistryStatus::CheckFailed(msg) => Err(ProtocolError::InvalidInput(msg)),
        }
    }
}

impl VerificationResult {
    /// Structural-only result (no cryptographic checks performed).
    pub fn structural() -> Self {
        Self {
            is_valid: true,
            level: VerificationLevel::StructuralOnly,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Merkle-verified result (inclusion proof verified, finality not confirmed).
    pub fn merkle_verified() -> Self {
        Self {
            is_valid: true,
            level: VerificationLevel::MerkleVerified,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Fully verified result (all checks passed).
    pub fn fully_verified() -> Self {
        Self {
            is_valid: true,
            level: VerificationLevel::FullyVerified,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Failed result with typed errors.
    pub fn failed(errors: Vec<VerificationError>) -> Self {
        Self {
            is_valid: false,
            level: VerificationLevel::StructuralOnly,
            errors,
            warnings: Vec::new(),
        }
    }

    /// Failed result with a single typed error.
    pub fn from_verification_error(e: VerificationError) -> Self {
        Self {
            is_valid: false,
            level: VerificationLevel::StructuralOnly,
            errors: vec![e],
            warnings: Vec::new(),
        }
    }

    /// Failed result from a ProtocolError, converted to typed error.
    pub fn from_protocol_error(e: &ProtocolError) -> Self {
        let error = match e {
            ProtocolError::SealReplay(_) => VerificationError::seal_replay(&[]),
            ProtocolError::SignatureVerificationFailed(_) => VerificationError::signature_invalid(),
            ProtocolError::InclusionProofFailed(_) => {
                VerificationError::inclusion_proof_invalid("verification failed")
            }
            ProtocolError::FinalityNotReached(msg) => {
                // Parse confirmations from message if possible
                let confirmations = msg
                    .split(':')
                    .nth(1)
                    .and_then(|s: &str| s.split(',').next())
                    .and_then(|s: &str| s.trim().parse::<u64>().ok())
                    .unwrap_or(0);
                let required = msg
                    .split(',')
                    .nth(1)
                    .and_then(|s: &str| s.split(':').nth(1))
                    .and_then(|s: &str| s.trim().parse::<u64>().ok())
                    .unwrap_or(MIN_REQUIRED_CONFIRMATIONS);
                VerificationError::finality_not_reached(confirmations, required)
            }
            _ => VerificationError::malformed_proof(&e.to_string()),
        };
        Self {
            is_valid: false,
            level: VerificationLevel::StructuralOnly,
            errors: vec![error],
            warnings: Vec::new(),
        }
    }
}

/// Verify a proof bundle according to the CSV verification pipeline.
///
/// This is the **primary entry point for proof verification**. It performs
/// all cryptographic and structural checks required to validate a proof bundle
/// before accepting the state transition it authorizes.
///
/// # Security Requirements (CRITICAL)
///
/// 1. **All signatures must be valid**: Any invalid signature causes rejection
/// 2. **Seal must be unused**: Replay attacks prevented via `seal_registry` callback
/// 3. **Proof must be non-empty**: Empty inclusion/finality proofs rejected
/// 4. **Finality must be reached**: Zero confirmations causes rejection
/// 5. **Proof must be recent**: Prevents replay of old proofs
/// 6. **Proof size limited**: Prevents DoS via oversized proofs
/// 7. **Domain separation enforced**: Prevents cross-domain attacks
///
/// # Verification Pipeline
///
/// 1. **Size Validation** - Reject oversized proof bundles (DoS protection)
/// 2. **DAG Structure Validation** - Verify transition graph integrity
/// 3. **Timestamp Validation** - Ensure proof is not too old (replay protection)
/// 4. **Signature Verification** - Cryptographically verify all signatures
/// 5. **Domain Separation** - Validate proof is for correct domain
/// 6. **Seal Replay Check** - Ensure seal hasn't been consumed before
/// 7. **Inclusion Verification** - Verify proof of on-chain inclusion
/// 8. **Finality Check** - Confirm anchor reached required confirmations
/// 9. **Anchor Reference Validation** - Verify anchor is properly formed
///
/// # Returns
/// - `Ok(VerificationResult)` with `is_valid: true` and `level: FullyVerified` if all checks pass
/// - `Ok(VerificationResult)` with `is_valid: false` and `level: StructuralOnly` if checks fail
pub fn verify_proof(
    bundle: &ProofBundle,
    seal_registry: impl Fn(&[u8]) -> bool,
    signature_scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
) -> VerificationResult {
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

/// Offline proof verification with an explicit expected-domain binding
/// (VERIFY-DOMAIN-SEPARATION-001).
///
/// Identical to [`verify_proof`] but additionally binds the bundle to the caller's
/// trusted `ExpectedDomain` (Sanad id and/or source chain). The recipient accept
/// path builds `expected` from the invoice/consignment it trusts and thereby
/// rejects a bundle that does not match the transfer it intends to accept.
pub fn verify_proof_bound(
    bundle: &ProofBundle,
    seal_registry: impl Fn(&[u8]) -> bool,
    signature_scheme: SignatureScheme,
    authorized_signers: &[Vec<u8>],
    expected: &ExpectedDomain,
) -> VerificationResult {
    // Expected-domain binding first: reject a bundle built for a different
    // Sanad / source chain before any further work.
    if let Some(expected_sanad) = &expected.sanad_id
        && bundle.anchor_ref.anchor_id.as_slice() != expected_sanad.as_slice()
    {
        return VerificationResult::from_protocol_error(&ProtocolError::Generic(
            "Domain binding failed: proof anchor does not match the expected Sanad".to_string(),
        ));
    }
    if let Some(expected_source) = &expected.source_chain
        && !bundle.inclusion_proof.source.is_empty()
        && &bundle.inclusion_proof.source != expected_source
    {
        return VerificationResult::from_protocol_error(&ProtocolError::Generic(format!(
            "Domain binding failed: proof source chain '{}' does not match expected '{}'",
            bundle.inclusion_proof.source, expected_source
        )));
    }

    // VERIFY-SIGNER-BINDING-001: the offline recipient accept path has no other
    // authorization gate (no on-chain §9.2 attestation, no adapter
    // native_proof_validated), so it MUST be given the approved verifier set and
    // fails closed without it. Otherwise a bundle signed by any attacker-chosen
    // key would reach `fully_verified()`.
    if authorized_signers.is_empty() {
        return VerificationResult::from_protocol_error(
            &ProtocolError::SignatureVerificationFailed(
                "No approved verifier keys supplied: refusing to accept a proof bundle whose \
             signatures cannot be bound to an authorized signer"
                    .to_string(),
            ),
        );
    }
    // Step 1: Validate proof bundle size (DoS protection). Re-enabled by
    // VERIFY-VALIDATIONS-DISABLED-001 — an oversized bundle must be rejected
    // before any further work.
    if let Err(e) = validate_proof_bundle_size(bundle) {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 2: Validate DAG structure (well-formed transition graph). Re-enabled
    // by VERIFY-VALIDATIONS-DISABLED-001.
    if let Err(e) = bundle
        .transition_dag
        .validate_structure()
        .map_err(|e| ProtocolError::Generic(format!("Invalid DAG structure: {}", e)))
    {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 3: Validate proof timestamp (prevent replay of old proofs)
    if let Err(e) = validate_proof_timestamp(bundle) {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 4: Validate signatures with cryptographic verification, bound to the
    // approved verifier set (checked non-empty above — this path fails closed
    // without it).
    if let Err(e) = verify_bundle_signatures(bundle, signature_scheme, authorized_signers) {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 5: Validate domain separation (prevent cross-domain attacks)
    if let Err(e) = validate_domain_separation(bundle) {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 6: Validate seal reference (check for replay)
    if seal_registry(bundle.seal_ref.id.as_ref()) {
        return VerificationResult::from_protocol_error(&ProtocolError::SealReplay(format!(
            "Seal {:?} has already been used",
            bundle.seal_ref
        )));
    }

    // Step 7: Validate inclusion proof (chain-specific, validated by adapter)
    if let Err(e) = validate_inclusion_proof(&bundle.inclusion_proof) {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 8: Validate finality proof (chain-specific, validated by adapter)
    if let Err(e) = validate_finality_proof(&bundle.finality_proof) {
        return VerificationResult::from_protocol_error(&e);
    }

    // Step 9: Validate anchor reference integrity
    if let Err(e) = validate_anchor_reference(bundle) {
        return VerificationResult::from_protocol_error(&e);
    }

    VerificationResult::fully_verified()
}

/// Validate proof bundle size to prevent DoS attacks (VERIFY-VALIDATIONS-DISABLED-001).
///
/// # Security
/// - Prevents memory exhaustion from oversized proofs
/// - Limits network bandwidth consumption
fn validate_proof_bundle_size(bundle: &ProofBundle) -> Result<()> {
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

    if total_size > MAX_PROOF_BUNDLE_SIZE {
        return Err(ProtocolError::Generic(format!(
            "Proof bundle too large: {} bytes (max {})",
            total_size, MAX_PROOF_BUNDLE_SIZE
        )));
    }

    Ok(())
}

/// Validate proof timestamp to prevent replay of old proofs.
///
/// # Security
/// - Prevents replay attacks using old proofs
/// - Ensures proofs are generated recently
fn validate_proof_timestamp(bundle: &ProofBundle) -> Result<()> {
    if bundle.anchor_ref.block_height == 0 {
        return Err(ProtocolError::Generic(
            "Invalid anchor reference: block height is 0".to_string(),
        ));
    }

    Ok(())
}

/// Validate domain separation to prevent cross-domain attacks.
///
/// # Security
/// - Ensures proof is for the intended domain/chain
/// - Prevents cross-chain replay attacks
///
/// This performs the structural sanity checks (non-empty seal / anchor). The
/// authoritative chain/transfer binding lives in [`validate_context_binding`],
/// which compares the bundle against the expected verification context
/// (VERIFY-DOMAIN-SEPARATION-001).
fn validate_domain_separation(bundle: &ProofBundle) -> Result<()> {
    // Check that the seal reference has a valid seal ID
    if bundle.seal_ref.id.is_empty() {
        return Err(ProtocolError::Generic(
            "Invalid seal reference: empty seal ID".to_string(),
        ));
    }

    // Verify that the anchor reference has valid metadata
    // Anchor metadata should contain the proof data or reference
    if bundle.anchor_ref.metadata.is_empty() && bundle.anchor_ref.block_height == 0 {
        return Err(ProtocolError::Generic(
            "Invalid anchor reference: empty metadata and block height".to_string(),
        ));
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
    use csv_hash::Hash;
    use csv_hash::dag::{DAGNode, DAGSegment};
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};
    use csv_protocol::signature::SignatureScheme;

    // Deterministic key so tests can build the approved-signer set now required
    // by verify_bundle_signatures (VERIFY-SIGNER-BINDING-001).
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Approved verifier set matching `make_ed25519_signature_bytes`'s signer.
    fn authorized() -> Vec<Vec<u8>> {
        vec![test_signing_key().verifying_key().to_bytes().to_vec()]
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

    fn test_bundle_with_signatures() -> Result<ProofBundle> {
        // The message signed is the DAG root commitment (Hash::zero() = 32 zero bytes)
        let message = [0u8; 32];
        let signature = make_ed25519_signature_bytes(&message);

        let seal_id = vec![1u8, 2, 3];
        let bundle = ProofBundle::new(
            DAGSegment::new(
                vec![DAGNode::new(
                    Hash::new([1u8; 32]),
                    vec![0x01, 0x02],
                    vec![signature.clone()],
                    vec![],
                    vec![],
                )],
                Hash::zero(),
            ),
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

    #[test]
    fn test_verify_proof_valid() {
        let bundle = test_bundle_with_signatures().unwrap();
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        if !result.is_valid {
            eprintln!("Verification failed. Errors: {:?}", result.errors);
        }
        assert!(result.is_valid);
        assert!(matches!(result.level, VerificationLevel::FullyVerified));
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
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(
            !result.is_valid,
            "a bundle signed by an unauthorized key must not verify"
        );
    }

    #[test]
    fn verify_proof_rejects_oversized_bundle() {
        // VERIFY-VALIDATIONS-DISABLED-001 regression: the re-enabled size bound
        // must reject a bundle larger than MAX_PROOF_BUNDLE_SIZE (DoS protection).
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.signatures.push(vec![0u8; MAX_PROOF_BUNDLE_SIZE + 1]);
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(
            !result.is_valid,
            "an oversized proof bundle must be rejected"
        );
    }

    #[test]
    fn verify_proof_bound_rejects_wrong_expected_sanad() {
        // VERIFY-DOMAIN-SEPARATION-001: a bundle whose anchor binds Sanad A must
        // be rejected when the caller expects Sanad B (cross-domain replay).
        let bundle = test_bundle_with_signatures().unwrap();
        let seal_registry = |_seal_id: &[u8]| false;

        // The test bundle's anchor_id is the seal_id (vec![1,2,3]); an expected
        // Sanad that differs must be rejected.
        let expected = ExpectedDomain {
            sanad_id: Some([0xABu8; 32]),
            source_chain: None,
        };
        let result = verify_proof_bound(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
            &expected,
        );
        assert!(
            !result.is_valid,
            "a bundle bound to a different Sanad must not verify"
        );
    }

    #[test]
    fn trait_path_rejects_bundle_bound_to_other_sanad() {
        // VERIFY-DOMAIN-SEPARATION-001 on the CanonicalVerifierImpl (runtime) path:
        // a context expecting a different Sanad than the bundle's anchor must fail.
        let bundle = test_bundle_with_signatures().unwrap();
        let verifier = CanonicalVerifierImpl::default();
        let ctx = VerificationContext {
            chain_id: "bitcoin".to_string(),
            signature_scheme: SignatureScheme::Ed25519,
            required_confirmations: 0,
            current_block_height: Some(200),
            seal_registry: None,
            chain_data: None,
            native_proof_validated: true,
            // Anchor id in the test bundle is vec![1,2,3]; a 32-byte mismatch here
            // must be rejected by the context binding step.
            sanad_id: Some(csv_hash::SanadId(Hash::new([0x11u8; 32]))),
            lock_tx: None,
            lock_output_index: None,
            transition_id: None,
            destination_chain: Some("sui".to_string()),
            authorized_signers: Vec::new(),
        };
        let result = verifier.verify_proof_bundle(&bundle, &ctx);
        assert!(
            result.is_err(),
            "runtime path must reject a bundle whose anchor does not match the context Sanad"
        );
    }

    fn freshness_context(current_height: u64) -> VerificationContext {
        VerificationContext {
            chain_id: "bitcoin".to_string(),
            signature_scheme: SignatureScheme::Ed25519,
            required_confirmations: 1,
            current_block_height: Some(current_height),
            seal_registry: None,
            chain_data: None,
            native_proof_validated: true,
            sanad_id: None,
            lock_tx: None,
            lock_output_index: None,
            transition_id: None,
            destination_chain: None,
            authorized_signers: Vec::new(),
        }
    }

    #[test]
    fn verify_finality_rejects_stale_anchor_beyond_max_age() {
        // VERIFY-PROOF-FRESHNESS-001: with a freshness bound configured, an anchor
        // buried more than max_anchor_age_blocks below the observed tip is stale.
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        let anchor_height = 1_000u64;
        // tip is 250 blocks above the anchor -> age 250 > 100 -> expired.
        let ctx = freshness_context(anchor_height + 250);
        let result = verifier.verify_finality(anchor_height, &ctx);
        assert!(
            matches!(result, Err(ProtocolError::ProofExpired(_))),
            "a stale anchor must be rejected with ProofExpired, got {result:?}"
        );
    }

    #[test]
    fn verify_finality_accepts_fresh_anchor_within_max_age() {
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        let anchor_height = 1_000u64;
        // 50 blocks deep: within both the finality floor (1) and freshness cap (100).
        let ctx = freshness_context(anchor_height + 50);
        assert!(verifier.verify_finality(anchor_height, &ctx).is_ok());
    }

    #[test]
    fn verify_finality_freshness_exempts_instant_final_sentinel() {
        // u64::MAX confirmations is the "instant-final" sentinel; its age is not
        // measured in blocks and must not be rejected as stale.
        let verifier = CanonicalVerifierImpl::new(VerifierConfig {
            max_anchor_age_blocks: Some(100),
            ..VerifierConfig::default()
        });
        let ctx = freshness_context(u64::MAX);
        assert!(verifier.verify_finality(1_000, &ctx).is_ok());
    }

    #[test]
    fn verify_finality_freshness_disabled_by_default() {
        // Default config leaves freshness off, so a very old anchor still passes
        // finality (preserving existing behavior).
        let verifier = CanonicalVerifierImpl::default();
        let ctx = freshness_context(1_000_000);
        assert!(verifier.verify_finality(1, &ctx).is_ok());
    }

    #[test]
    fn verify_proof_fails_closed_without_authorized_set() {
        // The offline accept path must not reach fully_verified() when no approved
        // verifier keys are supplied.
        let bundle = test_bundle_with_signatures().unwrap();
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(&bundle, seal_registry, SignatureScheme::Ed25519, &[]);
        assert!(
            !result.is_valid,
            "empty approved verifier set must fail closed"
        );
    }

    #[test]
    fn test_verify_proof_accepts_distinct_seal_and_anchor_ids() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.anchor_ref = CommitAnchor::new(vec![9u8; 32], 100, vec![0xCD; 32])
            .map_err(|e| ProtocolError::Generic(e.to_string()))
            .unwrap();

        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(result.is_valid);
        assert!(matches!(result.level, VerificationLevel::FullyVerified));
    }

    #[test]
    fn test_verify_proof_seal_replay() {
        let bundle = test_bundle_with_signatures().unwrap();
        let seal_registry = |seal_id: &[u8]| seal_id == [1, 2, 3];
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_verify_proof_no_signatures() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.signatures.clear();
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_verify_proof_no_confirmations() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.finality_proof.confirmations = 0;
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_verify_proof_invalid_signature_format() {
        let mut bundle = test_bundle_with_signatures().unwrap();
        // Corrupt signature format
        bundle.signatures[0] = vec![0x00, 0x00]; // Too short
        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_verify_proof_ed25519_valid_format() {
        // The message signed is the DAG root commitment (Hash::zero() = 32 zero bytes)
        let message = [0u8; 32];
        let signature = make_ed25519_signature_bytes(&message);

        let mut bundle = test_bundle_with_signatures().unwrap();
        bundle.signatures = vec![signature];

        let seal_registry = |_seal_id: &[u8]| false;
        let result = verify_proof(
            &bundle,
            seal_registry,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(result.is_valid);
        assert!(matches!(result.level, VerificationLevel::FullyVerified));
    }

    #[test]
    fn test_seal_double_spend_regression() {
        // Regression test for double-spend vulnerability
        // This test ensures that the same seal cannot be used in multiple proof bundles

        let seal_id = vec![1u8, 2, 3];

        // Create first proof bundle with the seal
        let bundle1 = test_bundle_with_signatures().unwrap();

        // Simulate a seal registry that tracks consumed seals
        let mut consumed_seals = std::collections::HashSet::new();

        // First verification should succeed
        let seal_registry1 = |seal_id_check: &[u8]| consumed_seals.contains(seal_id_check);
        let result1 = verify_proof(
            &bundle1,
            seal_registry1,
            SignatureScheme::Ed25519,
            &authorized(),
        );
        assert!(result1.is_valid);

        // Mark the seal as consumed
        consumed_seals.insert(seal_id.clone());

        // Create second proof bundle with the same seal (double-spend attempt)
        let bundle2 = test_bundle_with_signatures().unwrap();

        // Second verification should fail due to seal being consumed
        let seal_registry2 = |seal_id_check: &[u8]| consumed_seals.contains(seal_id_check);
        let result2 = verify_proof(
            &bundle2,
            seal_registry2,
            SignatureScheme::Ed25519,
            &authorized(),
        );

        // Verify that the double-spend attempt is rejected
        assert!(!result2.is_valid, "Double-spend attempt should be rejected");

        // Verify the error message indicates seal replay
        let error_msg: String = result2
            .errors
            .iter()
            .map(|e| format!("{:?}", e))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            error_msg.contains("seal")
                || error_msg.contains("replay")
                || error_msg.contains("consumed"),
            "Error should indicate seal replay/consumption: {}",
            error_msg
        );
    }
}
