//! Consignment envelope for the interactive off-chain transfer mode.
//!
//! A [`Consignment`] is the portable artifact the sender hands the recipient. It
//! reuses the existing [`ProofBundle`] (which already carries the transition DAG back
//! to a validated anchor, plus inclusion and finality proofs) and pairs it with the
//! [`Invoice`] it satisfies and the sanad being delivered. This replaces the earlier
//! JSON stub; correctness is entirely client-side (`accept`, ticket I3), with no
//! attestor, ZK, or destination gas.
//!
//! Canonical hashing uses CBOR via `csv-codec`; `serde_json` is never used here.

use csv_codec::{CodecError, from_canonical_cbor, to_canonical_cbor};
use csv_hash::{Hash, csv_tagged_hash};
use csv_protocol::closure::{ClosureProof, ClosureTrustMode, FinalizedCheckpoint};
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::{ConsumedStateRef, ResolvedTransition, SignatureScheme};
use serde::{Deserialize, Serialize};

use crate::invoice::Invoice;
use crate::primitives::SanadIdWire;

/// Current consignment envelope wire version.
pub const CONSIGNMENT_VERSION: u16 = 1;
/// Protocol semantics version carried by portable V2 consignments.
pub const CONSIGNMENT_V2_PROTOCOL_VERSION: u16 = 2;
/// Current portable consignment envelope version.
pub const CONSIGNMENT_V2_ENVELOPE_VERSION: u16 = 2;
/// Domain tag for the commitment signed by every V2 authorization.
pub const CONSIGNMENT_V2_COMMITMENT_TAG: &str = "consignment-v2";

/// The sender-produced envelope delivering a sanad against a recipient invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consignment {
    /// Consignment envelope wire version.
    pub version: u16,
    /// The invoice this consignment satisfies (binds destination seal + nonce).
    pub invoice: Invoice,
    /// The sanad being delivered.
    pub sanad_id: SanadIdWire,
    /// Reused proof bundle: the transition DAG history back to a validated anchor,
    /// plus inclusion and finality proofs. See [`ProofBundle`].
    pub proof_bundle: ProofBundle,
}

/// Inspection-only status for a V1 integrity dimension.
///
/// None of these values is a V2 assurance verdict. In particular,
/// [`Self::Unavailable`] must not be treated as successful verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyIntegrityStatus {
    /// The legacy artifact carries the material, but this decoder has not
    /// cryptographically verified it.
    PresentUnverified,
    /// A structural relationship is internally consistent.
    StructurallyConsistent,
    /// A structural relationship is internally contradictory.
    Contradicted,
    /// V1 has no representation for this integrity dimension.
    Unavailable,
}

/// Integrity dimensions reported by inspection of a legacy V1 consignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyIntegrityDimensions {
    /// Whether the legacy proof bundle names the invoice's destination seal.
    pub destination_binding: LegacyIntegrityStatus,
    /// Legacy proof material is retained but is not verified by wire decoding.
    pub legacy_proof_bundle: LegacyIntegrityStatus,
    /// V1 does not identify and close one distinct consumed state.
    pub source_closure: LegacyIntegrityStatus,
    /// V1 signatures do not authorize a commitment over the complete envelope.
    pub complete_envelope_authorization: LegacyIntegrityStatus,
    /// Portable non-equivocation requires V2 source closure and is unavailable.
    pub portable_non_equivocation: LegacyIntegrityStatus,
}

/// Safely inspectable fields from a canonical legacy V1 consignment.
///
/// This type deliberately has no conversion into [`ConsignmentV2`] and is not
/// accepted by the V2 validation API. Migration must reconstruct and verify a
/// complete V2 payload through the explicit V2 constructors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyConsignmentInspection {
    /// Exact legacy envelope version.
    pub legacy_version: u16,
    /// Recipient invoice present in the legacy envelope.
    pub invoice: Invoice,
    /// Sanad identifier present in the legacy envelope.
    pub sanad_id: SanadIdWire,
    /// Legacy proof material, retained for forensic inspection only.
    pub proof_bundle: ProofBundle,
    /// Explicit availability of each relevant integrity dimension.
    pub integrity: LegacyIntegrityDimensions,
}

/// Stable failure codes for explicit V1 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyConsignmentErrorCode {
    /// Bytes were not a decodable V1 CBOR object.
    MalformedEncoding,
    /// The input was extended, had trailing data, or was not canonical.
    NonCanonicalEncoding,
    /// The envelope version is not the one supported legacy version.
    UnsupportedVersion,
    /// A required V1 field is malformed or uses an unsupported nested version.
    UnsupportedArtifact,
}

/// A V1 inspection failure with a stable machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct LegacyConsignmentError {
    /// Stable code suitable for SDK and CLI boundaries.
    pub code: LegacyConsignmentErrorCode,
    /// Actionable diagnostic detail.
    pub detail: String,
}

impl LegacyConsignmentError {
    fn new(code: LegacyConsignmentErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl Consignment {
    /// Create a new consignment at the current [`CONSIGNMENT_VERSION`].
    pub fn new(invoice: Invoice, sanad_id: SanadIdWire, proof_bundle: ProofBundle) -> Self {
        Self {
            version: CONSIGNMENT_VERSION,
            invoice,
            sanad_id,
            proof_bundle,
        }
    }

    /// Deterministic CBOR encoding of the whole envelope.
    ///
    /// # Errors
    /// Returns a [`CodecError`] if canonical encoding fails.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>, CodecError> {
        to_canonical_cbor(self)
    }

    /// Explicitly decode a canonical V1 envelope for inspection only.
    ///
    /// This entry point never probes for another format and never returns an
    /// acceptance-capable V2 value.
    pub fn decode_v1_for_inspection(
        bytes: &[u8],
    ) -> Result<LegacyConsignmentInspection, LegacyConsignmentError> {
        let decoded: Self = from_canonical_cbor(bytes).map_err(|error| {
            LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::MalformedEncoding,
                error.to_string(),
            )
        })?;
        let canonical = to_canonical_cbor(&decoded).map_err(|error| {
            LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::MalformedEncoding,
                error.to_string(),
            )
        })?;
        if canonical != bytes {
            return Err(LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::NonCanonicalEncoding,
                "input is extended, trailing, or not the unique canonical V1 encoding",
            ));
        }
        if decoded.version != CONSIGNMENT_VERSION {
            return Err(LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::UnsupportedVersion,
                format!("unsupported legacy consignment version {}", decoded.version),
            ));
        }
        if decoded.invoice.version != crate::invoice::INVOICE_VERSION {
            return Err(LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::UnsupportedArtifact,
                format!(
                    "unsupported legacy invoice version {}",
                    decoded.invoice.version
                ),
            ));
        }
        if decoded.proof_bundle.version != 1 {
            return Err(LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::UnsupportedArtifact,
                format!(
                    "unsupported legacy proof-bundle version {}",
                    decoded.proof_bundle.version
                ),
            ));
        }
        if decoded.invoice.schema_id.is_empty() {
            return Err(LegacyConsignmentError::new(
                LegacyConsignmentErrorCode::UnsupportedArtifact,
                "legacy invoice schema_id is empty",
            ));
        }
        let destination_binding = match decoded.binds_invoice_seal() {
            Ok(true) => LegacyIntegrityStatus::StructurallyConsistent,
            Ok(false) => LegacyIntegrityStatus::Contradicted,
            Err(error) => {
                return Err(LegacyConsignmentError::new(
                    LegacyConsignmentErrorCode::UnsupportedArtifact,
                    error,
                ));
            }
        };
        let sanad_id = decoded.sanad_id.clone();
        csv_hash::SanadId::try_from(sanad_id).map_err(|error| {
            LegacyConsignmentError::new(LegacyConsignmentErrorCode::UnsupportedArtifact, error)
        })?;

        Ok(LegacyConsignmentInspection {
            legacy_version: decoded.version,
            invoice: decoded.invoice,
            sanad_id: decoded.sanad_id,
            proof_bundle: decoded.proof_bundle,
            integrity: LegacyIntegrityDimensions {
                destination_binding,
                legacy_proof_bundle: LegacyIntegrityStatus::PresentUnverified,
                source_closure: LegacyIntegrityStatus::Unavailable,
                complete_envelope_authorization: LegacyIntegrityStatus::Unavailable,
                portable_non_equivocation: LegacyIntegrityStatus::Unavailable,
            },
        })
    }

    /// Whether the bundled proof assigns the sanad to the exact [`SealPoint`] the
    /// invoice nominated (destination seal + anti-replay nonce). This is the anti-
    /// griefing binding: a consignment for one invoice cannot satisfy another.
    ///
    /// This is a structural check only; full client-side validation (finality, DAG
    /// linkage, replay) lands with `accept` (ticket I3).
    ///
    /// # Errors
    /// Returns an error if the invoice seal cannot be reduced to a `SealPoint`.
    pub fn binds_invoice_seal(&self) -> Result<bool, String> {
        let expected = self.invoice.bound_seal_point()?;
        Ok(self.proof_bundle.seal_ref == expected)
    }
}

/// A signature authorizing exactly one V2 consignment commitment.
///
/// Signature verification belongs to `csv-verifier`; the wire layer guarantees
/// that the claimed signed message is the envelope commitment and cannot be
/// redirected to another destination or successor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsignmentAuthorization {
    /// Signature algorithm used by the authorizer.
    pub scheme: SignatureScheme,
    /// Authorizer public key.
    pub public_key: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
    /// Commitment the signature claims to authorize.
    pub signed_commitment: Hash,
}

/// External inputs an isolated recipient must obtain before V2 acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsignmentProofRequirements {
    /// Exact finalized checkpoint against which inclusion is to be checked.
    pub checkpoint: FinalizedCheckpoint,
    /// Trust anchor the recipient is expected to use.
    pub trust_mode: ClosureTrustMode,
    /// Stable chain-native proof provider identifier.
    pub proof_provider_id: String,
    /// Stable verification-context identifier/digest.
    pub verification_context: Hash,
    /// Maximum checkpoint age, in blocks, accepted by the sender's profile.
    pub maximum_checkpoint_age: u64,
}

/// The fields committed to by a portable V2 consignment.
///
/// Keeping this payload separate from the commitment and signatures prevents
/// recursive encoding and makes the signing preimage independently reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsignmentV2Payload {
    /// Protocol semantics version.
    pub protocol_version: u16,
    /// Portable envelope version.
    pub envelope_version: u16,
    /// State whose unique successor is asserted.
    pub source: ConsumedStateRef,
    /// Fully resolved transition, including the parent output and new outputs.
    pub successor: ResolvedTransition,
    /// Real chain-native source closure witness.
    pub source_closure: ClosureProof,
    /// Recipient-issued invoice binding the destination seal and nonce.
    pub destination: Invoice,
    /// Explicit checkpoint, provider, context, freshness, and trust inputs.
    pub proof_requirements: ConsignmentProofRequirements,
}

/// Complete portable, closure-carrying consignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsignmentV2 {
    /// Every field whose mutation must invalidate authorization.
    pub payload: ConsignmentV2Payload,
    /// Domain-separated commitment to `payload`.
    pub commitment: Hash,
    /// Authorization evidence over `commitment`.
    pub authorizations: Vec<ConsignmentAuthorization>,
}

/// Stable failure codes for deterministic V2 decoding and envelope validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsignmentV2ErrorCode {
    /// Bytes were not a decodable V2 CBOR object.
    MalformedEncoding,
    /// The input decoded but was not the unique canonical representation.
    NonCanonicalEncoding,
    /// The protocol version is unsupported.
    UnsupportedProtocolVersion,
    /// The envelope version is unsupported.
    UnsupportedEnvelopeVersion,
    /// The source is not one of the transition's resolved inputs.
    SourceTransitionMismatch,
    /// The closure targets a different source.
    ClosureSourceMismatch,
    /// The closure commits to a different successor.
    ClosureSuccessorMismatch,
    /// The source closure envelope is invalid.
    InvalidClosureProof,
    /// The successor output does not bind the recipient invoice.
    DestinationMismatch,
    /// An external proof dependency is invalid or unnamed.
    InvalidProofRequirements,
    /// The stored commitment does not reproduce from the payload.
    CommitmentMismatch,
    /// No authorization evidence was supplied.
    MissingAuthorization,
    /// An authorization is empty or names another commitment.
    InvalidAuthorization,
}

/// A V2 wire failure with a stable machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct ConsignmentV2Error {
    /// Stable code suitable for SDK and CLI boundaries.
    pub code: ConsignmentV2ErrorCode,
    /// Actionable, non-authoritative diagnostic detail.
    pub detail: String,
}

impl ConsignmentV2Error {
    fn new(code: ConsignmentV2ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl ConsignmentV2Payload {
    /// Construct the current V2 payload without permitting version ambiguity.
    pub fn new(
        source: ConsumedStateRef,
        successor: ResolvedTransition,
        source_closure: ClosureProof,
        destination: Invoice,
        proof_requirements: ConsignmentProofRequirements,
    ) -> Self {
        Self {
            protocol_version: CONSIGNMENT_V2_PROTOCOL_VERSION,
            envelope_version: CONSIGNMENT_V2_ENVELOPE_VERSION,
            source,
            successor,
            source_closure,
            destination,
            proof_requirements,
        }
    }

    /// Reproduce the domain-separated commitment authorization signs.
    pub fn commitment(&self) -> Result<Hash, ConsignmentV2Error> {
        let bytes = to_canonical_cbor(self).map_err(|error| {
            ConsignmentV2Error::new(ConsignmentV2ErrorCode::MalformedEncoding, error.to_string())
        })?;
        Ok(Hash::new(csv_tagged_hash(
            CONSIGNMENT_V2_COMMITMENT_TAG,
            &bytes,
        )))
    }

    /// Validate payload bindings before authorization is produced.
    ///
    /// This establishes structural consistency only. Chain-native closure
    /// semantics and signatures still require their dedicated verifiers.
    pub fn validate_structure(&self) -> Result<(), ConsignmentV2Error> {
        if self.protocol_version != CONSIGNMENT_V2_PROTOCOL_VERSION {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::UnsupportedProtocolVersion,
                format!("unsupported protocol version {}", self.protocol_version),
            ));
        }
        if self.envelope_version != CONSIGNMENT_V2_ENVELOPE_VERSION {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::UnsupportedEnvelopeVersion,
                format!("unsupported envelope version {}", self.envelope_version),
            ));
        }
        let resolved_source = self
            .successor
            .inputs
            .iter()
            .find(|input| input.reference == self.source)
            .ok_or_else(|| {
                ConsignmentV2Error::new(
                    ConsignmentV2ErrorCode::SourceTransitionMismatch,
                    "source is absent from the resolved successor inputs",
                )
            })?;
        if resolved_source.parent.reference() != self.source
            || resolved_source.parent.recorded_commitment
                != resolved_source.parent.content_commitment()
        {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::SourceTransitionMismatch,
                "resolved parent does not reproduce the consumed source",
            ));
        }
        if self.source_closure.consumed_state != self.source {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::ClosureSourceMismatch,
                "closure proof names another consumed source",
            ));
        }
        if self.source_closure.successor_commitment != self.successor.commitment() {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::ClosureSuccessorMismatch,
                "closure proof names another successor commitment",
            ));
        }
        self.source_closure.validate().map_err(|error| {
            ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::InvalidClosureProof,
                error.to_string(),
            )
        })?;
        let destination = self.destination.bound_seal_point().map_err(|error| {
            ConsignmentV2Error::new(ConsignmentV2ErrorCode::DestinationMismatch, error)
        })?;
        if !self.successor.outputs.iter().any(|output| {
            csv_hash::seal::SealPoint::try_from(output.seal.clone())
                .is_ok_and(|seal| seal == destination)
        }) {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::DestinationMismatch,
                "no successor output is assigned to the invoice seal",
            ));
        }
        let requirements = &self.proof_requirements;
        requirements.checkpoint.validate().map_err(|error| {
            ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::InvalidProofRequirements,
                error.to_string(),
            )
        })?;
        if requirements.proof_provider_id.is_empty()
            || requirements.verification_context == Hash::zero()
            || requirements.maximum_checkpoint_age == 0
        {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::InvalidProofRequirements,
                "provider, verification context, and checkpoint-age bound are required",
            ));
        }
        Ok(())
    }
}

impl ConsignmentV2 {
    /// Build an unsigned V2 envelope. Authorization evidence is attached with
    /// [`Self::with_authorizations`] after signing [`Self::commitment`].
    pub fn new(payload: ConsignmentV2Payload) -> Result<Self, ConsignmentV2Error> {
        let commitment = payload.commitment()?;
        Ok(Self {
            payload,
            commitment,
            authorizations: Vec::new(),
        })
    }

    /// Attach authorization evidence and validate the complete envelope.
    pub fn with_authorizations(
        mut self,
        authorizations: Vec<ConsignmentAuthorization>,
    ) -> Result<Self, ConsignmentV2Error> {
        self.authorizations = authorizations;
        self.validate()?;
        Ok(self)
    }

    /// Deterministic CBOR encoding after all structural bindings are checked.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>, ConsignmentV2Error> {
        self.validate()?;
        to_canonical_cbor(self).map_err(|error| {
            ConsignmentV2Error::new(ConsignmentV2ErrorCode::MalformedEncoding, error.to_string())
        })
    }

    /// Explicit V2 decoder. It never auto-detects or promotes V1 artifacts.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, ConsignmentV2Error> {
        let decoded: Self = from_canonical_cbor(bytes).map_err(|error| {
            ConsignmentV2Error::new(ConsignmentV2ErrorCode::MalformedEncoding, error.to_string())
        })?;
        let canonical = to_canonical_cbor(&decoded).map_err(|error| {
            ConsignmentV2Error::new(ConsignmentV2ErrorCode::MalformedEncoding, error.to_string())
        })?;
        if canonical != bytes {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::NonCanonicalEncoding,
                "input is not the unique canonical CBOR encoding",
            ));
        }
        decoded.validate()?;
        Ok(decoded)
    }

    /// Validate all cross-field bindings without claiming cryptographic proof
    /// validity. Native proof and signature verification remain verifier work.
    pub fn validate(&self) -> Result<(), ConsignmentV2Error> {
        let payload = &self.payload;
        payload.validate_structure()?;
        let expected = payload.commitment()?;
        if self.commitment != expected {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::CommitmentMismatch,
                "payload does not reproduce the stored commitment",
            ));
        }
        if self.authorizations.is_empty() {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::MissingAuthorization,
                "at least one authorization is required",
            ));
        }
        if self.authorizations.iter().any(|authorization| {
            authorization.signed_commitment != self.commitment
                || authorization.public_key.is_empty()
                || authorization.signature.is_empty()
        }) {
            return Err(ConsignmentV2Error::new(
                ConsignmentV2ErrorCode::InvalidAuthorization,
                "authorization is empty or is bound to another commitment",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::SealDefinition;
    use csv_hash::Hash;
    use csv_hash::dag::DAGSegment;
    use csv_hash::seal::{CommitAnchor, SealPoint};
    use csv_protocol::SignatureScheme;
    use csv_protocol::closure::{
        ClosureProof, ClosureProofKind, ClosureTrustMode, FinalityPolicy, FinalizedCheckpoint,
    };
    use csv_protocol::exclusivity::{ConsumptionMode, ExclusivityClass, StateUseSchema};
    use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof};
    use csv_protocol::resolution::{ParentOutput, ResolvedInput, ResolvedTransition};
    use csv_protocol::state::StateAssignment;

    fn sample_invoice() -> Invoice {
        let seal = SealDefinition::sui(vec![0xCD; 32], 7).unwrap();
        Invoice::new(seal, vec![0xAA; 32], 0xBEEF).unwrap()
    }

    fn proof_bundle_with_seal(seal_ref: SealPoint) -> ProofBundle {
        ProofBundle {
            version: 1,
            transition_dag: DAGSegment::new(vec![], Hash::new([0u8; 32])),
            signatures: vec![],
            signature_scheme: SignatureScheme::Ed25519,
            seal_ref,
            anchor_ref: CommitAnchor {
                anchor_id: vec![0u8; 32],
                block_height: 0,
                metadata: vec![],
            },
            inclusion_proof: InclusionProof {
                proof_bytes: vec![1u8; 32],
                block_hash: Hash::new([1u8; 32]),
                position: 0,
                block_number: 1,
                leaf: Hash::new([3u8; 32]),
                root: Hash::new([4u8; 32]),
                siblings: vec![],
                leaf_index: 0,
                source: "test".to_string(),
            },
            finality_proof: FinalityProof {
                finality_data: vec![1u8; 32],
                block_hash: Hash::new([2u8; 32]),
                threshold: 2,
                confirmations: 6,
                data: vec![2u8; 32],
                source: "test".to_string(),
                is_deterministic: true,
            },
        }
    }

    fn sample_consignment(invoice: Invoice, bind: bool) -> Consignment {
        let seal_ref = if bind {
            invoice.bound_seal_point().unwrap()
        } else {
            SealPoint::new(vec![0xFF; 32], None, None).unwrap()
        };
        Consignment::new(
            invoice,
            SanadIdWire {
                bytes: hex::encode([0x55u8; 32]),
            },
            proof_bundle_with_seal(seal_ref),
        )
    }

    fn sample_v2() -> ConsignmentV2 {
        let invoice = sample_invoice();
        let destination = invoice.bound_seal_point().unwrap();
        let source = ConsumedStateRef::new(Hash::new([0x11; 32]), 0, 7);
        let mut schema = StateUseSchema::new();
        schema.bind(7, ExclusivityClass::Exclusive).unwrap();
        let parent = ParentOutput::sealed(
            source.transition_id,
            source.output_index,
            schema.bind_output(7).unwrap(),
            SealPoint::new(vec![0x22; 36], None, None).unwrap(),
            vec![0x33],
            vec![vec![0x44; 32]],
        );
        let successor = ResolvedTransition {
            transition_id: 9,
            inputs: vec![ResolvedInput {
                reference: source,
                parent,
                mode: ConsumptionMode::Exclusive,
            }],
            outputs: vec![StateAssignment::new(7, destination, vec![0x55])],
            validation_script: vec![0x66],
        };
        let closure = ClosureProof {
            consumed_state: source,
            successor_commitment: successor.commitment(),
            proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
            proof_material: vec![0x77; 64],
        };
        let requirements = ConsignmentProofRequirements {
            checkpoint: FinalizedCheckpoint {
                chain_id: "bitcoin".into(),
                network_id: "signet".into(),
                block_height: 100,
                block_id: vec![0x88; 32],
                finality_policy: FinalityPolicy::Confirmations(6),
            },
            trust_mode: ClosureTrustMode::LightClient,
            proof_provider_id: "bitcoin-spv-v1".into(),
            verification_context: Hash::new([0x99; 32]),
            maximum_checkpoint_age: 12,
        };
        let payload = ConsignmentV2Payload::new(source, successor, closure, invoice, requirements);
        let unsigned = ConsignmentV2::new(payload).unwrap();
        let authorization = ConsignmentAuthorization {
            scheme: SignatureScheme::Ed25519,
            public_key: vec![0xAA; 32],
            signature: vec![0xBB; 64],
            signed_commitment: unsigned.commitment,
        };
        unsigned.with_authorizations(vec![authorization]).unwrap()
    }

    #[test]
    fn canonical_cbor_round_trip() {
        let c = sample_consignment(sample_invoice(), true);
        let cbor = c.canonical_cbor().unwrap();
        let back: Consignment = csv_codec::from_canonical_cbor(&cbor).unwrap();
        assert_eq!(back.version, c.version);
        assert_eq!(back.invoice, c.invoice);
        assert_eq!(back.proof_bundle, c.proof_bundle);
    }

    #[test]
    fn serde_json_round_trip() {
        let c = sample_consignment(sample_invoice(), true);
        let json = serde_json::to_string(&c).unwrap();
        let back: Consignment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.invoice, c.invoice);
        assert_eq!(back.proof_bundle, c.proof_bundle);
    }

    #[test]
    fn binds_invoice_seal_detects_match_and_mismatch() {
        let bound = sample_consignment(sample_invoice(), true);
        assert!(bound.binds_invoice_seal().unwrap());

        let unbound = sample_consignment(sample_invoice(), false);
        assert!(!unbound.binds_invoice_seal().unwrap());
    }

    #[test]
    fn v1_inspection_reports_unavailable_v2_integrity() {
        let legacy = sample_consignment(sample_invoice(), true);
        let bytes = legacy.canonical_cbor().unwrap();
        let inspection = Consignment::decode_v1_for_inspection(&bytes).unwrap();

        assert_eq!(inspection.legacy_version, CONSIGNMENT_VERSION);
        assert_eq!(
            inspection.integrity.destination_binding,
            LegacyIntegrityStatus::StructurallyConsistent
        );
        assert_eq!(
            inspection.integrity.legacy_proof_bundle,
            LegacyIntegrityStatus::PresentUnverified
        );
        assert_eq!(
            inspection.integrity.source_closure,
            LegacyIntegrityStatus::Unavailable
        );
        assert_eq!(
            inspection.integrity.complete_envelope_authorization,
            LegacyIntegrityStatus::Unavailable
        );
        assert_eq!(
            inspection.integrity.portable_non_equivocation,
            LegacyIntegrityStatus::Unavailable
        );
        assert_eq!(
            hex::encode(csv_tagged_hash("consignment-v1-inspection-vector", &bytes)),
            "b21cebc995b7c215fea8e80b199e027d52aed925a17b12b8b42651c63d3000ce"
        );
    }

    #[test]
    fn v1_contradictory_destination_remains_inspectable() {
        let legacy = sample_consignment(sample_invoice(), false);
        let inspection =
            Consignment::decode_v1_for_inspection(&legacy.canonical_cbor().unwrap()).unwrap();
        assert_eq!(
            inspection.integrity.destination_binding,
            LegacyIntegrityStatus::Contradicted
        );
        assert_eq!(
            inspection.integrity.portable_non_equivocation,
            LegacyIntegrityStatus::Unavailable
        );
    }

    #[test]
    fn v1_decoder_rejects_extensions_and_unknown_versions() {
        #[derive(Serialize)]
        struct ExtendedV1 {
            version: u16,
            invoice: Invoice,
            sanad_id: SanadIdWire,
            proof_bundle: ProofBundle,
            source_closure: Vec<u8>,
            finality_upgrade: Vec<u8>,
        }

        let legacy = sample_consignment(sample_invoice(), true);
        let extended = ExtendedV1 {
            version: legacy.version,
            invoice: legacy.invoice.clone(),
            sanad_id: legacy.sanad_id.clone(),
            proof_bundle: legacy.proof_bundle.clone(),
            source_closure: vec![0xFA; 32],
            finality_upgrade: vec![0xFB; 32],
        };
        let bytes = to_canonical_cbor(&extended).unwrap();
        let error = Consignment::decode_v1_for_inspection(&bytes).unwrap_err();
        assert_eq!(
            error.code,
            LegacyConsignmentErrorCode::MalformedEncoding,
            "extension must fail with the stable malformed-encoding code"
        );

        let mut unknown = legacy;
        unknown.version = 99;
        assert_eq!(
            Consignment::decode_v1_for_inspection(&unknown.canonical_cbor().unwrap())
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn explicit_decoders_reject_competing_interpretations() {
        let v1_bytes = sample_consignment(sample_invoice(), true)
            .canonical_cbor()
            .unwrap();
        assert_eq!(
            ConsignmentV2::decode_v2(&v1_bytes).unwrap_err().code,
            ConsignmentV2ErrorCode::MalformedEncoding
        );

        let v2_bytes = sample_v2().canonical_cbor().unwrap();
        assert_eq!(
            Consignment::decode_v1_for_inspection(&v2_bytes)
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::MalformedEncoding
        );
    }

    #[test]
    fn malformed_truncated_and_extended_v1_fail_stably() {
        assert_eq!(
            Consignment::decode_v1_for_inspection(&[0xFF])
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::MalformedEncoding
        );

        let bytes = sample_consignment(sample_invoice(), true)
            .canonical_cbor()
            .unwrap();
        assert_eq!(
            Consignment::decode_v1_for_inspection(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::MalformedEncoding
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            Consignment::decode_v1_for_inspection(&trailing)
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::NonCanonicalEncoding
        );
    }

    #[test]
    fn malformed_v1_fields_fail_as_unsupported_artifacts() {
        let mut legacy = sample_consignment(sample_invoice(), true);
        legacy.sanad_id.bytes = "not-hex".into();
        assert_eq!(
            Consignment::decode_v1_for_inspection(&legacy.canonical_cbor().unwrap())
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::UnsupportedArtifact
        );

        let mut legacy = sample_consignment(sample_invoice(), true);
        legacy.proof_bundle.version = 2;
        assert_eq!(
            Consignment::decode_v1_for_inspection(&legacy.canonical_cbor().unwrap())
                .unwrap_err()
                .code,
            LegacyConsignmentErrorCode::UnsupportedArtifact
        );
    }

    #[test]
    fn v2_round_trip_is_explicit_and_canonical() {
        let consignment = sample_v2();
        assert_eq!(
            hex::encode(consignment.commitment.as_bytes()),
            "a30786a98a733fc92b8f26b4bbc64e45ef1a2bbf1c31ee5722f9a02344f577e3"
        );
        let bytes = consignment.canonical_cbor().unwrap();
        assert_eq!(ConsignmentV2::decode_v2(&bytes).unwrap(), consignment);

        let v1 = sample_consignment(sample_invoice(), true)
            .canonical_cbor()
            .unwrap();
        assert_eq!(
            ConsignmentV2::decode_v2(&v1).unwrap_err().code,
            ConsignmentV2ErrorCode::MalformedEncoding
        );
    }

    #[test]
    fn every_security_relevant_mutation_breaks_the_commitment() {
        let original = sample_v2();

        let mut destination = original.clone();
        destination.payload.destination.nonce ^= 1;
        assert_eq!(
            destination.validate().unwrap_err().code,
            ConsignmentV2ErrorCode::DestinationMismatch
        );

        let mut source = original.clone();
        source.payload.source.output_index += 1;
        assert_eq!(
            source.validate().unwrap_err().code,
            ConsignmentV2ErrorCode::SourceTransitionMismatch
        );

        let mut transition = original.clone();
        transition.payload.successor.validation_script.push(0xCC);
        assert_eq!(
            transition.validate().unwrap_err().code,
            ConsignmentV2ErrorCode::ClosureSuccessorMismatch
        );

        let mut closure = original.clone();
        closure.payload.source_closure.proof_material.push(0xDD);
        assert_eq!(
            closure.validate().unwrap_err().code,
            ConsignmentV2ErrorCode::CommitmentMismatch
        );
    }

    #[test]
    fn authorization_must_name_the_complete_envelope_commitment() {
        let mut consignment = sample_v2();
        consignment.authorizations[0].signed_commitment = Hash::new([0xEE; 32]);
        assert_eq!(
            consignment.validate().unwrap_err().code,
            ConsignmentV2ErrorCode::InvalidAuthorization
        );
    }

    #[test]
    fn trailing_bytes_are_rejected_as_noncanonical() {
        let mut bytes = sample_v2().canonical_cbor().unwrap();
        bytes.push(0);
        assert_eq!(
            ConsignmentV2::decode_v2(&bytes).unwrap_err().code,
            ConsignmentV2ErrorCode::NonCanonicalEncoding
        );
    }
}
