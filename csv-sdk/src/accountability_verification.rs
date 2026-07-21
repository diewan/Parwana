//! Pure accountability verification and the bounded local-import boundary.

pub use csv_accountability_verify::{
    AlgorithmStatus, AuthenticityStatus, EvidenceSummary, ReasonCode, ReplayStatus,
    RevocationStatus, Stage, StageDisposition, StageResult, TemporalContext,
    VerificationDisposition, VerificationInput, VerificationReport, assurance_profile, verify,
};

use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionIntent, ActionMandate,
    AttemptId, AuthenticityMaterial, ConsumptionRecord, ContextExtension, EvidenceKind,
    EvidenceNode, EvidenceNodeId, EvidenceRequirementStatus, ExecutionAttempt,
    ExecutionAttemptState, ExecutionOutcome, ExecutionReceipt, IntentId, MandateId, ObjectVersion,
    ProtocolVersion, SealConsumptionRecord, SourceLocator, VerificationContext,
};
use csv_wire::ActionIntentWire;
use serde::Deserialize;

/// Maximum accepted local verification-envelope size.
pub const MAX_LOCAL_VERIFICATION_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;

/// Fully decoded inputs for one local verification run.
pub struct DecodedVerificationBundle {
    /// Exact requested action.
    pub intent: ActionIntent,
    /// Pre-action authority.
    pub mandate: ActionMandate,
    /// Provider dispatch attempt.
    pub attempt: ExecutionAttempt,
    /// Producer outcome record.
    pub receipt: ExecutionReceipt,
    /// Canonically identified evidence graph.
    pub evidence: Vec<(EvidenceNodeId, EvidenceNode)>,
    /// Optional preserved single-use anchor, re-checked offline for independent single-use
    /// enforcement (Phase B, §5.9). `None` when the envelope carried no seal-consumption
    /// record, which the verifier reports as an external-corroboration limitation, never a
    /// failure (§5.5).
    pub single_use_anchor: Option<SealConsumptionRecord>,
}

/// Operator-selected, hash-bound context plus the conclusions supplied by its committed packages.
pub struct DecodedContextChoice {
    /// Human-readable local label; it is not part of protocol meaning.
    pub name: String,
    /// Exact effective verification context.
    pub context: VerificationContext,
    /// Conclusion from the committed revocation snapshot.
    pub revocation_status: RevocationStatus,
    /// Conclusion from the committed algorithm policy.
    pub algorithm_status: AlgorithmStatus,
    /// Conclusion from the committed single-use journal.
    pub replay_status: ReplayStatus,
    /// Context-supplied authenticity conclusions.
    pub evidence_authenticity: Vec<(EvidenceNodeId, AuthenticityStatus)>,
    /// Executor identity selected by the effective policy.
    pub expected_executor: Vec<u8>,
}

/// A local import failed before verification. No variant is downgraded to a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportError {
    /// No bytes were supplied.
    Empty,
    /// The input exceeded the pre-decode bound.
    TooLarge,
    /// JSON or hexadecimal transport syntax was malformed.
    Malformed,
    /// The envelope identifier is not supported.
    UnsupportedVersion,
    /// A decoded object violated protocol semantics or bindings.
    InvalidObject,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    intent: ActionIntentWire,
    mandate_canonical_hex: String,
    attempt: AttemptWire,
    receipt: ReceiptWire,
    evidence: Vec<EvidenceWire>,
    /// Optional disclosed single-use anchor. Absent in older bundles, so it defaults to
    /// `None`; a present-but-malformed record fails the whole import closed rather than
    /// being silently dropped.
    #[serde(default)]
    single_use_anchor: Option<SealConsumptionWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealConsumptionWire {
    seal_id_hex: String,
    nullifier_hex: String,
    commitment_hex: String,
    anchor_backend: String,
}

impl SealConsumptionWire {
    /// Decode into the canonical anchor type, failing closed on any drift.
    fn decode(self) -> Result<SealConsumptionRecord, ImportError> {
        let record = SealConsumptionRecord {
            seal_id: decode_digest32(&self.seal_id_hex)?,
            nullifier: decode_digest32(&self.nullifier_hex)?,
            commitment: decode_digest32(&self.commitment_hex)?,
            anchor_backend: self.anchor_backend,
        };
        record.validate().map_err(|_| ImportError::InvalidObject)?;
        Ok(record)
    }
}

/// Decode exactly 32 hex-encoded bytes, rejecting any other length or malformed hex.
fn decode_digest32(hex_str: &str) -> Result<[u8; 32], ImportError> {
    let bytes = hex::decode(hex_str).map_err(|_| ImportError::Malformed)?;
    bytes.try_into().map_err(|_| ImportError::InvalidObject)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextEnvelope {
    format: String,
    name: String,
    context_version: u16,
    protocol_major: u16,
    protocol_minor: u16,
    evaluation_time: u64,
    verifier_policy_digest_hex: String,
    trust_package_digest_hex: String,
    revocation_snapshot_digest_hex: String,
    algorithm_policy_digest_hex: String,
    external_evidence_policy_digest_hex: String,
    assurance_thresholds_digest_hex: String,
    extensions: Vec<ExtensionWire>,
    revocation_status: StatusWire,
    algorithm_status: StatusWire,
    replay_status: StatusWire,
    evidence_authenticity: Vec<AuthenticityAssessmentWire>,
    expected_executor_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtensionWire {
    registry_id: String,
    parameters_digest_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptWire {
    mandate_id_hex: String,
    mandate_digest_hex: String,
    intent_id_hex: String,
    reservation_token_digest_hex: String,
    executor_identity_hex: String,
    correlation_key_hex: String,
    started_at: u64,
    dispatch_boundary_at: Option<u64>,
    provider_request_digest_hex: String,
    provider_response_digest_hex: Option<String>,
    state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    mandate_id_hex: String,
    mandate_digest_hex: String,
    intent_id_hex: String,
    attempt_id_hex: String,
    executor_identity_hex: String,
    mandate_revision: u64,
    journal_entry_digest_hex: String,
    dispatch_evidence_refs: Vec<String>,
    target_evidence_refs: Vec<String>,
    started_at: u64,
    completed_at: Option<u64>,
    outcome: String,
    result_commitment_hex: Option<String>,
    evidence_requirements_status: Vec<RequirementWire>,
    producer_identity_hex: String,
    producer_signature_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementWire {
    registry_id: String,
    parameters_digest_hex: String,
    satisfied: bool,
    evidence_refs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EvidenceKindWire {
    Claim {
        proposition_digest_hex: String,
    },
    Observation {
        method_id: String,
    },
    Attestation {
        attester_identity_hex: String,
    },
    EvidenceGap {
        missing_registry_id: String,
        reason_digest_hex: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWire {
    id_hex: String,
    #[serde(flatten)]
    kind: EvidenceKindWire,
    producer_identity_hex: String,
    collected_at: u64,
    asserted_event_at: Option<u64>,
    content_digest_hex: String,
    media_type: String,
    source_locator: LocatorWire,
    authenticity: Option<AuthenticityWire>,
    disclosure_classification: String,
    relationships: Vec<String>,
}

#[derive(Deserialize)]
#[serde(tag = "disclosure", content = "value", rename_all = "snake_case")]
enum LocatorWire {
    Disclosed(String),
    Withheld(String),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticityWire {
    scheme_id: String,
    material_digest_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticityAssessmentWire {
    evidence_id_hex: String,
    status: StatusWire,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StatusWire {
    Allowed,
    Disallowed,
    Verified,
    Rejected,
    Fresh,
    Replayed,
    Revoked,
    NotRevoked,
    Unknown,
}

/// Decode the SDK-owned local envelope. This is transport decoding, never canonical serialization.
pub fn decode_local_verification_bundle(
    bytes: &[u8],
) -> Result<DecodedVerificationBundle, ImportError> {
    if bytes.is_empty() {
        return Err(ImportError::Empty);
    }
    if bytes.len() > MAX_LOCAL_VERIFICATION_ENVELOPE_BYTES {
        return Err(ImportError::TooLarge);
    }
    let wire: Envelope = serde_json::from_slice(bytes).map_err(|_| ImportError::Malformed)?;
    if wire.format != "org.diewan.accountability.local-verification.v1" {
        return Err(ImportError::UnsupportedVersion);
    }
    let intent = wire
        .intent
        .try_into()
        .map_err(|_| ImportError::InvalidObject)?;
    let mandate_bytes =
        hex::decode(wire.mandate_canonical_hex).map_err(|_| ImportError::Malformed)?;
    let mandate = ActionMandate::from_canonical_bytes(&mandate_bytes)
        .map_err(|_| ImportError::InvalidObject)?;
    let attempt = wire.attempt.decode()?;
    let receipt = wire.receipt.decode()?;
    let mut evidence = wire
        .evidence
        .into_iter()
        .map(EvidenceWire::decode)
        .collect::<Result<Vec<_>, _>>()?;
    evidence.sort_by_key(|item| item.0);
    let single_use_anchor = wire
        .single_use_anchor
        .map(SealConsumptionWire::decode)
        .transpose()?;
    Ok(DecodedVerificationBundle {
        intent,
        mandate,
        attempt,
        receipt,
        evidence,
        single_use_anchor,
    })
}

/// Decode a separately supplied context package. Bundle bytes cannot select their own trust inputs.
pub fn decode_local_context(bytes: &[u8]) -> Result<DecodedContextChoice, ImportError> {
    if bytes.is_empty() {
        return Err(ImportError::Empty);
    }
    if bytes.len() > MAX_LOCAL_VERIFICATION_ENVELOPE_BYTES {
        return Err(ImportError::TooLarge);
    }
    let wire: ContextEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ImportError::Malformed)?;
    if wire.format != "org.diewan.accountability.verification-context.v1"
        || wire.name.trim().is_empty()
    {
        return Err(ImportError::UnsupportedVersion);
    }
    let context = VerificationContext {
        context_version: ObjectVersion::try_new(wire.context_version)
            .map_err(|_| ImportError::UnsupportedVersion)?,
        protocol_version: ProtocolVersion::new(wire.protocol_major, wire.protocol_minor),
        evaluation_time: wire.evaluation_time,
        verifier_policy_digest: digest(&wire.verifier_policy_digest_hex)?,
        trust_package_digest: digest(&wire.trust_package_digest_hex)?,
        revocation_snapshot_digest: digest(&wire.revocation_snapshot_digest_hex)?,
        algorithm_policy_digest: digest(&wire.algorithm_policy_digest_hex)?,
        external_evidence_policy_digest: digest(&wire.external_evidence_policy_digest_hex)?,
        assurance_thresholds_digest: digest(&wire.assurance_thresholds_digest_hex)?,
        extensions: wire
            .extensions
            .into_iter()
            .map(|e| {
                Ok(ContextExtension {
                    registry_id: e.registry_id,
                    parameters_digest: digest(&e.parameters_digest_hex)?,
                })
            })
            .collect::<Result<_, _>>()?,
    };
    context.validate().map_err(|_| ImportError::InvalidObject)?;
    let mut evidence_authenticity = wire
        .evidence_authenticity
        .into_iter()
        .map(|a| {
            Ok((
                id(&a.evidence_id_hex)?,
                match a.status {
                    StatusWire::Verified => AuthenticityStatus::Verified,
                    StatusWire::Rejected => AuthenticityStatus::Rejected,
                    StatusWire::Unknown => AuthenticityStatus::Unknown,
                    _ => return Err(ImportError::InvalidObject),
                },
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    evidence_authenticity.sort_by_key(|item| item.0);
    Ok(DecodedContextChoice {
        name: wire.name,
        context,
        revocation_status: match wire.revocation_status {
            StatusWire::NotRevoked => RevocationStatus::NotRevoked,
            StatusWire::Revoked => RevocationStatus::Revoked,
            StatusWire::Unknown => RevocationStatus::Unknown,
            _ => return Err(ImportError::InvalidObject),
        },
        algorithm_status: match wire.algorithm_status {
            StatusWire::Allowed => AlgorithmStatus::Allowed,
            StatusWire::Disallowed => AlgorithmStatus::Disallowed,
            StatusWire::Unknown => AlgorithmStatus::Unknown,
            _ => return Err(ImportError::InvalidObject),
        },
        replay_status: match wire.replay_status {
            StatusWire::Fresh => ReplayStatus::Fresh,
            StatusWire::Replayed => ReplayStatus::Replayed,
            StatusWire::Unknown => ReplayStatus::Unknown,
            _ => return Err(ImportError::InvalidObject),
        },
        evidence_authenticity,
        expected_executor: bytes_hex(&wire.expected_executor_hex)?,
    })
}

impl AttemptWire {
    fn decode(self) -> Result<ExecutionAttempt, ImportError> {
        Ok(ExecutionAttempt {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            attempt_version: ACCOUNTABILITY_OBJECT_VERSION,
            mandate_id: MandateId::from_digest(digest(&self.mandate_id_hex)?),
            mandate_digest: digest(&self.mandate_digest_hex)?,
            intent_id: IntentId::from_digest(digest(&self.intent_id_hex)?),
            reservation_token_digest: digest(&self.reservation_token_digest_hex)?,
            executor_identity: bytes_hex(&self.executor_identity_hex)?,
            correlation_key: bytes_hex(&self.correlation_key_hex)?,
            started_at: self.started_at,
            dispatch_boundary_at: self.dispatch_boundary_at,
            provider_request_digest: digest(&self.provider_request_digest_hex)?,
            provider_response_digest: self
                .provider_response_digest_hex
                .as_deref()
                .map(digest)
                .transpose()?,
            state: match self.state.as_str() {
                "prepared" => ExecutionAttemptState::Prepared,
                "dispatching" => ExecutionAttemptState::Dispatching,
                "accepted" => ExecutionAttemptState::Accepted,
                "rejected" => ExecutionAttemptState::Rejected,
                "outcome_ambiguous" => ExecutionAttemptState::OutcomeAmbiguous,
                "reconciled_accepted" => ExecutionAttemptState::ReconciledAccepted,
                "reconciled_not_accepted" => ExecutionAttemptState::ReconciledNotAccepted,
                "abandoned_ambiguous" => ExecutionAttemptState::AbandonedAmbiguous,
                _ => return Err(ImportError::InvalidObject),
            },
        })
    }
}

impl ReceiptWire {
    fn decode(self) -> Result<ExecutionReceipt, ImportError> {
        Ok(ExecutionReceipt {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            receipt_version: ACCOUNTABILITY_OBJECT_VERSION,
            mandate_id: MandateId::from_digest(digest(&self.mandate_id_hex)?),
            mandate_digest: digest(&self.mandate_digest_hex)?,
            intent_id: IntentId::from_digest(digest(&self.intent_id_hex)?),
            attempt_id: AttemptId::from_digest(digest(&self.attempt_id_hex)?),
            executor_identity: bytes_hex(&self.executor_identity_hex)?,
            consumption_record: ConsumptionRecord {
                mandate_revision: self.mandate_revision,
                journal_entry_digest: digest(&self.journal_entry_digest_hex)?,
            },
            dispatch_evidence_refs: ids(&self.dispatch_evidence_refs)?,
            target_evidence_refs: ids(&self.target_evidence_refs)?,
            started_at: self.started_at,
            completed_at: self.completed_at,
            outcome: match self.outcome.as_str() {
                "succeeded" => ExecutionOutcome::Succeeded,
                "failed" => ExecutionOutcome::Failed,
                "rejected" => ExecutionOutcome::Rejected,
                "unknown" => ExecutionOutcome::Unknown,
                _ => return Err(ImportError::InvalidObject),
            },
            result_commitment: self
                .result_commitment_hex
                .as_deref()
                .map(digest)
                .transpose()?,
            evidence_requirements_status: self
                .evidence_requirements_status
                .into_iter()
                .map(|r| {
                    Ok(EvidenceRequirementStatus {
                        registry_id: r.registry_id,
                        parameters_digest: digest(&r.parameters_digest_hex)?,
                        satisfied: r.satisfied,
                        evidence_refs: ids(&r.evidence_refs)?,
                    })
                })
                .collect::<Result<_, _>>()?,
            producer_identity: bytes_hex(&self.producer_identity_hex)?,
            producer_signature: bytes_hex(&self.producer_signature_hex)?,
        })
    }
}

impl EvidenceWire {
    fn decode(self) -> Result<(EvidenceNodeId, EvidenceNode), ImportError> {
        let supplied = id(&self.id_hex)?;
        let node = EvidenceNode {
            kind: match self.kind {
                EvidenceKindWire::Claim {
                    proposition_digest_hex,
                } => EvidenceKind::Claim {
                    proposition_digest: digest(&proposition_digest_hex)?,
                },
                EvidenceKindWire::Observation { method_id } => {
                    EvidenceKind::Observation { method_id }
                }
                EvidenceKindWire::Attestation {
                    attester_identity_hex,
                } => EvidenceKind::Attestation {
                    attester_identity: bytes_hex(&attester_identity_hex)?,
                },
                EvidenceKindWire::EvidenceGap {
                    missing_registry_id,
                    reason_digest_hex,
                } => EvidenceKind::EvidenceGap {
                    missing_registry_id,
                    reason_digest: digest(&reason_digest_hex)?,
                },
            },
            producer_identity: bytes_hex(&self.producer_identity_hex)?,
            collected_at: self.collected_at,
            asserted_event_at: self.asserted_event_at,
            content_digest: digest(&self.content_digest_hex)?,
            media_type: self.media_type,
            source_locator: match self.source_locator {
                LocatorWire::Disclosed(v) => SourceLocator::Disclosed(v),
                LocatorWire::Withheld(v) => SourceLocator::Withheld(digest(&v)?),
            },
            authenticity: self
                .authenticity
                .map(|a| {
                    Ok(AuthenticityMaterial {
                        scheme_id: a.scheme_id,
                        material_digest: digest(&a.material_digest_hex)?,
                    })
                })
                .transpose()?,
            disclosure_classification: self.disclosure_classification,
            relationships: ids(&self.relationships)?,
        };
        if node.id().map_err(|_| ImportError::InvalidObject)? != supplied {
            return Err(ImportError::InvalidObject);
        }
        Ok((supplied, node))
    }
}

fn bytes_hex(value: &str) -> Result<Vec<u8>, ImportError> {
    hex::decode(value).map_err(|_| ImportError::Malformed)
}
fn digest(value: &str) -> Result<[u8; 32], ImportError> {
    bytes_hex(value)?
        .try_into()
        .map_err(|_| ImportError::Malformed)
}
fn id(value: &str) -> Result<EvidenceNodeId, ImportError> {
    Ok(EvidenceNodeId::from_digest(digest(value)?))
}
fn ids(values: &[String]) -> Result<Vec<EvidenceNodeId>, ImportError> {
    values.iter().map(|value| id(value)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_rejects_empty_malformed_and_unsupported_envelopes() {
        assert!(matches!(
            decode_local_verification_bundle(b""),
            Err(ImportError::Empty)
        ));
        assert!(matches!(
            decode_local_verification_bundle(b"{"),
            Err(ImportError::Malformed)
        ));
        assert!(matches!(
            decode_local_context(br#"{"format":"old"}"#),
            Err(ImportError::Malformed)
        ));
    }

    #[test]
    fn context_import_is_explicit_and_hash_bound() {
        let digest = "11".repeat(32);
        let json = format!(
            r#"{{"format":"org.diewan.accountability.verification-context.v1","name":"Production policy","context_version":1,"protocol_major":0,"protocol_minor":1,"evaluation_time":150,"verifier_policy_digest_hex":"{digest}","trust_package_digest_hex":"{digest}","revocation_snapshot_digest_hex":"{digest}","algorithm_policy_digest_hex":"{digest}","external_evidence_policy_digest_hex":"{digest}","assurance_thresholds_digest_hex":"{digest}","extensions":[],"revocation_status":"unknown","algorithm_status":"unknown","replay_status":"unknown","evidence_authenticity":[],"expected_executor_hex":"6578656375746f72"}}"#
        );
        let imported = decode_local_context(json.as_bytes()).expect("supported context");
        assert_eq!(imported.name, "Production policy");
        assert!(imported.context.id().is_ok());
        assert_eq!(imported.revocation_status, RevocationStatus::Unknown);
    }

    #[test]
    fn seal_consumption_wire_decodes_a_well_formed_record() {
        let wire = SealConsumptionWire {
            seal_id_hex: "11".repeat(32),
            nullifier_hex: "22".repeat(32),
            commitment_hex: "33".repeat(32),
            anchor_backend: "csv-seal.local.v1".to_owned(),
        };
        let record = wire.decode().expect("well-formed anchor decodes");
        assert_eq!(record.seal_id, [0x11; 32]);
        assert_eq!(record.nullifier, [0x22; 32]);
        assert_eq!(record.commitment, [0x33; 32]);
        assert_eq!(record.anchor_backend, "csv-seal.local.v1");
    }

    #[test]
    fn seal_consumption_wire_fails_closed_on_malformed_records() {
        // Malformed hex is a transport error.
        let bad_hex = SealConsumptionWire {
            seal_id_hex: "zz".repeat(32),
            nullifier_hex: "22".repeat(32),
            commitment_hex: "33".repeat(32),
            anchor_backend: "csv-seal.local.v1".to_owned(),
        };
        assert!(matches!(bad_hex.decode(), Err(ImportError::Malformed)));

        // A wrong-length digest is a bound violation, not mere syntax.
        let short = SealConsumptionWire {
            seal_id_hex: "11".repeat(31),
            nullifier_hex: "22".repeat(32),
            commitment_hex: "33".repeat(32),
            anchor_backend: "csv-seal.local.v1".to_owned(),
        };
        assert!(matches!(short.decode(), Err(ImportError::InvalidObject)));

        // An all-zero digest and an empty backend both fail the canonical validation.
        let zero = SealConsumptionWire {
            seal_id_hex: "00".repeat(32),
            nullifier_hex: "22".repeat(32),
            commitment_hex: "33".repeat(32),
            anchor_backend: "csv-seal.local.v1".to_owned(),
        };
        assert!(matches!(zero.decode(), Err(ImportError::InvalidObject)));
        let empty_backend = SealConsumptionWire {
            seal_id_hex: "11".repeat(32),
            nullifier_hex: "22".repeat(32),
            commitment_hex: "33".repeat(32),
            anchor_backend: String::new(),
        };
        assert!(matches!(
            empty_backend.decode(),
            Err(ImportError::InvalidObject)
        ));
    }

    #[test]
    fn oversized_input_is_rejected_before_json_decode() {
        let bytes = vec![b' '; MAX_LOCAL_VERIFICATION_ENVELOPE_BYTES + 1];
        assert!(matches!(
            decode_local_verification_bundle(&bytes),
            Err(ImportError::TooLarge)
        ));
    }

    #[test]
    fn sdk_facade_computes_a_positive_fixture_without_io() {
        let fixture = csv_testkit::accountability::AccountabilityFixture::valid();
        let authenticity = fixture
            .evidence
            .iter()
            .filter(|(_, node)| node.authenticity.is_some())
            .map(|(id, _)| (*id, AuthenticityStatus::Verified))
            .collect::<Vec<_>>();
        let output = verify(
            &fixture.context,
            VerificationInput {
                intent: &fixture.intent,
                mandate: &fixture.mandate,
                attempt: &fixture.attempt,
                receipt: &fixture.receipt,
                evidence: &fixture.evidence,
                evidence_authenticity: &authenticity,
                expected_executor: &fixture.executor,
                revocation_status: RevocationStatus::NotRevoked,
                algorithm_status: AlgorithmStatus::Allowed,
                replay_status: ReplayStatus::Fresh,
                single_use_anchor: None,
            },
        )
        .expect("fixture context is supported");
        assert_eq!(output.result.disposition, VerificationDisposition::Valid);
        assert_eq!(
            output.verification_context_id,
            fixture.context.id().unwrap()
        );
    }
}
