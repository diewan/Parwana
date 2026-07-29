//! Deterministic, atomic recipient acceptance of portable V2 consignments.

use csv_chain_ports::ClosureProofVerifier;
use csv_hash::Hash;
use csv_protocol::signature::Signature;
use csv_protocol::{
    ClosureDimensionStatus, ClosureTrustMode, FinalizedCheckpoint, SignatureScheme, StateUseSchema,
};
use csv_storage::{
    AcceptedAssuranceReading, AcceptedAssuranceReport, AcceptedStateError,
    AcceptedStateObservation, AcceptedStateRecord, AcceptedStateStatus, AcceptedStateStore,
};
use csv_verifier::{
    DimensionAssurance, DimensionStatus, ProofKind, ProofProvider, ProtocolAssuranceDimension,
    ProtocolAssuranceReport, ProtocolAssuranceReportBuilder, ProtocolReasonCode,
    status_registry_id,
};
use csv_wire::{ConsignmentV2, ConsignmentV2Error, ConsignmentV2ErrorCode};

/// A signer the recipient explicitly trusts to authorize a consignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedSigner {
    /// Signature algorithm expected for this key.
    pub scheme: SignatureScheme,
    /// Canonical public-key bytes.
    pub public_key: Vec<u8>,
}

/// All recipient-controlled inputs to one deterministic acceptance decision.
pub struct AcceptanceContext<'a> {
    /// Digest naming the exact verification rules and external inputs.
    pub verification_context: Hash,
    /// Exact finalized checkpoint against which closure must be verified.
    pub checkpoint: &'a FinalizedCheckpoint,
    /// Expected chain-native proof-material provider.
    pub proof_provider_id: &'a str,
    /// Trust assumption permitted by the recipient.
    pub trust_mode: ClosureTrustMode,
    /// Recipient's maximum accepted checkpoint age.
    pub maximum_checkpoint_age: u64,
    /// Schema used to validate state-use semantics.
    pub state_use_schema: &'a StateUseSchema,
    /// Explicit recipient-controlled authorization set.
    pub authorized_signers: &'a [AuthorizedSigner],
}

/// Stable stage-specific recipient acceptance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptanceErrorCode {
    /// Canonical V2 decoding or version validation failed.
    Decode,
    /// Canonical DAG or transition state semantics failed.
    Semantics,
    /// Authorization was absent, untrusted, malformed, or cryptographically invalid.
    Authorization,
    /// Chain-native source-closure verification could not establish closure.
    SourceClosure,
    /// Inclusion was not established.
    Inclusion,
    /// Checkpoint finality was not established.
    Finality,
    /// Checkpoint freshness was not established.
    Freshness,
    /// Destination invoice binding failed.
    DestinationBinding,
    /// Explicit caller and consignment verification inputs disagree.
    VerificationContext,
    /// Another successor already consumed the source state.
    Conflict,
    /// Atomic persistence failed.
    Persistence,
}

impl AcceptanceErrorCode {
    /// Stable registry identifier suitable for CLI, SDK, and persistence boundaries.
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::Decode => "ACCEPT.V2.DECODE",
            Self::Semantics => "ACCEPT.V2.SEMANTICS",
            Self::Authorization => "ACCEPT.V2.AUTHORIZATION",
            Self::SourceClosure => "ACCEPT.V2.SOURCE_CLOSURE",
            Self::Inclusion => "ACCEPT.V2.INCLUSION",
            Self::Finality => "ACCEPT.V2.FINALITY",
            Self::Freshness => "ACCEPT.V2.FRESHNESS",
            Self::DestinationBinding => "ACCEPT.V2.DESTINATION_BINDING",
            Self::VerificationContext => "ACCEPT.V2.VERIFICATION_CONTEXT",
            Self::Conflict => "ACCEPT.V2.CONFLICT",
            Self::Persistence => "ACCEPT.V2.PERSISTENCE",
        }
    }

    /// Every failure code this family defines, in stable published order.
    pub const ALL: &'static [Self] = &[
        Self::Decode,
        Self::Semantics,
        Self::Authorization,
        Self::SourceClosure,
        Self::Inclusion,
        Self::Finality,
        Self::Freshness,
        Self::DestinationBinding,
        Self::VerificationContext,
        Self::Conflict,
        Self::Persistence,
    ];
}

/// Actionable rejection detail with a stable machine-readable code.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", code.registry_id())]
pub struct AcceptanceError {
    /// Pipeline-stage code.
    pub code: AcceptanceErrorCode,
    /// Non-authoritative diagnostic detail.
    pub detail: String,
}

impl AcceptanceError {
    fn new(code: AcceptanceErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Successful acceptance, including the complete typed assurance report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceResult {
    /// Accepted successor transition commitment.
    pub transition_id: Hash,
    /// Full dimensioned report used for the commit decision.
    pub assurance: ProtocolAssuranceReport,
}

impl AcceptanceResult {
    /// Stable registry identifier for a successful V2 acceptance.
    ///
    /// The acceptance vocabulary needs an affirmative member: without one, the
    /// only publishable codes are failures, and a package describing the
    /// positive path has nothing real to name. This is the code the portable
    /// conformance package's `valid-v2` case tells a consumer to expect.
    pub const REGISTRY_ID: &'static str = "ACCEPT.V2.ACCEPTED";

    /// Stable registry identifier for this outcome.
    pub const fn registry_id(&self) -> &'static str {
        Self::REGISTRY_ID
    }
}

/// Verified V2 consignment whose fields cannot be replaced by callers.
pub struct VerifiedConsignment {
    consignment: ConsignmentV2,
    closure: csv_protocol::ClosureVerificationResult,
    assurance: ProtocolAssuranceReport,
}

impl VerifiedConsignment {
    /// Verified successor transition commitment.
    pub fn transition_id(&self) -> Hash {
        self.consignment.payload.successor.commitment()
    }

    /// Complete typed assurance report produced by verification.
    pub fn assurance(&self) -> &ProtocolAssuranceReport {
        &self.assurance
    }
}

/// Verify a canonical V2 consignment without mutating recipient state.
pub async fn verify_consignment_v2(
    bytes: &[u8],
    context: &AcceptanceContext<'_>,
    closure_verifier: &dyn ClosureProofVerifier,
) -> Result<VerifiedConsignment, AcceptanceError> {
    let consignment = ConsignmentV2::decode_v2(bytes).map_err(map_wire_error)?;

    verify_decoded_consignment(consignment, context, closure_verifier).await
}

async fn verify_decoded_consignment(
    consignment: ConsignmentV2,
    context: &AcceptanceContext<'_>,
    closure_verifier: &dyn ClosureProofVerifier,
) -> Result<VerifiedConsignment, AcceptanceError> {
    let requirements = &consignment.payload.proof_requirements;
    if requirements.verification_context != context.verification_context
        || &requirements.checkpoint != context.checkpoint
        || requirements.proof_provider_id != context.proof_provider_id
        || requirements.trust_mode != context.trust_mode
        || requirements.maximum_checkpoint_age != context.maximum_checkpoint_age
        || context.maximum_checkpoint_age == 0
    {
        return Err(AcceptanceError::new(
            AcceptanceErrorCode::VerificationContext,
            "consignment proof requirements do not exactly match recipient inputs",
        ));
    }

    // Stage 2: validate semantics using recipient-supplied schema rules.
    consignment
        .payload
        .successor
        .validate_rules(context.state_use_schema)
        .map_err(|error| AcceptanceError::new(AcceptanceErrorCode::Semantics, error.to_string()))?;

    // Stage 3: embedded keys are evidence, not authority. At least one valid
    // signature must match the recipient's explicit authorization set, and every
    // supplied signature must be valid to prevent smuggling malformed evidence.
    if context.authorized_signers.is_empty() {
        return Err(AcceptanceError::new(
            AcceptanceErrorCode::Authorization,
            "recipient authorized-signer set is empty",
        ));
    }
    let mut trusted_signature = false;
    for authorization in &consignment.authorizations {
        Signature::new(
            authorization.signature.clone(),
            authorization.public_key.clone(),
            consignment.commitment.as_bytes().to_vec(),
        )
        .verify(authorization.scheme)
        .map_err(|error| {
            AcceptanceError::new(AcceptanceErrorCode::Authorization, error.to_string())
        })?;
        trusted_signature |= context.authorized_signers.iter().any(|signer| {
            signer.scheme == authorization.scheme && signer.public_key == authorization.public_key
        });
    }
    if !trusted_signature {
        return Err(AcceptanceError::new(
            AcceptanceErrorCode::Authorization,
            "no valid signature belongs to the recipient's authorized signer set",
        ));
    }

    // Stages 4–6: the provider consumes actual proof bytes. Its independent
    // dimension readings are never collapsed into one success flag.
    let closure = closure_verifier
        .verify_closure(&consignment.payload.source_closure, context.checkpoint)
        .await
        .map_err(|error| {
            AcceptanceError::new(AcceptanceErrorCode::SourceClosure, error.to_string())
        })?;
    closure.validate().map_err(|error| {
        AcceptanceError::new(AcceptanceErrorCode::SourceClosure, error.to_string())
    })?;
    if closure.checkpoint != *context.checkpoint
        || closure.proof_provider_id != context.proof_provider_id
        || closure.trust_mode != context.trust_mode
        || closure.proof_kind != consignment.payload.source_closure.proof_kind
    {
        return Err(AcceptanceError::new(
            AcceptanceErrorCode::VerificationContext,
            "closure result provenance does not match recipient inputs",
        ));
    }
    let closure_failure = if closure
        .reason_codes
        .iter()
        .any(|code| code == "PROTOCOL.CLOSURE.CONFLICT")
    {
        AcceptanceErrorCode::Conflict
    } else {
        AcceptanceErrorCode::SourceClosure
    };
    require_satisfied(
        closure.source_closure,
        closure_failure,
        &closure.reason_codes,
    )?;
    require_satisfied(
        closure.proof_validity,
        AcceptanceErrorCode::Inclusion,
        &closure.reason_codes,
    )?;
    require_satisfied(
        closure.checkpoint_finality,
        AcceptanceErrorCode::Finality,
        &closure.reason_codes,
    )?;
    require_satisfied(
        closure.checkpoint_freshness,
        AcceptanceErrorCode::Freshness,
        &closure.reason_codes,
    )?;

    // Destination was structurally checked during decode; repeat it at its named
    // pipeline boundary so future structural refactors cannot silently omit it.
    let destination = consignment
        .payload
        .destination
        .bound_seal_point()
        .map_err(|error| AcceptanceError::new(AcceptanceErrorCode::DestinationBinding, error))?;
    if !consignment.payload.successor.outputs.iter().any(|output| {
        csv_hash::seal::SealPoint::try_from(output.seal.clone())
            .is_ok_and(|seal| seal == destination)
    }) {
        return Err(AcceptanceError::new(
            AcceptanceErrorCode::DestinationBinding,
            "successor does not assign an output to the invoiced seal",
        ));
    }

    let mut report_builder = ProtocolAssuranceReportBuilder::new(context.verification_context);
    report_builder
        .record(satisfied(
            ProtocolAssuranceDimension::CanonicalStructure,
            ProofKind::CanonicalRules,
            ProtocolReasonCode::StructureValidated,
        ))
        .record(satisfied(
            ProtocolAssuranceDimension::TransitionSemantics,
            ProofKind::CanonicalRules,
            ProtocolReasonCode::TransitionBindingVerified,
        ))
        .record(satisfied(
            ProtocolAssuranceDimension::Authorization,
            ProofKind::DigitalSignature,
            ProtocolReasonCode::SignaturesVerified,
        ))
        .record_closure_result(&closure);
    let report = report_builder.build();

    Ok(VerifiedConsignment {
        consignment,
        closure,
        assurance: report,
    })
}

/// Verify a canonical V2 consignment and atomically persist its accepted successor.
///
/// Repeating the same request is idempotent. A different successor for the same
/// source produces [`AcceptanceErrorCode::Conflict`].
pub async fn accept_consignment_v2(
    bytes: &[u8],
    context: &AcceptanceContext<'_>,
    closure_verifier: &dyn ClosureProofVerifier,
    store: &dyn AcceptedStateStore,
) -> Result<AcceptanceResult, AcceptanceError> {
    let verified = verify_consignment_v2(bytes, context, closure_verifier).await?;
    let transition_id = verified.transition_id();
    let consignment = &verified.consignment;
    let record = AcceptedStateRecord {
        transition_id,
        consumed_state: consignment.payload.source,
        created_outputs: consignment.payload.successor.created_output_commitments(),
        closure_id: consignment.payload.source_closure.commitment(),
        closure: verified.closure,
        assurance: persisted_report(&verified.assurance),
        transfer_id: None,
        status: AcceptedStateStatus::Final,
        observations: vec![AcceptedStateObservation {
            sequence: 0,
            status: AcceptedStateStatus::Final,
            checkpoint_id: context.checkpoint.commitment(),
            // The storage layer owns this observation's vocabulary; the
            // acceptance decision's own outcome code is
            // `AcceptanceResult::REGISTRY_ID`. Two layers, two published
            // families — never a third, unregistered spelling.
            reason: csv_storage::CheckpointObservationCode::Committed
                .registry_id()
                .into(),
        }],
    };
    store.accept(record).await.map_err(map_store_error)?;

    Ok(AcceptanceResult {
        transition_id,
        assurance: verified.assurance,
    })
}

fn satisfied(
    dimension: ProtocolAssuranceDimension,
    proof_kind: ProofKind,
    reason: ProtocolReasonCode,
) -> DimensionAssurance {
    DimensionAssurance::new(
        dimension,
        DimensionStatus::Satisfied,
        [reason],
        ProofProvider::local(proof_kind),
        Vec::<String>::new(),
    )
}

fn require_satisfied(
    status: ClosureDimensionStatus,
    code: AcceptanceErrorCode,
    reasons: &[String],
) -> Result<(), AcceptanceError> {
    if status == ClosureDimensionStatus::Satisfied {
        Ok(())
    } else {
        Err(AcceptanceError::new(
            code,
            format!("{status:?}: {}", reasons.join(",")),
        ))
    }
}

fn persisted_report(report: &ProtocolAssuranceReport) -> AcceptedAssuranceReport {
    AcceptedAssuranceReport {
        verification_context_digest: report.verification_context_digest(),
        report_digest: report.digest(),
        readings: report
            .dimensions()
            .iter()
            .map(|reading| AcceptedAssuranceReading {
                dimension: reading.dimension.registry_id().into(),
                status: status_registry_id(reading.status).into(),
                reason_codes: reading
                    .reason_codes
                    .iter()
                    .map(|code| code.registry_id().into())
                    .collect(),
                provider_id: reading.provider.provider_id.clone(),
                limitations: reading.limitations.clone(),
            })
            .collect(),
    }
}

fn map_store_error(error: AcceptedStateError) -> AcceptanceError {
    match error {
        AcceptedStateError::Conflict {
            existing_transition,
        } => AcceptanceError::new(
            AcceptanceErrorCode::Conflict,
            format!("source already has successor {existing_transition}"),
        ),
        other => AcceptanceError::new(AcceptanceErrorCode::Persistence, other.to_string()),
    }
}

fn map_wire_error(error: ConsignmentV2Error) -> AcceptanceError {
    let code = match error.code {
        ConsignmentV2ErrorCode::MalformedEncoding
        | ConsignmentV2ErrorCode::NonCanonicalEncoding
        | ConsignmentV2ErrorCode::UnsupportedProtocolVersion
        | ConsignmentV2ErrorCode::UnsupportedEnvelopeVersion => AcceptanceErrorCode::Decode,
        ConsignmentV2ErrorCode::SourceTransitionMismatch
        | ConsignmentV2ErrorCode::ClosureSourceMismatch
        | ConsignmentV2ErrorCode::ClosureSuccessorMismatch
        | ConsignmentV2ErrorCode::InvalidClosureProof => AcceptanceErrorCode::Semantics,
        ConsignmentV2ErrorCode::DestinationMismatch => AcceptanceErrorCode::DestinationBinding,
        ConsignmentV2ErrorCode::InvalidProofRequirements => {
            AcceptanceErrorCode::VerificationContext
        }
        ConsignmentV2ErrorCode::CommitmentMismatch
        | ConsignmentV2ErrorCode::MissingAuthorization
        | ConsignmentV2ErrorCode::InvalidAuthorization => AcceptanceErrorCode::Authorization,
    };
    AcceptanceError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use csv_chain_ports::{AdapterError, AdapterResult};
    use csv_hash::seal::SealPoint;
    use csv_protocol::ConsumedStateRef;
    use csv_protocol::closure::{
        ClosureProof, ClosureProofKind, ClosureVerificationResult, FinalityPolicy,
    };
    use csv_protocol::exclusivity::{ConsumptionMode, ExclusivityClass};
    use csv_protocol::resolution::{ParentOutput, ResolvedInput, ResolvedTransition};
    use csv_protocol::state::StateAssignment;
    use csv_storage::InMemoryAcceptedStateStore;
    use csv_wire::{
        ConsignmentAuthorization, ConsignmentProofRequirements, ConsignmentV2Payload, Invoice,
        SealDefinition,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const VALID_PROOF_BYTE: u8 = 0x77;

    struct TestClosureVerifier;

    #[async_trait]
    impl ClosureProofVerifier for TestClosureVerifier {
        async fn verify_closure(
            &self,
            proof: &ClosureProof,
            checkpoint: &FinalizedCheckpoint,
        ) -> AdapterResult<ClosureVerificationResult> {
            let proof_validity = if proof.proof_material == vec![VALID_PROOF_BYTE; 64] {
                ClosureDimensionStatus::Satisfied
            } else {
                ClosureDimensionStatus::Failed
            };
            Ok(ClosureVerificationResult {
                chain_id: checkpoint.chain_id.clone(),
                network_id: checkpoint.network_id.clone(),
                proof_kind: proof.proof_kind.clone(),
                checkpoint: checkpoint.clone(),
                proof_validity,
                checkpoint_finality: ClosureDimensionStatus::Satisfied,
                checkpoint_freshness: ClosureDimensionStatus::Satisfied,
                source_closure: if proof_validity == ClosureDimensionStatus::Satisfied {
                    ClosureDimensionStatus::Satisfied
                } else {
                    ClosureDimensionStatus::Failed
                },
                trust_mode: ClosureTrustMode::LightClient,
                verifier_id: "test-cryptographic-verifier-v1".into(),
                proof_provider_id: "bitcoin-spv-v1".into(),
                reason_codes: vec!["TEST.CLOSURE.EVALUATED".into()],
            })
        }
    }

    struct DimensionFailureVerifier {
        code: AcceptanceErrorCode,
    }

    /// Recipient-independent stand-in for one finalized source-chain ordering.
    #[derive(Default)]
    struct FinalizedSourceOrdering {
        winner: std::sync::Mutex<Option<Hash>>,
    }

    #[async_trait]
    impl ClosureProofVerifier for FinalizedSourceOrdering {
        async fn verify_closure(
            &self,
            proof: &ClosureProof,
            checkpoint: &FinalizedCheckpoint,
        ) -> AdapterResult<ClosureVerificationResult> {
            let mut winner = self.winner.lock().expect("ordering lock");
            let accepted = winner.is_none_or(|commitment| commitment == proof.successor_commitment);
            if winner.is_none() {
                *winner = Some(proof.successor_commitment);
            }
            let status = if accepted {
                ClosureDimensionStatus::Satisfied
            } else {
                ClosureDimensionStatus::Failed
            };
            Ok(ClosureVerificationResult {
                chain_id: checkpoint.chain_id.clone(),
                network_id: checkpoint.network_id.clone(),
                proof_kind: proof.proof_kind.clone(),
                checkpoint: checkpoint.clone(),
                proof_validity: status,
                checkpoint_finality: ClosureDimensionStatus::Satisfied,
                checkpoint_freshness: ClosureDimensionStatus::Satisfied,
                source_closure: status,
                trust_mode: ClosureTrustMode::LightClient,
                verifier_id: "finalized-source-ordering-v1".into(),
                proof_provider_id: "bitcoin-spv-v1".into(),
                reason_codes: vec![if accepted {
                    "PROTOCOL.CLOSURE.UNIQUE_SUCCESSOR".into()
                } else {
                    "PROTOCOL.CLOSURE.CONFLICT".into()
                }],
            })
        }
    }

    #[async_trait]
    impl ClosureProofVerifier for DimensionFailureVerifier {
        async fn verify_closure(
            &self,
            proof: &ClosureProof,
            checkpoint: &FinalizedCheckpoint,
        ) -> AdapterResult<ClosureVerificationResult> {
            let mut result = TestClosureVerifier
                .verify_closure(proof, checkpoint)
                .await?;
            match self.code {
                AcceptanceErrorCode::Inclusion => {
                    result.proof_validity = ClosureDimensionStatus::Failed
                }
                AcceptanceErrorCode::Finality => {
                    result.checkpoint_finality = ClosureDimensionStatus::Failed
                }
                AcceptanceErrorCode::Freshness => {
                    result.checkpoint_freshness = ClosureDimensionStatus::Failed
                }
                AcceptanceErrorCode::SourceClosure => {
                    result.source_closure = ClosureDimensionStatus::Failed
                }
                _ => unreachable!(),
            }
            Ok(result)
        }
    }

    struct FailingStore;

    #[async_trait]
    impl AcceptedStateStore for FailingStore {
        async fn accept(&self, _: AcceptedStateRecord) -> Result<(), AcceptedStateError> {
            Err(AcceptedStateError::Storage("injected failure".into()))
        }

        async fn get(
            &self,
            _: &ConsumedStateRef,
        ) -> Result<Option<AcceptedStateRecord>, AcceptedStateError> {
            Ok(None)
        }

        async fn reconcile_checkpoint(
            &self,
            _: Hash,
            _: csv_storage::CheckpointDisposition,
        ) -> Result<Vec<Hash>, AcceptedStateError> {
            Ok(Vec::new())
        }
    }

    struct Fixture {
        bytes: Vec<u8>,
        context_digest: Hash,
        checkpoint: FinalizedCheckpoint,
        schema: StateUseSchema,
        signer: AuthorizedSigner,
        source: ConsumedStateRef,
    }

    fn fixture(output_byte: u8, proof_byte: u8) -> Fixture {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let invoice = Invoice::new(
            SealDefinition::sui(vec![0xCD; 32], 7).unwrap(),
            vec![1; 32],
            9,
        )
        .unwrap();
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
            vec![signing_key.verifying_key().to_bytes().to_vec()],
        );
        let successor = ResolvedTransition {
            transition_id: 9,
            inputs: vec![ResolvedInput {
                reference: source.clone(),
                parent,
                mode: ConsumptionMode::Exclusive,
            }],
            outputs: vec![StateAssignment::new(7, destination, vec![output_byte])],
            validation_script: vec![0x66],
        };
        let checkpoint = FinalizedCheckpoint {
            chain_id: "bitcoin".into(),
            network_id: "signet".into(),
            block_height: 100,
            block_id: vec![0x88; 32],
            finality_policy: FinalityPolicy::Confirmations(6),
        };
        let context_digest = Hash::new([0x99; 32]);
        let payload = ConsignmentV2Payload::new(
            source.clone(),
            successor.clone(),
            ClosureProof {
                consumed_state: source.clone(),
                successor_commitment: successor.commitment(),
                proof_kind: ClosureProofKind::BitcoinTransactionInclusion,
                proof_material: vec![proof_byte; 64],
            },
            invoice,
            ConsignmentProofRequirements {
                checkpoint: checkpoint.clone(),
                trust_mode: ClosureTrustMode::LightClient,
                proof_provider_id: "bitcoin-spv-v1".into(),
                verification_context: context_digest,
                maximum_checkpoint_age: 12,
            },
        );
        let unsigned = ConsignmentV2::new(payload).unwrap();
        let commitment = unsigned.commitment;
        let signature = signing_key.sign(commitment.as_bytes());
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let signed = unsigned
            .with_authorizations(vec![ConsignmentAuthorization {
                scheme: SignatureScheme::Ed25519,
                public_key: public_key.clone(),
                signature: signature.to_bytes().to_vec(),
                signed_commitment: commitment,
            }])
            .unwrap();
        Fixture {
            bytes: signed.canonical_cbor().unwrap(),
            context_digest,
            checkpoint,
            schema,
            signer: AuthorizedSigner {
                scheme: SignatureScheme::Ed25519,
                public_key,
            },
            source,
        }
    }

    async fn accept(
        fixture: &Fixture,
        store: &dyn AcceptedStateStore,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        accept_with_verifier(fixture, store, &TestClosureVerifier).await
    }

    async fn accept_with_verifier(
        fixture: &Fixture,
        store: &dyn AcceptedStateStore,
        verifier: &dyn ClosureProofVerifier,
    ) -> Result<AcceptanceResult, AcceptanceError> {
        accept_consignment_v2(
            &fixture.bytes,
            &AcceptanceContext {
                verification_context: fixture.context_digest,
                checkpoint: &fixture.checkpoint,
                proof_provider_id: "bitcoin-spv-v1",
                trust_mode: ClosureTrustMode::LightClient,
                maximum_checkpoint_age: 12,
                state_use_schema: &fixture.schema,
                authorized_signers: std::slice::from_ref(&fixture.signer),
            },
            verifier,
            store,
        )
        .await
    }

    #[tokio::test]
    async fn success_returns_full_typed_report_and_is_idempotent() {
        let fixture = fixture(0x55, VALID_PROOF_BYTE);
        let store = InMemoryAcceptedStateStore::default();
        let first = accept(&fixture, &store).await.unwrap();
        let second = accept(&fixture, &store).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.assurance.dimensions().len(), 7);
        assert!(first.assurance.foundational_shortfalls().is_empty());
        let saved = store.get(&fixture.source).await.unwrap().unwrap();
        assert_eq!(saved.assurance.report_digest, first.assurance.digest());
        assert_eq!(saved.closure.proof_provider_id, "bitcoin-spv-v1");
        assert_eq!(saved.closure.checkpoint, fixture.checkpoint);
        // The portable-conformance package's `valid-v2` case tells a consumer to
        // expect this outcome code, and the persisted observation carries the
        // storage family's own code rather than a third spelling.
        assert_eq!(first.registry_id(), "ACCEPT.V2.ACCEPTED");
        assert_eq!(
            saved.observations.last().unwrap().reason,
            "STORAGE.ACCEPTANCE.COMMITTED"
        );
    }

    #[test]
    fn every_acceptance_code_publishes_one_distinct_registry_identifier() {
        let mut ids: Vec<&'static str> = AcceptanceErrorCode::ALL
            .iter()
            .map(|code| code.registry_id())
            .chain(core::iter::once(AcceptanceResult::REGISTRY_ID))
            .collect();
        for id in &ids {
            assert!(
                id.starts_with("ACCEPT.V2."),
                "{id} is outside the namespace recipient acceptance owns"
            );
        }
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            count,
            "two acceptance outcomes share an identifier"
        );
    }

    #[tokio::test]
    async fn forged_nonempty_proof_cannot_upgrade_assurance() {
        let fixture = fixture(0x55, 0xFA);
        let error = accept(&fixture, &InMemoryAcceptedStateStore::default())
            .await
            .unwrap_err();
        assert_eq!(error.code, AcceptanceErrorCode::SourceClosure);
    }

    #[tokio::test]
    async fn every_native_dimension_has_a_distinct_stable_failure() {
        let fixture = fixture(0x55, VALID_PROOF_BYTE);
        for code in [
            AcceptanceErrorCode::Inclusion,
            AcceptanceErrorCode::Finality,
            AcceptanceErrorCode::Freshness,
            AcceptanceErrorCode::SourceClosure,
        ] {
            let error = accept_with_verifier(
                &fixture,
                &InMemoryAcceptedStateStore::default(),
                &DimensionFailureVerifier { code },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, code);
        }
    }

    #[tokio::test]
    async fn schema_semantics_failure_is_distinct_from_structure() {
        let mut fixture = fixture(0x55, VALID_PROOF_BYTE);
        fixture.schema = StateUseSchema::new();
        let error = accept(&fixture, &InMemoryAcceptedStateStore::default())
            .await
            .unwrap_err();
        assert_eq!(error.code, AcceptanceErrorCode::Semantics);
    }

    #[tokio::test]
    async fn independent_successors_race_to_one_stable_conflict() {
        let first = fixture(0x55, VALID_PROOF_BYTE);
        let second = fixture(0x56, VALID_PROOF_BYTE);
        let store = InMemoryAcceptedStateStore::default();
        let (left, right) = tokio::join!(accept(&first, &store), accept(&second, &store));
        assert_ne!(left.is_ok(), right.is_ok());
        let error = left.err().or_else(|| right.err()).unwrap();
        assert_eq!(error.code, AcceptanceErrorCode::Conflict);
        assert!(store.get(&first.source).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn isolated_recipients_cannot_both_accept_one_source() {
        for first_output in [0x55, 0x56] {
            let left = fixture(first_output, VALID_PROOF_BYTE);
            let right = fixture(
                if first_output == 0x55 { 0x56 } else { 0x55 },
                VALID_PROOF_BYTE,
            );
            let left_store = InMemoryAcceptedStateStore::default();
            let right_store = InMemoryAcceptedStateStore::default();
            let ordering = FinalizedSourceOrdering::default();

            let first = accept_with_verifier(&left, &left_store, &ordering).await;
            let second = accept_with_verifier(&right, &right_store, &ordering).await;

            assert!(first.is_ok());
            assert_eq!(second.unwrap_err().code, AcceptanceErrorCode::Conflict);
            assert!(left_store.get(&left.source).await.unwrap().is_some());
            assert!(right_store.get(&right.source).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn persistence_failure_leaves_no_partial_acceptance() {
        let fixture = fixture(0x55, VALID_PROOF_BYTE);
        let store = FailingStore;
        let error = accept(&fixture, &store).await.unwrap_err();
        assert_eq!(error.code, AcceptanceErrorCode::Persistence);
        assert!(store.get(&fixture.source).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn explicit_context_and_trusted_signer_are_mandatory() {
        let fixture = fixture(0x55, VALID_PROOF_BYTE);
        let store = InMemoryAcceptedStateStore::default();
        let wrong_context = AcceptanceContext {
            verification_context: Hash::new([3; 32]),
            checkpoint: &fixture.checkpoint,
            proof_provider_id: "bitcoin-spv-v1",
            trust_mode: ClosureTrustMode::LightClient,
            maximum_checkpoint_age: 12,
            state_use_schema: &fixture.schema,
            authorized_signers: std::slice::from_ref(&fixture.signer),
        };
        assert_eq!(
            accept_consignment_v2(&fixture.bytes, &wrong_context, &TestClosureVerifier, &store)
                .await
                .unwrap_err()
                .code,
            AcceptanceErrorCode::VerificationContext
        );

        let no_signer = AcceptanceContext {
            verification_context: fixture.context_digest,
            checkpoint: &fixture.checkpoint,
            proof_provider_id: "bitcoin-spv-v1",
            trust_mode: ClosureTrustMode::LightClient,
            maximum_checkpoint_age: 12,
            state_use_schema: &fixture.schema,
            authorized_signers: &[],
        };
        assert_eq!(
            accept_consignment_v2(&fixture.bytes, &no_signer, &TestClosureVerifier, &store)
                .await
                .unwrap_err()
                .code,
            AcceptanceErrorCode::Authorization
        );
    }

    #[test]
    fn malformed_bytes_have_stable_decode_code() {
        let fixture = fixture(0x55, VALID_PROOF_BYTE);
        let context = AcceptanceContext {
            verification_context: fixture.context_digest,
            checkpoint: &fixture.checkpoint,
            proof_provider_id: "bitcoin-spv-v1",
            trust_mode: ClosureTrustMode::LightClient,
            maximum_checkpoint_age: 12,
            state_use_schema: &fixture.schema,
            authorized_signers: std::slice::from_ref(&fixture.signer),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime
            .block_on(accept_consignment_v2(
                &[0xFF],
                &context,
                &TestClosureVerifier,
                &InMemoryAcceptedStateStore::default(),
            ))
            .unwrap_err();
        assert_eq!(error.code, AcceptanceErrorCode::Decode);
    }

    #[test]
    fn adapter_errors_remain_actionable() {
        let error = AdapterError::ProofVerificationFailed("bad branch".into());
        assert!(error.to_string().contains("bad branch"));
    }
}
