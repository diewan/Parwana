//! Deterministic accountability fixtures and adversarial mutation helpers.

use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionIntent, ActionMandate,
    AuthenticityMaterial, ConsumptionRecord, DbMigrationCodec, DbMigrationIntentV1,
    ED25519_SIGNATURE_ALGORITHM, EvidenceKind, EvidenceNode, EvidenceNodeId,
    EvidenceRequirementStatus, ExecutionAttempt, ExecutionAttemptState, ExecutionOutcome,
    ExecutionPolicy, ExecutionReceipt, GitHubDeploymentIntentV1, MandateRequirement,
    MandateSubject, MigrationDirection, ProfileCodec, RequiredContexts, SignatureRequirements,
    SourceLocator, VerificationContext,
};

/// Complete, internally consistent first-slice verification fixture.
#[derive(Clone)]
pub struct AccountabilityFixture {
    /// Exact action intent.
    pub intent: ActionIntent,
    /// Pre-action mandate.
    pub mandate: ActionMandate,
    /// Provider dispatch attempt.
    pub attempt: ExecutionAttempt,
    /// Producer receipt.
    pub receipt: ExecutionReceipt,
    /// Content-addressed evidence graph.
    pub evidence: Vec<(EvidenceNodeId, EvidenceNode)>,
    /// Stable executor expected by the mandate.
    pub executor: Vec<u8>,
    /// Effective verification context.
    pub context: VerificationContext,
}

impl AccountabilityFixture {
    /// Builds a deterministic valid fixture containing a claim, observation,
    /// and attestation.
    pub fn valid() -> Self {
        let required_contexts = RequiredContexts::explicit(vec!["build".into(), "security".into()])
            .expect("static required contexts are valid");
        let profile = GitHubDeploymentIntentV1 {
            repository_id: 42,
            repository_owner: "diewan".into(),
            repository_name: "piteka".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            exact_ref: "0123456789abcdef0123456789abcdef01234567".into(),
            environment_id: 7,
            environment_name: "production".into(),
            deployment_gate_policy_digest: required_contexts
                .gate_policy_id()
                .expect("static gate policy is valid"),
            required_contexts,
            payload_commitment: [3; 32],
            artifact_digest: Some([4; 32]),
        };
        let intent = ActionIntent::github_deployment(
            b"requester:alice".to_vec(),
            90,
            [6; 32],
            vec![[7; 32]],
            profile,
        )
        .expect("static intent is valid");
        let executor = b"executor:piteka".to_vec();
        let requirement = MandateRequirement {
            registry_id: "org.diewan.evidence.github-deployment.v1".into(),
            parameters_digest: [8; 32],
        };
        let mandate = ActionMandate {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            mandate_version: ACCOUNTABILITY_OBJECT_VERSION,
            intent_id: intent.id().expect("static intent has an id"),
            issuer_identity: b"authority:acme".to_vec(),
            subject: MandateSubject::Identity(executor.clone()),
            authority_domain: b"tenant:acme".to_vec(),
            valid_from: 100,
            expires_at: 200,
            maximum_dispatches: 1,
            constraints: vec![],
            evidence_requirements: vec![requirement.clone()],
            execution_policy: ExecutionPolicy {
                registry_id: "org.diewan.execution.single-use.v1".into(),
                parameters_digest: [9; 32],
            },
            parent_mandate: None,
            revocation_reference: Some([10; 32]),
            issued_at: 95,
            nonce: [11; 32],
            signature_requirements: SignatureRequirements {
                algorithm: ED25519_SIGNATURE_ALGORITHM.into(),
                key_id: b"key:authority:1".to_vec(),
            },
        };
        let mandate_id = mandate.id().expect("static mandate has an id");
        let attempt = ExecutionAttempt {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            attempt_version: ACCOUNTABILITY_OBJECT_VERSION,
            mandate_id,
            mandate_digest: *mandate_id.as_bytes(),
            intent_id: mandate.intent_id,
            reservation_token_digest: [12; 32],
            executor_identity: executor.clone(),
            correlation_key: b"github-deployment:1001".to_vec(),
            started_at: 110,
            dispatch_boundary_at: Some(111),
            provider_request_digest: [13; 32],
            provider_response_digest: Some([14; 32]),
            state: ExecutionAttemptState::Accepted,
        };

        let claim = evidence_node(
            EvidenceKind::Claim {
                proposition_digest: [15; 32],
            },
            b"executor:piteka",
            None,
        );
        let observation = evidence_node(
            EvidenceKind::Observation {
                method_id: "org.diewan.observe.github-api.v1".into(),
            },
            b"github:api",
            Some(AuthenticityMaterial {
                scheme_id: "org.diewan.auth.github-app-response.v1".into(),
                material_digest: [16; 32],
            }),
        );
        let attestation = evidence_node(
            EvidenceKind::Attestation {
                attester_identity: b"github:webhook".to_vec(),
            },
            b"github:webhook",
            Some(AuthenticityMaterial {
                scheme_id: "org.diewan.auth.github-webhook-sha256.v1".into(),
                material_digest: [17; 32],
            }),
        );
        let mut evidence = vec![
            (claim.id().expect("static claim has an id"), claim),
            (
                observation.id().expect("static observation has an id"),
                observation,
            ),
            (
                attestation.id().expect("static attestation has an id"),
                attestation,
            ),
        ];
        evidence.sort_by_key(|(id, _)| *id);
        let evidence_ids: Vec<_> = evidence.iter().map(|(id, _)| *id).collect();
        let receipt = ExecutionReceipt {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            receipt_version: ACCOUNTABILITY_OBJECT_VERSION,
            mandate_id,
            mandate_digest: *mandate_id.as_bytes(),
            intent_id: mandate.intent_id,
            attempt_id: attempt.id(&mandate).expect("static attempt has an id"),
            executor_identity: executor.clone(),
            consumption_record: ConsumptionRecord {
                mandate_revision: 2,
                journal_entry_digest: [18; 32],
            },
            dispatch_evidence_refs: evidence_ids.clone(),
            target_evidence_refs: evidence_ids.clone(),
            started_at: attempt.started_at,
            completed_at: Some(120),
            outcome: ExecutionOutcome::Succeeded,
            result_commitment: Some([19; 32]),
            evidence_requirements_status: vec![EvidenceRequirementStatus {
                registry_id: requirement.registry_id,
                parameters_digest: requirement.parameters_digest,
                satisfied: true,
                evidence_refs: evidence_ids,
            }],
            producer_identity: b"piteka:receipt-producer".to_vec(),
            producer_signature: vec![20; 64],
        };
        let context = VerificationContext {
            context_version: ACCOUNTABILITY_OBJECT_VERSION,
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            evaluation_time: 150,
            verifier_policy_digest: [21; 32],
            trust_package_digest: [22; 32],
            revocation_snapshot_digest: [23; 32],
            algorithm_policy_digest: [24; 32],
            external_evidence_policy_digest: [25; 32],
            assurance_thresholds_digest: [26; 32],
            extensions: vec![],
        };
        Self {
            intent,
            mandate,
            attempt,
            receipt,
            evidence,
            executor,
            context,
        }
    }

    /// Builds a complete database-migration (PROFILE-02) fixture from exact
    /// canonical profile bytes through a bound receipt and evidence graph.
    ///
    /// This is intentionally a second profile rather than a renamed GitHub
    /// fixture: its target, requirement, correlation key, provider evidence,
    /// and authenticity schemes all carry database-migration semantics.
    pub fn valid_db_migration() -> Self {
        let mut fixture = Self::valid();
        let profile = DbMigrationIntentV1 {
            database_id: 9001,
            database_name: "accounts".into(),
            environment_id: 42,
            environment_name: "production".into(),
            migration_id: "20260723_add_receipt_index".into(),
            migration_digest: [31; 32],
            direction: MigrationDirection::Forward,
            allow_destructive: false,
            statement_count: 2,
            change_ticket: "CHG-2026-0723".into(),
        };
        let codec = DbMigrationCodec::default();
        fixture.intent = ActionIntent::new(
            codec.descriptor(),
            &codec,
            profile
                .canonical_bytes()
                .expect("static profile is canonical"),
            b"requester:alice".to_vec(),
            90,
            [6; 32],
            vec![[7; 32]],
        )
        .expect("static database migration intent is valid");

        fixture.mandate.intent_id = fixture.intent.id().expect("static intent has an id");
        fixture.mandate.evidence_requirements[0].registry_id =
            "evidence.db-migration.applied-record".into();
        fixture.attempt.correlation_key = b"db-migration:20260723_add_receipt_index".to_vec();
        fixture.attempt.provider_request_digest = [32; 32];
        fixture.attempt.provider_response_digest = Some([33; 32]);

        for (_, node) in &mut fixture.evidence {
            node.source_locator =
                SourceLocator::Disclosed("database:migration:20260723_add_receipt_index".into());
            match &mut node.kind {
                EvidenceKind::Claim { .. } => {
                    node.producer_identity = b"executor:piteka-migration".to_vec();
                }
                EvidenceKind::Observation { method_id } => {
                    *method_id = "org.diewan.observe.database-migration.v1".into();
                    node.producer_identity = b"database:provider-api".to_vec();
                }
                EvidenceKind::Attestation { attester_identity } => {
                    *attester_identity = b"database:migration-ledger".to_vec();
                    node.producer_identity = b"database:migration-ledger".to_vec();
                }
                _ => unreachable!("base fixture contains only positive evidence kinds"),
            }
            if let Some(authenticity) = &mut node.authenticity {
                authenticity.scheme_id = "org.diewan.auth.database-provider-response.v1".into();
            }
        }
        fixture.evidence = fixture
            .evidence
            .into_iter()
            .map(|(_, node)| (node.id().expect("static evidence has an id"), node))
            .collect();
        fixture.evidence.sort_by_key(|(id, _)| *id);
        let evidence_ids: Vec<_> = fixture.evidence.iter().map(|(id, _)| *id).collect();
        fixture.receipt.dispatch_evidence_refs = evidence_ids.clone();
        fixture.receipt.target_evidence_refs = evidence_ids.clone();
        fixture.receipt.evidence_requirements_status[0].registry_id =
            fixture.mandate.evidence_requirements[0].registry_id.clone();
        fixture.receipt.evidence_requirements_status[0].evidence_refs = evidence_ids;
        fixture.receipt.result_commitment = Some([34; 32]);
        fixture.rebind_execution();
        fixture
    }

    /// Rebinds the attempt and receipt after a deliberate mandate mutation.
    pub fn rebind_execution(&mut self) {
        let mandate_id = self.mandate.id().expect("mutated mandate remains valid");
        self.attempt.mandate_id = mandate_id;
        self.attempt.mandate_digest = *mandate_id.as_bytes();
        self.attempt.intent_id = self.mandate.intent_id;
        self.receipt.mandate_id = mandate_id;
        self.receipt.mandate_digest = *mandate_id.as_bytes();
        self.receipt.intent_id = self.mandate.intent_id;
        self.receipt.attempt_id = self
            .attempt
            .id(&self.mandate)
            .expect("mutated attempt remains valid");
    }
}

fn evidence_node(
    kind: EvidenceKind,
    producer: &[u8],
    authenticity: Option<AuthenticityMaterial>,
) -> EvidenceNode {
    EvidenceNode {
        kind,
        producer_identity: producer.to_vec(),
        collected_at: 118,
        asserted_event_at: Some(115),
        content_digest: [27; 32],
        media_type: "application/cbor".into(),
        source_locator: SourceLocator::Disclosed("github:deployment:1001".into()),
        authenticity,
        disclosure_classification: "internal".into(),
        relationships: vec![],
    }
}
