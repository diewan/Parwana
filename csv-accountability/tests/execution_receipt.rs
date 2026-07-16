use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionMandate,
    ConsumptionRecord, ED25519_SIGNATURE_ALGORITHM, EvidenceNodeId, EvidenceRequirementStatus,
    ExecutionAttempt, ExecutionAttemptState, ExecutionOutcome, ExecutionPolicy, IntentId,
    MandateRequirement, MandateSubject, ReceiptError, SignatureRequirements,
};

fn mandate() -> ActionMandate {
    ActionMandate {
        protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
        mandate_version: ACCOUNTABILITY_OBJECT_VERSION,
        intent_id: IntentId::from_digest([1; 32]),
        issuer_identity: vec![2],
        subject: MandateSubject::Identity(vec![3]),
        authority_domain: b"tenant:acme".to_vec(),
        valid_from: 100,
        expires_at: 200,
        maximum_dispatches: 1,
        constraints: vec![],
        evidence_requirements: vec![MandateRequirement {
            registry_id: "org.diewan.evidence.github.v1".into(),
            parameters_digest: [4; 32],
        }],
        execution_policy: ExecutionPolicy {
            registry_id: "org.diewan.execution.once.v1".into(),
            parameters_digest: [5; 32],
        },
        parent_mandate: None,
        revocation_reference: None,
        issued_at: 90,
        nonce: [6; 32],
        signature_requirements: SignatureRequirements {
            algorithm: ED25519_SIGNATURE_ALGORITHM.into(),
            key_id: b"key-1".to_vec(),
        },
    }
}

fn make_attempt(state: ExecutionAttemptState) -> ExecutionAttempt {
    let mandate = mandate();
    ExecutionAttempt {
        protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
        attempt_version: ACCOUNTABILITY_OBJECT_VERSION,
        mandate_id: mandate.id().unwrap(),
        mandate_digest: *mandate.id().unwrap().as_bytes(),
        intent_id: mandate.intent_id,
        reservation_token_digest: [7; 32],
        executor_identity: b"executor:piteka".to_vec(),
        correlation_key: b"deployment:123".to_vec(),
        started_at: 110,
        dispatch_boundary_at: Some(111),
        provider_request_digest: [8; 32],
        provider_response_digest: match state {
            ExecutionAttemptState::Accepted
            | ExecutionAttemptState::Rejected
            | ExecutionAttemptState::ReconciledAccepted
            | ExecutionAttemptState::ReconciledNotAccepted => Some([9; 32]),
            _ => None,
        },
        state,
    }
}

fn make_receipt(
    attempt: &ExecutionAttempt,
    outcome: ExecutionOutcome,
) -> csv_accountability::ExecutionReceipt {
    let mandate = mandate();
    csv_accountability::ExecutionReceipt {
        protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
        receipt_version: ACCOUNTABILITY_OBJECT_VERSION,
        mandate_id: attempt.mandate_id,
        mandate_digest: attempt.mandate_digest,
        intent_id: attempt.intent_id,
        attempt_id: attempt.id(&mandate).unwrap(),
        executor_identity: attempt.executor_identity.clone(),
        consumption_record: ConsumptionRecord {
            mandate_revision: 2,
            journal_entry_digest: [10; 32],
        },
        dispatch_evidence_refs: vec![EvidenceNodeId::from_digest([11; 32])],
        target_evidence_refs: vec![EvidenceNodeId::from_digest([12; 32])],
        started_at: attempt.started_at,
        completed_at: (outcome != ExecutionOutcome::Unknown).then_some(120),
        outcome,
        result_commitment: matches!(
            outcome,
            ExecutionOutcome::Succeeded | ExecutionOutcome::Failed
        )
        .then_some([13; 32]),
        evidence_requirements_status: vec![EvidenceRequirementStatus {
            registry_id: "org.diewan.evidence.github.v1".into(),
            parameters_digest: [4; 32],
            satisfied: true,
            evidence_refs: vec![EvidenceNodeId::from_digest([12; 32])],
        }],
        producer_identity: b"piteka:receipt-producer".to_vec(),
        producer_signature: vec![14; 64],
    }
}

#[test]
fn success_failure_rejected_and_unknown_vectors_are_distinct_and_valid() {
    let mandate = mandate();
    for (state, outcome) in [
        (ExecutionAttemptState::Accepted, ExecutionOutcome::Succeeded),
        (ExecutionAttemptState::Accepted, ExecutionOutcome::Failed),
        (ExecutionAttemptState::Rejected, ExecutionOutcome::Rejected),
        (
            ExecutionAttemptState::OutcomeAmbiguous,
            ExecutionOutcome::Unknown,
        ),
    ] {
        let attempt = make_attempt(state);
        let receipt = make_receipt(&attempt, outcome);
        assert!(receipt.validate(&mandate, &attempt).is_ok());
        assert_ne!(
            receipt.id(&mandate, &attempt).unwrap().into_bytes(),
            [0; 32]
        );
    }
}

#[test]
fn receipt_cannot_bind_a_different_intent_or_attempt() {
    let mandate = mandate();
    let attempt = make_attempt(ExecutionAttemptState::Accepted);
    let mut receipt = make_receipt(&attempt, ExecutionOutcome::Succeeded);
    receipt.intent_id = IntentId::from_digest([99; 32]);
    assert_eq!(
        receipt.validate(&mandate, &attempt),
        Err(ReceiptError::BindingMismatch)
    );

    let mut receipt = make_receipt(&attempt, ExecutionOutcome::Succeeded);
    receipt.attempt_id = make_attempt(ExecutionAttemptState::Rejected)
        .id(&mandate)
        .unwrap();
    assert_eq!(
        receipt.validate(&mandate, &attempt),
        Err(ReceiptError::BindingMismatch)
    );
}

#[test]
fn unknown_is_preserved_and_cannot_claim_a_result() {
    let mandate = mandate();
    let attempt = make_attempt(ExecutionAttemptState::OutcomeAmbiguous);
    let mut receipt = make_receipt(&attempt, ExecutionOutcome::Unknown);
    assert!(receipt.validate(&mandate, &attempt).is_ok());
    receipt.outcome = ExecutionOutcome::Succeeded;
    receipt.completed_at = Some(120);
    receipt.result_commitment = Some([13; 32]);
    assert_eq!(
        receipt.validate(&mandate, &attempt),
        Err(ReceiptError::OutcomeMismatch)
    );
}

#[test]
fn raw_reservation_secret_has_no_export_field() {
    let mandate = mandate();
    let attempt = make_attempt(ExecutionAttemptState::Accepted);
    let bytes = attempt.canonical_bytes(&mandate).unwrap();
    assert!(bytes.windows(32).any(|window| window == [7; 32]));
    assert!(
        !bytes
            .windows(22)
            .any(|window| window == b"raw-reservation-secret")
    );
}
