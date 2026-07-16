use csv_accountability::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, ActionMandate, CasReservation,
    DispatchCertainty, ED25519_SIGNATURE_ALGORITHM, ExecutionAttemptState, ExecutionPolicy,
    IntentId, MandateJournalEntry, MandateRequirement, MandateState, MandateSubject,
    NonAcceptanceEvidence, QuarantineReleasePolicy, ReservationError, ReservationSnapshot,
    SignatureRequirements, TransitionContext, TransitionError, validate_journal,
    validate_mandate_transition, validate_reservation_cas,
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

#[test]
fn reservation_contract_has_one_database_winner() {
    let mandate = mandate();
    let id = mandate.id().unwrap();
    let snapshot = ReservationSnapshot {
        mandate_id: id,
        state: MandateState::Issued,
        revision: 7,
    };
    let winner = validate_reservation_cas(&mandate, snapshot, 7, 100, [9; 32]).unwrap();
    assert_eq!(
        winner,
        CasReservation {
            mandate_id: id,
            expected_state: MandateState::Issued,
            expected_revision: 7,
            next_state: MandateState::Reserved,
            next_revision: 8,
            reservation_token_digest: [9; 32],
        }
    );

    let after_winner = ReservationSnapshot {
        mandate_id: id,
        state: winner.next_state,
        revision: winner.next_revision,
    };
    assert_eq!(
        validate_reservation_cas(&mandate, after_winner, 7, 100, [8; 32]),
        Err(ReservationError::RevisionMismatch)
    );
    assert_eq!(
        validate_reservation_cas(&mandate, after_winner, 8, 100, [8; 32]),
        Err(ReservationError::NotIssued)
    );
}

#[test]
fn reservation_fails_closed_at_time_and_identity_boundaries() {
    let mandate = mandate();
    let snapshot = ReservationSnapshot {
        mandate_id: mandate.id().unwrap(),
        state: MandateState::Issued,
        revision: 0,
    };
    assert!(validate_reservation_cas(&mandate, snapshot, 0, 100, [1; 32]).is_ok());
    assert_eq!(
        validate_reservation_cas(&mandate, snapshot, 0, 200, [1; 32]),
        Err(ReservationError::NotCurrentlyValid)
    );
    let wrong = ReservationSnapshot {
        mandate_id: IntentId::from_digest([8; 32]).into_bytes().into(),
        ..snapshot
    };
    assert_eq!(
        validate_reservation_cas(&mandate, wrong, 0, 100, [1; 32]),
        Err(ReservationError::MandateMismatch)
    );
}

#[test]
fn consumed_mandate_cannot_be_reserved_again() {
    assert!(validate_mandate_transition(
        MandateState::Consumed,
        MandateState::Reserved,
        Some(ExecutionAttemptState::Prepared),
        &TransitionContext::before_dispatch(),
    )
    .is_err());
}

#[test]
fn github_v1_quarantine_can_only_be_consumed_or_abandoned() {
    let context = TransitionContext::github_v1_ambiguous();
    assert_eq!(
        validate_mandate_transition(
            MandateState::Quarantined,
            MandateState::Released,
            Some(ExecutionAttemptState::ReconciledNotAccepted),
            &context,
        ),
        Err(TransitionError::UnsafeRelease)
    );
    assert!(
        validate_mandate_transition(
            MandateState::Quarantined,
            MandateState::Abandoned,
            Some(ExecutionAttemptState::AbandonedAmbiguous),
            &context,
        )
        .is_ok()
    );
}

#[test]
fn quarantine_release_requires_exact_profile_defined_evidence() {
    let policy_id = "org.example.provider.non-acceptance.v1";
    let context = TransitionContext {
        dispatch_certainty: DispatchCertainty::PossiblyAccepted,
        quarantine_release_policy: QuarantineReleasePolicy::ProfileDefined {
            policy_id: policy_id.into(),
            policy_digest: [1; 32],
        },
        non_acceptance_evidence: Some(NonAcceptanceEvidence {
            policy_id: policy_id.into(),
            policy_digest: [1; 32],
            evidence_digest: [2; 32],
        }),
    };
    assert!(
        validate_mandate_transition(
            MandateState::Quarantined,
            MandateState::Released,
            Some(ExecutionAttemptState::ReconciledNotAccepted),
            &context,
        )
        .is_ok()
    );
    let mut wrong = context;
    wrong
        .non_acceptance_evidence
        .as_mut()
        .unwrap()
        .policy_digest = [3; 32];
    assert_eq!(
        validate_mandate_transition(
            MandateState::Quarantined,
            MandateState::Released,
            Some(ExecutionAttemptState::ReconciledNotAccepted),
            &wrong,
        ),
        Err(TransitionError::InvalidNonAcceptanceEvidence)
    );
}

#[test]
fn exported_journal_validates_revisions_order_and_reconciliation() {
    let id = mandate().id().unwrap();
    let entries = vec![
        MandateJournalEntry {
            mandate_id: id,
            previous_revision: 0,
            revision: 1,
            from: MandateState::Issued,
            to: MandateState::Reserved,
            attempt_state: Some(ExecutionAttemptState::Prepared),
            occurred_at: 110,
            context: TransitionContext::before_dispatch(),
        },
        MandateJournalEntry {
            mandate_id: id,
            previous_revision: 1,
            revision: 2,
            from: MandateState::Reserved,
            to: MandateState::Quarantined,
            attempt_state: Some(ExecutionAttemptState::OutcomeAmbiguous),
            occurred_at: 111,
            context: TransitionContext::github_v1_ambiguous(),
        },
        MandateJournalEntry {
            mandate_id: id,
            previous_revision: 2,
            revision: 3,
            from: MandateState::Quarantined,
            to: MandateState::Consumed,
            attempt_state: Some(ExecutionAttemptState::ReconciledAccepted),
            occurred_at: 120,
            context: TransitionContext {
                dispatch_certainty: DispatchCertainty::Accepted,
                quarantine_release_policy: QuarantineReleasePolicy::Never,
                non_acceptance_evidence: None,
            },
        },
    ];
    assert_eq!(
        validate_journal(id, MandateState::Issued, 0, &entries),
        Ok((MandateState::Consumed, 3))
    );

    let mut adversarial = entries;
    adversarial[1].revision = 9;
    assert_eq!(
        validate_journal(id, MandateState::Issued, 0, &adversarial),
        Err(TransitionError::InvalidJournal)
    );
}
