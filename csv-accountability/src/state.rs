//! Pure mandate transition and database compare-and-swap semantics.
//!
//! This module defines protocol law only. It contains no repository, lock, database,
//! clock, or mutable live-state implementation. Piteka persists the projection and
//! applies [`CasReservation`] as one conditional database update.

use alloc::{string::String, vec::Vec};

use crate::{ActionMandate, MandateError, MandateId};

/// Maximum registered profile/policy identifier length in transition evidence.
pub const MAX_STATE_POLICY_ID_BYTES: usize = 128;

/// Exported mandate projection states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MandateState {
    /// An action has been proposed but not approved and signed.
    Proposed,
    /// Signed authority is available for reservation.
    Issued,
    /// One execution attempt owns the active reservation.
    Reserved,
    /// Provider acceptance was established and the mandate is permanently used.
    Consumed,
    /// The unused mandate passed its exclusive expiry.
    Expired,
    /// The unused mandate was revoked.
    Revoked,
    /// A reservation ended after definite pre-acceptance rejection.
    Released,
    /// The provider may have accepted the action; automatic retry is forbidden.
    Quarantined,
    /// An unresolved quarantine was permanently closed without claiming non-occurrence.
    Abandoned,
}

/// Exported execution-attempt projection states used when validating transition pairs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionAttemptState {
    /// The attempt was created against a reservation.
    Prepared,
    /// The provider request may be in flight.
    Dispatching,
    /// Provider acceptance was established.
    Accepted,
    /// Definite rejection occurred before provider acceptance.
    Rejected,
    /// The request may have been accepted, so retry is unsafe.
    OutcomeAmbiguous,
    /// Reconciliation found the correlated accepted action.
    ReconciledAccepted,
    /// Reconciliation proved non-acceptance under a registered provider policy.
    ReconciledNotAccepted,
    /// The unresolved attempt was permanently closed with unknown outcome.
    AbandonedAmbiguous,
}

/// What is known about whether an external system could have accepted the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchCertainty {
    /// No request crossed the external dispatch boundary.
    NotDispatched,
    /// The provider definitely rejected before acceptance.
    DefinitePreAcceptanceRejection,
    /// The provider may have accepted the action.
    PossiblyAccepted,
    /// The provider definitely accepted the action.
    Accepted,
}

/// Profile law for releasing a quarantined mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuarantineReleasePolicy {
    /// The profile has no sufficient absence predicate; release is unreachable.
    Never,
    /// This registered policy defines evidence sufficient to prove non-acceptance.
    ProfileDefined {
        /// Stable profile/policy identifier.
        policy_id: String,
        /// Commitment to the exact policy parameters.
        policy_digest: [u8; 32],
    },
}

/// Evidence offered to prove non-acceptance after possible provider acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonAcceptanceEvidence {
    /// Registered policy under which the evidence is sufficient.
    pub policy_id: String,
    /// Exact committed policy parameters.
    pub policy_digest: [u8; 32],
    /// Nonzero digest of the exported reconciliation evidence.
    pub evidence_digest: [u8; 32],
}

/// Inputs required to validate one state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionContext {
    /// Knowledge at the external dispatch boundary.
    pub dispatch_certainty: DispatchCertainty,
    /// Provider-profile rule for quarantine release.
    pub quarantine_release_policy: QuarantineReleasePolicy,
    /// Evidence supplied for a quarantine release, if any.
    pub non_acceptance_evidence: Option<NonAcceptanceEvidence>,
}

impl TransitionContext {
    /// Context for transitions that have not crossed a dispatch boundary.
    pub const fn before_dispatch() -> Self {
        Self {
            dispatch_certainty: DispatchCertainty::NotDispatched,
            quarantine_release_policy: QuarantineReleasePolicy::Never,
            non_acceptance_evidence: None,
        }
    }

    /// Context for the first-slice GitHub profile after possible acceptance.
    pub const fn github_v1_ambiguous() -> Self {
        Self {
            dispatch_certainty: DispatchCertainty::PossiblyAccepted,
            quarantine_release_policy: QuarantineReleasePolicy::Never,
            non_acceptance_evidence: None,
        }
    }
}

/// A protocol-invalid mandate transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The state edge is absent from the protocol state diagram.
    IllegalTransition,
    /// Release is inconsistent with what is known at the dispatch boundary.
    UnsafeRelease,
    /// Profile-defined non-acceptance evidence is missing, malformed, or mismatched.
    InvalidNonAcceptanceEvidence,
    /// Mandate and execution-attempt projections disagree.
    AttemptStateMismatch,
    /// Journal identity, revisions, timestamps, or ordering are invalid.
    InvalidJournal,
}

/// Validates one mandate edge and any paired execution-attempt state.
pub fn validate_mandate_transition(
    from: MandateState,
    to: MandateState,
    attempt_state: Option<ExecutionAttemptState>,
    context: &TransitionContext,
) -> Result<(), TransitionError> {
    let legal_edge = matches!(
        (from, to),
        (MandateState::Proposed, MandateState::Issued)
            | (MandateState::Issued, MandateState::Reserved)
            | (MandateState::Issued, MandateState::Revoked)
            | (MandateState::Issued, MandateState::Expired)
            | (MandateState::Reserved, MandateState::Consumed)
            | (MandateState::Reserved, MandateState::Released)
            | (MandateState::Reserved, MandateState::Quarantined)
            | (MandateState::Quarantined, MandateState::Consumed)
            | (MandateState::Quarantined, MandateState::Released)
            | (MandateState::Quarantined, MandateState::Abandoned)
    );
    if !legal_edge {
        return Err(TransitionError::IllegalTransition);
    }

    match (from, to) {
        (MandateState::Issued, MandateState::Reserved) => {
            require_attempt(attempt_state, ExecutionAttemptState::Prepared)?;
            if context.dispatch_certainty != DispatchCertainty::NotDispatched {
                return Err(TransitionError::AttemptStateMismatch);
            }
        }
        (MandateState::Reserved, MandateState::Consumed) => {
            require_attempt(attempt_state, ExecutionAttemptState::Accepted)?;
            if context.dispatch_certainty != DispatchCertainty::Accepted {
                return Err(TransitionError::AttemptStateMismatch);
            }
        }
        (MandateState::Reserved, MandateState::Released) => {
            require_attempt(attempt_state, ExecutionAttemptState::Rejected)?;
            if context.dispatch_certainty != DispatchCertainty::DefinitePreAcceptanceRejection {
                return Err(TransitionError::UnsafeRelease);
            }
        }
        (MandateState::Reserved, MandateState::Quarantined) => {
            require_attempt(attempt_state, ExecutionAttemptState::OutcomeAmbiguous)?;
            if context.dispatch_certainty != DispatchCertainty::PossiblyAccepted {
                return Err(TransitionError::AttemptStateMismatch);
            }
        }
        (MandateState::Quarantined, MandateState::Consumed) => {
            require_attempt(attempt_state, ExecutionAttemptState::ReconciledAccepted)?;
            if context.dispatch_certainty != DispatchCertainty::Accepted {
                return Err(TransitionError::AttemptStateMismatch);
            }
        }
        (MandateState::Quarantined, MandateState::Released) => {
            require_attempt(attempt_state, ExecutionAttemptState::ReconciledNotAccepted)?;
            validate_non_acceptance_evidence(context)?;
        }
        (MandateState::Quarantined, MandateState::Abandoned) => {
            require_attempt(attempt_state, ExecutionAttemptState::AbandonedAmbiguous)?;
            if context.dispatch_certainty != DispatchCertainty::PossiblyAccepted {
                return Err(TransitionError::AttemptStateMismatch);
            }
        }
        _ if attempt_state.is_some() => return Err(TransitionError::AttemptStateMismatch),
        _ => {}
    }
    Ok(())
}

fn require_attempt(
    actual: Option<ExecutionAttemptState>,
    expected: ExecutionAttemptState,
) -> Result<(), TransitionError> {
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(TransitionError::AttemptStateMismatch)
    }
}

fn validate_non_acceptance_evidence(context: &TransitionContext) -> Result<(), TransitionError> {
    if context.dispatch_certainty != DispatchCertainty::PossiblyAccepted {
        return Err(TransitionError::UnsafeRelease);
    }
    let QuarantineReleasePolicy::ProfileDefined {
        policy_id,
        policy_digest,
    } = &context.quarantine_release_policy
    else {
        return Err(TransitionError::UnsafeRelease);
    };
    if !valid_policy_id(policy_id) {
        return Err(TransitionError::InvalidNonAcceptanceEvidence);
    }
    let evidence = context
        .non_acceptance_evidence
        .as_ref()
        .ok_or(TransitionError::InvalidNonAcceptanceEvidence)?;
    if evidence.policy_id != *policy_id
        || evidence.policy_digest != *policy_digest
        || evidence.evidence_digest == [0; 32]
    {
        return Err(TransitionError::InvalidNonAcceptanceEvidence);
    }
    Ok(())
}

fn valid_policy_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STATE_POLICY_ID_BYTES
        && value.is_ascii()
        && value.trim() == value
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

/// The persisted values against which Piteka performs a reservation CAS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationSnapshot {
    /// Mandate being reserved.
    pub mandate_id: MandateId,
    /// Current persisted projection state.
    pub state: MandateState,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
}

/// Conditional update contract to apply atomically in Piteka PostgreSQL.
///
/// The update succeeds only where all `expected_*` values still match. Advancing
/// the revision in the same statement makes concurrent requests from one snapshot
/// mutually exclusive: at most one database update can affect a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CasReservation {
    /// Mandate row to update.
    pub mandate_id: MandateId,
    /// State required by the update predicate.
    pub expected_state: MandateState,
    /// Revision required by the update predicate.
    pub expected_revision: u64,
    /// State stored by the winning update.
    pub next_state: MandateState,
    /// Revision stored by the winning update.
    pub next_revision: u64,
    /// Digest of the secret reservation token; the raw token is never exported.
    pub reservation_token_digest: [u8; 32],
}

/// A reservation request that cannot safely become a CAS update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationError {
    /// Mandate canonical validation failed.
    InvalidMandate,
    /// Snapshot refers to another mandate.
    MandateMismatch,
    /// Expected revision is stale or cannot advance.
    RevisionMismatch,
    /// Only an issued mandate can be reserved.
    NotIssued,
    /// Reservation time falls outside the mandate validity interval.
    NotCurrentlyValid,
    /// Reservation-token digest is absent.
    InvalidReservationToken,
}

/// Constructs the exact conditional update required for one-winner reservation.
pub fn validate_reservation_cas(
    mandate: &ActionMandate,
    snapshot: ReservationSnapshot,
    expected_revision: u64,
    reserved_at: u64,
    reservation_token_digest: [u8; 32],
) -> Result<CasReservation, ReservationError> {
    let mandate_id = mandate.id().map_err(map_mandate_error)?;
    if snapshot.mandate_id != mandate_id {
        return Err(ReservationError::MandateMismatch);
    }
    if snapshot.revision != expected_revision {
        return Err(ReservationError::RevisionMismatch);
    }
    let next_revision = expected_revision
        .checked_add(1)
        .ok_or(ReservationError::RevisionMismatch)?;
    if snapshot.state != MandateState::Issued {
        return Err(ReservationError::NotIssued);
    }
    if !mandate
        .is_valid_at(reserved_at)
        .map_err(map_mandate_error)?
    {
        return Err(ReservationError::NotCurrentlyValid);
    }
    if reservation_token_digest == [0; 32] {
        return Err(ReservationError::InvalidReservationToken);
    }
    Ok(CasReservation {
        mandate_id,
        expected_state: MandateState::Issued,
        expected_revision,
        next_state: MandateState::Reserved,
        next_revision,
        reservation_token_digest,
    })
}

fn map_mandate_error(_: MandateError) -> ReservationError {
    ReservationError::InvalidMandate
}

/// One immutable exported mandate-projection journal entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateJournalEntry {
    /// Mandate whose projection changed.
    pub mandate_id: MandateId,
    /// Revision before the transition.
    pub previous_revision: u64,
    /// Revision after the transition.
    pub revision: u64,
    /// Previous projection state.
    pub from: MandateState,
    /// New projection state.
    pub to: MandateState,
    /// Paired attempt state when the edge requires one.
    pub attempt_state: Option<ExecutionAttemptState>,
    /// Transition timestamp in Unix seconds.
    pub occurred_at: u64,
    /// Evidence and dispatch-boundary context used to validate the edge.
    pub context: TransitionContext,
}

/// Validates an ordered exported projection journal without owning live state.
pub fn validate_journal(
    mandate_id: MandateId,
    initial_state: MandateState,
    initial_revision: u64,
    entries: &[MandateJournalEntry],
) -> Result<(MandateState, u64), TransitionError> {
    let mut state = initial_state;
    let mut revision = initial_revision;
    let mut last_time = None;
    for entry in entries {
        let next_revision = revision
            .checked_add(1)
            .ok_or(TransitionError::InvalidJournal)?;
        if entry.mandate_id != mandate_id
            || entry.from != state
            || entry.previous_revision != revision
            || entry.revision != next_revision
            || last_time.is_some_and(|time| entry.occurred_at < time)
        {
            return Err(TransitionError::InvalidJournal);
        }
        validate_mandate_transition(entry.from, entry.to, entry.attempt_state, &entry.context)?;
        state = entry.to;
        revision = entry.revision;
        last_time = Some(entry.occurred_at);
    }
    Ok((state, revision))
}

/// Returns the complete state-diagram edges for documentation and conformance tests.
pub fn mandate_transition_edges() -> Vec<(MandateState, MandateState)> {
    alloc::vec![
        (MandateState::Proposed, MandateState::Issued),
        (MandateState::Issued, MandateState::Reserved),
        (MandateState::Issued, MandateState::Revoked),
        (MandateState::Issued, MandateState::Expired),
        (MandateState::Reserved, MandateState::Consumed),
        (MandateState::Reserved, MandateState::Released),
        (MandateState::Reserved, MandateState::Quarantined),
        (MandateState::Quarantined, MandateState::Consumed),
        (MandateState::Quarantined, MandateState::Released),
        (MandateState::Quarantined, MandateState::Abandoned),
    ]
}
