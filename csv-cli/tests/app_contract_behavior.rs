//! CLI behavior over the shared application contract (APPS-CONTRACT-004).
//!
//! These exercise the contract through `csv_sdk::contract` — the exact API the
//! CLI's own command paths call, and the one `csv-wallet` will call. They are the
//! regression fence for the properties the reference application depends on:
//! a receipt cannot claim a completion the runtime never established, a finality
//! event carries the tip it was measured against, a mode is never offered an
//! action it cannot honor, and an unknown contract version is refused outright.
//!
//! Terminal output is deliberately not asserted on: it is not part of the
//! contract, and nothing downstream parses it.

use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;
use csv_protocol::verification_levels::VerificationLevel;
use csv_runtime::FinalityObservation;
use csv_sdk::contract::{
    self, ArtifactKind, ContractError, FinalityEvidence, NextAction, ReceiptBody, RecoveryPlan,
    RuntimeHealthReport, TransferMode, TransferPhase, TransferReceipt, decode, encode,
};

const SANAD: [u8; 32] = [0x11; 32];
const REPLAY: [u8; 32] = [0x22; 32];

fn sanad_id() -> SanadId {
    SanadId::new(SANAD)
}

fn source() -> ChainId {
    ChainId::new("bitcoin")
}

fn destination() -> ChainId {
    ChainId::new("sui")
}

/// A finality observation with a real, adapter-read tip.
fn observed(confirmations: u64, required: u64) -> FinalityObservation {
    FinalityObservation {
        confirming_block_height: 100,
        confirmations,
        required_confirmations: required,
        observed_tip_height: Some(100 + confirmations),
    }
}

fn runtime_receipt(
    finality: Option<FinalityObservation>,
    assurance: Option<VerificationLevel>,
) -> csv_runtime::TransferReceipt {
    csv_runtime::TransferReceipt {
        transfer_id: "transfer-1".to_string(),
        replay_id: csv_hash::Hash::new(REPLAY),
        lock_tx_hash: "aa".repeat(32),
        mint_tx_hash: "bb".repeat(32),
        // Via the SDK re-export: the CLI never imports an adapter crate directly.
        materialization: csv_sdk::transfers::DestinationMaterialization::unavailable("sui"),
        finality,
        assurance,
    }
}

// ── Receipts carry runtime IDs and permitted next actions ───────────────────

#[test]
fn a_completed_materialize_receipts_the_runtime_transfer_and_replay_ids() {
    let receipt = contract::materialize_receipt(
        &runtime_receipt(
            Some(observed(6, 6)),
            Some(VerificationLevel::ConsensusVerified),
        ),
        &sanad_id(),
        &source(),
        &destination(),
    )
    .expect("a consensus-verified mint is receiptable");

    assert_eq!(receipt.mode(), TransferMode::Materialize);
    assert_eq!(receipt.transfer_id(), Some("transfer-1"));
    assert_eq!(
        receipt.replay_id().map(|r| r.bytes.clone()),
        Some(hex::encode(REPLAY)),
        "the replay id is the runtime's, and the receipt must carry it verbatim"
    );
    assert!(!receipt.next_actions.is_empty());
    for action in &receipt.next_actions {
        assert!(action.validate_for_mode(TransferMode::Materialize).is_ok());
    }
}

#[test]
fn a_send_receipt_never_offers_resume_or_retry() {
    // An off-chain send has no destination phase. Offering `resume` would send the
    // user at a runtime call that cannot exist for this transfer.
    let receipt = contract::send_receipt(
        "transfer-1",
        &sanad_id(),
        &source(),
        &csv_hash::seal::SealPoint::new(vec![0xAA; 32], Some(1), None).unwrap(),
        &csv_hash::seal::SealPoint::new(vec![0xCD; 32], Some(7), None).unwrap(),
        &[0x33; 32],
        b"consignment-bytes",
    )
    .expect("a send is receiptable");

    assert_eq!(receipt.mode(), TransferMode::Send);
    assert!(matches!(receipt.body, ReceiptBody::Send(_)));
    assert!(
        !receipt.next_actions.contains(&NextAction::Resume)
            && !receipt.next_actions.contains(&NextAction::Retry),
        "send must not advertise a destination-phase action: {:?}",
        receipt.next_actions
    );
    assert!(
        NextAction::Resume
            .validate_for_mode(TransferMode::Send)
            .is_err()
    );
}

// ── Finality events carry observed tip/evidence ─────────────────────────────

#[test]
fn an_awaiting_finality_event_carries_the_tip_the_depth_was_measured_against() {
    let outcome = csv_sdk::transfers::TransferOutcome::Pending {
        transfer_id: "transfer-1".to_string(),
        lock_tx_hash: "aa".repeat(32),
        finality: observed(2, 6),
    };

    let event = contract::materialize_event(&outcome, &sanad_id(), &source())
        .expect("a pending advance is an event");

    match &event.phase {
        TransferPhase::AwaitingFinality {
            evidence:
                FinalityEvidence::ObservedTip {
                    observed_tip_height,
                    confirming_block_height,
                    confirmations,
                    required_confirmations,
                },
        } => {
            assert_eq!(*observed_tip_height, 102);
            assert_eq!(*confirming_block_height, 100);
            assert_eq!(*confirmations, 2);
            assert_eq!(*required_confirmations, 6);
        }
        other => panic!("a finality event must carry an observed tip, got {other:?}"),
    }
    assert!(event.next_actions.contains(&NextAction::Resume));
}

#[test]
fn evidence_whose_count_contradicts_its_tip_is_rejected() {
    // Claiming six confirmations while the observed tip implies one is a fabrication,
    // and the contract will not encode it.
    let fabricated = FinalityEvidence::ObservedTip {
        confirming_block_height: 100,
        observed_tip_height: 101,
        confirmations: 6,
        required_confirmations: 6,
    };
    assert!(matches!(
        fabricated.validate(),
        Err(ContractError::InvalidField { .. })
    ));
}

#[test]
fn a_zero_depth_finality_policy_is_rejected() {
    // A required depth of zero makes the finality gate pass by construction.
    let tautology = FinalityEvidence::ObservedTip {
        confirming_block_height: 100,
        observed_tip_height: 100,
        confirmations: 0,
        required_confirmations: 0,
    };
    assert!(tautology.validate().is_err());
}

// ── No structural-only verification presented as success ────────────────────

#[test]
fn a_mint_verified_only_structurally_is_never_receipted() {
    let result = contract::materialize_receipt(
        &runtime_receipt(
            Some(observed(6, 6)),
            Some(VerificationLevel::StructuralOnly),
        ),
        &sanad_id(),
        &source(),
        &destination(),
    );
    assert!(
        result.is_err(),
        "a structural parse is not a proof, and must never be receipted as a completed mint"
    );
}

#[test]
fn a_mint_whose_lock_never_reached_finality_is_never_receipted() {
    let result = contract::materialize_receipt(
        &runtime_receipt(
            Some(observed(2, 6)),
            Some(VerificationLevel::ConsensusVerified),
        ),
        &sanad_id(),
        &source(),
        &destination(),
    );
    assert!(
        result.is_err(),
        "a mint may not be receipted next to a live observation showing the lock short of finality"
    );
}

#[test]
fn a_journal_recovered_receipt_states_that_it_re_observed_nothing() {
    // Resuming an already-completed transfer re-reads neither chain nor proof.
    let receipt = contract::materialize_receipt(
        &runtime_receipt(None, None),
        &sanad_id(),
        &source(),
        &destination(),
    )
    .expect("a journal-recovered completion is receiptable");

    match &receipt.body {
        ReceiptBody::Materialize(b) => {
            assert_eq!(b.finality, FinalityEvidence::JournalRecovered);
            assert!(
                !b.finality.is_final(),
                "an unobserved record must never read as final"
            );
        }
        other => panic!("expected a materialize body, got {other:?}"),
    }
}

// ── Unknown versions fail closed ────────────────────────────────────────────

#[test]
fn a_receipt_from_an_unknown_schema_version_is_refused() {
    let receipt = contract::materialize_receipt(
        &runtime_receipt(
            Some(observed(6, 6)),
            Some(VerificationLevel::ConsensusVerified),
        ),
        &sanad_id(),
        &source(),
        &destination(),
    )
    .expect("receipt");

    let mut bytes = encode(&receipt).expect("encodes");
    // Round-trips as itself …
    assert!(decode::<TransferReceipt>(&bytes).is_ok());

    // … but a peer speaking a schema this build does not implement is refused,
    // not interpreted optimistically.
    let mut future = receipt.clone();
    future.header.schema_version = contract::APP_CONTRACT_SCHEMA_VERSION + 1;
    bytes = csv_codec::to_canonical_cbor(&future).expect("raw encode");

    match decode::<TransferReceipt>(&bytes) {
        Err(ContractError::UnsupportedSchemaVersion { found, supported }) => {
            assert_eq!(found, contract::APP_CONTRACT_SCHEMA_VERSION + 1);
            assert_eq!(supported, contract::APP_CONTRACT_SCHEMA_VERSION);
        }
        other => panic!("an unknown schema version must fail closed, got {other:?}"),
    }
}

#[test]
fn an_artifact_of_the_wrong_kind_is_refused() {
    let receipt = contract::materialize_receipt(
        &runtime_receipt(
            Some(observed(6, 6)),
            Some(VerificationLevel::ConsensusVerified),
        ),
        &sanad_id(),
        &source(),
        &destination(),
    )
    .expect("receipt");
    let bytes = encode(&receipt).expect("encodes");

    // The same bytes must not decode as a different artifact just because the
    // shapes happen to be compatible.
    assert!(matches!(
        decode::<RecoveryPlan>(&bytes),
        Err(ContractError::ArtifactMismatch {
            expected: ArtifactKind::RecoveryPlan,
            ..
        })
    ));
}

#[test]
fn a_truncated_artifact_is_refused() {
    let report = contract::health_report(
        &csv_observability::runtime_health::RuntimeHealth::Healthy,
        &[],
    )
    .expect("health report");
    let bytes = encode(&report).expect("encodes");

    assert!(decode::<RuntimeHealthReport>(&bytes[..bytes.len() / 2]).is_err());
}

// ── Recovery actions come from the runtime, not the UI ──────────────────────

#[test]
fn an_awaiting_finality_plan_permits_exactly_resume_and_status() {
    let plan = contract::awaiting_finality_plan("transfer-1", &observed(2, 6))
        .expect("a locked transfer has a recovery plan");

    assert_eq!(plan.transfer_id, "transfer-1");
    assert_eq!(plan.mode, TransferMode::Materialize);
    assert!(plan.permitted_actions.contains(&NextAction::Resume));
    for action in &plan.permitted_actions {
        assert!(action.validate_for_mode(TransferMode::Materialize).is_ok());
    }

    let bytes = encode(&plan).expect("encodes");
    assert_eq!(decode::<RecoveryPlan>(&bytes).expect("decodes"), plan);
}

// ── Runtime health is reported, never inferred ──────────────────────────────

#[test]
fn a_failing_component_cannot_be_reported_under_an_overall_healthy_runtime() {
    use csv_observability::runtime_health::RuntimeHealth;
    use csv_runtime::runtime_mode::HealthCheck;

    let failing = vec![HealthCheck {
        component: "replay_db".to_string(),
        healthy: false,
        error: Some("unreachable".to_string()),
        timestamp: std::time::SystemTime::now(),
    }];

    assert!(
        contract::health_report(&RuntimeHealth::Healthy, &failing).is_err(),
        "a security-relevant failure must not be downgraded into a healthy report"
    );

    let unsafe_report = contract::health_report(&RuntimeHealth::Unsafe, &failing)
        .expect("an unsafe runtime still reports");
    assert!(
        !unsafe_report.is_operational(),
        "an unsafe runtime must not read as fit to execute authority operations"
    );
}
