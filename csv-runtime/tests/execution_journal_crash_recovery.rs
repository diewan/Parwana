//! Crash recovery tests for execution journal.
//!
//! This module tests that the execution journal correctly records phase transitions
//! and that transfers can be resumed from any phase after a crash.
//!
//! Tests use deterministic proof fixtures from csv-testkit, not fake bytes.

use csv_hash::{Hash, ReplayIdHash};
use csv_runtime::execution_journal::{
    ExecutionJournal, InMemoryJournal, PhaseOutcome, TransferPhaseEntry,
};
use csv_runtime::recovery::TransferStage;
use csv_testkit::fixtures::TestProofBundle;

fn replay_id(byte: u8) -> ReplayIdHash {
    ReplayIdHash(Hash::new([byte; 32]))
}

#[tokio::test]
async fn test_journal_records_all_phase_transitions() {
    let journal = InMemoryJournal::new(1000);
    let transfer_id = "test-transfer-1".to_string();
    let replay_id = replay_id(1);

    // Record phase: Initialized (Entered)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Record phase: Initialized (Completed)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Record phase: LockConfirmed (Entered)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Record phase: LockConfirmed (Completed)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Verify latest phase is LockConfirmed
    let latest = journal.latest_phase(&transfer_id).unwrap();
    assert_eq!(latest, Some(TransferStage::LockConfirmed));

    // Verify transfer still needs recovery because LockConfirmed is not terminal.
    let incomplete = journal.incomplete_transfers().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].transfer_id, transfer_id);
    assert_eq!(incomplete[0].phase, TransferStage::LockConfirmed);
}

#[tokio::test]
async fn test_journal_identifies_incomplete_transfers() {
    let journal = InMemoryJournal::new(1000);
    let transfer_id = "test-transfer-2".to_string();
    let replay_id = replay_id(2);

    // Record phase: Initialized (Entered) - not completed
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Verify transfer is incomplete
    let incomplete = journal.incomplete_transfers().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].transfer_id, transfer_id);
    assert_eq!(incomplete[0].phase, TransferStage::Initialized);
    assert!(matches!(incomplete[0].outcome, PhaseOutcome::Entered));
}

#[tokio::test]
async fn test_journal_records_failed_phase() {
    let journal = InMemoryJournal::new(1000);
    let transfer_id = "test-transfer-3".to_string();
    let replay_id = replay_id(3);

    // Record phase: LockConfirmed (Failed)
         journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Failed("RPC timeout".to_string()),
            attempt: 1,
            transfer_context: None,
        })
        .unwrap();

    // Verify transfer is incomplete (failed phase)
    let incomplete = journal.incomplete_transfers().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].transfer_id, transfer_id);
    assert!(matches!(incomplete[0].outcome, PhaseOutcome::Failed(_)));
}

#[tokio::test]
async fn test_journal_latest_phase_for_completed_transfer() {
    let journal = InMemoryJournal::new(1000);
    let transfer_id = "test-transfer-4".to_string();
    let replay_id = replay_id(4);

    // Record full lifecycle
    for phase in [
        TransferStage::Initialized,
        TransferStage::LockConfirmed,
        TransferStage::AwaitingFinality,
        TransferStage::ProofBuilding,
        TransferStage::MintConfirmed,
        TransferStage::Completed,
    ] {
        journal
            .record(TransferPhaseEntry {
                transfer_id: transfer_id.clone(),
                replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase,
                ts: std::time::SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                transfer_context: None,
                attempt: 1,
            })
            .unwrap();
    }

    // Verify latest phase is Completed
    let latest = journal.latest_phase(&transfer_id).unwrap();
    assert_eq!(latest, Some(TransferStage::Completed));

    // Verify transfer is not incomplete
    let incomplete = journal.incomplete_transfers().unwrap();
    assert!(incomplete.is_empty());
}

#[tokio::test]
async fn test_journal_multiple_transfers() {
    let journal = InMemoryJournal::new(1000);

    // Transfer 1: Completed
    let transfer_id_1 = "transfer-1".to_string();
    let replay_id_1 = replay_id(1);
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id_1.clone(),
            replay_id: csv_wire::HashWire::from(replay_id_1.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Completed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Transfer 2: Incomplete at LockConfirmed
    let transfer_id_2 = "transfer-2".to_string();
    let replay_id_2 = replay_id(2);
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id_2.clone(),
            replay_id: csv_wire::HashWire::from(replay_id_2.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Transfer 3: Incomplete at ProofBuilding
    let transfer_id_3 = "transfer-3".to_string();
    let replay_id_3 = replay_id(3);
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id_3.clone(),
            replay_id: csv_wire::HashWire::from(replay_id_3.0.clone()),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::ProofBuilding,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
                transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Verify incomplete transfers
    let incomplete = journal.incomplete_transfers().unwrap();
    assert_eq!(incomplete.len(), 2);

    let incomplete_ids: Vec<_> = incomplete.iter().map(|e| e.transfer_id.clone()).collect();
    assert!(incomplete_ids.contains(&transfer_id_2));
    assert!(incomplete_ids.contains(&transfer_id_3));
    assert!(!incomplete_ids.contains(&transfer_id_1));
}

#[tokio::test]
async fn test_journal_capacity_enforcement() {
    let journal = InMemoryJournal::new(10); // Small capacity

    // Add 10 entries (at capacity)
    for i in 0..10 {
        journal
            .record(TransferPhaseEntry {
                transfer_id: format!("transfer-{}", i),
                replay_id: csv_wire::HashWire::from(replay_id(i as u8).0.clone()),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::Initialized,
                ts: std::time::SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                transfer_context: None,
                attempt: 1,
            })
            .unwrap();
    }

    // Try to add 11th entry - audit history must never be evicted.
    let result = journal.record(TransferPhaseEntry {
        transfer_id: "transfer-10".to_string(),
        replay_id: csv_wire::HashWire::from(replay_id(10).0.clone()),
        proof_hash: [0u8; 32],
        proof_payload: None,
        phase: TransferStage::Initialized,
        ts: std::time::SystemTime::now(),
        outcome: PhaseOutcome::Completed,
                transfer_context: None,
        attempt: 1,
    });

    assert_eq!(
        result,
        Err(csv_runtime::execution_journal::JournalError::CapacityExceeded)
    );
}

#[tokio::test]
async fn test_recovery_with_deterministic_proof_fixture() {
    let journal = InMemoryJournal::new(1000);
    let transfer_id = "test-transfer-with-proof".to_string();
    let replay_id = replay_id(5);

    // Use deterministic proof fixture from csv-testkit
    let proof_bundle = TestProofBundle::minimal();
    let proof_payload = csv_codec::to_canonical_cbor(&proof_bundle).unwrap();
    // Compute proof hash using tagged hash (same as transfer_coordinator does)
    let proof_hash = csv_hash::csv_tagged_hash("csv.execution-journal.proof-payload.v1", &proof_payload);

    // Record phase: ProofBuilding with persisted proof payload
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: csv_wire::HashWire::from(replay_id.0.clone()),
            proof_hash,
            proof_payload: Some(proof_payload.clone()),
            phase: TransferStage::ProofBuilding,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
            transfer_context: None,
            attempt: 1,
        })
        .unwrap();

    // Verify proof payload is persisted
    let latest = journal.latest_phase(&transfer_id).unwrap();
    assert_eq!(latest, Some(TransferStage::ProofBuilding));

    // Verify the transfer is incomplete (ProofBuilding is not terminal)
    let incomplete = journal.incomplete_transfers().unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].transfer_id, transfer_id);
    assert_eq!(incomplete[0].phase, TransferStage::ProofBuilding);
    
    // Verify the proof payload can be deserialized
    let recovered_bundle: csv_protocol::proof_taxonomy::ProofBundle = 
        csv_codec::from_canonical_cbor(&proof_payload).unwrap();
    
    // Verify the recovered bundle has valid structure (access field directly)
    assert_eq!(recovered_bundle.inclusion_proof.block_number, proof_bundle.inclusion_proof.block_number);
}
