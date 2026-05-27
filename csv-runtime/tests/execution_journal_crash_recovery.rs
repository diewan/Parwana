//! Crash recovery tests for execution journal.
//!
//! This module tests that the execution journal correctly records phase transitions
//! and that transfers can be resumed from any phase after a crash.

use csv_hash::{Hash, ReplayIdHash};
use csv_runtime::execution_journal::{
    ExecutionJournal, InMemoryJournal, PhaseOutcome, TransferPhaseEntry,
};
use csv_runtime::recovery::TransferStage;

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
            replay_id: replay_id.clone(),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
            attempt: 1,
        })
        .unwrap();

    // Record phase: Initialized (Completed)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: replay_id.clone(),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
            attempt: 1,
        })
        .unwrap();

    // Record phase: LockConfirmed (Entered)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: replay_id.clone(),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
            attempt: 1,
        })
        .unwrap();

    // Record phase: LockConfirmed (Completed)
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id.clone(),
            replay_id: replay_id.clone(),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
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
            replay_id: replay_id.clone(),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Initialized,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
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
            replay_id: replay_id.clone(),
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Failed("RPC timeout".to_string()),
            attempt: 1,
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
                replay_id: replay_id.clone(),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase,
                ts: std::time::SystemTime::now(),
                outcome: PhaseOutcome::Completed,
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
            replay_id: replay_id_1,
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::Completed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Completed,
            attempt: 1,
        })
        .unwrap();

    // Transfer 2: Incomplete at LockConfirmed
    let transfer_id_2 = "transfer-2".to_string();
    let replay_id_2 = replay_id(2);
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id_2.clone(),
            replay_id: replay_id_2,
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::LockConfirmed,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
            attempt: 1,
        })
        .unwrap();

    // Transfer 3: Incomplete at ProofBuilding
    let transfer_id_3 = "transfer-3".to_string();
    let replay_id_3 = replay_id(3);
    journal
        .record(TransferPhaseEntry {
            transfer_id: transfer_id_3.clone(),
            replay_id: replay_id_3,
            proof_hash: [0u8; 32],
            proof_payload: None,
            phase: TransferStage::ProofBuilding,
            ts: std::time::SystemTime::now(),
            outcome: PhaseOutcome::Entered,
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
                replay_id: replay_id(i as u8),
                proof_hash: [0u8; 32],
                proof_payload: None,
                phase: TransferStage::Initialized,
                ts: std::time::SystemTime::now(),
                outcome: PhaseOutcome::Completed,
                attempt: 1,
            })
            .unwrap();
    }

    // Try to add 11th entry - should fail or evict
    let result = journal.record(TransferPhaseEntry {
        transfer_id: "transfer-10".to_string(),
        replay_id: replay_id(10),
        proof_hash: [0u8; 32],
        proof_payload: None,
        phase: TransferStage::Initialized,
        ts: std::time::SystemTime::now(),
        outcome: PhaseOutcome::Completed,
        attempt: 1,
    });

    // The InMemoryJournal should handle capacity - either fail or evict
    // For now, we just verify it doesn't panic
    let _ = result;
}
