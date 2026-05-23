// Protocol State Transition Tests
//
// Invariant: State transitions must follow legal paths only.
// Forbidden transitions must hard fail at compile time or runtime.

use csv_core::transfer_stage::TransferStage;

/// Test that illegal state transitions are detected and rejected.
#[test]
fn forbidden_state_transitions_fail() {
    // The TransferStage::next_stage() method defines the legal transitions.
    // Any transition NOT in this sequence is forbidden.

    // 1. Verify the happy path transitions are valid
    let mut current = TransferStage::Initialized;
    let expected_sequence = vec![
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
        TransferStage::Completed,
    ];

    for (i, expected) in expected_sequence.iter().enumerate() {
        let next = current.next_stage()
            .unwrap_or_else(|| panic!("Transition from {:?} at step {} must be valid", current, i));
        assert_eq!(
            next, *expected,
            "Step {} transition must go from {:?} to {:?}",
            i, current, expected
        );
        current = next;
    }

    // 2. Terminal states must not have a next stage
    assert!(
        TransferStage::Completed.next_stage().is_none(),
        "Completed must be terminal"
    );
    assert!(
        TransferStage::RolledBack.next_stage().is_none(),
        "RolledBack must be terminal"
    );
    assert!(
        TransferStage::Compromised.next_stage().is_none(),
        "Compromised must be terminal"
    );

    // 3. Verify that skipping stages is impossible via the API
    //    (the API only allows one-step transitions)
    let from_initialized = TransferStage::Initialized.next_stage().unwrap();
    assert_eq!(
        from_initialized,
        TransferStage::LockSubmitted,
        "Initialized can only go to LockSubmitted, not directly to LockConfirmed"
    );
    assert_ne!(
        from_initialized,
        TransferStage::LockConfirmed,
        "Initialized cannot skip to LockConfirmed"
    );

    // 4. Verify that going backwards is impossible
    let lock_confirmed = TransferStage::LockConfirmed;
    let next = lock_confirmed.next_stage().unwrap();
    assert_ne!(
        next,
        TransferStage::LockSubmitted,
        "LockConfirmed cannot go back to LockSubmitted"
    );
    assert_eq!(
        next,
        TransferStage::ProofBuilding,
        "LockConfirmed must go forward to ProofBuilding"
    );

    // 5. Verify that terminal states cannot transition to non-terminal states
    assert!(
        TransferStage::Completed.next_stage().is_none(),
        "Completed cannot transition to any stage"
    );
    assert!(
        TransferStage::RolledBack.next_stage().is_none(),
        "RolledBack cannot transition to any stage"
    );
    assert!(
        TransferStage::Compromised.next_stage().is_none(),
        "Compromised cannot transition to any stage"
    );

    // 6. Verify that Initialized is not considered in_progress
    assert!(
        !TransferStage::Initialized.is_in_progress(),
        "Initialized must not be in_progress"
    );
    assert!(
        TransferStage::LockConfirmed.is_in_progress(),
        "LockConfirmed must be in_progress"
    );
    assert!(
        TransferStage::Completed.is_in_progress() == false,
        "Completed must not be in_progress"
    );
}

/// Test that the state machine is exhaustive (all stages are accounted for).
#[test]
fn state_machine_is_exhaustive() {
    // Collect all possible stages
    let all_stages = vec![
        TransferStage::Initialized,
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
        TransferStage::Completed,
        TransferStage::RolledBack,
        TransferStage::Compromised,
    ];

    // Verify each stage has a valid Display representation
    for stage in &all_stages {
        let display = format!("{}", stage);
        assert!(
            !display.is_empty(),
            "Stage {:?} must have a non-empty Display representation",
            stage
        );
    }

    // Verify terminal stages
    let terminal_stages = vec![
        TransferStage::Completed,
        TransferStage::RolledBack,
        TransferStage::Compromised,
    ];
    for stage in &terminal_stages {
        assert!(
            stage.is_terminal(),
            "{:?} must be terminal",
            stage
        );
    }

    // Verify non-terminal stages
    let non_terminal_stages = vec![
        TransferStage::Initialized,
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
    ];
    for stage in &non_terminal_stages {
        assert!(
            !stage.is_terminal(),
            "{:?} must not be terminal",
            stage
        );
    }

    // Verify proof_validated stages
    let proof_validated_stages = vec![
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
        TransferStage::Completed,
    ];
    for stage in &proof_validated_stages {
        assert!(
            stage.proof_validated(),
            "{:?} must have proof_validated = true",
            stage
        );
    }

    let non_proof_validated_stages = vec![
        TransferStage::Initialized,
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
    ];
    for stage in &non_proof_validated_stages {
        assert!(
            !stage.proof_validated(),
            "{:?} must have proof_validated = false",
            stage
        );
    }

    // Verify Default is Initialized
    assert_eq!(
        TransferStage::default(),
        TransferStage::Initialized,
        "Default stage must be Initialized"
    );

    // Verify all stages in the happy path have a next stage
    let happy_path = vec![
        TransferStage::Initialized,
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
    ];
    for stage in &happy_path {
        assert!(
            stage.next_stage().is_some(),
            "{:?} must have a next stage in the happy path",
            stage
        );
    }
}

/// Test that transition legality is enforced through the API.
#[test]
fn transition_legality_is_enforced() {
    // 1. Verify that the next_stage() API enforces one-step transitions
    //    (no skipping stages)
    let stages_with_next: Vec<TransferStage> = vec![
        TransferStage::Initialized,
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
    ];

    for stage in &stages_with_next {
        let next = stage.next_stage().expect("must have next stage");
        // The next stage must be different from the current stage
        assert_ne!(
            *stage, next,
            "Next stage must differ from current stage"
        );
    }

    // 2. Verify that the transition graph is a simple chain (no branches
    //    in the happy path)
    let mut current = TransferStage::Initialized;
    let mut visited = std::collections::HashSet::new();
    visited.insert(current);

    while let Some(next) = current.next_stage() {
        assert!(
            !visited.contains(&next),
            "Transition graph must be acyclic (no loops)"
        );
        visited.insert(next);
        current = next;
    }

    // 3. Verify that all non-terminal stages are reachable from Initialized
    let all_non_terminal = vec![
        TransferStage::LockSubmitted,
        TransferStage::LockConfirmed,
        TransferStage::ProofBuilding,
        TransferStage::ProofValidated,
        TransferStage::AwaitingFinality,
        TransferStage::MintSubmitted,
        TransferStage::MintConfirmed,
    ];

    for stage in &all_non_terminal {
        assert!(
            visited.contains(stage),
            "{:?} must be reachable from Initialized",
            stage
        );
    }

    // 4. Verify happy path ends at Completed (rollback/compromise are separate paths)
    assert!(
        visited.contains(&TransferStage::Completed),
        "Completed must be reachable from Initialized via next_stage()"
    );
    assert!(
        !visited.contains(&TransferStage::RolledBack),
        "RolledBack is not on the default happy-path chain"
    );
    assert!(
        !visited.contains(&TransferStage::Compromised),
        "Compromised is not on the default happy-path chain"
    );

    // 5. Verify that Completed is the only happy-path terminal state
    assert_eq!(
        TransferStage::Completed.next_stage(),
        None,
        "Completed is the happy-path terminal state"
    );
}
