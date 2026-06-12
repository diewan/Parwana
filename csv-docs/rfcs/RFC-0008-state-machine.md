# RFC-0008: State Machine

## Status

Partially Implemented (Phase 9 completed 2026-06-13 - recovery state transitions implemented)

## Motivation

Current runtime state explosion with many transfer states:

- awaiting_finality
- completed
- compromised
- locked
- minting
- proof_building
- proof_validated
- rolled_back

This is approaching unmanageable state-machine complexity. Missing:

- Formal transition graph generation
- Exhaustive model checking
- Forbidden transition proofs
- Temporal property verification

## Proposed Change

### 1. Generate Transition Graph

Automatically generate:

```rust
transition_graph.rs
```

From state definitions, test:

- All legal transitions
- All forbidden transitions
- Liveness
- Deadlocks
- Rollback legality

### 2. Define State Machine Constitution

Create `/docs/state-machine.md` defining:

- State definitions
- Transition rules
- Forbidden transitions
- Rollback semantics
- Finality semantics
- Error recovery ✅ Implemented via TransferCoordinator recovery methods

### 3. Add Model Checking

MANDATORY:

```rust
TLA+
Alloy
```

Models:

- Replay safety
- Ownership uniqueness
- Rollback recovery ✅ Implemented via CheckpointManager and ExecutionJournal
- Proof consistency

### 4. Simplify State Machine

## Implementation Status

**Completed 2026-06-13 (Phase 9 - Recovery State Transitions):**

- ✅ TransferStage enum with all recovery states implemented in csv-protocol
- ✅ State machine logic in TransferCoordinator.resume_transfer()
- ✅ Recovery paths for all stages: LockSubmitted, LockConfirmed, AwaitingFinality, ProofBuilding, ProofValidated, MintSubmitted, MintConfirmed
- ✅ Crash recovery tests for all state transitions
- ✅ ExecutionJournal provides phase-by-phase audit trail

**Remaining Work:**

- Formal transition graph generation (not yet implemented)
- Model checking with TLA+/Alloy (models exist in formal/ but not integrated into CI)
- Forbidden transition proofs (manual tests exist, automated proofs pending)

**Result:** Recovery state machine is fully implemented with crash-safe transitions. Formal verification models exist but are not yet integrated into CI.

Reduce state explosion:

- Merge similar states
- Use state composition
- Explicit state hierarchy
- Minimal state set

## Rationale

Formal state machine prevents:

- State explosion
- Illegal transitions
- Deadlocks
- Inconsistent state handling
- Runtime bugs

## Impact

BREAKING CHANGE: State machine redesign.

- Simplify transfer states
- Add formal verification
- Update runtime logic
- Add state machine tests

## Alternatives

- Keep current state explosion (REJECTED - unmaintainable)
- Ad hoc state transitions (REJECTED - unsafe)

## Unresolved Questions

- State machine formalism?
- Model checking toolchain?
- State migration strategy?
