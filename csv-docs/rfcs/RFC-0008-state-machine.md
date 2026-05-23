# RFC-0008: State Machine

## Status

Proposed

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
- Error recovery

### 3. Add Model Checking

MANDATORY:

```rust
TLA+
Alloy
```

Models:

- Replay safety
- Ownership uniqueness
- Rollback recovery
- Proof consistency

### 4. Simplify State Machine

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
