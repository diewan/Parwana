# ADR 003: Elimination of Legacy csv-core Crate

## Status

Accepted

## Context

The `csv-core` crate is self-declared as "Legacy crate — migration in progress." It contains a mix of protocol types, storage abstractions, observability code, and SDK boundaries. This violates the layered architecture defined in dep_graph_constitution.rs and creates circular dependencies. The crate must be eliminated by migrating its modules to appropriate target crates.

## Decision

Delete `csv-core` by migrating all its modules to their correct architectural layer:

| Module | Target Crate | Layer |
|--------|-------------|-------|
| client | csv-sdk | L8 (SDK) |
| consignment | csv-wire | L1 (Wire) |
| transition | csv-protocol | L3 (Protocol) |
| store/state_store | csv-storage | L5 (Storage traits) |
| recovery_engine | csv-coordinator | L5 (Orchestration) |
| trust_package | csv-verifier | L4 (Verification) |
| validator | csv-verifier | L4 (Verification) |
| performance | csv-observability | Infrastructure |
| runtime_health | csv-observability | Infrastructure |
| adapter | csv-protocol | L3 (Protocol) |
| certification | csv-proof | L2 (Proof types) |
| collections | csv-algebra | L0 (Pure types) |
| compatibility | csv-protocol | L3 (Protocol) |
| wallet_types | csv-sdk | L8 (SDK) |
| zk_proof | csv-verifier | L4 (Verification) |
| data_authority | csv-protocol | L3 (Protocol) |

### Migration Process

1. Map all modules to target crates
2. Migrate csv-sdk off csv-core (last direct dependent)
3. Add architecture guard test to prevent new csv-core dependencies
4. Remove csv-core from workspace members
5. Delete csv-core directory
6. Create TOMBSTONE.md in git history

## Consequences

### Positive
- Clean architectural layering
- No circular dependencies
- Clear module ownership
- Easier to understand dependency graph

### Negative
- Large migration effort
- Temporary breaking changes
- Need to update all import sites

## Enforcement

- Architecture guard test `csv_core_has_no_reverse_dependents` fails if any crate depends on csv-core
- CI runs this test on every PR
- csv-core cannot be re-added to workspace without explicit approval

## References

- Workstream B in csv_migration_plan.md
- dep_graph_constitution.rs
