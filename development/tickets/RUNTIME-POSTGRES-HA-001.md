---
id: RUNTIME-POSTGRES-HA-001
title: "Decide fate of 5 orphaned Postgres-HA files in csv-runtime"
theme: "runtime HA/coordinator lease scaffolding"
crate: "csv-runtime"
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-runtime/src/lib.rs"
target_patterns:
  - "pub mod distributed_coordinator_lease;"
  - "pub mod replay_database;"
target_file_2: "csv-runtime/src/postgres_store.rs"
target_patterns_2:
  - "pub struct PostgresLeaseStore"
  - "pub struct PostgresEventStore"
  - "pub struct AsyncPostgresEventStore"
interface_files:
  - "csv-runtime/src/deployment_profile.rs"
  - "csv-runtime/src/coordinator_lease_postgres.rs"
  - "csv-runtime/src/replay_record_types.rs"
  - "csv-runtime/src/adversarial.rs"
  - "csv-runtime/Cargo.toml"
  - "csv-storage/Cargo.toml"
reference_crate: "csv-storage"
reference_file: "csv-storage/Cargo.toml"
reference_patterns:
  - "postgres = [\"dep:sqlx\"]"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-runtime --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-runtime --no-default-features --features postgres"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-runtime --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo build --workspace --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "vec![0u8;"
  - "Hash::new([0u8; 32])"
  - "Ok(true) // Placeholder"
  - "Ok(0) // Placeholder"
contract_files:
  - ""
cross_boundary_check: false
---

## Problem

Five files in `csv-runtime/src/` are not declared via any `mod` statement in
`csv-runtime/src/lib.rs` and are therefore not compiled into the crate at all:

- `deployment_profile.rs` (132 lines) — a `DeploymentProfile` enum for
  per-environment finality thresholds.
- `coordinator_lease_postgres.rs` (243 lines) — `PostgresCoordinatorLease`, an
  HA advisory-lock-backed coordinator lease.
- `replay_record_types.rs` (37 lines) — a `ReplayState` enum.
- `postgres_store.rs` (693 lines) — `PostgresLeaseStore`, `PostgresEventStore`,
  and `AsyncPostgresEventStore`.
- `adversarial.rs` (294 lines) — a reorg / HA-failover / race-condition test
  harness.

`csv-runtime/Cargo.toml` defines a `postgres` feature
(`postgres = ["dep:sqlx", "dep:chrono", "csv-storage/postgres"]`) that pulls in
`sqlx`/`chrono` as optional dependencies, but nothing in the compiled crate
graph consumes them: the five files above are the only code that would need
them, and none of the five are reachable.

Two things are easy to conflate with this and are explicitly **not** what this
ticket is about:

- `csv-storage`'s own `postgres` feature (`postgres = ["dep:sqlx"]` in
  `csv-storage/Cargo.toml`) is correctly wired and out of scope here.
- `csv-testkit/src/adversarial.rs` is a separate, correctly-wired module with
  the same file name as the orphaned `csv-runtime/src/adversarial.rs`. They are
  unrelated; this ticket only concerns the uncompiled `csv-runtime` copy.

## Why it matters

A Cargo feature that silently does nothing when enabled is misleading to
operators who might turn on `postgres` expecting HA/Postgres-backed
coordination and get a no-op. Conversely, roughly 1,400 lines of apparently
real HA lease/event-store code sitting uncompiled on disk is either a missed
integration step or scaffolding that should have been removed when the work
was parked.

## Task

Investigate git history (`git log --follow -- csv-runtime/src/postgres_store.rs`,
`csv-runtime/src/coordinator_lease_postgres.rs`, etc.) to determine whether this
was scaffolding for a Postgres-backed HA coordinator lease that got parked
mid-implementation, and produce a decision:

- **(a) Finish and wire in.** If Postgres-backed HA coordination is still
  wanted: declare the five modules in `csv-runtime/src/lib.rs`, wire
  `PostgresCoordinatorLease` into the coordinator lease trait the runtime
  actually uses (see `csv-runtime/src/distributed_coordinator_lease.rs` /
  `csv-runtime/src/user_runtime_lease.rs` for the trait shape it needs to
  satisfy), wire `PostgresLeaseStore` / `PostgresEventStore` /
  `AsyncPostgresEventStore` into the real lease/event-store implementations the
  runtime selects at construction time, and add integration tests gated behind
  the `postgres` feature.
- **(b) Archive.** If this is superseded or no longer wanted: delete the five
  files, and either remove the `postgres` feature entirely or correct its scope
  so it no longer gates dependencies that nothing uses.

Do not half-do both paths — the acceptance criteria below branch on which one is
chosen.

## Acceptance criteria

- If wired in (path a):
  - [ ] All five modules are declared in `csv-runtime/src/lib.rs` and reachable
        from the crate's public surface where appropriate.
  - [ ] `PostgresCoordinatorLease` / `PostgresLeaseStore` / `PostgresEventStore`
        / `AsyncPostgresEventStore` are actually selected and used by the
        runtime when the `postgres` feature is enabled, not merely compiled.
  - [ ] `cargo check -p csv-runtime --no-default-features --features postgres`
        exercises real code paths, and at least one integration test runs
        against them.
  - [ ] The HA deployment mode is documented (README or a runbook under
        `csv-docs/`).
- If archived (path b):
  - [ ] The five files are deleted.
  - [ ] The `postgres` feature is removed from `csv-runtime/Cargo.toml`, or its
        scope is corrected so it no longer gates `sqlx`/`chrono` behind a
        feature that does nothing.
  - [ ] No dangling references to the deleted modules remain anywhere in
        `csv-runtime`.
- [ ] All `verify_commands` pass.
- [ ] A repo-wide search confirms no other crate assumed these modules existed
      (e.g. no doc or config referencing a Postgres HA mode that no longer
      exists after archiving).

## Notes

This is a decision ticket. Investigate first, then commit to one path — do not
leave the modules half-declared or the feature half-scoped. `csv-storage`'s
`postgres` feature is a working reference for what "correctly wired" looks
like, but it does not itself need any changes here.
