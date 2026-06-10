# UNWIRED.md — Implementation Checklist

**Last validated:** 2025-06-09
**Status:** Active tracking document — all items validated against current codebase.

## Completed

- [x] **Bind proof recovery to transfer** — `VerificationContext` in `csv-verifier/src/verifier.rs:355` has all required fields: `sanad_id` (372), `lock_tx` (374), `lock_output_index` (376), `transition_id` (378), `destination_chain` (380). `verify_recovery_proof` in `csv-runtime/src/transfer_coordinator.rs:1681` validates these by binding proof seal to transfer sanad_id (1728-1740), binding anchor metadata to lock transaction (1742-1756), and constructing `VerificationContext` with all fields (1758-1773).

- [x] **Wire chain-adapter RPCs through csv-wire** — `csv-wire/src/rpc/` contains: `bitcoin.rs`, `ethereum.rs`, `solana.rs`, `aptos.rs`, `celestia.rs`, `mod.rs`.

- [x] **Enforce csv-wire via deny.toml** — `deny.toml` has forbidden edges blocking `serde::Serialize` and `serde_json` for csv-hash, csv-protocol, csv-proof, csv-verifier, csv-schema, csv-content (lines 47-103).

- [x] **Migrate csv-sdk off csv-core** — No `csv_core` imports in `csv-sdk/src/`. csv-core excluded from workspace: `exclude = ["csv-core"]` in root `Cargo.toml:3`. csv-core directory removed; see `csv-core-TOMBSTONE.md`.

- [x] **Add architecture guard for csv-core elimination** — `nothing_new_depends_on_csv_core` test exists at `csv-architecture/tests/architecture_guard.rs:127`. Checks both cargo metadata dependencies and source file imports.

- [x] **Delete csv-core crate** — csv-core directory removed. `csv-core-TOMBSTONE.md` created with full migration path. Architecture guard tests enforce no re-entry.

- [x] **Integrate observability types into runtime** — `csv-runtime/src/runtime_mode.rs:21` imports `RuntimeHealth` from `csv_observability::runtime_health`. Used throughout runtime mode state machine (229-409).

- [x] **Add Celestia to chain references** — Celestia referenced in runtime (`transfer_coordinator.rs:2720`, `policy.rs:67`). Chains use string-based identifiers (no compile-time Chain enum).

- [x] **Add runtime subcommand** — `Runtime` subcommand in `Commands` enum at `csv-cli/src/main.rs:169` with `RuntimeAction`. Dispatched at line 222.

- [x] **Add content subcommand** — `Content` subcommand in `Commands` enum at `csv-cli/src/main.rs:162` with `ContentAction`. Dispatched at line 221.

- [x] **Add trust subcommand** — `Trust` subcommand in `Commands` enum at `csv-cli/src/main.rs:175` with `TrustAction`. Dispatched at line 223.

- [x] **Organize examples** — `csv-examples/getting-started/`, `csv-examples/advanced/`, `csv-examples/cli-tutorial/` all exist.

- [x] **Create CLI tutorial** — `csv-examples/cli-tutorial/csv-cli-tutorial.md` exists.

- [x] **Add Solana to test matrix** — Solana pairs in `csv-cli/src/commands/tests.rs:78-80`: `(solana, sui)`, `(solana, ethereum)`, `(solana, aptos)`.

- [x] **Implement execute_from_proof recovery** — `execute_from_proof` at `csv-runtime/src/transfer_coordinator.rs:1914`. Recovery for `ProofValidated` at line 1557 loads `proof_payload` from journal entry, validates hash (1567), calls `execute_from_proof` (1572).

## Partially Implemented

- [~] **Implement persistent execution journal** — `csv-runtime/src/postgres_store.rs` exists with `PostgresLeaseStore` and `PostgresEventStore`. However, the execution journal itself is `InMemoryJournal` and `RocksDbExecutionJournal` in `csv-runtime/src/execution_journal.rs`. PostgreSQL provides lease coordination and event sourcing, not a dedicated `PostgresExecutionJournal`. The UNWIRED.md claim of "PostgreSQL-backed execution journal" was inaccurate.

- [~] **Fix recovery lease authority** — `LeaseConfig` in `csv-runtime/src/config.rs:180` has `default_duration`, `max_duration`, `renewal_threshold`. Production defaults (63-66): `default_duration: 3600s`, `max_duration: 86400s`, `renewal_threshold: 300s`. Development defaults (100-103): `default_duration: 1800s`, `max_duration: 7200s`, `renewal_threshold: 300s`. The original claim of "30s default, 300s max" was inaccurate. Only `renewal_threshold` matches at 300s.

- [~] **Wire proof_payload into ExecutionJournalEntry** — `TransferPhaseEntry` in `csv-runtime/src/execution_journal.rs:43` has `proof_payload: Option<Vec<u8>>` (line 52). However, it does NOT have `block_height` or `tx_hash_bytes` fields as originally claimed. The struct has: `transfer_id`, `replay_id`, `proof_hash`, `proof_payload`, `phase`, `ts`, `outcome`, `attempt`.

- [~] **Implement execute_from_lock recovery** — `execute_from_lock` exists at `csv-runtime/src/transfer_coordinator.rs:1796`. Recovery for `LockConfirmed` at line 1532 calls `execute_from_lock` but relies on `cached_transfer` from memory (not from journal). The recovery does NOT load a LockConfirmed journal entry to reconstruct the Locked typestate. It re-verifies the lock from scratch.

- [~] **Implement AwaitingFinality recovery** — Recovery for `AwaitingFinality` at line 1580 calls `execute_from_lock` which re-checks finality. It does NOT specifically re-poll a finality monitor with proof height from journal.

- [~] **Implement ProofBuilding recovery** — Recovery for `ProofBuilding` at line 1544 calls `execute_from_lock` which regenerates proof. It does NOT check for a persisted checkpoint before regenerating.

- [~] **Wire csv-coordinator isolation-domain behavior** — `csv-coordinator/src/cell.rs` has `ChainCell` with bounded mpsc queue, `CellCircuitBreaker`, and `MemoryCeiling`. However, the `cell_worker` function (line 133) has a **stub implementation**: it logs the transfer but does not actually process it (line 164: `let _anchor_id = transfer_id;` discards the transfer data). The isolation infrastructure is present but the actual per-chain execution logic is not wired.

- [~] **Wire chain_management.rs commands** — `ChainCommands` enum exists at `csv-cli/src/chain_management.rs:9` with `List`, `Show`, `Discover`, `Validate`, `CreateTemplate` variants. However, it is **NOT connected** to the `Commands` enum in `main.rs`. The `Commands` enum uses `ChainAction` from `commands/chain.rs` (line 88), not `ChainCommands`. `ChainCommands` is defined but never imported or used in the CLI dispatch.

## Pending

- [ ] **Strip serde from L0-L4 internal types** — `development/serde_audit_manifest.md` reports "Total types found: **128**" (not 196 as originally claimed). L0 types in csv-hash still have conditional serde derives. L1 types in csv-proof have unconditional `#[derive(Serialize, Deserialize)]`. csv-protocol has 183 matches for Serialize/Deserialize derives. The manifest categorizes L0 as "MUST STRIP", L1 as "SHOULD STRIP", L2-L4 as "MAY KEEP".
