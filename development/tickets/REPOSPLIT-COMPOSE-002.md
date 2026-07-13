---
id: REPOSPLIT-COMPOSE-002
title: "Move concrete chain and wallet assembly to the application composition boundary"
theme: multi-repo-composition
crate: csv-coordinator
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: .agents/AGENT.md
target_file: csv-coordinator/src/wallet_factory.rs
target_patterns:
  - "use csv_bitcoin"
  - "use csv_ethereum"
  - "use csv_sui"
  - "use csv_aptos"
  - "use csv_solana"
target_file_2: csv-coordinator/Cargo.toml
target_patterns_2:
  - "Chain adapters"
  - "csv-bitcoin"
interface_files:
  - csv-adapter-factory/src/lib.rs
  - csv-sdk/src/builder.rs
  - csv-runtime/src/adapter_registry.rs
reference_crate: csv-adapter-factory
reference_file: csv-adapter-factory/src/lib.rs
reference_patterns:
  - "AdapterFactory"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-coordinator -p csv-adapter-factory -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-architecture"
  - "cargo clippy -p csv-coordinator -p csv-adapter-factory -p csv-sdk --all-features -- -D warnings"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "unwrap()"
  - "expect("
  - "silent fallback"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

The reconciled architecture intentionally permits `csv-coordinator` to perform
feature-gated adapter assembly. That is coherent inside one workspace, but it
couples the proposed runtime repository to every concrete adapter repository.
`wallet_factory.rs` imports five chain implementations directly, while adapter
factory and SDK composition facilities already exist elsewhere.

## Why it matters

A multi-repository runtime must accept injected chain capabilities. Concrete
selection belongs at an executable/application composition root. The move must
not let CLI or SDK bypass `TransferCoordinator`, the execution journal,
admission control, replay checks, or strict finality.

## Task

Move concrete chain and wallet construction from `csv-coordinator` into the
adapter/application composition layer. Keep coordinator logic chain-neutral and
inject constructed ports or factories. Consolidate duplicate composition paths
without moving transfer authority out of runtime.

## Acceptance criteria

- [ ] `csv-coordinator` has no dependencies on concrete chain adapter crates.
- [ ] `csv-coordinator` has no chain-name-specific imports in production source.
- [ ] One documented composition path constructs and registers every supported adapter.
- [ ] CLI and SDK still delegate all transfer authority to `csv-runtime`.
- [ ] Missing or disabled adapters produce explicit capability errors without fallback.
- [ ] Architecture tests prevent concrete adapters from returning to coordinator.
- [ ] All `verify_commands` pass.

## Notes

This ticket follows `REPOSPLIT-PORTS-001`. Do not solve it by moving authority
state or transfer orchestration into the adapter factory or CLI.
