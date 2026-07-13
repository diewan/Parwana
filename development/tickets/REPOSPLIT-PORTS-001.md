---
id: REPOSPLIT-PORTS-001
title: "Separate chain-neutral ports from concrete adapter implementation infrastructure"
theme: multi-repo-ports
crate: csv-adapter-core
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: .agents/AGENT.md
target_file: csv-adapters/csv-adapter-core/src/lib.rs
target_patterns:
  - "pub trait ChainAdapter"
  - "pub trait AdapterRegistry"
target_file_2: csv-runtime/src/adapter_registry.rs
target_patterns_2:
  - "use csv_adapter_core"
  - "impl AdapterRegistryTrait"
interface_files:
  - csv-runtime/src/transfer_coordinator.rs
  - csv-protocol/src/chain_adapter_traits.rs
reference_crate: csv-runtime
reference_file: csv-runtime/src/lib.rs
reference_patterns:
  - "pub use csv_adapter_core"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-runtime -p csv-adapter-core"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-architecture --test dep_graph_constitution"
  - "cargo clippy -p csv-runtime -p csv-adapter-core --all-features -- -D warnings"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "unwrap()"
  - "expect("
  - "unsafe"
  - "Ok(true)"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

`csv-runtime` correctly avoids concrete chain crates, but its public authority
path depends on `csv-adapter-core`, which currently lives under the concrete
adapter tree. A future `csv-runtime-rs` repository would therefore depend on an
implementation repository for the interfaces it needs to compile. The current
layout also makes ownership of `ChainAdapter`, capability ports, registry
interfaces, errors, finality results, and materialization results ambiguous.

## Why it matters

Repository direction should match dependency direction. Runtime authority must
own or consume chain-neutral contracts without importing implementation
infrastructure. Moving interfaces must not change verification, finality,
replay, mint, settlement, or error semantics.

## Task

Create a neutral home for the runtime-facing adapter ports. Prefer a focused
crate such as `csv-chain-ports`, or place the interfaces in an existing neutral
crate only if the dependency DAG proves that choice is acyclic. Move only
chain-neutral traits and their protocol result/error types. Keep concrete
configuration, factories, RPC clients, and chain-specific helpers in the
adapter group. Migrate runtime and adapter implementations mechanically.

## Acceptance criteria

- [ ] Runtime-facing ports no longer reside under `csv-adapters/`.
- [ ] The neutral ports crate has no concrete adapter, networking, storage backend, or application dependency.
- [ ] `csv-runtime` depends only on the neutral ports package, not `csv-adapter-core`.
- [ ] All six adapters implement the same unchanged fail-closed port contracts.
- [ ] Finality and replay-related result types retain their existing semantics and tests.
- [ ] Architecture CI prevents neutral ports from importing adapter implementations.
- [ ] All `verify_commands` pass.

## Notes

Treat this as a boundary relocation, not an opportunity to redesign protocol
behavior. If a type cannot be moved without importing concrete infrastructure,
split that type rather than adding an upward dependency.
