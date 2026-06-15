---
id: C-CLI-UTXO-001
title: "Replace CLI Sanad UTXO validation skip with runtime/adaptor-backed verification"
theme: C
crate: csv-cli
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: csv-cli/.agents/AGENT.md
target_file: csv-cli/src/commands/sanads.rs
target_patterns:
  - "// For now, skip on-chain validation to avoid RPC dependency"
  - "// TODO: Implement proper UTXO validation using Bitcoin adapter"
interface_files:
  - csv-runtime/src/transfer_coordinator.rs
  - csv-protocol/src/chain_adapter_traits.rs
  - csv-adapters/csv-bitcoin/src/ops.rs
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "cargo check -p csv-cli"
  - "cargo test -p csv-cli"
  - "cargo test -p csv-architecture"
---

## Problem

The CLI Sanad command skips on-chain validation to avoid an RPC dependency and leaves a TODO to use the Bitcoin adapter.

## Why it matters

CLI code must not bypass runtime verification or call adapters directly. This gap can normalize unverified UTXO assumptions in user-facing flows.

## Task

Replace the skip path with a runtime-mediated validation path. The CLI should delegate to the configured runtime/client layer and fail closed when RPC or validation support is unavailable. Do not import chain adapters directly into `csv-cli` if that violates the architecture guard.

## Acceptance criteria

- [ ] The skip comments are removed.
- [ ] CLI validation delegates through runtime/client boundaries, not direct adapter imports.
- [ ] Missing RPC/config returns a typed error, not success.
- [ ] A test covers the unavailable-RPC fail-closed path.
- [ ] `cargo check -p csv-cli` passes.
- [ ] `cargo test -p csv-cli` passes.
- [ ] `cargo test -p csv-architecture` passes.

## Notes

The architecture rule is more important than quick wiring. If no runtime API exists yet, add a small runtime-facing validation method and test the dependency boundary.
