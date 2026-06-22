---
id: CLI-STATE-001
title: "Remove protocol decisions from local CLI state"
theme: "CLI Honest Mode"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-cli/src/state.rs"
target_patterns:
  - "sanads"
target_file_2: "csv-cli/src/commands/sanads.rs"
target_patterns_2:
  - "state"
interface_files:
  - "csv-cli/src/commands/seals.rs"
  - "csv-cli/src/commands/cross_chain/status.rs"
  - "csv-sdk/src/runtime.rs"
  - "csv-protocol/src/chain_adapter_traits.rs"
reference_crate: "development"
reference_file: "development/CANONICAL-NAMING.md"
reference_patterns:
  - "get_sanad_state"
verify_commands:
  - "cargo test -p csv-cli --test integration_tests"
  - "cargo test -p csv-architecture"
forbidden_patterns:
  - "Active"
  - "Consumed"
  - "local canonical"
  - "fallback to local"
contract_files:
  - "csv-cli/src/commands/sanads.rs"
  - "csv-cli/src/commands/seals.rs"
  - "csv-cli/src/commands/cross_chain/status.rs"
cross_boundary_check: true
---

## Problem

Some CLI state and status paths can infer protocol state from local records. Local records are allowed for display history, wallet metadata, cached transaction references, and user convenience, but not as canonical truth.

## Why it matters

A constitutional protocol runtime cannot allow a CLI cache to decide whether a Sanad or seal is active, consumed, transferred, locked, or minted.

## Task

Audit every CLI path that reports Sanad, seal, or transfer state. Replace protocol decisions with runtime/adapter-backed queries. When only local data exists, label it explicitly as `local display cache` and fail closed for protocol commands that require canonical state.

## Acceptance criteria

- [ ] `csv sanad state` uses runtime-backed canonical state.
- [ ] `csv sanad trace` uses runtime/adapter lifecycle events where available.
- [ ] Local fallback is labeled `local display cache`, never canonical.
- [ ] Missing chain query fails closed for protocol commands.
- [ ] Tests prove local cache cannot mark an on-chain consumed Sanad as active.
