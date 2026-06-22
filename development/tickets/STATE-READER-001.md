---
id: STATE-READER-001
title: "Wire SanadStateReader into CLI"
theme: "Canonical State and Trace"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-protocol/src/chain_adapter_traits.rs"
target_patterns:
  - "SanadStateReader"
target_file_2: "csv-cli/src/commands/sanads.rs"
target_patterns_2:
  - "trace"
interface_files:
  - "csv-sdk/src/runtime.rs"
  - "csv-adapters/csv-bitcoin/src/ops.rs"
  - "csv-adapters/csv-ethereum/src/ops.rs"
  - "csv-adapters/csv-sui/src/ops.rs"
  - "csv-adapters/csv-aptos/src/ops.rs"
  - "csv-adapters/csv-solana/src/ops.rs"
reference_crate: "development"
reference_file: "development/CANONICAL-NAMING.md"
reference_patterns:
  - "SanadStateView"
verify_commands:
  - "cargo test -p csv-protocol"
  - "cargo test -p csv-cli --test integration_tests"
forbidden_patterns:
  - "parse RPC in CLI"
  - "local canonical"
  - "fallback to cache"
contract_files:
  - "csv-protocol/src/chain_adapter_traits.rs"
  - "csv-cli/src/commands/sanads.rs"
cross_boundary_check: true
---

## Problem

State and trace paths need adapter-backed canonical readers instead of ad-hoc CLI logic.

## Why it matters

The CLI must not parse chain-specific RPC responses directly or infer canonical state from local display records.

## Task

Implement or fail-closed for `get_sanad_state`, `get_seal_state`, and `trace_sanad`, then route `csv sanad state`, `csv sanad trace`, and `csv seal verify` through those APIs.

## Acceptance criteria

- [ ] Ethereum reads contract state.
- [ ] Bitcoin reads UTXO/anchor/seal state.
- [ ] Sui/Aptos/Solana either read real object/resource/account state or return capability unavailable.
- [ ] No CLI command parses chain-specific RPC responses directly for canonical state.
- [ ] Trace output includes local display records only as supplemental data.
