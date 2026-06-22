---
id: PROD-FAILCLOSED-001
title: "No mock fallback in production adapters"
theme: "Production Safety"
crate: "csv-adapters"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-ethereum/src/ops.rs"
target_patterns:
  - "mock"
target_file_2: "csv-adapters/csv-aptos/src/ops.rs"
target_patterns_2:
  - "mock"
interface_files:
  - "csv-protocol/src/chain_adapter_traits.rs"
  - "csv-sdk/src/runtime.rs"
reference_crate: "csv-adapters"
reference_file: "csv-adapters/csv-bitcoin/src/ops.rs"
reference_patterns:
  - "check_readiness"
verify_commands:
  - "cargo test -p csv-ethereum"
  - "cargo test -p csv-aptos"
  - "cargo test -p csv-architecture"
forbidden_patterns:
  - "fallback"
  - "mock"
  - "warning and continue"
  - "default seal protocol"
contract_files:
  - "csv-adapters/csv-ethereum/src/ops.rs"
  - "csv-adapters/csv-aptos/src/ops.rs"
cross_boundary_check: true
---

## Problem

Production adapter constructors must not fall back to mock/default protocol instances when RPC or contract/program configuration fails.

## Why it matters

Mock fallback can make a production CLI appear to create, verify, or transfer protocol state that does not exist on-chain.

## Task

Replace fallback-to-mock behavior with fail-closed errors and readiness failures.

## Acceptance criteria

- [ ] Bad RPC config fails at startup/readiness.
- [ ] Missing contract/program config fails at readiness.
- [ ] No production constructor logs warning and continues with mock behavior.
- [ ] Tests prove production mode rejects missing real RPC dependencies.
