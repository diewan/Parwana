---
id: EVM-SANAD-001
title: "Ethereum Sepolia Sanad creation"
theme: "Same-chain Sanad MVP"
crate: "csv-adapters/csv-ethereum"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-ethereum/src/ops.rs"
target_patterns:
  - "check_readiness"
target_file_2: "csv-adapters/csv-ethereum/src/seal_protocol.rs"
target_patterns_2:
  - "contract"
interface_files:
  - "csv-adapters/csv-ethereum/src/sanad_contract.rs"
  - "csv-cli/src/commands/contracts.rs"
  - "csv-cli/src/commands/sanads.rs"
  - "csv-protocol/src/chain_adapter_traits.rs"
reference_crate: "csv-adapters/csv-ethereum"
reference_file: "csv-adapters/csv-ethereum/src/bindings/csv_seal.rs"
reference_patterns:
  - "event"
verify_commands:
  - "cargo test -p csv-ethereum"
  - "cargo test -p csv-cli --test integration_tests"
forbidden_patterns:
  - "mock"
  - "fallback"
  - "warning and continue"
contract_files:
  - "csv-adapters/csv-ethereum/src/ops.rs"
  - "csv-adapters/csv-ethereum/src/sanad_contract.rs"
  - "csv-cli/src/commands/sanads.rs"
cross_boundary_check: true
---

## Problem

Ethereum Sepolia must become the first smart-contract-backed Sanad flow, with contract address validation, canonical events, state query, consume path, and finality checks.

## Why it matters

Contract-backed flows should demonstrate the runtime boundary without mock fallback or local CLI state.

## Task

Ensure the CLI can verify configured contract address, create a Sanad through the contract, read canonical events, store tx hash/block height, enforce finality policy, query contract state, and consume the Sanad on-chain.

## Acceptance criteria

- [ ] No mock fallback if contract/RPC construction fails.
- [ ] Contract address is validated before use.
- [ ] Event schema matches canonical event documentation.
- [ ] `csv sanad state --chain ethereum <id>` reads contract state.
- [ ] `csv sanad consume` changes state on-chain and trace reflects it.
