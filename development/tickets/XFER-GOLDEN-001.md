---
id: XFER-GOLDEN-001
title: "First contract-chain cross-chain route"
theme: "Cross-chain MVP"
crate: "csv-runtime"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-runtime/src/transfer_coordinator.rs"
target_patterns:
  - "finality"
target_file_2: "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
target_patterns_2:
  - "validate_source_proof"
interface_files:
  - "csv-adapters/csv-sui/src/runtime_adapter.rs"
  - "csv-adapters/csv-aptos/src/runtime_adapter.rs"
  - "csv-sdk/src/transfers.rs"
  - "csv-cli/src/commands/cross_chain/transfer.rs"
reference_crate: "csv-adapters/csv-ethereum"
reference_file: "csv-adapters/csv-ethereum/src/ops.rs"
reference_patterns:
  - "get_sanad_state"
verify_commands:
  - "cargo test -p csv-runtime"
  - "cargo test -p csv-ethereum"
  - "cargo test -p csv-cli --test integration_tests"
forbidden_patterns:
  - "mint without verified source proof"
  - "skip finality"
  - "replay accepted"
contract_files:
  - "csv-runtime/src/transfer_coordinator.rs"
  - "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
cross_boundary_check: true
---

## Problem

The first cross-chain MVP should be proven on the easiest contract-backed route before Bitcoin-source transfer.

## Why it matters

Contract-backed routes reduce SPV complexity and exercise the runtime path: lock, finality, proof, verify, mint, replay persistence, and trace.

## Task

Choose the strongest supported route, preferably Ethereum Sepolia -> Sui testnet or Ethereum Sepolia -> Aptos testnet, and implement the first successful contract-chain transfer.

## Acceptance criteria

- [ ] Source lock tx confirmed.
- [ ] Finality threshold enforced.
- [ ] Proof bundle generated from source evidence.
- [ ] Proof bundle verified before mint.
- [ ] Destination mint tx confirmed.
- [ ] Replay DB marks transfer consumed only after mint confirmation.
- [ ] Re-running the same transfer fails as replay.
- [ ] Malformed proof cannot mint.
- [ ] Destination chain cannot mint without verified source proof.
