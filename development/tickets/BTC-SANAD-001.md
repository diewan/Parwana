---
id: BTC-SANAD-001
title: "Bitcoin Signet Sanad creation"
theme: "Same-chain Sanad MVP"
crate: "csv-adapters/csv-bitcoin"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-bitcoin/src/wallet_operations.rs"
target_patterns:
  - "UTXO"
target_file_2: "csv-adapters/csv-bitcoin/src/seal_protocol.rs"
target_patterns_2:
  - "commitment"
interface_files:
  - "csv-adapters/csv-bitcoin/src/ops.rs"
  - "csv-adapters/csv-bitcoin/src/runtime_adapter.rs"
  - "csv-cli/src/commands/sanads.rs"
  - "csv-protocol/src/chain_adapter_traits.rs"
reference_crate: "csv-adapters/csv-bitcoin"
reference_file: "csv-adapters/csv-bitcoin/src/json_rpc.rs"
reference_patterns:
  - "gettxout"
verify_commands:
  - "cargo test -p csv-bitcoin"
  - "cargo test -p csv-cli --test integration_tests"
forbidden_patterns:
  - "Hash::new([0u8; 32])"
  - "skip on-chain validation"
  - "mark consumed before broadcast"
contract_files:
  - "csv-adapters/csv-bitcoin/src/wallet_operations.rs"
  - "csv-adapters/csv-bitcoin/src/seal_protocol.rs"
  - "csv-adapters/csv-bitcoin/src/ops.rs"
cross_boundary_check: true
---

## Problem

Bitcoin Sanad creation is not yet a stable end-to-end product flow.

## Why it matters

Bitcoin Signet is the first recommended seal-backed reference flow. UTXO selection, broadcast, finality, and local consumed marking must be crash-safe and fail-closed.

## Task

Implement and test funded BIP-86 address scanning, UTXO selection, single-use seal construction, commitment publication, anchor tx capture, confirmation/finality checks, and Sanad record persistence.

## Acceptance criteria

- [ ] `csv wallet scan --chain bitcoin` finds Signet UTXOs.
- [ ] `csv sanad create --chain bitcoin` creates a real on-chain anchor.
- [ ] Failed broadcast does not consume local UTXO.
- [ ] Already-spent UTXO fails closed and tries another UTXO only when safe.
- [ ] Anchor tx is usable for proof generation.
- [ ] Replay attempt using the same UTXO fails.
