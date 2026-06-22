---
id: BTC-XFER-001
title: "Bitcoin-source cross-chain transfer"
theme: "Bitcoin-source MVP"
crate: "csv-adapters/csv-bitcoin"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-bitcoin/src/runtime_adapter.rs"
target_patterns:
  - "validate_source_proof"
target_file_2: "csv-adapters/csv-bitcoin/src/seal_protocol.rs"
target_patterns_2:
  - "confirmation"
interface_files:
  - "csv-runtime/src/transfer_coordinator.rs"
  - "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
  - "csv-cli/src/commands/cross_chain/transfer.rs"
reference_crate: "csv-adapters/csv-bitcoin"
reference_file: "csv-adapters/csv-bitcoin/src/ops.rs"
reference_patterns:
  - "get_sanad_state"
verify_commands:
  - "cargo test -p csv-bitcoin"
  - "cargo test -p csv-runtime"
forbidden_patterns:
  - "skip finality"
  - "same UTXO"
  - "empty proof"
contract_files:
  - "csv-adapters/csv-bitcoin/src/runtime_adapter.rs"
  - "csv-adapters/csv-bitcoin/src/seal_protocol.rs"
cross_boundary_check: true
---

## Problem

Bitcoin-source transfer must wait until a contract-chain route works, then prove Bitcoin Signet Sanad -> destination mint with SPV/finality evidence.

## Why it matters

The same Bitcoin UTXO must never authorize two destination mints, and reorgs below finality must prevent minting.

## Task

Implement Bitcoin Signet source transfer to the strongest supported destination, with proofs binding Sanad ID, UTXO outpoint, owner, commitment, destination chain, and transfer ID.

## Acceptance criteria

- [ ] Bitcoin lock/consume proof is SPV-backed.
- [ ] Confirmation depth is enforced.
- [ ] Reorg below finality prevents mint.
- [ ] Proof binds Sanad ID, UTXO outpoint, owner, commitment, destination chain, and transfer ID.
- [ ] Destination mint rejects proof replay.
- [ ] Same Bitcoin UTXO cannot authorize two destination mints.
