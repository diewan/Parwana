---
id: XFER-RUNTIME-001
title: "SDK transfer builder exposes runtime receipt faithfully"
theme: "Cross-chain MVP"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-cli/src/commands/cross_chain/transfer.rs"
target_patterns:
  - "transfer_id"
target_file_2: "csv-sdk/src/transfers.rs"
target_patterns_2:
  - "transfer"
interface_files:
  - "csv-runtime/src/transfer_coordinator.rs"
  - "csv-cli/src/commands/cross_chain/status.rs"
reference_crate: "csv-runtime"
reference_file: "csv-runtime/src/transfer_coordinator.rs"
reference_patterns:
  - "replay"
verify_commands:
  - "cargo test -p csv-cli --test integration_tests"
  - "cargo test -p csv-runtime"
forbidden_patterns:
  - "timestamp"
  - "local transfer id"
  - "mark source Sanad consumed"
contract_files:
  - "csv-cli/src/commands/cross_chain/transfer.rs"
  - "csv-sdk/src/transfers.rs"
  - "csv-runtime/src/transfer_coordinator.rs"
cross_boundary_check: true
---

## Problem

`csv cross-chain transfer` must be a thin wrapper around `TransferCoordinator`, but CLI paths can still generate or display local transfer state.

## Why it matters

The runtime is the only authority for transfer ID, replay ID, lock/mint status, and completion.

## Task

Ensure the CLI receives and displays the real runtime receipt: transfer ID, chains, lock tx/block, finality, proof hash, mint tx/block, replay ID, final state, and journal/event IDs.

## Acceptance criteria

- [ ] Runtime is the only source of transfer ID/replay ID.
- [ ] CLI cannot mark source Sanad consumed unless runtime reports final transfer state.
- [ ] Failed mint produces rolled-back or recoverable state, not local success.
- [ ] `cross-chain status` reads runtime state/event store, not only local display cache.
