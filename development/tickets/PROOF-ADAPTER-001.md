---
id: PROOF-ADAPTER-001
title: "Remove minimal/empty adapter proof construction"
theme: "Canonical Proofs"
crate: "csv-adapters"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-protocol/src/chain_adapter_traits.rs"
target_patterns:
  - "validate_source_proof"
target_file_2: "csv-adapters/csv-bitcoin/src/runtime_adapter.rs"
target_patterns_2:
  - "validate_source_proof"
interface_files:
  - "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
  - "csv-adapters/csv-solana/src/runtime_adapter.rs"
  - "csv-adapters/csv-sui/src/runtime_adapter.rs"
  - "csv-adapters/csv-aptos/src/runtime_adapter.rs"
reference_crate: "csv-protocol"
reference_file: "csv-protocol/src/finality/capabilities.rs"
reference_patterns:
  - "CapabilityUnavailable"
verify_commands:
  - "cargo test -p csv-protocol"
  - "cargo test -p csv-bitcoin"
  - "cargo test -p csv-ethereum"
forbidden_patterns:
  - "empty transition_data"
  - "empty proof bytes"
  - "empty signatures"
  - "zero seal IDs"
  - "minimal ProofBundle"
  - "Ok(())"
contract_files:
  - "csv-adapters/csv-bitcoin/src/runtime_adapter.rs"
  - "csv-adapters/csv-ethereum/src/runtime_adapter.rs"
  - "csv-adapters/csv-solana/src/runtime_adapter.rs"
  - "csv-adapters/csv-sui/src/runtime_adapter.rs"
  - "csv-adapters/csv-aptos/src/runtime_adapter.rs"
cross_boundary_check: true
---

## Problem

Some adapters still build minimal proof bundles or treat structural presence as validation success.

## Why it matters

Destination minting must depend on verified chain-specific inclusion and finality evidence. Unsupported proof paths must return `CapabilityUnavailable`, not success.

## Task

Remove empty/minimal proof construction and placeholder validation. Each adapter must either build real chain-specific proof material or fail closed with an exact reason.

## Acceptance criteria

- [ ] Bitcoin proof includes SPV inclusion data and confirmation/finality evidence.
- [ ] Ethereum proof includes event/log/account proof or contract-verifiable evidence.
- [ ] Sui/Aptos proofs include object/resource/checkpoint evidence.
- [ ] Solana proof includes account/PDA/instruction evidence.
- [ ] No adapter accepts malformed source proof.
- [ ] Negative tests exist per adapter.
