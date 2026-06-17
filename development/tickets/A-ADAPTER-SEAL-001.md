---
id: A-ADAPTER-SEAL-001
title: "Replace seal_protocol.rs placeholder sanad_id/commitment/state_root across adapters"
theme: A
crate: csv-adapters
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-sui/src/seal_protocol.rs
target_patterns:
  - "let sanad_id = vec![0u8; 32]; // Placeholder - should be actual sanad ID"
  - "let commitment = vec![0u8; 32]; // Placeholder - should be actual commitment"
  - "let state_root = vec![0u8; 32]; // Placeholder - should be actual state root"
target_file_2: csv-adapters/csv-aptos/src/seal_protocol.rs
target_patterns_2:
  - "0, // placeholder version"
  - "let signatures: Vec<Vec<u8>> = vec![]; // Placeholder - would need to parse from DAG bytes"
target_file_3: csv-adapters/csv-celestia/src/seal_protocol.rs
target_patterns_3:
  - "[0u8; 32], // placeholder commitment"
  - "let signatures: Vec<Vec<u8>> = vec![]; // Placeholder - would need to parse from DAG bytes"
interface_files:
  - csv-protocol/src/seal_protocol.rs
  - csv-protocol/src/anchor.rs
verify_commands:
  - "cargo check -p csv-sui"
  - "cargo check -p csv-aptos"
  - "cargo check -p csv-celestia"
  - "cargo test -p csv-sui"
  - "cargo test -p csv-aptos"
  - "cargo test -p csv-celestia"
---

## Problem

Multiple adapters have placeholder values in their seal protocol implementations:

**Sui** (`csv-sui/src/seal_protocol.rs`): Creates `sanad_id`, `commitment`, and `state_root` as `vec![0u8; 32]` — all zeros.

**Aptos** (`csv-aptos/src/seal_protocol.rs`): Uses `0` as a placeholder version and empty signatures vector.

**Celestia** (`csv-celestia/src/seal_protocol.rs`): Uses `[0u8; 32]` as placeholder commitment and empty signatures.

These placeholder values mean seal operations appear to succeed with invalid data.

## Why it matters

Seal operations are security-critical. Placeholder values mean:
- Seal records have zeroed sanad IDs, commitments, and state roots
- Signature verification would fail (empty signatures)
- Cross-chain verification would reject these seals
- The adapter appears to work but produces unusable seals

## Task

Replace placeholder values with actual data from the chain:
1. **Sui**: Derive `sanad_id` from the actual sanad object, `commitment` from the transaction data, `state_root` from the Sui state root
2. **Aptos**: Use the actual Aptos version from the ledger and parse signatures from the DAG bytes
3. **Celestia**: Use the actual Celestia blob commitment and parse signatures from the DAG

If the required data is not yet available from the chain SDK, return a typed error indicating what data is needed rather than returning zeros.

## Acceptance criteria

- [ ] Sui seal protocol uses actual sanad_id, commitment, and state_root (not zeros)
- [ ] Aptos seal protocol uses actual version and parses signatures from DAG
- [ ] Celestia seal protocol uses actual commitment and parses signatures from DAG
- [ ] No `vec![0u8; 32]` or `[0u8; 32]` placeholder values remain in seal protocol code
- [ ] `cargo check` passes for all 3 adapter crates
- [ ] `cargo test` passes for all 3 adapter crates

## Notes

The placeholder values are in the seal creation/publish paths. Check if the chain SDK provides the required data. If not, add the necessary SDK calls.
