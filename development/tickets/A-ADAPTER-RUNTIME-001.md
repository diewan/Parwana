---
id: A-ADAPTER-RUNTIME-001
title: "Replace runtime adapter stubs with proper proof bundle construction"
theme: A
crate: csv-adapters
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-solana/src/runtime_adapter.rs
target_patterns:
  - "// For now, return Available as the seal protocol handles availability checks"
target_file_2: csv-adapters/csv-aptos/src/runtime_adapter.rs
target_patterns_2:
  - "// For now, return Available as the seal protocol handles availability checks"
  - "// Use empty signatures for now (signature verification is done via inclusion proof)"
target_file_3: csv-adapters/csv-ethereum/src/runtime_adapter.rs
target_patterns_3:
  - "// For now, return a minimal ProofBundle with the inclusion proof"
  - "transfer.sanad_id, // Use sanad_id as commitment for now"
target_file_4: csv-adapters/csv-bitcoin/src/runtime_adapter.rs
target_patterns_4:
  - "// Use empty signatures for now (signature verification is done via inclusion proof)"
interface_files:
  - csv-protocol/src/seal_protocol.rs
  - csv-protocol/src/proof_bundle.rs
verify_commands:
  - "cargo check -p csv-solana"
  - "cargo check -p csv-aptos"
  - "cargo check -p csv-ethereum"
  - "cargo check -p csv-bitcoin"
  - "cargo test -p csv-solana"
  - "cargo test -p csv-aptos"
  - "cargo test -p csv-ethereum"
  - "cargo test -p csv-bitcoin"
---

## Problem

Multiple runtime adapters have stub implementations for proof bundle construction:

**Solana** & **Aptos**: Return `Available` for seal status without actual verification, and use empty signatures.

**Ethereum**: Creates a minimal proof bundle and uses `sanad_id` as a placeholder commitment.

**Bitcoin**: Uses empty signatures for proof bundles.

## Why it matters

Runtime adapters are the bridge between the protocol and chain-specific implementations. Stub proof bundles mean:
- Cross-chain verification receives malformed or incomplete proof data
- Seal status is reported as "Available" without actual verification
- Empty signatures break signature verification in downstream consumers

## Task

Replace stub proof bundle construction with proper implementations:
1. Construct `ProofBundle` with actual chain-specific proof data
2. Use real signatures from the chain (or return a typed error if signatures are not available)
3. Use the correct commitment (from the lock/proof material, not `sanad_id`)
4. Verify seal status against actual chain state before returning `Available`

## Acceptance criteria

- [ ] All runtime adapters construct proper `ProofBundle` with real chain data
- [ ] No empty signatures in proof bundles (or typed error if unavailable)
- [ ] Commitment is derived from actual lock/proof material, not `sanad_id`
- [ ] Seal status verification checks actual chain state
- [ ] All "For now" and placeholder comments are removed
- [ ] `cargo check` passes for all 4 adapter crates
- [ ] `cargo test` passes for all 4 adapter crates

## Notes

The `ProofBundle` type is defined in `csv-protocol/src/proof_bundle.rs`. Each adapter should populate it with chain-specific proof data from their respective `seal_protocol.rs` implementations.
