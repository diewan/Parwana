---
id: A-ETH-REGISTRY-001
title: "Wire Ethereum seal registry verification into production path"
theme: A
crate: csv-adapters/csv-ethereum
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-ethereum/src/seal_protocol.rs
target_patterns:
  - "// TODO: Implement verify_seal_registry method on EthereumVerifier"
  - "// For now, skip on-chain verification"
target_file_2: csv-adapters/csv-ethereum/src/runtime_adapter.rs
target_patterns_2:
  - "// For now, return a minimal ProofBundle with the inclusion proof"
  - "transfer.sanad_id, // Use sanad_id as commitment for now"
interface_files:
  - csv-protocol/src/seal_protocol.rs
  - csv-protocol/src/chain_adapter_traits.rs
  - csv-adapters/csv-ethereum/src/verifier.rs
reference_crate: csv-adapters/csv-solana
reference_file: csv-adapters/csv-solana/src/runtime_adapter.rs
reference_patterns:
  - "async fn check_seal_registry("
verify_commands:
  - "cargo check -p csv-ethereum"
  - "cargo test -p csv-ethereum"
---

## Problem

Ethereum seal consumption checks local registry state but explicitly skips the on-chain registry verification. The runtime proof construction also creates a minimal proof bundle and temporarily uses `sanad_id` as commitment.

## Why it matters

Local registry state alone is not authoritative for replay protection. The adapter rules require no bypass paths around verification and no placeholder verification. Ethereum must query or prove the CSV seal registry state before marking a seal consumed.

## Task

Wire `EthereumVerifier::verify_seal_registry` into `csv-adapters/csv-ethereum/src/seal_protocol.rs` and remove the skip path. Then tighten runtime proof construction so the commitment comes from the verified lock/proof material, not from `sanad_id` as a placeholder.

## Acceptance criteria

- [ ] On-chain seal registry verification is called in the production consumption path when RPC/verifier support is configured.
- [ ] If RPC/verifier support is unavailable for a security-critical check, the code fails closed with a typed error instead of relying silently on local state.
- [ ] Proof bundle construction no longer uses `sanad_id` as a placeholder commitment.
- [ ] Negative test proves replay/used-seal verification rejects a consumed seal or malformed proof.
- [ ] `cargo check -p csv-ethereum` passes.
- [ ] `cargo test -p csv-ethereum` passes.

## Notes

This is a reference-quality security ticket. After completing it, write a pattern note for other registry-verification adapter gaps.
