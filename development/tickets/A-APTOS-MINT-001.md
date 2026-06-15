---
id: A-APTOS-MINT-001
title: "Remove Aptos mint proof-position and state fallback placeholders"
theme: A
crate: csv-adapters/csv-aptos
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-aptos/src/ops.rs
target_patterns:
  - "[0u8; 32] // Fallback to zero hash if proof too short"
  - "// For now, use a simple hash-based derivation"
  - "// For now, return a basic state with the commitment from the resource"
interface_files:
  - csv-protocol/src/chain_adapter_traits.rs
  - csv-adapters/csv-aptos/src/entry_function.rs
  - csv-adapters/csv-aptos/src/proofs.rs
reference_crate: csv-adapters/csv-ethereum
reference_file: csv-adapters/csv-ethereum/src/ops.rs
reference_patterns:
  - "async fn mint_sanad("
verify_commands:
  - "cargo check -p csv-aptos"
  - "cargo test -p csv-aptos"
---

## Problem

Aptos minting falls back to zero state-root data when proof bytes are too short and derives Merkle leaf position with a temporary hash-based shortcut. State reading also contains a temporary basic-state path.

## Why it matters

Minting must be based on verified inclusion proof structure. A short or malformed proof must fail; it cannot become a zero root or guessed leaf position.

## Task

Parse the Aptos lock proof into explicit fields required by the Move entry function. Reject insufficient proof bytes. Replace hash-derived leaf-position guessing with either proof-format parsing or a fail-closed typed error until the proof format is available. Replace the basic state fallback with real resource parsing or an explicit unsupported-state error.

## Acceptance criteria

- [ ] Short proof bytes no longer produce `[0u8; 32]` state roots.
- [ ] Leaf position comes from proof structure or returns `Err(...)`.
- [ ] State reader no longer fabricates state from commitment alone.
- [ ] Positive test covers a valid parsed proof shape.
- [ ] Negative test rejects short/malformed proof bytes.
- [ ] `cargo check -p csv-aptos` passes.
- [ ] `cargo test -p csv-aptos` passes.

## Notes

If the proof format is not specified enough, add the smallest type/API needed rather than guessing from raw bytes.
