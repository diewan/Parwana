---
id: D-PROOF-DESERIALIZE-001
title: "Implement proof deserialization stubs for InclusionProof, FinalityProof, TransferState"
theme: D
crate: csv-protocol
priority: P2
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-protocol/src/proof_taxonomy.rs
target_patterns:
  - "InclusionProof deserialization not yet implemented"
  - "FinalityProof deserialization not yet implemented"
target_file_2: csv-protocol/src/cross_chain.rs
target_patterns_2:
  - "TransferState deserialization not yet implemented"
interface_files:
  - csv-protocol/src/proof_bundle.rs
  - csv-protocol/src/cross_chain.rs
verify_commands:
  - "cargo check -p csv-protocol"
  - "cargo test -p csv-protocol"
---

## Problem

`csv-protocol/src/proof_taxonomy.rs` has deserialization stubs for:
- `InclusionProof` (line 591) — returns "not yet implemented"
- `FinalityProof` (line 735) — returns "not yet implemented"

`csv-protocol/src/cross_chain.rs` has a deserialization stub for:
- `TransferState` (line 365-366) — returns "not yet implemented"

These stubs mean proof data cannot be deserialized from wire format, breaking cross-chain verification.

## Why it matters

Proof deserialization is critical for:
- Receiving proofs from other chains
- Verifying cross-chain transfers
- Storing proofs in local storage
- CLI proof verification commands

Without working deserialization, the protocol cannot accept or verify proofs from external sources.

## Task

Implement deserialization for `InclusionProof`, `FinalityProof`, and `TransferState`. Check if the types already have serialization logic (for encoding) and implement the reverse (decoding).

If the types don't have serialization yet, implement both serialization and deserialization using the canonical encoding format.

## Acceptance criteria

- [ ] `InclusionProof` can be deserialized from canonical bytes
- [ ] `FinalityProof` can be deserialized from canonical bytes
- [ ] `TransferState` can be deserialized from canonical bytes
- [ ] All "not yet implemented" deserialization errors are removed
- [ ] Roundtrip test: serialize → deserialize produces identical data
- [ ] `cargo check -p csv-protocol` passes
- [ ] `cargo test -p csv-protocol` passes

## Notes

Check if the types already have `CanonicalEncoding` implementations. If so, implement the reverse (decoding). If not, implement both.
