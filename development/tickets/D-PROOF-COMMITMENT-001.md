---
id: D-PROOF-COMMITMENT-001
title: "Implement ProofMetadata and EnhancedCommitment deserialization stubs"
theme: D
crate: csv-proof
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: csv-proof/.agents/AGENT.md
target_file: csv-proof/src/commitments_ext.rs
target_patterns:
  - "ProofMetadata deserialization not yet implemented"
  - "EnhancedCommitment deserialization not yet implemented"
interface_files:
  - csv-proof/src/lib.rs
  - csv-codec/src/canonical.rs
verify_commands:
  - "cargo check -p csv-proof"
  - "cargo test -p csv-proof"
---

## Problem

`csv-proof/src/commitments_ext.rs` has deserialization stubs:
- `ProofMetadata` (lines 249, 264) — returns "not yet implemented" for ManualBinary encoding
- `EnhancedCommitment` (line 497) — returns "not yet implemented"

## Why it matters

Proof metadata and enhanced commitments are used in cross-chain proof verification. Without deserialization, these types cannot be received from wire format.

## Task

Implement deserialization for `ProofMetadata` and `EnhancedCommitment`. Check if serialization already exists and implement the reverse.

## Acceptance criteria

- [ ] `ProofMetadata` can be deserialized from ManualBinary encoding
- [ ] `EnhancedCommitment` can be deserialized
- [ ] All "not yet implemented" deserialization errors are removed
- [ ] Roundtrip test: serialize → deserialize produces identical data
- [ ] `cargo check -p csv-proof` passes
- [ ] `cargo test -p csv-proof` passes

## Notes

The ManualBinary encoding is a simple binary format. Check the serialization code for the expected byte layout.
