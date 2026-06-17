---
id: D-VERIFIER-001
title: "Implement anchor verification stub in csv-verifier"
theme: D
crate: csv-verifier
priority: P2
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: csv-verifier/.agents/AGENT.md
target_file: csv-verifier/src/anchors.rs
target_patterns:
  - "Anchor verification not implemented for this chain"
interface_files:
  - csv-verifier/src/lib.rs
  - csv-protocol/src/anchor.rs
verify_commands:
  - "cargo check -p csv-verifier"
  - "cargo test -p csv-verifier"
---

## Problem

`csv-verifier/src/anchors.rs` has a stub that returns "Anchor verification not implemented for this chain". This means the verifier cannot verify anchors (proofs of inclusion/finality) for any chain.

## Why it matters

Anchor verification is critical for:
- Verifying that a proof is included in a block
- Verifying chain finality
- Cross-chain proof validation

Without anchor verification, the verifier cannot validate any proofs.

## Task

Implement anchor verification for at least Ethereum (as a reference implementation). The verifier should:
1. Check the anchor data against the chain state
2. Verify the inclusion proof (Merkle proof)
3. Verify the finality proof (if applicable)

Check if there are existing chain adapter verification functions that can be reused.

## Acceptance criteria

- [ ] Anchor verification works for Ethereum (reference implementation)
- [ ] Returns typed error for unsupported chains (not a stub)
- [ ] "not implemented" error is removed
- [ ] Positive test verifies a valid anchor
- [ ] Negative test rejects an invalid anchor
- [ ] `cargo check -p csv-verifier` passes
- [ ] `cargo test -p csv-verifier` passes

## Notes

The Ethereum anchor verification can reuse the Merkle proof verification from `csv-protocol/src/proof_taxonomy.rs`.
