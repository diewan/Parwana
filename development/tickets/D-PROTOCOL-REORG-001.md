---
id: D-PROTOCOL-REORG-001
title: "Replace reconciliation block existence stub with proper proof revalidation"
theme: D
crate: csv-protocol
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-protocol/src/reorg/reconciliation.rs
target_patterns:
  - "// For now, we verify block existence and log the result"
  - "// For now, we return success if the block exists"
interface_files:
  - csv-protocol/src/reorg/mod.rs
  - csv-protocol/src/anchor.rs
verify_commands:
  - "cargo check -p csv-protocol"
  - "cargo test -p csv-protocol"
---

## Problem

`csv-protocol/src/reorg/reconciliation.rs` has a `revalidate_proof` method that only checks if a block exists on the canonical chain. It does NOT:
- Look up the commitment from transfer state
- Verify the commitment exists in the block via inclusion proof
- Rebuild and verify the Merkle proof

Instead, it returns `ProofRevalidationResult { valid: true }` whenever the block exists, regardless of whether the actual proof material is valid.

## Why it matters

This is a security-critical reorg handling path. During a chain reorganization, previously confirmed anchors may become invalid. The reconciliation must verify that the commitment and proof are still valid in the new canonical chain. Returning `valid: true` based solely on block existence means:
- Invalid proofs are accepted during reorgs
- Replay attacks via reorg are possible
- The protocol's finality guarantees are weakened

## Task

Implement proper proof revalidation in `revalidate_proof`:
1. Look up the transfer's commitment from local state
2. Verify the commitment exists in the block (via inclusion proof)
3. Rebuild and verify the Merkle proof against the block's state root
4. Return `valid: false` if any step fails

If full implementation requires access to transfer state that's not available in this method, refactor to accept the necessary state as a parameter or use a trait abstraction.

## Acceptance criteria

- [ ] `revalidate_proof` verifies the commitment exists in the block, not just block existence
- [ ] Merkle proof is rebuilt and verified against the block's state root
- [ ] Returns `valid: false` when proof material is invalid or missing
- [ ] Returns `valid: true` only when full proof revalidation passes
- [ ] All "For now" comments about block existence are removed
- [ ] `cargo check -p csv-protocol` passes
- [ ] `cargo test -p csv-protocol` passes
- [ ] Negative test proves invalid proof is rejected during revalidation

## Notes

The current implementation is at lines 303-315 of `reconciliation.rs`. The `ProofRevalidationResult` struct is already defined — just the validation logic is incomplete.
