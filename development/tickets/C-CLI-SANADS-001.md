---
id: C-CLI-SANADS-001
title: "Replace CLI sanads.rs stubs with proper implementations or documented TODOs"
theme: C
crate: csv-cli
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: csv-cli/.agents/AGENT.md
target_file: csv-cli/src/commands/sanads.rs
target_patterns:
  - "// Compute simple Merkle root (for now, just hash all hashes concatenated)"
  - "// For now, just log - full implementation would parse policy file"
  - "/// Query lifecycle events for a Sanad (placeholder"
  - "// For now, return the creation event from local state"
interface_files:
  - csv-cli/src/output.rs
  - csv-protocol/src/sanad.rs
verify_commands:
  - "cargo check -p csv-cli"
  - "cargo test -p csv-cli"
---

## Problem

`csv-cli/src/commands/sanads.rs` has several stub implementations:

1. **Merkle root computation** (line ~266): Uses a simple SHA-256 hash of concatenated attachment hashes instead of the proper `csv-content` Merkle tree implementation.

2. **Disclosure policy parsing** (line ~289, ~295): Logs the policy file path but doesn't actually parse it. Full implementation would parse a JSON/YAML policy file.

3. **Lifecycle events query** (line ~2192, ~2214): Returns only the creation event from local state. Full implementation would query chain adapter event indexing.

## Why it matters

These stubs affect CLI user experience and data accuracy:
- The Merkle root is computed incorrectly (not a proper Merkle tree)
- Policy files are silently ignored
- Lifecycle events are incomplete

## Task

1. Replace the simple Merkle root computation with the proper `csv-content` Merkle tree implementation
2. For disclosure policy parsing: either implement basic JSON parsing or return a typed error indicating the feature is not yet available
3. For lifecycle events: either implement chain event queries or return a typed error indicating the feature requires Phase 5 (SanadStateReader trait)

Prioritize option 1 (Merkle root) as it's a correctness issue. Options 2 and 3 can be typed errors with clear documentation.

## Acceptance criteria

- [ ] Merkle root uses `csv-content` Merkle tree implementation, not simple hash concatenation
- [ ] Disclosure policy parsing either works or returns a clear typed error
- [ ] Lifecycle events either query chain data or return a clear typed error
- [ ] All "for now" comments about these stubs are removed
- [ ] `cargo check -p csv-cli` passes
- [ ] `cargo test -p csv-cli` passes

## Notes

The Merkle root computation is in the attachment processing section. The `csv-content` crate provides `MerkleTree` which should be used instead of the manual SHA-256 loop.
