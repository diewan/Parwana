---
id: F-CODEC-001
title: "Finish canonical UTF-8 normalization and hash API boundary"
theme: F
crate: csv-codec
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: AGENTS.md
target_file: csv-codec/src/encode.rs
target_patterns:
  - "// TODO: Add NFC normalization"
target_file_2: csv-codec/src/canonical.rs
target_patterns_2:
  - "This is a simplified version that doesn't include the full Hash type."
interface_files:
  - csv-codec/src/lib.rs
  - csv-codec/src/error.rs
  - csv-docs/rfcs/RFC-0001-canonical-serialization.md
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "cargo check -p csv-codec"
  - "cargo test -p csv-codec"
---

## Problem

`encode_string` claims canonical UTF-8 normalization but currently returns raw UTF-8 bytes. `canonical_hash` also documents that it is simplified and does not use the full protocol hash boundary.

## Why it matters

Canonical serialization must be stable across languages and platforms. A string that is visually identical but encoded with a different Unicode normalization form must not produce a different protocol commitment.

## Task

Implement NFC normalization for canonical string encoding and resolve the simplified hash API boundary in `canonical_hash` without introducing raw protocol hashing in production paths.

Prefer a small, explicit dependency such as `unicode-normalization` if the crate does not already have one. If `csv-codec` must remain hash-type agnostic, make the API boundary explicit in docs/tests and remove the misleading production-simplification language.

## Acceptance criteria

- [ ] `encode_string` normalizes to NFC before emitting bytes.
- [ ] Tests cover canonically equivalent composed/decomposed Unicode strings.
- [ ] `canonical_hash` no longer presents a production simplification as acceptable protocol behavior.
- [ ] No raw hash shortcut is added in protocol logic.
- [ ] `cargo check -p csv-codec` passes.
- [ ] `cargo test -p csv-codec` passes.

## Notes

This is a good warm-up ticket because it is small and low blast-radius, but it still exercises the context-pack workflow.
