---
id: G-STORE-001
title: "Address csv-store rusqlite TODO and legacy placeholder"
theme: G
crate: csv-store
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 20
agent_md: csv-store/.agents/AGENT.md
target_file: csv-store/src/lib.rs
target_patterns:
  - "// TODO: Rewrite operations/*.rs to use rusqlite (currently uses sqlx which is not a dependency)"
interface_files:
  - csv-store/src/state/domain.rs
verify_commands:
  - "cargo check -p csv-store"
  - "cargo test -p csv-store"
---

## Problem

`csv-store/src/lib.rs` has a TODO comment: "Rewrite operations/*.rs to use rusqlite (currently uses sqlx which is not a dependency)". This indicates the store module was planned to use rusqlite but the rewrite hasn't been done.

## Why it matters

This is a low-priority technical debt item. The store currently uses sqlx (which is not even a dependency), meaning the operations module may be non-functional or use a different backend. The TODO indicates an intended migration to rusqlite.

## Task

Either:
1. Implement the rusqlite rewrite as described in the TODO, OR
2. If the rewrite is no longer the plan, remove the TODO and document the actual storage strategy

Check if the `operations` module exists and what it does. If it's non-functional, consider deprecating it. If it's the intended backend, implement the rusqlite migration.

## Acceptance criteria

- [ ] The TODO comment is resolved (either implemented or removed with explanation)
- [ ] The storage backend is clearly documented
- [ ] `cargo check -p csv-store` passes
- [ ] `cargo test -p csv-store` passes

## Notes

This is a low-priority item. If the rusqlite rewrite is out of scope for this cycle, replace the TODO with a clear statement of the current storage strategy and a link to a tracking issue for the rewrite.
