---
id: D-STORAGE-001
title: "Implement storage backend trait methods that return 'not implemented'"
theme: D
crate: csv-storage
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: csv-storage/.agents/AGENT.md
target_file: csv-storage/src/traits.rs
target_patterns:
  - "confirm_consumed not implemented for this backend"
  - "mark_rolled_back not implemented for this backend"
  - "store_transfer_entry not implemented for this backend"
  - "load_all_transfers not implemented for this backend"
interface_files:
  - csv-storage/src/lib.rs
  - csv-protocol/src/transfer.rs
verify_commands:
  - "cargo check -p csv-storage"
  - "cargo test -p csv-storage"
---

## Problem

`csv-storage/src/traits.rs` has 4 trait methods that return "not implemented" errors:
- `confirm_consumed` — marks a transfer as consumed
- `mark_rolled_back` — marks a transfer as rolled back due to reorg
- `store_transfer_entry` — stores a transfer entry
- `load_all_transfers` — loads all transfer entries

These are core storage operations that must be implemented for the transfer coordinator to work.

## Why it matters

Without these methods, the transfer coordinator cannot:
- Track transfer state changes
- Handle reorgs properly
- Persist transfer data
- Query transfer history

## Task

Implement these 4 methods in the storage backend. The trait is defined in `csv-storage/src/traits.rs`. Check if there are existing backend implementations (in-memory, RocksDB, PostgreSQL) and implement the methods for each.

If the storage backend doesn't have the necessary schema, add the required columns/tables.

## Acceptance criteria

- [ ] `confirm_consumed` marks a transfer as consumed in the storage backend
- [ ] `mark_rolled_back` marks a transfer as rolled back
- [ ] `store_transfer_entry` persists a transfer entry
- [ ] `load_all_transfers` returns all transfer entries from storage
- [ ] All "not implemented" errors are removed
- [ ] `cargo check -p csv-storage` passes
- [ ] `cargo test -p csv-storage` passes

## Notes

Check if there are existing storage backend implementations. If not, create a basic in-memory implementation for testing.
