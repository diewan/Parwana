---
id: B-SDK-TRANSFERS-001
title: "Replace placeholder transfer ID fallback in SDK with proper error"
theme: B
crate: csv-sdk
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: csv-sdk/.agents/AGENT.md
target_file: csv-sdk/src/transfers.rs
target_patterns:
  - "Falling back to placeholder transfer ID"
  - "// Fallback: return a placeholder transfer ID"
interface_files:
  - csv-sdk/src/error.rs
  - csv-sdk/src/transfer_manager.rs
verify_commands:
  - "cargo check -p csv-sdk"
  - "cargo test -p csv-sdk"
---

## Problem

`csv-sdk/src/transfers.rs` has a fallback path that returns a placeholder transfer ID when the runtime coordinator is not available:

```rust
log::error!("TransferBuilder: Falling back to placeholder transfer ID - runtime-coordinator feature enabled but coordinator not available");
// ...
let transfer_id = format!("0x{}", hex::encode(&csv_hash::Hash::new([0u8; 32])));
Ok(transfer_id)
```

This returns a transfer ID of `0x0000000000000000000000000000000000000000000000000000000000000000` (all zeros) when the coordinator is unavailable.

## Why it matters

A zero transfer ID is indistinguishable from a legitimately created transfer with a zero hash. Callers that receive this ID will think a transfer was created when it wasn't. This can lead to:
- Confusion in transfer tracking
- Incorrect state assumptions in downstream code
- Silent failures in transfer workflows

## Task

Replace the placeholder transfer ID fallback with a proper typed error. Instead of returning `Ok(transfer_id)` with a zero hash, return `Err(SdkError::CoordinatorNotAvailable)` or similar. The error should clearly indicate that the runtime coordinator is required for transfer creation.

## Acceptance criteria

- [ ] No placeholder transfer ID is returned — returns a typed error instead
- [ ] Error message clearly indicates the runtime coordinator is required
- [ ] All "Falling back to placeholder transfer ID" log messages are removed
- [ ] `cargo check -p csv-sdk` passes
- [ ] `cargo test -p csv-sdk` passes

## Notes

The fallback path is at lines 417-426 of `transfers.rs`. Check if there are callers that depend on the `Ok(transfer_id)` path and update them to handle the error case.
