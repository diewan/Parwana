---
id: B-SDK-CAPABILITY-001
title: "Replace SDK transfer/burn/balance capability placeholders with runtime-backed fail-closed APIs"
theme: B
crate: csv-sdk
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 30
agent_md: AGENTS.md
target_file: csv-sdk/src/sanads.rs
target_patterns:
  - "// Get all sanads (we'll filter in memory for now - can optimize later)"
  - "// For now, return FeatureNotEnabled error with context"
target_file_2: csv-sdk/src/wallet.rs
target_patterns_2:
  - "// For now, return the key's signature capability"
  - "// For now, return fallback signature as full Schnorr signing requires transaction context"
  - "// For now, we return a typed error indicating the capability is not enabled."
interface_files:
  - csv-runtime/src/transfer_coordinator.rs
  - csv-sdk/src/client.rs
  - csv-sdk/src/error.rs
reference_crate: csv-runtime
reference_file: csv-runtime/src/transfer_coordinator.rs
reference_patterns:
  - "pub struct TransferCoordinator"
verify_commands:
  - "cargo check -p csv-sdk"
  - "cargo test -p csv-sdk"
---

## Problem

The SDK exposes user-facing transfer, burn, balance, and signing helpers that either filter inefficiently in memory, return feature-not-enabled placeholders, or use fallback signing behavior for contexts that require real transaction-aware signing.

## Why it matters

SDK APIs become the path applications use. They must not silently bypass runtime coordination or return fake capabilities. Fail-closed errors are acceptable only if the API clearly routes users to the runtime-backed implementation.

## Task

Tighten these SDK methods so cross-chain transfer/burn/balance operations delegate to `csv-runtime`/configured client services when available and return explicit typed errors when unavailable. Remove or quarantine fallback signatures from production transaction-signing paths.

## Acceptance criteria

- [ ] User-facing SDK methods do not imply unavailable features are implemented.
- [ ] Runtime-backed paths are used where configured.
- [ ] Fallback signatures cannot be used for production transaction signing.
- [ ] Tests cover configured success path or explicit fail-closed unsupported path.
- [ ] `cargo check -p csv-sdk` passes.
- [ ] `cargo test -p csv-sdk` passes.

## Notes

This may split into follow-up tickets if one method requires runtime API additions. Keep each commit small.
