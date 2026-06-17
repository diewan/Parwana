---
id: D-PROTOCOL-SIG-001
title: "Implement ML-DSA-65 stub with proper feature-gated error or full implementation"
theme: D
crate: csv-protocol
priority: P2
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-protocol/src/signature.rs
target_patterns:
  - "/// ML-DSA-65 verification without the pq feature (stub)"
  - "fn verify_ml_dsa65(_signature: &[8], _public_key: &[8], _message: &[8]) -> Result<()>"
interface_files:
  - csv-protocol/src/error.rs
verify_commands:
  - "cargo check -p csv-protocol"
  - "cargo test -p csv-protocol"
---

## Problem

`csv-protocol/src/signature.rs` has a `verify_ml_dsa65` function that is a stub when the `pq` feature is not enabled. It always returns `ProtocolError::SignatureVerificationFailed("ML-DSA-65 verification requires the 'pq' feature to be enabled")`. This means ML-DSA-65 signatures can never be verified without the feature flag.

## Why it matters

ML-DSA-65 (formerly DILITHIUM) is the post-quantum signature scheme for the protocol. Having a stub that always fails means:
- Post-quantum signature verification is completely non-functional without the feature flag
- The `pq` feature gate is the only way to enable PQ verification, but the stub suggests the implementation may be incomplete even with the flag

## Task

Either:
1. Implement full ML-DSA-65 verification when the `pq` feature is enabled (using the `ml-dsa` crate), OR
2. If full implementation is out of scope, replace the stub with a clear `unimplemented!` or a documented `todo!` that points to a tracking issue, and ensure the error message is actionable

The current stub is misleading because it suggests the feature exists but is just gated, when in fact the implementation is absent.

## Acceptance criteria

- [ ] ML-DSA-65 verification works correctly when `pq` feature is enabled
- [ ] When `pq` feature is disabled, the error is clear and actionable (not a misleading stub)
- [ ] No placeholder verification remains in production paths
- [ ] `cargo check -p csv-protocol --all-features` passes
- [ ] `cargo test -p csv-protocol --all-features` passes

## Notes

Check if the `ml-dsa` crate is already a dependency (with the `pq` feature gate). If so, implement the verification using that crate. If not, add it as a feature-gated dependency.
