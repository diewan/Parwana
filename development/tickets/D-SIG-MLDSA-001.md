---
id: D-SIG-MLDSA-001
title: "Remove ML-DSA placeholder key derivation and make pq feature boundary explicit"
theme: D
crate: csv-protocol
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: AGENTS.md
target_file: csv-protocol/src/signature.rs
target_patterns:
  - "// For now, we use a simplified derivation - the full ML-DSA key generation"
  - "// Placeholder: In production, use proper ML-DSA key generation"
  - "// For now, use the first 32 bytes as a placeholder public key"
  - "/// ML-DSA-65 verification without the pq feature (stub)"
interface_files:
  - csv-protocol/src/error.rs
  - csv-protocol/Cargo.toml
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "cargo check -p csv-protocol"
  - "cargo test -p csv-protocol"
---

## Problem

ML-DSA support has placeholder public-key derivation and a stub boundary when the `pq` feature is disabled.

## Why it matters

Signature code is protocol-critical. Placeholder public keys or ambiguous feature fallbacks can make invalid ownership proofs appear structurally valid.

## Task

Replace placeholder ML-DSA public-key derivation with real keypair/public-key generation under the `pq` feature. When `pq` is disabled, ensure all ML-DSA signing/verification paths return explicit unsupported-feature errors and cannot be mistaken for a verification attempt.

## Acceptance criteria

- [ ] No placeholder public-key derivation remains for ML-DSA.
- [ ] `pq`-enabled path uses the actual ML-DSA implementation consistently.
- [ ] `pq`-disabled path fails closed with a typed error.
- [ ] Positive test verifies a valid ML-DSA signature under `pq` if feature tests are available.
- [ ] Negative test rejects malformed public key/signature.
- [ ] `cargo check -p csv-protocol` passes.
- [ ] `cargo test -p csv-protocol` passes.

## Notes

Do not replace ML-DSA with a different signature scheme to satisfy tests. If feature-gated dependencies are missing, add the minimal feature-gated plumbing and keep unsupported mode explicit.
