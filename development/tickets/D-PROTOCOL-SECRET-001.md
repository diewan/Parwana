---
id: D-PROTOCOL-SECRET-001
title: "Replace zero-bytes placeholder in SharedSecretHandle::none() with proper read-only mode"
theme: D
crate: csv-protocol
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: .agents/AGENT.md
target_file: csv-protocol/src/secret.rs
target_patterns:
  - "// Create a handle with zero bytes as placeholder"
  - "let key = SecretKey::new([0u8; 32]);"
interface_files:
  - csv-protocol/src/secret.rs
verify_commands:
  - "cargo check -p csv-protocol"
  - "cargo test -p csv-protocol"
---

## Problem

`csv-protocol/src/secret.rs` has a `SharedSecretHandle::none()` method that creates a handle with zero bytes as a placeholder:

```rust
pub fn none() -> Self {
    // Create a handle with zero bytes as placeholder
    let key = SecretKey::new([0u8; 32]);
    Self::new(SecretHandle::from_key(key))
}
```

This creates a handle with a real `SecretKey` containing all zeros, which:
1. Is a valid (but dangerous) secret key that could sign messages
2. Misleads callers into thinking they have a valid key when they don't
3. Violates the principle that read-only handles should not hold any key material

## Why it matters

If `none()` is used to create a read-only handle, callers might accidentally use it for signing operations. A zero-key is cryptographically weak and could be exploited. The method should either:
- Return `Option<SharedSecretHandle>` with `None` for read-only mode, OR
- Use a sentinel type that cannot be used for signing

## Task

Replace the zero-bytes placeholder with a proper read-only mode. Options:
1. Change `none()` to return `Option<SharedSecretHandle>` — `None` means read-only
2. Add a separate `ReadOnlyHandle` type that has no key material
3. Use `Option<SecretHandle>` internally and return `None` from `as_bytes()` for read-only mode

Choose the approach that best fits the existing API. The key requirement: a read-only handle must NOT hold any key material (even zero bytes).

## Acceptance criteria

- [ ] `SharedSecretHandle::none()` does not create a `SecretKey` with zero bytes
- [ ] Read-only handles cannot be used for signing operations
- [ ] `as_bytes()` returns `None` for read-only handles
- [ ] All callers of `none()` are reviewed for correctness
- [ ] `cargo check -p csv-protocol` passes
- [ ] `cargo test -p csv-protocol` passes

## Notes

Search for all callers of `SharedSecretHandle::none()` to understand the usage pattern before choosing the replacement approach.
