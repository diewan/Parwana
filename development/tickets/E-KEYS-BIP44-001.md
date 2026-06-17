---
id: E-KEYS-BIP44-001
title: "Replace simple key derivation with proper BIP-32 HD key derivation"
theme: E
crate: csv-keys
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: csv-keys/.agents/AGENT.md
target_file: csv-keys/src/bip44.rs
target_patterns:
  - "// Simple derivation - in production would use proper BIP-32"
  - "// For now, derive directly from seed + path components"
interface_files:
  - csv-keys/src/bip44.rs
verify_commands:
  - "cargo check -p csv-keys"
  - "cargo test -p csv-keys"
---

## Problem

`csv-keys/src/bip44.rs` has a `derive_secp256k1` function that uses a simple SHA-256 hash of seed + path components instead of proper BIP-32 HD key derivation:

```rust
// Simple derivation - in production would use proper BIP-32
// For now, derive directly from seed + path components
use sha2::{Digest, Sha256};
let mut hasher = Sha256::new();
hasher.update(seed);
hasher.update(path.purpose.to_le_bytes());
hasher.update(path.coin_type.to_le_bytes());
hasher.update(path.account.to_le_bytes());
hasher.update(path.change.to_le_bytes());
hasher.update(path.address_index.to_le_bytes());
let result = hasher.finalize();
```

This is NOT BIP-32 compliant. BIP-32 uses HMAC-SHA512 with a hierarchical structure (master key → child keys → grandchild keys), not a single SHA-256 hash.

## Why it matters

BIP-32 HD wallet derivation is the standard for Bitcoin, Ethereum, and many other chains. Using a non-standard derivation means:
- Keys derived here are incompatible with standard BIP-32 wallets
- Users cannot import/export keys between this implementation and standard wallets
- The derivation is not cryptographically equivalent to BIP-32 (different security properties)

## Task

Replace the simple SHA-256 derivation with proper BIP-32 HD key derivation. Use the `bip32` crate (check if it's already a dependency) to:
1. Derive a master key from the 64-byte seed
2. Derive child keys using the BIP-32 path structure (purpose' → coin_type' → account' → change → address_index)

If the `bip32` crate is not available, add it as a dependency. The derivation path format should follow BIP-44/BIP-84/BIP-86 conventions depending on the chain.

## Acceptance criteria

- [ ] `derive_secp256k1` uses BIP-32 HD key derivation (HMAC-SHA512 based)
- [ ] Keys are derived following the path structure: purpose' → coin_type' → account' → change → address_index
- [ ] The "Simple derivation" and "For now" comments are removed
- [ ] Derived keys are compatible with standard BIP-32 wallets for the same path
- [ ] `cargo check -p csv-keys` passes
- [ ] `cargo test -p csv-keys` passes
- [ ] Test verifies that the same seed + path produces consistent keys across runs

## Notes

The `derive_ed25519` function may also need review — Ed25519 key derivation has different standards (SLIP-0010 for Ed25519). Check if it also uses a simplified approach.
