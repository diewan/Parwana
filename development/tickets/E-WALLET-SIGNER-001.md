---
id: E-WALLET-SIGNER-001
title: "Return real wallet signer/public key instead of placeholder bytes and None"
theme: E
crate: csv-wallet
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: AGENTS.md
target_file: csv-wallet/src/wallet.rs
target_patterns:
  - "vec![0u8; 32], // Placeholder public key"
  - "// For now, return None as we can't clone trait objects"
interface_files:
  - csv-wallet/src/signer.rs
  - csv-wallet/src/wallet_traits.rs
  - csv-wallet/src/keystore.rs
reference_crate: csv-sdk
reference_file: csv-sdk/src/wallet.rs
reference_patterns:
  - "pub fn sign("
  - "fn sign_ethereum("
verify_commands:
  - "cargo check -p csv-wallet"
  - "cargo test -p csv-wallet"
---

## Problem

Wallet construction exposes placeholder public-key bytes and `get_signer` returns `None` because trait objects cannot be cloned in the current design.

## Why it matters

Wallet signatures and public keys are part of ownership and authorization. Placeholder key material can make tests pass while production has no real signing path.

## Task

Refactor wallet signer storage/access so callers can retrieve a real signer or signing capability without cloning an unclonable trait object. Replace placeholder public-key bytes with derived public key material from the actual key source.

## Acceptance criteria

- [ ] No placeholder public key is returned in production wallet code.
- [ ] `get_signer` or its replacement returns usable signing capability or a typed error.
- [ ] The design avoids leaking private key material.
- [ ] Positive test signs/verifies a message using the retrieved signer/capability.
- [ ] Negative test proves missing key/signing capability fails closed.
- [ ] `cargo check -p csv-wallet` passes.
- [ ] `cargo test -p csv-wallet` passes.

## Notes

A good design may use `Arc<dyn Signer>` internally and return a cloned `Arc`, or expose a narrower signing method instead of returning the trait object.
