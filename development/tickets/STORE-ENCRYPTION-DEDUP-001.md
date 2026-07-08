---
id: STORE-ENCRYPTION-DEDUP-001
title: "Resolve duplicate encryption implementations (csv-store vs csv-content)"
theme: "encryption implementation hygiene"
crate: "csv-store"
priority: P2
security_critical: true
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-store/src/encrypted_storage.rs"
target_patterns:
  - "pub struct EncryptedEnvelope"
  - "type HmacSha256 = Hmac<Sha256>;"
  - "const CURRENT_VERSION: u32 = 1;"
  - "const INDEX_KEY: &str = \"__csv_encrypted_index\";"
target_file_2: "csv-content/src/encryption.rs"
target_patterns_2:
  - "pub struct EncryptionDescriptor"
  - "pub struct EncryptionEnvelope"
interface_files:
  - "csv-store/src/lib.rs"
  - "csv-cli/src/commands/content.rs"
reference_crate: "csv-content"
reference_file: "csv-content/src/encryption.rs"
reference_patterns:
  - "use csv_content::encryption::{EncryptionDescriptor, EncryptionEnvelope};"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-store --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-content --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-store --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-content --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo build --workspace --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "vec![0u8;"
  - "Hash::new([0u8; 32])"
  - "Ok(true) // Placeholder"
  - "Ok(0) // Placeholder"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

`csv-store/src/encrypted_storage.rs` implements a complete encryption stack —
`EncryptedEnvelope` with `encrypt`/`decrypt`, a `CURRENT_VERSION` constant, an
`HmacSha256` type alias, and an `INDEX_KEY` constant — and is publicly
re-exported from `csv-store/src/lib.rs` (`pub use encrypted_storage::{...}`).
A repo-wide grep for `encrypted_storage`/`EncryptedEnvelope` outside
`csv-store/src/` returns nothing: no crate in the workspace calls it.

The path that is actually live runs through `csv-content/src/encryption.rs`
(`EncryptionDescriptor`, `EncryptionEnvelope`) and is called from
`csv-cli/src/commands/content.rs`'s `cmd_encrypt`/`cmd_decrypt`, which do the
actual AES-256-GCM encrypt/decrypt work directly in the CLI command using those
types as the envelope/descriptor container.

Comparing the two: both use AES-256-GCM with a randomized 12-byte nonce, so the
core cipher choice is the same. They are **not** cryptographically identical,
though:

- `csv-store`'s `EncryptedEnvelope::encrypt` derives keys via PBKDF2-HMAC-SHA256
  (600,000 iterations) from a password, and additionally computes a standalone
  HMAC-SHA256 tag over `ciphertext || nonce` on top of AES-GCM's own built-in
  authentication tag (`encrypted_storage.rs` lines ~71–117, ~152–155).
- The `csv-content`/CLI path takes a raw 32-byte hex key directly (no KDF at
  all — `key_id` is decoded as the key itself in
  `csv-cli/src/commands/content.rs::cmd_encrypt`) and relies solely on
  AES-GCM's built-in tag, with no separate HMAC layer.

So the two implementations diverge in key handling (password+PBKDF2 vs.
raw-key) and in authentication layering (double-MAC vs. single AEAD tag), even
though they agree on cipher and nonce size.

## Why it matters

This is security-critical because it is encryption code specifically. Two
independent encryption implementations in the same protocol codebase is a
security-hygiene concern even though only one is currently reachable: a future
caller could reasonably import either `csv_store::EncryptedEnvelope` or
`csv_content::encryption::{EncryptionDescriptor, EncryptionEnvelope}`, and
because they differ in key-derivation and authentication model, picking the
wrong one is not merely redundant — it changes the actual security properties
(e.g. whether a raw key or a password is expected, and whether there's a
password-based KDF at all).

## Task

Pick the canonical implementation. Default assumption: `csv-content`'s
`encryption.rs` types plus the `csv-cli` `cmd_encrypt`/`cmd_decrypt` logic that
uses them, since that is the only path with a real caller today. Then either:

- **(a) Delete the unused path.** Remove `csv-store/src/encrypted_storage.rs`
  and its public re-export from `csv-store/src/lib.rs`.
- **(b) Keep both, but delegate.** If `csv-store`'s `EncryptedEnvelope` is
  actually intended as a public API surface for external SDK consumers of
  `csv-store` (check whether `csv-store` has consumers outside this workspace —
  note `publish = true` is set workspace-wide as a convention, not a
  distinguishing signal by itself, so this needs a stronger signal than the
  Cargo.toml flag), keep it, but make it delegate to (or be delegated to by) a
  single shared implementation rather than maintaining two independent
  encrypt/decrypt code paths with different KDF and authentication behavior.

## Acceptance criteria

- [ ] Exactly one encryption implementation remains canonical for this purpose
      in the workspace, or a documented reason exists for keeping both with no
      drift risk between them (i.e. they no longer independently reimplement
      encrypt/decrypt with different KDF/MAC choices).
- [ ] No dead encryption code with zero callers remains without an explicit
      "kept for external API" justification recorded in a doc comment.
- [ ] If deleted, `csv-store/src/lib.rs` no longer re-exports
      `encrypted_storage` items, and a repo-wide search confirms no remaining
      references.
- [ ] If kept and delegated, the two code paths use the same KDF, nonce
      handling, and authentication approach — no unexplained divergence.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, weakened crypto (e.g. dropping the AEAD tag or PBKDF2
      iteration count), or silent fallbacks.
- [ ] Existing tests in whichever implementation is kept continue to pass,
      including the nonce-randomization and tamper-detection regression tests
      already present in `csv-store/src/encrypted_storage.rs` if that
      implementation is retained.
- [ ] All `verify_commands` pass.

## Notes

Do not "merge" the two by silently picking one's behavior and leaving the
other's tests/callers referencing the old semantics — if the decision is (b),
the delegation must be real (one code path calling the other), not two call
sites that happen to produce similar output today.
