---
id: PQ-MLDSA-001
title: "csv-wallet does not wire up to csv-protocol's ML-DSA-65 post-quantum signing"
theme: "post-quantum wallet signer support"
crate: csv-wallet
priority: P2
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-wallet/src/signer.rs"
target_patterns:
  - "SignatureScheme::MlDsa65 => Err(crate::error::WalletError::SigningFailed("
  - "MlDsa65 signing not yet implemented"
target_file_2: "csv-wallet/src/wallet.rs"
target_patterns_2:
  - "SignatureScheme::MlDsa65 => Err(WalletError::KeyDerivation("
  - "ML-DSA-65 public key derivation not yet implemented"
interface_files:
  - "csv-protocol/src/signature.rs"
  - "csv-wallet/Cargo.toml"
reference_crate: "csv-protocol"
reference_file: "csv-protocol/src/signature.rs"
reference_patterns:
  - "pub fn generate_ml_dsa65_keys"
  - "pub fn sign_ml_dsa65"
  - "fn verify_ml_dsa65"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-wallet --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-wallet --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-protocol --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-protocol --all-features"
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
contract_files: []
cross_boundary_check: false
---

## Problem

`csv-wallet`'s signer surfaces unconditionally reject `SignatureScheme::MlDsa65`:

- `csv-wallet/src/signer.rs:147-149` — `MemorySigner::sign`:
  ```rust
  SignatureScheme::MlDsa65 => Err(crate::error::WalletError::SigningFailed(
      "MlDsa65 signing not yet implemented".to_string(),
  )),
  ```
- `csv-wallet/src/wallet.rs:96-98` — `WalletManager::derive_public_key`:
  ```rust
  SignatureScheme::MlDsa65 => Err(WalletError::KeyDerivation(
      "ML-DSA-65 public key derivation not yet implemented".to_string(),
  )),
  ```

**Important correction to the original audit finding:** ML-DSA-65 signing,
verification, and key generation are *not* actually unimplemented at the
protocol layer. `csv-protocol/src/signature.rs` already has a real,
tested implementation behind the `pq` feature:

- `generate_ml_dsa65_keys()` (line 439) — real keypair generation via
  `pqcrypto_dilithium::dilithium3::keypair`.
- `sign_ml_dsa65()` (line 456) — real signing via
  `pqcrypto_dilithium::dilithium3::sign`.
- `verify_ml_dsa65()` (line 476, `#[cfg(feature = "pq")]`) — real verification
  via `pqcrypto_dilithium::dilithium3::open`, with a correctly fail-closed
  `#[cfg(not(feature = "pq"))]` counterpart (line 518-525) that returns
  `Err("ML-DSA-65 verification requires the 'pq' feature to be enabled")`
  rather than panicking or lying.
- Tests already exist and pass: `test_ml_dsa65_valid_signature`,
  `test_ml_dsa65_invalid_signature_rejected`,
  `test_ml_dsa65_malformed_public_key`, `test_ml_dsa65_malformed_signature`,
  `test_ml_dsa65_requires_pq_feature`, `test_ml_dsa65_verify_requires_pq_feature`.

The actual gap is narrower than "implement ML-DSA-65 from scratch": `csv-wallet`
has **no `pq` feature at all** in `csv-wallet/Cargo.toml`, and neither
`signer.rs` nor `wallet.rs` has any `#[cfg(feature = "pq")]` gating — the
`MlDsa65` arms in `MemorySigner::sign` and `WalletManager::derive_public_key`
are unconditional dead ends regardless of what feature flags are enabled
anywhere in the workspace. `csv-wallet` never calls
`csv_protocol::signature::{generate_ml_dsa65_keys, sign_ml_dsa65}` at all.

`csv-protocol/src/signature.rs`'s own module doc (lines 11-14) states *"ML-DSA-65
... Long-lived proof bundles must use ML-DSA-65,"* confirming this is a stated
protocol goal, not a speculative one — `csv-wallet` (the crate responsible for
producing signatures on behalf of end users/operators) is the missing link
between that stated goal and an actual PQ-capable signer.

## Why it matters

Fail-closed here is correctly conservative — `.agents/AGENT.md` requires this
(no fake PQ signatures) — but a real PQ-capable protocol layer that no wallet
surface can reach is not useful. If ML-DSA-65 is required for long-lived proof
bundles per `csv-protocol/src/signature.rs`'s own doc comment, `csv-wallet`
needs a real path to produce them, not just reject the scheme unconditionally.

## Task

- Add a `pq` feature to `csv-wallet/Cargo.toml` that enables `csv-protocol`'s
  `pq` feature (and depends on the same `pqcrypto-dilithium`/`pqcrypto-traits`
  crates as needed for key/type handling in `csv-wallet`).
- Wire `MemorySigner::sign`'s `SignatureScheme::MlDsa65` arm to call
  `csv_protocol::signature::sign_ml_dsa65` under `#[cfg(feature = "pq")]`,
  keeping today's `Err("... requires the 'pq' feature ...")`-style message
  under `#[cfg(not(feature = "pq"))]` — do not silently panic or accept
  malformed keys.
- Wire `WalletManager::derive_public_key`'s `SignatureScheme::MlDsa65` arm to
  call `csv_protocol::signature::generate_ml_dsa65_keys` (or the correct
  public-key-from-secret-key derivation, if `pqcrypto_dilithium` requires
  deriving from a stored keypair rather than a raw secret key — confirm the
  exact API shape `pqcrypto_dilithium::dilithium3` exposes before assuming
  parity with the secp256k1/ed25519 arms) under `#[cfg(feature = "pq")]`, with
  the same fail-closed behavior when `pq` is disabled.
- Ensure `MemorySigner`'s `SecretVec<u8>` secret-key storage is sized/handled
  correctly for ML-DSA-65's much larger key material (4032-byte secret key,
  1952-byte public key per `csv-protocol/src/signature.rs`'s doc comments) —
  do not assume 32-byte keys anywhere in the `pq` path.

## Acceptance criteria

- [ ] `csv-wallet` has a `pq` feature that, when enabled, allows
      `MemorySigner::sign` and `WalletManager::derive_public_key` to actually
      produce/derive ML-DSA-65 material by calling into `csv-protocol`'s
      existing implementation — not a reimplementation.
- [ ] Without the `pq` feature, `csv-wallet`'s `MlDsa65` arms remain a clear
      fail-closed error (not a panic), matching today's behavior.
- [ ] Positive test: with `pq` enabled, `MemorySigner` produces an ML-DSA-65
      signature that `csv_protocol::signature`'s own verifier accepts, and
      `WalletManager::derive_public_key` produces a public key of the correct
      length for the scheme.
- [ ] Negative test: a forged/corrupted ML-DSA-65 signature is rejected by
      verification.
- [ ] All `verify_commands` pass.

## Notes

Do not re-implement ML-DSA-65 cryptography inside `csv-wallet` — the audit
confirmed `csv-protocol/src/signature.rs` already has a correct, tested
implementation behind its own `pq` feature; this ticket is about plumbing
`csv-wallet` through to it, not writing new post-quantum crypto.
