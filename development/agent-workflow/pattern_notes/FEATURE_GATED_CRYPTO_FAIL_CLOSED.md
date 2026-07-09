# Pattern: feature-gated cryptography that fails closed

**Resolved in:** `PQ-MLDSA-001`
**Reference file:** `csv-wallet/src/signer.rs` (`MemorySigner::sign_ml_dsa65`)
**Applies to:** any crate exposing a scheme/algorithm it may not have compiled in

## What the gap was

`csv-wallet` rejected `SignatureScheme::MlDsa65` unconditionally:

```rust
SignatureScheme::MlDsa65 => Err(WalletError::SigningFailed(
    "MlDsa65 signing not yet implemented".to_string(),
)),
```

But ML-DSA-65 *was* implemented — in `csv-protocol/src/signature.rs`, behind a
`pq` feature, with real `pqcrypto_dilithium` keygen/sign/verify and passing tests.
The gap was that `csv-wallet` had **no `pq` feature at all**, so the arm was a
dead end regardless of workspace flags. A PQ-capable protocol layer that no wallet
surface could reach.

## Correct implementation shape

- Add a forwarding feature, so one flag lights up the whole path:

  ```toml
  # csv-wallet/Cargo.toml
  pq = ["csv-protocol/pq"]
  ```

- Write **both** arms of the `cfg`. The `not(feature)` arm returns an error that
  *names the missing feature*, so the failure is actionable rather than mysterious:

  ```rust
  #[cfg(feature = "pq")]
  fn sign_ml_dsa65(&self, message: &[u8]) -> Result<Signature, WalletError> {
      let bytes = csv_protocol::signature::sign_ml_dsa65(message, self.secret_key.expose_secret())?;
      Ok(Signature { bytes, scheme: SignatureScheme::MlDsa65 })
  }

  #[cfg(not(feature = "pq"))]
  fn sign_ml_dsa65(&self, _message: &[u8]) -> Result<Signature, WalletError> {
      Err(WalletError::SigningFailed(
          "ML-DSA-65 signing requires the 'pq' feature to be enabled on csv-wallet".to_string(),
      ))
  }
  ```

- The lower layer owns the implementation; the upper layer **delegates**. Never
  re-implement the primitive at the wallet/adapter layer.
- Never stub, fake, or truncate a signature to make the type-check pass.

## Chain-specific notes

Not chain-specific. The same three-part shape (forwarding feature, real arm,
error-naming-the-feature arm) already appears in:

| Surface | Feature | Fail-closed error |
|---|---|---|
| `csv-protocol::signature::verify_ml_dsa65` | `pq` | "requires the 'pq' feature" |
| `csv-ethereum::verify_seal_registry` | `rpc` | see `REGISTRY_VERIFICATION_WIRING.md` |
| adapter `submit_attested_mint` | `rpc` | "the 'rpc' feature is not enabled" |

## Tests added

- Positive (`#[cfg(feature = "pq")]`):
  `ml_dsa65_signature_round_trips_through_protocol_verify` — a `MemorySigner`
  signature verifies through `csv_protocol::signature::verify_signatures`.
- Negative/adversarial (`#[cfg(feature = "pq")]`):
  `tampered_ml_dsa65_signature_is_rejected`.
- Regression (`#[cfg(not(feature = "pq"))]`):
  `ml_dsa65_fails_closed_without_pq_feature` asserts the error text contains
  `'pq' feature`.

**Run the crate both ways.** `cargo test -p csv-wallet` and
`cargo test -p csv-wallet --features pq` exercise disjoint test sets; a green run
of one proves nothing about the other.

## Gotchas

**ML-DSA has no secret→public derivation.** `WalletManager::derive_public_key`
cannot serve `MlDsa65`: FIPS 204 / Dilithium3 exposes keypair generation only, and
pqcrypto's `SecretKey` carries no public-key accessor. The correct resolution is
to fail closed there with an accurate message and provide
`WalletManager::generate_ml_dsa65_keypair()` as the only way to obtain a usable
key. Do not "fix" that arm by hashing the secret key into something
public-key-shaped.

**`sign_ml_dsa65` returns a signed message, not a detached signature.** It is
`signature ‖ message` (because verification uses `dilithium3::open`), so it is
*not* a fixed 3309 bytes. Any code that slices a fixed signature length off the
front will corrupt it.

An "unimplemented" error is not proof that something is unimplemented. Check the
layer below before writing the implementation — `PQ-MLDSA-001`'s original audit
finding said ML-DSA-65 was missing; it was fully present and tested one crate down.
