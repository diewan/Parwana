# Pattern: keystore-resolved signing, never raw key material in `key_id`

**Resolved in:** `BTC-SIGN-KEYSTORE-001`
**Reference file:** `csv-adapters/csv-bitcoin/src/ops.rs` (`BitcoinSigningKeyStore`, `secret_key_for`)
**Applies to:** every adapter implementing `ChainSigner::sign_message` / `sign_transaction`

## What the gap was

`BitcoinChainSigner`'s `ChainSigner` impl treated its `key_id: &str` parameter as
a **hex-encoded secp256k1 private key**, decoded it, and signed with it directly:

```rust
// Parse key_id as hex-encoded secret key (for testing/development only)
let key_bytes = hex::decode(key_id)?;
let secret_key = SecretKey::from_slice(&key_bytes)?;
```

`key_id` is an opaque *reference* in the trait contract. Any caller that
forwarded a user-supplied identifier was one hex string away from signing with
attacker-chosen key material, and every call site had to smuggle a private key
through a `&str`.

## Correct implementation shape

- Define a narrow resolver trait owned by the adapter. It maps an opaque
  `key_id` to signing material and returns `Err` when the id is unknown.
- The signer holds `Option<Arc<dyn …SigningKeyStore>>`. `new(...)` leaves it
  `None`; `with_key_store(...)` supplies it.
- One private `secret_key_for(&self, key_id)` helper is the **only** place that
  produces a `SecretKey`. Both `sign_message` and `sign_transaction` go through
  it, so there is a single choke point to audit.
- With no keystore configured, `secret_key_for` returns `Err` — it must not fall
  back to parsing `key_id`. This is the whole point of the ticket.
- Signing material is carried as `csv_keys::SecretKey` and reached only via
  `expose_secret()` at the moment of use. Never `Debug`-format it, log it, or put
  it in an error string.

## Minimal reference excerpt

```rust
// csv-adapters/csv-bitcoin/src/ops.rs
pub trait BitcoinSigningKeyStore: Send + Sync {
    /// Resolve an opaque key ID to signing material.
    fn signing_key(&self, key_id: &str) -> ChainOpResult<csv_keys::SecretKey>;
}

fn secret_key_for(&self, key_id: &str) -> ChainOpResult<secp256k1::SecretKey> {
    let key_store = self.key_store.as_ref().ok_or_else(|| {
        ChainOpError::SigningError(
            "Bitcoin signing key store is not configured; refusing to treat key_id as raw key material"
                .to_string(),
        )
    })?;
    let key = key_store.signing_key(key_id)?;
    secp256k1::SecretKey::from_slice(key.expose_secret())
        .map_err(|e| ChainOpError::SigningError(format!("Invalid keystore secret key: {}", e)))
}
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-bitcoin | `BitcoinSigningKeyStore` (done) | Runtime adapter still constructs `BitcoinChainSigner::new(..)` — see gotchas |
| csv-ethereum | secp256k1 resolver; same shape | Signing digest differs (EIP-191/712), key handling identical |
| csv-solana | Ed25519 resolver | 32-byte seed vs 64-byte expanded key |
| csv-sui | Ed25519 resolver | Adapter currently reads `signer_private_key` from `SuiConfig` — same anti-pattern, different door |
| csv-aptos | Ed25519 resolver | — |
| csv-celestia | — | — |

Note the mint-verifier signing path is a *separate* surface with its own
resolver (`csv-adapter-factory/src/mint_signer.rs`, `MINT-KEYS-001`). Do not
merge them: one authorizes a mint, the other spends a UTXO.

## Tests added

- Positive: `sign_message_uses_keystore_resolved_key` — a keystore-backed signer
  produces a 64-byte signature that `verify_signature` accepts under the
  resolved key's public key.
- Negative/adversarial: `sign_message_raw_hex_key_id_without_keystore_fails_closed`
  — passing a hex-encoded private key as `key_id` with no keystore must error
  with `"key store is not configured"`, never sign. This is the exact exploit the
  ticket closed.
- Regression/constitution: `sign_message_unknown_key_fails_closed` — an
  unresolvable `key_id` errors with `"not found"` rather than signing.

## Gotchas

**Fail-closed is not the same as wired up.** `BitcoinRuntimeAdapter`'s
`sign_message` (`ops.rs`, near the bottom) still builds its signer with
`BitcoinChainSigner::new(self.network)` — no keystore — so that entry point now
*always* errors. Correct per the ticket, but it means the path is inert. Injecting
a keystore into the runtime adapter is unfinished work, not settled design. Check
before assuming Bitcoin signing works end-to-end through the runtime.

Do not "helpfully" restore a hex-parsing branch behind `#[cfg(test)]` or a
`dev`/`insecure` feature. Tests should supply an in-memory keystore instead —
see `TestSigningKeyStore` in the same file, which is a `HashMap` behind the
trait.

`key_id` is opaque. Its format is the keystore's business; the signer must never
inspect, decode, or validate its shape.
