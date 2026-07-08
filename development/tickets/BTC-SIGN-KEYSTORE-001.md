---
id: BTC-SIGN-KEYSTORE-001
title: "sign_message bypasses keystore abstraction, treats key_id as raw private key"
theme: "Bitcoin adapter key handling"
crate: csv-bitcoin
priority: P1
security_critical: true
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-bitcoin/src/ops.rs"
target_patterns:
  - "impl ChainSigner for BitcoinChainSigner"
  - "async fn sign_message(&self, message: &[u8], key_id: &str)"
  - "Parse key_id as hex-encoded secret key"
interface_files:
  - "csv-adapters/csv-bitcoin/src/wallet_operations.rs"
  - "csv-keys/src/keystore.rs"
  - "csv-keys/src/file_keystore.rs"
reference_crate: "csv-bitcoin"
reference_file: "csv-adapters/csv-bitcoin/src/wallet_operations.rs"
reference_patterns:
  - "async fn sign_transaction"
  - "Fail closed. The previous implementation treated"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-bitcoin --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-bitcoin --all-features"
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
  - "hex::decode(key_id)"
contract_files: []
cross_boundary_check: false
---

## Problem

`BitcoinChainSigner`'s `ChainSigner::sign_message` implementation
(`csv-adapters/csv-bitcoin/src/ops.rs:340-388`) treats its `key_id` parameter
as a raw hex-encoded secp256k1 private key and signs with it directly:

```rust
async fn sign_message(&self, message: &[u8], key_id: &str) -> ChainOpResult<Vec<u8>> {
    // Note: In production, the key_id would be used to retrieve the key from secure storage
    // This implementation assumes the key_id encodes the necessary signing material
    // For now, we return an error indicating keystore integration is required

    // Parse key_id as hex-encoded secret key (for testing/development only)
    // In production, this should use the keystore crate
    let key_bytes = hex::decode(key_id).map_err(|_| {
        ChainOpError::SigningError(
            "Invalid key_id format. Expected hex-encoded key reference.".to_string(),
        )
    })?;

    if key_bytes.len() != 32 {
        return Err(ChainOpError::SigningError(
            "Invalid key length. Expected 32 bytes.".to_string(),
        ));
    }

    let secret_key = SecretKey::from_slice(&key_bytes)...
    // ... signs the message with this secret key and returns a real signature
```

The comment *"For now, we return an error indicating keystore integration is
required"* describes fail-closed behavior that the code does not actually
implement — the function does not return an error for a missing/unresolved
keystore entry; it only errors on malformed hex or wrong length, and
otherwise happily signs using `key_id` reinterpreted as raw key bytes. The
comment is stale/misleading relative to what the code does.

`BitcoinBackend::sign_message` (`ops.rs:2124-2127`, the `ChainSigner` impl for
`BitcoinBackend`) delegates straight to this same `BitcoinChainSigner::sign_message`,
so both call surfaces reach the same bug.

This is inconsistent with the project's own established pattern for
fail-closed key handling. `csv-adapters/csv-bitcoin/src/wallet_operations.rs::sign_transaction`
(lines 159-173) correctly refuses to produce an unbound/bare signature:

```rust
async fn sign_transaction(&self, _seed: &[u8], _tx_data: &[u8]) -> Result<Vec<u8>, WalletError> {
    // Fail closed. The previous implementation treated `tx_data` as a raw
    // 32-byte digest and produced a bare ECDSA signature over it, with no
    // sighash construction, no input/prevout binding, and no witness
    // assembly. That is not a spendable Bitcoin signature and must never be
    // returned. ...
    Err(WalletError::Signing(
        "Bitcoin transaction signing is not implemented: refusing to \
         produce a bare ECDSA signature ...".to_string(),
    ))
}
```

`sign_message` in `ops.rs` does not follow this pattern: it signs anyway,
using the caller-supplied `key_id` string as raw key material rather than
looking the key up through `csv-keys`' keystore abstraction
(`csv-keys/src/keystore.rs`, `file_keystore.rs`, `browser_keystore.rs`).

## Why it matters

Any code path that treats an ID string as directly-usable raw key material
sidesteps whatever access-control, audit, or HSM abstraction the keystore
layer is meant to provide. Inconsistent key-handling paths — one function that
correctly resolves keys through the keystore, another that treats the same
kind of parameter as a raw key — are a known source of key-leak bugs; this
project has previously remediated a related class of issue (see prior "Gate 0"
raw-signing remediation in project history). This also means any caller of
`sign_message` who passes what they believe is an opaque keystore reference
is instead handing this function 32 bytes it will directly load as a secp256k1
secret key — a caller mistake here has a much higher blast radius than a
normal invalid-input error.

## Task

- Route `BitcoinChainSigner::sign_message` through the same keystore lookup
  abstraction `wallet_operations.rs` uses (or the equivalent keystore trait
  from `csv-keys`), resolving `key_id` to signing material via the keystore
  rather than `hex::decode`-ing it directly as a raw private key.
- Remove or correct the stale comment claiming an error is returned when
  keystore integration is missing.
- Ensure `key_id` is never treated as raw key material anywhere in this
  function; an unresolvable `key_id` must fail closed with a clear error.
- Update `BitcoinBackend::sign_message` only if its delegation needs to change
  as a result (it currently just forwards to `BitcoinChainSigner::sign_message`).

## Acceptance criteria

- [ ] `sign_message` no longer accepts a raw hex-encoded private key disguised
      as `key_id`.
- [ ] `key_id` is resolved via the keystore abstraction before any signing
      occurs.
- [ ] Positive test: a valid `key_id` that resolves via the keystore signs
      correctly and produces a verifiable Bitcoin message signature.
- [ ] Negative test: an unknown/unresolvable `key_id` fails closed with a clear
      error, not a signature.
- [ ] The stale "we return an error indicating keystore integration is
      required" comment is removed or corrected to match actual behavior.
- [ ] All `verify_commands` pass.

## Notes

`wallet_operations.rs::sign_transaction` is the reference for *shape*
(fail closed rather than producing output that looks legitimate but bypasses
a real construction/lookup step) even though it addresses a different gap
(sighash construction, not keystore lookup) — do not copy its error verbatim,
model the fail-closed posture and keystore-first lookup pattern instead.
