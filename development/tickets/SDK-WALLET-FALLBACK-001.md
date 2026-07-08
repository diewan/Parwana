---
id: SDK-WALLET-FALLBACK-001
title: "Wallet address derivation must fail closed instead of encoding seed bytes"
theme: "SDK wallet key derivation"
crate: csv-sdk
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-sdk/src/wallet.rs"
target_patterns:
  - "fn eth_address_with_path"
  - "fn sui_address_with_path"
  - "fn aptos_address_with_path"
  - "fn sol_address_with_path"
  - "unknown-chain:{}"
interface_files:
  - "csv-sdk/src/wallet.rs"
  - "csv-cli/src/wallet_identity.rs"
  - "csv-keys/src/bip44.rs"
reference_crate: "csv-cli"
reference_file: "csv-cli/src/wallet_identity.rs"
reference_patterns:
  - "pub(crate) fn address"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --no-default-features --features std,tokio,native"
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
  - "hex::encode(&self.seed"
contract_files: []
cross_boundary_check: false
---

## Problem

`csv-sdk/src/wallet.rs` implements `Wallet::eth_address_with_path` (line 314),
`Wallet::sui_address_with_path` (line 382), `Wallet::aptos_address_with_path`
(line 416), and `Wallet::sol_address_with_path` (line 450). All four have the
same shape:

```rust
fn eth_address_with_path(&self, account: u32, index: u32) -> String {
    #[cfg(feature = "wallet")]
    {
        // ... real BIP-32/SLIP-10 derivation ...
        // Fallback if derivation fails
        format!("0x{}", hex::encode(&self.seed[0..20]))
    }

    #[cfg(not(feature = "wallet"))]
    {
        format!("0x{}", hex::encode(&self.seed[0..20]))
    }
}
```

Two independent problems live in this shape:

1. When the `wallet` feature is enabled but derivation fails (`XPrv::new`
   returns `None`, `derive_child` errors, `bip44::derive_key` /
   `bip44::derive_address_from_key` return `Err`), the function does not
   propagate the error — it falls through to `format!("0x{}",
   hex::encode(&self.seed[..N]))` (or `format!("sol:{}", ...)` for Solana),
   silently returning a string built directly from raw seed bytes,
   reinterpreted as if it were a derived address.
2. `wallet` is **not** in `csv-sdk`'s default feature set (`default = ["std",
   "tokio", "native"]`, `csv-sdk/Cargo.toml:89`). Any consumer who builds
   `csv-sdk` without explicitly opting into `wallet` silently gets the
   `#[cfg(not(feature = "wallet"))]` branch on every call — the seed-encoding
   path is not a rare failure case, it is the default behavior.

The same-shaped bug also appears in `Wallet::address(&self, chain: ChainId) ->
String` (line 205) itself, whose `_` arm for an unrecognized chain returns
`format!("unknown-chain:{}", hex::encode(&self.seed[..8]))` — again, seed bytes
encoded as a address-shaped string with no error path. Per `.agents/AGENT.md
§5.1` ("fixing only one occurrence is forbidden"), fix this arm in the same
change.

All four `_with_path` functions are declared as `-> String` (infallible), so no
caller —
including the documented public example at `wallet.rs:70-86`
(`let eth_address = restored.address("ethereum");`) — has any way to detect
that the value returned is not a real derived address.

## Why it matters

This violates the "no silent fallback behavior" invariant in `.agents/AGENT.md`
(`§1.7`). Raw BIP-39 seed bytes are the master secret for every key the wallet
can ever derive. Encoding a slice of them as an "address" and returning it
through the same infallible API that returns real addresses means a consumer
of this public SDK surface — e.g., generating a receiving address for a
cross-chain deposit — can silently obtain a string that looks like an address
but is not tied to any key the wallet (or anyone) controls. Funds sent to it
would be unrecoverable.

**Scoping note (do not re-litigate):** the CLI's own wallet flow does not hit
this bug. `csv-cli/src/wallet_identity.rs::WalletIdentity::address()` is a
separate, correctly `Result`-returning implementation and is unaffected. This
ticket is specifically about `csv-sdk`'s public convenience API
(`csv_sdk::wallet::Wallet`), used by external SDK consumers who are not going
through the CLI's derivation path.

## Task

- Change `eth_address_with_path`, `sui_address_with_path`,
  `aptos_address_with_path`, and `sol_address_with_path` (and their `_address`
  zero-argument wrappers, `eth_address`/`sui_address`/`aptos_address`/
  `sol_address`) to return `Result<String, WalletError>`.
- Every derivation failure path (`XPrv::new` returning `None`,
  `derive_child` erroring, `bip44::derive_key`/`bip44::derive_address_from_key`
  returning `Err`) must propagate as `Err(WalletError::...)` — never fall
  through to encoding `self.seed` bytes.
- When the `wallet` feature is disabled, return a clear
  `Err(WalletError::UnsupportedChain(..))`-style error (the crate already has
  this variant, see `wallet.rs:22-27`) instead of the seed-encoding fallback.
  Do not leave a silent, feature-gated behavior change in an infallible `String`
  return type.
- Update `Wallet::address(&self, chain: ChainId) -> String` (line 205) and the
  duplicate `address` at line 747, which call these helpers, to propagate the
  `Result` (change their signature to `Result<String, WalletError>` as well, or
  document/justify why not if a narrower fix is chosen).
- Update the doc example at `wallet.rs:70-86` to reflect the new fallible
  signature.
- Update all in-repo callers of `Wallet::address`/the `_with_path` helpers to
  handle the `Result`.

## Acceptance criteria

- [ ] No code path in `eth_address_with_path`, `sui_address_with_path`,
      `aptos_address_with_path`, or `sol_address_with_path` returns a string
      derived from `hex::encode(&self.seed[..N])` or similar raw seed bytes.
- [ ] A forced derivation failure (e.g., a malformed/short seed, or a mocked
      derivation error) returns `Err`, not a seed-encoded string.
- [ ] Building `csv-sdk` without the `wallet` feature yields a clear
      compile-time or explicit runtime error path for address derivation, not a
      silent seed-encoded string.
- [ ] The public doc example compiles/reads correctly against the new fallible
      signature.
- [ ] Positive test: successful derivation for at least one chain returns the
      expected, real derived address.
- [ ] Negative test: a forced derivation failure returns `Err`, and the test
      asserts the error is *not* a string containing seed bytes.
- [ ] All `verify_commands` pass, including the `--no-default-features
      --features std,tokio,native` build (i.e., without `wallet`).

## Notes

`csv-cli/src/wallet_identity.rs::WalletIdentity::address()` is the reference
for "this is what a fail-closed, `Result`-returning address derivation looks
like in this codebase" — it is a separate implementation from `csv-sdk`'s and
does not need to change, but its shape (propagate `Result`, no fallback) is
the target shape here.
