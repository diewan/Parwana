---
id: CLEANUP-BTC-ERROR-CODES-001
title: "Remove unused Bitcoin error-code constants"
theme: "Bitcoin adapter cleanup"
crate: "csv-adapters/csv-bitcoin"
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-bitcoin/src/error.rs"
target_patterns:
  - "pub const BITCOIN_RPC_ERROR: u32 = 3001;"
  - "pub const BITCOIN_INSUFFICIENT_FUNDS: u32 = 3008;"
  - "mod error_codes {"
interface_files:
  - ""
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-bitcoin --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-bitcoin --all-features"
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
cross_boundary_check: false
---

## Problem

`csv-adapters/csv-bitcoin/src/error.rs`'s private `mod error_codes` block
defines two overlapping sets of numeric error-code constants with the same
underlying values:

- `BITCOIN_RPC_ERROR` (3001), `BITCOIN_TX_NOT_FOUND` (3002),
  `BITCOIN_UTXO_SPENT` (3003), `BITCOIN_MERKLE_PROOF` (3004),
  `BITCOIN_REORG` (3005), `BITCOIN_REGISTRY_FULL` (3006),
  `BITCOIN_INSUFFICIENT_CONFIRMATIONS` (3007), `BITCOIN_INSUFFICIENT_FUNDS`
  (3008) — 8 constants, all with a `BITCOIN_` prefix.
- `BTC_RPC_ERROR` (3001), `BTC_TRANSACTION_NOT_FOUND` (3002),
  `BTC_UTXO_SPENT` (3003), `BTC_INVALID_MERKLE_PROOF` (3004),
  `BTC_REGISTRY_FULL` (3006), `BTC_REORG_DETECTED` (3005),
  `BTC_INSUFFICIENT_CONFIRMATIONS` (3007), `BTC_INSUFFICIENT_FUNDS` (3008),
  plus `BTC_MPC_ERROR` (3009), `BTC_STORAGE_ERROR` (3010), and
  `BTC_TRANSACTION_ERROR` (3011) — 11 constants, all with a `BTC_` prefix.

`HasErrorSuggestion::error_code()` on `BitcoinError` (around
`error.rs:178`–`192`) matches exclusively on the `BTC_*` set via
`error_codes::BTC_*`. A repo-wide grep confirms all 8 `BITCOIN_*`-prefixed
constants have zero references anywhere, including within `error.rs` itself
beyond their own definitions — they are pure dead weight, apparently left over
from an earlier, superseded error-code naming scheme that was replaced by the
`BTC_*` set without removing the old names.

## Why it matters

Minor dead weight; low priority but trivial to fix, and having two
differently-prefixed constant sets with identical numeric values sitting side
by side in the same module is a plausible source of confusion for anyone
adding a new error code later (which prefix is "the" scheme?).

## Task

Remove the 8 unused `BITCOIN_*`-prefixed constants
(`BITCOIN_RPC_ERROR` through `BITCOIN_INSUFFICIENT_FUNDS`). The `BTC_*`
constants are live (matched in `error_code()`) and must not be touched or
renumbered — `mod error_codes` is a private module, but the numeric values it
returns via `HasErrorSuggestion::error_code()` and `error_codes::docs_url()`
are part of `BitcoinError`'s effective external error-reporting surface (e.g.
via `docs_url`), so avoid renumbering the constants that remain in use even
though they are not directly `pub`. Removing only the unused `BITCOIN_*` set
leaves gaps in the numbering (3001–3008 duplicated by 3009–3011 continuing the
`BTC_*` sequence); that is fine — do not renumber the `BTC_*` set to close the
gap.

## Acceptance criteria

- [ ] All 8 unused `BITCOIN_*`-prefixed constants are removed from
      `mod error_codes` in `csv-adapters/csv-bitcoin/src/error.rs`.
- [ ] The 11 `BTC_*`-prefixed constants and their values are unchanged.
- [ ] `csv-bitcoin` builds and its tests pass.
- [ ] A repo-wide grep confirms no references to the removed constants remain.
- [ ] All `verify_commands` pass.
- [ ] No breaking change to the numeric error codes that remain in use
      (`BTC_*` values and their meanings are unchanged).

## Notes

If it later turns out these `BITCOIN_*` values are serialized or exposed to
external consumers somewhere outside this crate (none were found in this
audit), stop and re-scope rather than deleting — but the repo-wide search
performed for this ticket found only the two definition blocks in
`error.rs` and no external references.
