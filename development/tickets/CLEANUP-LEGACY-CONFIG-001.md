---
id: CLEANUP-LEGACY-CONFIG-001
title: "Remove dead legacy wallet-config migration shims"
theme: "CLI config cleanup"
crate: "csv-cli"
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-cli/src/config.rs"
target_patterns:
  - "struct CsvWalletData"
  - "struct CsvAccount"
  - "pub(crate) struct LegacyWalletConfig"
  - "static CSV_WALLET_CACHE"
  - "fn get_csv_wallet_cache"
  - "fn get_cached_wallet_config"
  - "pub fn parse_network"
  - "fn load_from_file"
  - "fn find_account"
  - "fn to_secret_handle"
interface_files:
  - "csv-cli/src/main.rs"
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli --all-features"
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

`csv-cli/src/config.rs` holds a cluster of items self-documented in their own
doc comments as a migration shim — "legacy, for migration from csv-wallet <
0.4" — with zero callers anywhere in `csv-cli`:

- `CsvWalletData` and its `load_from_file`/`find_account` methods
- `CsvAccount`
- `LegacyWalletConfig` and its `to_secret_handle` method
- the `CSV_WALLET_CACHE` static and `get_csv_wallet_cache`/
  `get_cached_wallet_config` helper functions
- `parse_network`

A repo-wide grep for each of these names outside `config.rs` returns nothing.
Tracing the call graph inside `config.rs` shows the only caller of this whole
cluster is `Config::wallet(&self, chain: &Chain) -> Option<LegacyWalletConfig>`
— itself marked `#[deprecated(since = "0.4.0", note = "Use unified storage
WalletConfig instead")]` — and `Config::wallet()` itself has no callers either
(the only textual match for `.wallet(` outside this method's own definition is
an unrelated string literal in a CLI help message, not a real call). So the
entire chain rooted at `Config::wallet()` is dead, not just the leaf items.

Note: `LegacyWalletConfigToml` (a distinct type used by the still-live
`Config::wallet_account()` and `Config::set_wallet()` paths) is **not** part of
this cluster and must not be touched — it backs the live config.toml wallet
path.

## Why it matters

Pure dead weight, but low-risk to remove since everything in this cluster is
private (`config.rs`-local) and already self-documented as legacy.

## Task

Delete the listed cluster, and also delete `Config::wallet()` itself, since it
is the sole caller of the cluster and is itself unreachable (only its own
`#[deprecated]` annotation references it — no other code path calls it). Leave
`Config::wallet_account()`, `Config::set_wallet()`, and `LegacyWalletConfigToml`
untouched; they back the live config.toml wallet path and are unrelated to this
cluster.

If the blanket `#![allow(dead_code)]` on this file (see
`LINT-DEADCODE-HYGIENE-001`) was solely hiding this cluster, remove the blanket
allow too and confirm the file compiles clean without it. If other items in the
file still need suppression after this cluster is removed, leave that
triage to `LINT-DEADCODE-HYGIENE-001` and note here which items remain.

## Acceptance criteria

- [ ] `CsvWalletData`, `CsvAccount`, `LegacyWalletConfig`, `CSV_WALLET_CACHE`,
      `get_csv_wallet_cache`, `get_cached_wallet_config`, `parse_network`, and
      `Config::wallet()` are all removed.
- [ ] `LegacyWalletConfigToml`, `Config::wallet_account()`, and
      `Config::set_wallet()` are left untouched.
- [ ] `csv-cli` builds and its tests pass.
- [ ] A repo-wide search confirms no remaining references to any removed item.
- [ ] All `verify_commands` pass.

## Notes

This ticket does not need to resolve the blanket `#![allow(dead_code)]` on
`csv-cli/src/config.rs` beyond confirming whether this cluster was the only
thing it was hiding — full triage of that file's lint suppression is
`LINT-DEADCODE-HYGIENE-001`'s job, which should run after this ticket lands.
