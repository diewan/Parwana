---
id: WASM-REMOTE-001
title: "Remote chain dispatch: browser coordinator forwards chain actions to a user-owned native host"
theme: wasm-remote-dispatch
crate: csv-wire
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-wire/src/lib.rs
target_patterns:
  - "pub mod"
target_file_2: csv-sdk/src/builder.rs
target_patterns_2:
  - "adapter_registry"
  - "runtime-coordinator"
interface_files:
  - csv-adapters/csv-adapter-core/src/lib.rs
  - csv-runtime/src/adapter_registry.rs
reference_crate: csv-adapter-factory
reference_file: csv-sdk/Cargo.toml
reference_patterns:
  - "runtime-coordinator"
verify_commands:
  - "cargo test --workspace --all-features"
  - "cargo build -p csv-sdk --no-default-features --features std,wasm,wallet,runtime-coordinator --target wasm32-unknown-unknown"
  - "cargo clippy --workspace --all-features -- -D warnings"
forbidden_patterns:
  - "serde_json in canonical hashing paths"
  - "private key material in any remote request or response"
  - "block_on"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

After the redb migration and dependency gating, `csv-sdk` with the
`runtime-coordinator` feature compiles on wasm32 and runs the full
`TransferCoordinator` (journaling, verification, resume). But its adapter
registry is empty there: the concrete chain adapters cannot compile to wasm
(c-kzg and other native libraries) and should not run in a browser tab anyway.
Today every chain-touching call fails closed with "Adapter not found for
chain". A browser or thin-client wallet therefore cannot lock, mint, confirm,
or read chain state.

## Why it matters

The wallet roadmap is web/mobile/desktop over one core. The chosen topology is
remote dispatch: the coordinator (client-side validation, proof verification
before mint, journal) runs in the client, while the chain actions execute on a
native host the user owns (their `csv` daemon). Without this, the browser
build is limited to offline flows (keys, invoices, consignment verification).

## Task

1. **Wire messages in csv-wire** (csv-wire owns ALL transport encoding). New
   module (e.g. `csv-wire/src/remote.rs`) defining a versioned
   request/response envelope pair with one variant per adapter-registry
   method: `lock_sanad`, `mint_sanad`, `check_seal_registry`,
   `build_inclusion_proof`, `validate_source_proof`, `confirm_tx`,
   `tx_finality`, `get_balance`, `settle_escrow`, `refund_escrow`, plus the
   sync metadata queries (`capabilities`, `signature_scheme`). Payloads use
   existing wire types; encoding is canonical CBOR via csv-codec. serde_json
   must not appear anywhere in this path.
2. **Client adapter crate** (new, e.g. `csv-adapters/csv-remote`): implements
   the `ChainAdapter` port traits from csv-adapter-core by encoding each call
   to the wire envelope and POSTing it to a configured host URL (reqwest —
   its fetch backend keeps the crate wasm-clean; transport must be fully
   async, no `block_on`). One instance per chain id. Depends only on
   csv-adapter-core, csv-wire, csv-codec, reqwest.
3. **Host endpoint** (native only): a `csv runtime serve` subcommand (or
   equivalent) that decodes envelopes and dispatches them to the host's local
   `AdapterRegistry` populated by csv-adapter-factory. The host process owns
   its runtime state as usual; the endpoint is a dumb port-forwarder over the
   registry, not a second decision-maker.
4. **SDK wiring**: on wasm32 (and optionally native thin clients), when a
   remote host URL is configured, the builder registers one remote adapter
   per enabled chain instead of leaving the registry empty. No configured
   host → current fail-closed behavior stays.

## Acceptance criteria

- All `verify_commands` pass; wasm gate builds with the remote adapter wired.
- Round-trip test: coordinator on one side, in-process host on the other,
  executes lock→verify→mint against a mock chain adapter, including resume
  after a dropped connection (journal idempotency preserved).
- Fail-closed preserved: unreachable host, malformed envelope, version
  mismatch, or unknown chain each produce a typed error, never a fallback.
- No private key material crosses the wire in either direction. The browser
  holds wallet/ownership keys; the host holds only its own chain-submission
  keys. Requests are authenticated (bearer token or mTLS — decide and
  document; the host is user-owned, not a public service).
- Finality checks still execute in the client coordinator (finality is never
  optional); the host must not be able to short-circuit them.

## Notes

- Term check ("remote dispatch", "host", "envelope" — re-wordable on request):
  *host* = the user-owned native csv daemon executing chain actions; *remote
  dispatch* = forwarding adapter port calls to it; *envelope* = the versioned
  CBOR request/response wrapper.
- Durability caveat: with the coordinator in the browser, journal/replay state
  lives in evictable browser storage until an IndexedDB backend exists
  (separate ticket). Double-spend safety does not rest on it — on-chain
  replay tombstones and idempotent host-side locks remain the backstop — but
  resume context can be lost on eviction. Ship the IndexedDB ticket before
  recommending browser transfers for meaningful value.
- Prerequisite work landed 2026-07-14: factory is a native-only target-scoped
  dependency; `runtime-coordinator` compiles on wasm against an empty
  registry; CI gates exist in `.github/workflows/architecture.yml`.
