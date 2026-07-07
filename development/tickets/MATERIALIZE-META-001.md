---
id: MATERIALIZE-META-001
title: "Return destination materialization metadata from chain adapters"
theme: "cross-chain materialize UX"
crate: "csv-runtime"
priority: P1
security_critical: true
model_hint: sonnet
status: open
context_radius: 20
agent_md: "AGENTS.md"
target_file: "csv-runtime/src/transfer_coordinator.rs"
target_patterns:
  - "pub struct TransferReceipt"
  - ".mint_sanad(&transfer.destination_chain, &transfer, &mint_payload)"
  - "mint_tx_hash: mint_result.tx_hash"
target_file_2: "csv-sdk/src/transfers.rs"
target_patterns_2:
  - "pub struct TransferReceipt"
  - "mint_tx_hash: receipt.mint_tx_hash"
interface_files:
  - "csv-protocol/src/chain_adapter_traits.rs"
  - "csv-adapters/csv-sui/src/runtime_adapter.rs"
reference_crate: "csv-adapters/csv-sui"
reference_file: "csv-adapters/csv-sui/src/runtime_adapter.rs"
reference_patterns:
  - "submit_attested_mint"
  - "destination_owner"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-runtime --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli state_tests --all-features"
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
  - "csv-contracts/sui/contracts"
cross_boundary_check: true
---

## Problem

The on-chain materialize path can complete a source-to-destination transfer, but
the runtime receipt currently exposes only the destination mint transaction hash.
That is enough to display "a mint transaction happened", but not enough for the
CLI to persist a complete destination-side `SanadRecord` that can later be shown,
queried, consumed, or transferred on the destination chain.

Required destination metadata:

- `destination_seal_ref`
- `destination_object_id`
- `destination_registry_ref`
- `destination_commitment`
- `destination_owner`

Today the CLI must not create a destination `SanadRecord` from only
`mint_tx_hash`; doing so would fabricate local ownership/authority state without
the chain-native object or seal reference needed for later lifecycle operations.

## Why it matters

Materialize UX needs durable evidence and a usable handle for the destination
asset. After Bitcoin -> Sui materialize, an operator should be able to answer:

- which Sui object/seal was created?
- which registry entry records it?
- which commitment was materialized?
- who owns it?
- which reference should later `csv sanad show`, `csv sanad state`,
  `csv sanad consume`, or a destination-chain transfer use?

This touches a minting path and must preserve the invariant that CLI display
state is only a cache. The runtime/adapter path must return chain-observed
metadata; the CLI must not guess, derive fake references, or treat a transaction
hash as a destination seal/object id.

## Task

Add a typed destination materialization metadata result to the chain adapter
mint path and propagate it through:

1. destination adapter mint result,
2. `csv-runtime` `TransferReceipt`,
3. `csv-sdk` `TransferReceipt`,
4. CLI transfer cache,
5. CLI Sanad display/listing.

Start with Sui as the reference implementation. The Sui adapter should extract
the metadata from the submitted/confirmed mint transaction or the destination
registry read path, not fabricate it locally. Other destination adapters may
return `None` or a typed "not available" value only if the interface documents
that the adapter has not implemented destination metadata yet; they must not fill
placeholder zero hashes or synthetic object ids.

## Proposed shape

Introduce a runtime/SDK-visible struct similar to:

```rust
pub struct DestinationMaterialization {
    pub destination_seal_ref: Option<String>,
    pub destination_object_id: Option<String>,
    pub destination_registry_ref: Option<String>,
    pub destination_commitment: Option<String>,
    pub destination_owner: Option<String>,
}
```

Prefer a stronger typed representation if existing protocol/wire types already
exist for seal refs, object refs, owners, or commitments. Keep serialization
canonical where protocol state is involved; do not use `serde_json` in canonical
hashing paths.

## Acceptance criteria

- [ ] Destination adapter mint result has a typed metadata field; Sui fills it
      from chain-observed mint/registry data.
- [ ] `csv-runtime::TransferReceipt` carries destination materialization
      metadata alongside `mint_tx_hash`.
- [ ] `csv-sdk::transfers::TransferReceipt` faithfully forwards the runtime
      metadata without computing or defaulting it.
- [ ] CLI completed materialize cache persists the destination owner and the
      available destination object/seal/registry/commitment metadata.
- [ ] `csv sanad show <sanad_id>` and `csv sanad list` display available
      destination references without implying missing fields exist.
- [ ] If enough metadata is available to construct a real destination
      `SanadRecord`, the CLI records it with the correct destination chain and
      seal/object reference. If not enough metadata is available, the CLI keeps
      only transfer evidence and explains the missing reference.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, zero-hash placeholders, fake proofs, synthetic object ids, or
      silent fallbacks.
- [ ] Positive test covers a completed Sui materialize receipt with destination
      metadata propagated to CLI display state.
- [ ] Negative test covers missing destination metadata: CLI must not fabricate
      a destination `SanadRecord` from `mint_tx_hash` alone.
- [ ] All `verify_commands` pass.

## Notes

Do not make the CLI authoritative. The destination chain remains authoritative
for ownership and lifecycle. CLI state is a display/discovery cache that should
be refreshable from destination chain queries or events.

Open design question: if `destination_seal_ref` and `destination_object_id` are
different chain-native concepts on Sui, decide which one is the primary handle
for future Sanad lifecycle commands and document that in the adapter trait.
