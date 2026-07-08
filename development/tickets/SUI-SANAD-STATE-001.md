---
id: SUI-SANAD-STATE-001
title: "get_sanad_state has no on-chain view function, fails closed"
theme: "Sui adapter sanad state query"
crate: csv-sui
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-sui/src/ops.rs"
target_patterns:
  - "impl SanadStateReader for SuiBackend"
  - "async fn get_sanad_state"
  - "TODO: Add Move contract view function to expose sanad state fields via RPC"
interface_files:
  - "csv-cli/src/commands/sanads.rs"
  - "csv-contracts/sui/sources/csv_seal.move"
reference_crate: "csv-sui"
reference_file: "csv-adapters/csv-sui/src/ops.rs"
reference_patterns:
  - "async fn get_seal_state"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sui --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-sui --all-features"
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
  - "csv-contracts/sui/sources/csv_seal.move"
cross_boundary_check: false
---

## Problem

`SuiBackend`'s `SanadStateReader::get_sanad_state`
(`csv-adapters/csv-sui/src/ops.rs:1589-1620`) fetches the Sui object for a
given `sanad_id`, but cannot populate `CanonicalSanadState` from it and fails
closed instead:

```rust
async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
    let object_id = sui_sdk_types::Address::from_bytes(sanad_id.as_bytes())...?;
    ...
    let object = object_response.into_inner().object;

    match object {
        Some(_) => {
            // The Sui RPC/SDK types do not currently expose the sanad state fields
            // (state, owner, commitment, timestamps) needed to populate CanonicalSanadState.
            // Returning a capability error instead of placeholder data per security requirements.
            // TODO: Add Move contract view function to expose sanad state fields via RPC
            Err(ChainOpError::CapabilityUnavailable(
                "Sui object structure does not expose sanad state fields. \
                 Add a view function to the Move contract to return state, owner, commitment, and timestamps.".to_string(),
            ))
        }
        None => Err(ChainOpError::RpcError("Sanad object not found".to_string())),
    }
}
```

This is a deliberate, documented fail-closed gap — the comment explicitly
states the alternative (returning placeholder data) was rejected "per
security requirements" — not a silent bug. It blocks a real feature: `csv
sanad state --chain sui <sanad_id>` (`SanadAction::State` →
`csv-cli/src/commands/sanads.rs::cmd_state`) currently cannot return canonical
on-chain state for Sui.

Note the on-chain `Seal` struct (`csv-contracts/sui/sources/csv_seal.move:122-144`)
already carries the needed fields (`commitment`, `state`, `owner`,
`created_at`, `locked_at`, `consumed_at`, `minted_at`, `refunded_at`), and the
module already exposes some getters (`state()`, `sanad_id()`, `owner()`,
`id()` at lines 717-727) but no `commitment()` or timestamp getters. Whether
the adapter's real gap is (a) missing Move getter functions, or (b) the
specific Rust RPC client (`sui_rpc::proto::sui::rpc::v2::GetObjectRequest`)
not requesting/parsing decoded Move object content, needs to be confirmed as
part of this ticket — the existing comment attributes it to the RPC/SDK types
not exposing the fields, which may mean the fix is on the adapter's RPC-call
side (request object content) rather than (or in addition to) the Move
contract side.

## Why it matters

This is an intentional fail-closed gap consistent with `.agents/AGENT.md §1.2`
("no placeholder verification") and §3 ("Verification code may NEVER ...
substitute defaults") — it correctly refuses to fabricate sanad state rather
than return zeroed/default fields. It is worth tracking as a real ticket
rather than leaving as a bare TODO because it blocks a documented CLI
capability for one of five supported chains.

## Task

- Determine whether the gap is in the Move contract (missing view/getter
  functions for `commitment` and timestamps) or in the adapter's RPC call
  (not requesting/decoding Move object content from `GetObjectRequest`), or
  both.
- If Move-side: add the missing getter function(s) to
  `csv-contracts/sui/sources/csv_seal.move` exposing `commitment` and the
  relevant timestamp fields (mirroring the existing `state()`/`owner()`/
  `sanad_id()` getters), and rebuild/redeploy the contract artifact as needed
  for test fixtures.
- Wire `get_sanad_state` to use the real on-chain data (either via a
  dev-inspect/read-only call to the new getter(s), or by requesting and
  decoding full Move object content from the existing `GetObjectRequest` if
  that turns out to be sufficient) instead of failing closed.
- Preserve the existing fail-closed behavior for the "sanad genuinely does not
  exist" case (`None => Err(RpcError("Sanad object not found"))`).

## Acceptance criteria

- [ ] `get_sanad_state` returns real on-chain state (state, owner, commitment,
      relevant timestamps) for an existing Sui Seal object.
- [ ] Test coverage for a successful state query against a real/fixture Seal
      object.
- [ ] Fail-closed behavior is preserved and tested for a sanad that genuinely
      does not exist (no object at that address).
- [ ] No placeholder/default/zeroed fields are substituted anywhere in this
      path.
- [ ] All `verify_commands` pass.

## Notes

`get_seal_state` (immediately below `get_sanad_state` in `ops.rs`) is a useful
nearby reference for how this adapter otherwise structures Sui object
queries — check whether it has the same fundamental limitation before
assuming its approach can be reused as-is.
