# Pattern: deterministic chain-bound state, never wall-clock

**Resolved in:** `SUI-CREATE-SEAL-STATE-001`, `SUI-SANAD-STATE-001`
**Reference file:** `csv-adapters/csv-sui/src/seal_protocol.rs` (`canonical_creation_fields`), `csv-adapters/csv-sui/src/ops.rs`
**Applies to:** every adapter deriving seal state or reading canonical Sanad state

## What the gap was

Two distinct fabrications, both in the Sui adapter:

1. **Creation** — `create_seal` folded `SystemTime::now()` into the derived
   `state_root`. Two calls with identical logical inputs produced different
   seals. Wall-clock entropy is not chain state.
2. **Reading** — `CanonicalSanadState` was assembled with placeholder/default
   values when the on-chain `Seal` object was missing or unreadable, presenting
   invented state as observed state.

## Correct implementation shape

**For canonical creation:**

- The SDK derives the canonical owner-bound `sanad_id` and commitment before
  any chain write. Every adapter receives both through `ChainBackend::create_seal`.
- The on-chain `SanadCreated` footprint must carry those exact values. An
  adapter-local wall-clock, RNG, gas-reference, or commitment-as-ID derivation
  creates a second incompatible identity and is forbidden.
- Transaction gas objects remain real chain inputs, but they must not replace
  protocol identity fields.

**For reading (canonical state):**

- Decode every field from the real on-chain object contents.
- A missing or malformed object returns `Err(ChainOpError::CapabilityUnavailable(..))`.
  Never substitute defaults, zero hashes, or `SystemTime::now()` for lifecycle
  timestamps.

## Minimal reference excerpt

```rust
// csv-adapters/csv-sui/src/seal_protocol.rs
fn canonical_creation_fields(
    sanad_id: Hash,
    commitment: Hash,
) -> ([u8; 32], [u8; 32]) {
    (*sanad_id.as_bytes(), *commitment.as_bytes())
}

// csv-adapters/csv-sui/src/ops.rs — reading fails closed
let contents = object.contents.and_then(|bcs| bcs.value).ok_or_else(|| {
    ChainOpError::CapabilityUnavailable(
        "Sui RPC did not return Seal object contents; cannot derive canonical sanad state"
            .to_string(),
    )
})?;
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-sui | SDK canonical ID/commitment pre-execution; `Seal` Move object contents post-execution | Read created object id/version/digest from transaction effects |
| csv-aptos | Ledger version + resource read under `@csv_seal` | Do not use ledger version bytes as a block hash |
| csv-ethereum | Block hash / receipt root | Do not use `block.timestamp` as entropy |
| csv-bitcoin | Outpoint `(txid, vout)` is already the natural chain-bound anchor | Display vs internal txid byte order |
| csv-solana | Recent blockhash + PDA read | A closed PDA is not an absent PDA — check tombstones |
| csv-celestia | Namespace + share commitment | — |

## Tests added

- Positive: `sanad_state_from_view_maps_real_fields` — a fully-populated Seal
  object decodes into real `CanonicalSanadState` fields (state, owner,
  commitment, nullifier, all lifecycle timestamps) with no placeholder
  substitution.
- Negative/adversarial: missing/malformed object contents return
  `CapabilityUnavailable` rather than default state.
- Regression/constitution: `creation_fields_are_the_sdk_canonical_values` and
  Solana's `create_seal_abi_keeps_canonical_id_distinct_from_commitment` pin the
  identity propagation and prevent commitment-as-ID regression.

## Gotchas

The old tx-digest-as-object-id fallback is removed. Creation now fails if the
effects omit, ambiguously report, or malform the created Seal object reference.
