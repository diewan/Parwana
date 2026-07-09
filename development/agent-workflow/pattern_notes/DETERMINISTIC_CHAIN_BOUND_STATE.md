# Pattern: deterministic chain-bound state, never wall-clock

**Resolved in:** `SUI-CREATE-SEAL-STATE-001`, `SUI-SANAD-STATE-001`
**Reference file:** `csv-adapters/csv-sui/src/seal_protocol.rs` (`derive_seal_inputs`), `csv-adapters/csv-sui/src/ops.rs`
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

**For derivation (creation):**

- The derivation must be a **pure function** of chain-bound inputs, so identical
  logical inputs always yield identical `(sanad_id, state_root, commitment)`.
- Inputs must be *reconstructable by a verifier who inspects the transaction*.
  On Sui the strongest pre-execution anchor is the set of gas coins consumed:
  `gas_ref_digest` commits to each coin's real `(object_id, version, digest)`.
  Combine that with package id, sender, and a value-derived nonce.
- The nonce must be derived (e.g. from `value`), never from a clock or RNG.
- Domain-tag the hash (`b"csv.sui.state-root.v2"`).

**For reading (canonical state):**

- Decode every field from the real on-chain object contents.
- A missing or malformed object returns `Err(ChainOpError::CapabilityUnavailable(..))`.
  Never substitute defaults, zero hashes, or `SystemTime::now()` for lifecycle
  timestamps.

## Minimal reference excerpt

```rust
// csv-adapters/csv-sui/src/seal_protocol.rs
/// - deterministic — identical inputs always yield identical outputs, so
///   creating a seal twice for the same logical inputs never drifts (there is
///   no `SystemTime::now()` entropy), and
/// - chain-bound & reconstructable — a verifier who inspects the transaction
///   sees exactly which on-chain objects these values commit to.
fn derive_seal_inputs(
    package_id_bytes: [u8; 32],
    sender_bytes: &[u8],
    nonce: u64,
    gas_ref_digest: [u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) { /* Blake2b, domain-tagged */ }

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
| csv-sui | Gas coin refs pre-execution; `Seal` Move object contents post-execution | Checkpoint API is private in `sui-rpc`, hence the gas-ref anchor |
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
- Regression/constitution: `derive_seal_inputs_is_deterministic` — calling the
  derivation twice with identical inputs must produce identical output. This is
  the test that pins the `SystemTime::now()` regression.

## Gotchas

**There is still a fallback worth revisiting.** In `create_seal`, when the
created-object id cannot be extracted from transaction effects, the code falls
back to using the transaction digest as the object id
(`// Fallback: use transaction digest as object ID`). A tx digest is not an
object id. It is chain-bound and deterministic, so it does not violate this
pattern's letter, but a later reader may treat it as a real object id. If you
touch this path, prefer failing closed.

The determinism test is cheap and catches the entire class. When you port this
pattern to another adapter, write the "same inputs twice, assert equal" test
first — it fails immediately against any clock or RNG in the derivation.

Domain-tag version bumps (`csv.sui.state-root.v2`) change every derived id. Do
not bump the tag without treating it as a state-format migration.
