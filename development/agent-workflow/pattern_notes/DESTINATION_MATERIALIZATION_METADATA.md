# Pattern: destination materialization metadata

**Resolved in:** `MATERIALIZE-META-001`
**Reference file:** `csv-adapters/csv-sui/src/runtime_adapter.rs`
**Applies to:** every adapter implementing `ChainAdapter::submit_attested_mint`

## What the gap was

`MintResult` carried only `tx_hash` + `block_height`. A transaction hash proves a
mint transaction happened; it is not an object id, seal reference, registry
reference, commitment, or owner. The CLI had nothing real to persist for the
destination side, and the temptation was to synthesize a destination
`SanadRecord` from the mint tx hash.

## Correct implementation shape

- `MintResult` carries a typed `materialization: DestinationMaterialization`
  (`csv-adapters/csv-adapter-core/src/lib.rs`). Every field except `chain_id` is
  `Option`.
- An adapter that cannot recover a field leaves it `None`. It must **never**
  substitute the mint tx hash, a zero hash, or a synthetic object id.
- An adapter with no destination metadata at all returns
  `DestinationMaterialization::unavailable(chain_id)` — an explicit absence
  value, not a `Default`.
- Runtime and SDK receipts forward the value verbatim. They must not recompute
  or default it.
- The CLI gates display/persistence on `has_display_metadata()`, which is true
  only when at least one field beyond `chain_id` is populated. When false it
  prints `"not reported by adapter"` rather than rendering an empty record.

## Minimal reference excerpt

```rust
// csv-adapters/csv-adapter-core/src/lib.rs
impl DestinationMaterialization {
    /// Explicitly mark destination metadata as unavailable.
    pub fn unavailable(chain_id: impl Into<String>) -> Self {
        Self { chain_id: chain_id.into(), object_id: None, seal_ref: None,
               registry_ref: None, commitment: None, owner: None }
    }

    /// True when the metadata contains displayable destination state beyond
    /// the mint transaction hash.
    pub fn has_display_metadata(&self) -> bool {
        self.object_id.is_some() || self.seal_ref.is_some()
            || self.registry_ref.is_some() || self.commitment.is_some()
            || self.owner.is_some()
    }
}

// csv-adapters/csv-sui/src/runtime_adapter.rs — reference fill
Ok(MintResult {
    tx_hash,
    block_height,
    materialization: DestinationMaterialization {
        chain_id: self.chain_id.clone(),
        object_id: None,
        seal_ref: None,
        registry_ref: Some(format!("0x{}", hex::encode(registry_id))),
        commitment: Some(attestation.commitment),
        owner: Some(attestation.destination_owner),
    },
})
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-sui | Registry object id from config; `object_id` needs the created-object id from transaction effects | Currently `object_id: None` — effects parsing not wired |
| csv-aptos | Resource address under `@csv_seal`; event stream for commitment | Resource address ≠ module address |
| csv-ethereum | `unavailable(...)` today; would need the `SanadMinted` event log | Do not use the mint tx hash as an object id |
| csv-bitcoin | Not a mint destination; `unavailable(...)` | — |
| csv-solana | `unavailable(...)` today; would need the minted PDA | Tombstone PDAs are not the Sanad record |
| csv-celestia | n/a — no runtime adapter, no `MintResult` | Not a mint destination; nothing to fill |

## Tests added

- Positive: Sui mint returns populated `registry_ref` / `commitment` / `owner`.
- Negative/adversarial: none required — absence is representable, not an error.
- Regression/constitution: CLI prints "not reported by adapter" when
  `has_display_metadata()` is false, so no record is fabricated.

## Gotchas

**The Sui reference fill is weaker than the ticket's wording.** The ticket asked
adapters to fill fields "only from chain-observed transaction effects, events,
object reads, or registry reads." Sui's `commitment` and `owner` are echoed back
from the runtime-supplied `MintAttestationInputs`, and `registry_ref` comes from
adapter config — none of the three is read back from the chain. They are true
only because `submit_attested_mint` returned `Ok`, i.e. the transaction that
carried those exact values succeeded. That is defensible, but it is *inputs
confirmed by success*, not *chain-observed state*. The genuinely chain-observed
field, `object_id`, is still `None`.

Do not copy this shortcut into a new adapter without deciding whether the caller
can distinguish the two. If you populate `object_id`, read it from transaction
effects — never from the tx digest.

Absence is a value. `unavailable(...)` is a deliberate statement that the adapter
observed nothing; do not derive `Default` for `DestinationMaterialization` and do
not let a `None` field silently become an empty string downstream.
