# Pattern: fail-closed fixed-width decode, never zero-fill

**Resolved in:** `DECODE-ZEROFILL-FAILCLOSED-001`
**Reference file:** `csv-protocol/src/wire.rs` (`HashWire::to_hash`, `SanadIdWire::to_sanad_id`)
**Applies to:** every canonical encoder, nullifier path, and wire→domain decoder

## What the gap was

Twenty-three sites across `csv-protocol/src/replay/registry.rs` and
`csv-protocol/src/sanad.rs` turned a malformed field into 32 zero bytes:

```rust
let sanad_id_bytes = nullifier.sanad_id.as_bytes().unwrap_or_else(|_| vec![0u8; 32]);
let mut arr = [0u8; 32];
if sanad_id_bytes.len() == 32 { arr.copy_from_slice(&sanad_id_bytes); }
```

Two failure modes, and the second is the dangerous one:

1. `as_bytes()` errors → substitute zeros → proceed as if valid.
2. `as_bytes()` **succeeds** with a short value (valid hex, wrong length) → the
   `if len == 32` guard silently doesn't fire → `arr` stays all zeros → proceed.

In `ReplayConstitutionValidator::validate_nullifier` this meant the nullifier was
recomputed *over the zeros*. The "is not zero" guards inspect the **wire** fields
(non-zero), while the recomputation inspects the **decoded** arrays (zero). An
attacker who supplied `nullifier = compute_nullifier(0, chain, 0)` alongside a
short-but-non-zero `sanad_id` passed every check.

## Correct implementation shape

- Put the length check **inside one canonical decoder** on the wire type, and
  make `TryFrom` delegate to it. One implementation, no second opinion:

  ```rust
  impl HashWire {
      pub fn to_hash(&self) -> Result<Hash, String> {
          let bytes = self.as_bytes()?;                     // hex validity
          let arr: [u8; 32] = bytes.as_slice().try_into()   // width validity
              .map_err(|_| format!("Hash must be 32 bytes, got {}", bytes.len()))?;
          Ok(Hash::new(arr))
      }
  }
  impl TryFrom<HashWire> for Hash {
      fn try_from(wire: HashWire) -> Result<Self, String> { wire.to_hash() }
  }
  ```

- Every hashing / indexing / canonical-encoding caller uses `?`. Where the
  enclosing function returned `()`, **change the signature** — `remove()` became
  `Result<(), ReplayError>` and `cleanup_expired()` became
  `Result<usize, ReplayError>`. Do not keep a silent fallback to preserve a
  signature.
- Registry index keys go through the same decoder, so a malformed entry cannot be
  filed under an all-zero key where it would alias or evict a good one.
- For optional fields, `None` stays `None`, but *present-but-malformed* fails:
  `wire.map(|w| hash_field(w, name)).transpose()?`.

## Minimal reference excerpt

```rust
// csv-protocol/src/replay/registry.rs — the security-critical site
let sanad_id = nullifier.sanad_id.to_hash()
    .map_err(|_| ReplayError::InvalidNullifier)?;
let source_seal_ref = nullifier.source_seal_ref.to_hash()
    .map_err(|_| ReplayError::InvalidNullifier)?;

let computed = ReplayNullifier::compute_nullifier(
    sanad_id, nullifier.source_chain, source_seal_ref);
```

## Chain-specific notes

Not chain-specific — this is a protocol-layer decoder rule. But the same shape
belongs anywhere untrusted bytes reach a fixed-width buffer:

| Surface | Rule |
|---|---|
| `csv-wire` / `csv-protocol` wire types | one `to_*` decoder, `TryFrom` delegates |
| Adapter chain reads (object contents, logs) | `CapabilityUnavailable` on malformed, never defaults |
| Instruction/tx decoding | ignore short data; never index past the end |

## Tests added

- Positive: `validate_nullifier_accepts_well_formed`,
  `register_accepts_well_formed_nullifier`.
- Negative/adversarial: **`zero_key_nullifier_forgery_is_rejected`** — the one
  that matters. It builds `nullifier = compute_nullifier(0, chain, 0)` with
  short non-zero `sanad_id` / `source_seal_ref`. Verified to **fail** against the
  pre-fix validator and pass after.
- Regression: `distinct_malformed_sanad_ids_do_not_collapse_to_one_nullifier`,
  `register_rejects_malformed_sanad_id` (asserts `stats().total == 0`).

## Gotchas

**A "rejects malformed input" test can pass against the broken code for the wrong
reason.** Feeding only a short `sanad_id` still gets rejected pre-fix, because the
recomputed nullifier no longer matches the supplied one. The test only
discriminates if the attacker *also* supplies the matching zero-key nullifier.
Always check that a regression test actually fails against the old code — revert
the fix, run it, restore.

**`SanadId::from_bytes` is not a decoder.** It *hashes* any input that is not
exactly 32 bytes, so `TryFrom<SanadIdWire>` never failed on length: a truncated
wire value decoded to a well-formed but entirely different SanadId. Route wire
decoding through `SanadIdWire::to_sanad_id`, and leave `from_bytes` alone — it has
legitimate callers that want that behavior.

Fixed-width MCE encoding compounds this. A hash field that encoded as 16 bytes
would shift every subsequent field, so the zero-fill was hiding a latent
encoding-corruption bug as well as a security one.
