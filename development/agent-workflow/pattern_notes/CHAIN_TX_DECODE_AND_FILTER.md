# Pattern: decoding and filtering chain transactions for CSV activity

**Resolved in:** `SOL-SYNC-DECODE-001`
**Reference file:** `csv-adapters/csv-solana/src/sync_coordinator.rs`
**Applies to:** any adapter background sync / indexer / trace feature

## What the gap was

`SyncCoordinator::process_slot` fetched blocks and logged a transaction count.
The CSV program id was accepted as `_csv_program_id` and never used, with a
`// TODO: Implement proper transaction filtering` where the decoding belonged.
Background monitoring could not discover protocol transactions at all.

## Correct implementation shape

- **Classify by discriminator, into a typed enum.** Reuse the discriminators the
  adapter already derives for *building* instructions (`anchor_client::discriminators`)
  rather than hardcoding bytes a second time.
- **Represent the unknown.** An instruction addressed to the CSV program whose
  discriminator matches nothing is `Unrecognized`, not dropped: on our own program
  that means a program upgrade or a newer IDL, which is worth surfacing.
- **Treat chain data as untrusted.** Bounds-check `program_id_index` against the
  resolved key list; ignore instruction data shorter than a discriminator; skip
  keys that fail to parse. One malformed transaction must not abort the slot.
- **Resolve the full account-key list.** Static keys come from the message, but
  address-lookup-table keys live in the transaction *meta*. Order matters:
  static, then loaded writable, then loaded readonly. A versioned transaction that
  invokes the program via a lookup table is invisible if you only read static keys.
- **Carry the success bit.** A failed transaction had no on-chain effect;
  consumers must not read it as a state transition. Surface `succeeded`, don't
  silently drop it.
- **Surface a typed observation, bounded.** If no downstream consumer exists yet,
  add a bounded buffer with a drain accessor — not a `tracing::debug!`.

## Minimal reference excerpt

```rust
fn from_instruction_data(data: &[u8]) -> Option<Self> {
    // Short data is ignored, never indexed into or padded.
    let discriminator: [u8; 8] = data.get(..8)?.try_into().ok()?;
    let table = [
        (discriminators::create_seal(), Self::CreateSeal),
        (discriminators::mint_sanad(),  Self::MintSanad),
        // ...
    ];
    Some(table.iter().find(|(e, _)| *e == discriminator)
        .map(|(_, k)| *k).unwrap_or(Self::Unrecognized))
}

// Bounds-check the program-id index against the *resolved* key list.
let program_id = account_keys.get(instruction.program_id_index as usize)?;
if program_id != csv_program_id { return None; }
```

## Chain-specific notes

| Adapter | Program/contract identity | Where "loaded" keys hide |
|---|---|---|
| csv-solana | program id in account keys; 8-byte Anchor discriminator | `meta.loaded_addresses` (ALT) — see gotchas |
| csv-ethereum | `log.address == contract`; `topics[0]` = event sig | logs are per-receipt, not per-tx |
| csv-sui | `MoveCall { package, module, function }` in tx effects | — |
| csv-aptos | entry function `@csv_seal::module::fn` | — |
| csv-bitcoin | outpoint / OP_RETURN commitment, no program id | witness vs scriptSig |

## Tests added

- Positive: `csv_transaction_is_surfaced_with_its_instruction_kind`.
- Fixture block with both relevant and irrelevant transactions:
  `mixed_block_surfaces_only_csv_instructions` (asserts instruction *indexes*, so
  a filter that returns the right count for the wrong instructions still fails).
- Negative/adversarial: `non_csv_transaction_is_ignored`,
  `short_instruction_data_is_ignored_without_panic` (loops `0..8` bytes),
  `unknown_discriminator_on_csv_program_is_reported`,
  `failed_transaction_is_marked_unsuccessful`.
- Regression/constitution: `default_program_id_is_csv_seal_not_system_program`.

Build fixtures by bincode-serializing a real `VersionedTransaction` into
base64 — `EncodedTransaction::decode()` runs `sanitize()`, so hand-rolled bytes
are rejected.

## Gotchas

**`Pubkey::default()` is the System Program.** The old `SyncCoordinatorConfig::default()`
used it as a "placeholder" `csv_program_id`. It is the all-zero key, which is
`11111111111111111111111111111111` — so a default-configured coordinator would
match every SOL transfer in every slot as a CSV instruction. Default to the real
deployed program id, and pin it with a test. There is no safe zero value for a
program id.

**Do not name `VersionedTransaction` in a signature.** In `solana-sdk` 3.x it is a
deprecated re-export behind the `full` feature. Take `&[Pubkey]` (the static keys)
and the meta instead, and let the concrete type stay inferred at the call site.

Bound the observation buffer. The background loop has no consumer of its own; an
unbounded `Vec` grows for the life of the process.
