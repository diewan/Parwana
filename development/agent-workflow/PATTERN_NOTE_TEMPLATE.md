# Pattern: <short name>

**Resolved in:** `<ticket ID>`  
**Reference file:** `<path>`  
**Applies to:** `<other ticket IDs>`

## What the gap was

One or two sentences explaining what the placeholder did.

## Correct implementation shape

Describe the reusable shape, not just the exact code:

- Which trait or protocol contract this satisfies.
- Which chain-agnostic data is required.
- Which chain-specific RPC/SDK calls are needed.
- Which failures must return `Err(...)` rather than defaulting or warning.
- Which test cases prove the behavior.

## Minimal reference excerpt

```rust
// Paste only the key 20-50 lines. Do not paste the whole file.
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-sui | | |
| csv-aptos | | |
| csv-ethereum | | |
| csv-bitcoin | | |
| csv-solana | | |
| csv-celestia | | |

## Tests added

- Positive:
- Negative/adversarial:
- Regression/constitution:

## Gotchas

List anything that a later agent is likely to get wrong.
