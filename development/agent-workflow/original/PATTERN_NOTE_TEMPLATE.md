<!--
PATTERN NOTE TEMPLATE
=====================
Copy this to development/agent-workflow/pattern_notes/<reference-ID>.md
after closing a ticket that is the FIRST instance of a pattern repeated
across multiple chain adapters (most of Theme A).

Keep it to one page. The whole point is that the next five tickets for the
same gap (one per remaining adapter) can be solved by an agent that has
ONLY: its own stub file, this note, and its own crate's trait impls — not
the reference adapter's full source and not a re-derivation of protocol
semantics.
-->

# Pattern: <short name, e.g. "Inclusion proof construction from RPC block data">

**Resolved in:** `<reference ticket ID>` (`<reference_crate>/<reference_file>`)
**Applies to:** list the other adapters/tickets this pattern covers
(e.g. `A-SUI-001`, `A-APTOS-002`, `A-ETH-002`, ...)

## What the gap was

One or two sentences. What did the placeholder do instead of the real
thing (e.g. "returned `Ok(InclusionProof::empty())` without querying the
chain").

## What the correct implementation does

Describe the shape of the fix in terms that transfer across chains:
- Which trait method(s) this satisfies (`csv-protocol/src/chain_adapter_traits.rs`)
- What chain-agnostic data it needs (block header, inclusion path, finality
  depth, etc.) and where that comes from in the trait/runtime layer
- What chain-*specific* data each adapter needs to supply (this is the part
  that differs per adapter — be explicit so the next agent knows exactly
  what to look up for its chain)
- Error cases that must produce `Err(...)`, not `Ok(default)` — per
  AGENT.md §3, verification paths must reject malformed/missing data

## Reference snippet

A short (≤40 line) excerpt from the reference implementation showing the
key shape — not the whole function, just enough to pattern-match against.

```rust
// paste the essential excerpt here
```

## Chain-specific lookups needed for remaining adapters

| Adapter | What it needs to look up | Where (RPC method / SDK call) |
|---|---|---|
| csv-adapters/csv-sui | ... | ... |
| csv-adapters/csv-aptos | ... | ... |
| ... | | |

## Tests added for the reference implementation

List the test names/files so equivalent tests can be written for each
remaining adapter (positive + malformed-input, per AGENT.md §6).

## Gotchas

Anything chain-specific that tripped up the reference implementation and
will likely trip up the others too.
