# Pattern: on-chain seal registry verification, local state is only a cache

**Resolved in:** `A-ETH-REGISTRY-001` (no context pack; predates the current ticket flow)
**Reference file:** `csv-adapters/csv-ethereum/src/verifier.rs`, `csv-adapters/csv-ethereum/src/seal_protocol.rs`
**Applies to:** every adapter implementing `SealProtocol::enforce_seal`

> **Rollout status (verified 2026-07-10).** Ethereum is the *only* adapter with
> this pattern. `verify_seal_registry` exists solely in `csv-ethereum`. Bitcoin,
> Solana, Sui, Aptos, and Celestia enforce seals against local registry state
> alone. Treat this note as one worked example plus an open rollout, not as a
> description of the repository.

## What the gap was

`enforce_seal` decided whether a seal had been consumed by consulting only the
adapter's in-process `seal_registry`. Local state is a cache: it can be corrupted,
it can be cold after a restart, and two processes on different machines each hold
their own. Nothing in that path consults the chain, which is the only authority on
whether a single-use seal has already been spent — so the single-use guarantee
held only for a single long-lived process.

## Correct implementation shape

- The chain is authoritative; the local registry is a **fast negative cache**.
  Check local first to short-circuit an obvious replay, then always confirm
  against the chain before allowing the seal through.
- On-chain verification lives in the adapter's verifier module behind the `rpc`
  feature, and issues a real contract call (`isSealUsed` or equivalent) — never
  an inferred or assumed result.
- Mark the seal used in local state **after** the on-chain check returns, not
  before. The reverse order lets a failed on-chain read leave a seal poisoned.
- Compile without `rpc` and the function must return `Err`, naming the missing
  feature. A build that cannot reach the chain must not fall back to local state:
  the fallback is precisely the vulnerability.
- Verification failures are typed (`VerificationFailure::ReplayDetected`), not
  stringly-typed.

See `FEATURE_GATED_CRYPTO_FAIL_CLOSED.md` for the general three-part
feature-gate shape (forwarding feature, real arm, error-naming-the-feature arm)
that this is an instance of.

## Minimal reference excerpt

```rust
// csv-adapters/csv-ethereum/src/seal_protocol.rs
async fn enforce_seal(&self, seal: Self::SealPoint) -> Result<(), Box<dyn Error>> {
    // Fast path: an obvious replay never needs an RPC round-trip.
    if self.seal_registry.lock()?.is_seal_used(&seal) {
        return Err(Box::new(ProtocolError::SealReplay(..)));
    }

    // Authoritative path.
    #[cfg(feature = "rpc")]
    {
        let result = self.verifier.verify_seal_registry(seal_id).await?;
        if !result.valid {
            return Err(Box::new(ProtocolError::SealReplay(..)));
        }
    }
    #[cfg(not(feature = "rpc"))]
    return Err(Box::new(ProtocolError::NetworkError(
        "On-chain seal registry verification requires the 'rpc' feature".to_string(),
    )));

    // Only now is the cache allowed to learn about it.
    self.seal_registry.lock()?.mark_seal_used(&seal)?;
    Ok(())
}
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-ethereum | `eth_call` → `isSealUsed(bytes32)`; bool is the last byte of a 32-byte word | Done. Do not read `result[31]` without checking the word is 32 bytes |
| csv-sui | Registry object read; consumed seals live in a `Table` | Registry object id ≠ package id |
| csv-aptos | Resource/table read under `@csv_seal` | Resource address ≠ module address |
| csv-solana | Nullifier / minted PDA read | A closed PDA is not an absent PDA — check the never-closed tombstone PDAs |
| csv-bitcoin | Outpoint is spent-or-not; ask the UTXO set | Needs a REST indexer; JSON-RPC alone cannot scan |
| csv-celestia | — | Not a seal-enforcement surface |

## Tests added

All in `csv-adapters/csv-ethereum/src/seal_protocol.rs`:

- Positive: `test_enforce_seal_replay` — a seal already in the local registry is
  rejected on the fast path.
- Negative/adversarial: `test_enforce_seal_on_chain_consumed` — mock RPC reports
  the seal consumed → `enforce_seal` returns `SealReplay` even though the local
  registry believes the seal is fresh. This is the test that proves local state
  is not trusted.
- Regression/constitution: `test_enforce_seal_fails_closed_without_rpc` — built
  `#[cfg(not(feature = "rpc"))]`, `enforce_seal` errors rather than falling back
  to local state.

Missing: there is no test for the fully-successful on-chain path (chain reports
unused → seal enforced → local cache updated). `test_create_seal` does not cover
it. Worth adding when this pattern is ported to the next adapter.

## Gotchas

**A cache consulted first is not a cache trusted.** The fast-path local check is
only sound because it can *reject*, never *accept*. If you ever let a local
"unused" verdict skip the chain read, you have rebuilt the original bug. Any
refactor that makes the on-chain call conditional deserves the same scrutiny as
removing it.

**Commitments must bind to on-chain transaction data.** The original ticket also
removed a placeholder that used `sanad_id` as its own commitment. Bind to
something the chain actually observed — the lock transaction hash, a receipt
log — never to an identifier the caller supplied. (The `ProofLeafV1` code that
this note used to illustrate here was deleted by the thin-registry rewrite,
`TRM-ETH-*`; the principle outlived the code.)

**Anti-patterns that mean this pattern was undone:** a `// TODO: implement
verify_seal_registry` with a `let _ = seal_id;`, a `#[cfg(not(feature = "rpc"))]`
arm that comments "rely on local registry only", or a `VerificationResult` built
with `valid: true` and no preceding chain read.

## References

- Agent rules: `csv-adapters/.agents/AGENT.md`
- Protocol invariants: `csv-docs/PROTOCOL_INVARIANTS.md`
- Threat model: `csv-docs/THREAT_MODEL.md`
