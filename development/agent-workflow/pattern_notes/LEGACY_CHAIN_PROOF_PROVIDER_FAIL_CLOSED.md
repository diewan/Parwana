# Pattern: legacy ChainProofProvider fail-closed

**Resolved in:** `PROOF-INCLUSION-ETH-001`, `PROOF-INCLUSION-APT-001`  
**Reference file:** `csv-adapters/csv-ethereum/src/ops.rs`  
**Applies to:** legacy standalone `ChainProofProvider` inclusion paths

## What the gap was

The legacy standalone proof provider built local event payloads and labeled them inclusion proofs. Its paired verifier then checked self-supplied proof bytes rather than independently verifying transaction, receipt, accumulator, or state inclusion against chain-fetched roots.

## Correct implementation shape

- `ChainProofProvider::build_inclusion_proof` must either construct real chain-native inclusion evidence or return `Err(...)`.
- `verify_inclusion_native` must not infer success from commitment bytes appearing inside caller-supplied proof data.
- If the maintained runtime path is `ChainProofPort`, retire the legacy provider path with `ChainOpError::CapabilityUnavailable` and a message pointing callers to the runtime path.
- Tests should call both build and verify on a mock-backed adapter and assert the legacy path fails closed.

## Minimal reference excerpt

```rust
Err(ChainOpError::CapabilityUnavailable(
    "Legacy Ethereum ChainProofProvider inclusion proofs are disabled: \
     this path previously fabricated event payloads instead of MPT receipt \
     inclusion evidence. Use the runtime ChainProofPort path, which builds \
     proof bundles from finalized transaction receipts."
        .to_string(),
))
```

## Chain-specific notes

| Adapter | Required lookup | Edge cases |
|---|---|---|
| csv-aptos | Transaction/accumulator proof against ledger state if re-enabled | Do not use ledger version bytes as a block hash |
| csv-ethereum | Receipt MPT proof against block receipts root if re-enabled | Do not compare state root bytes to proof payload bytes |

## Tests added

- Positive: none; legacy path is retired.
- Negative/adversarial: mock-backed build rejects instead of fabricating proof bytes.
- Regression/constitution: mock-backed verify rejects forged proof bytes containing the commitment.

## Gotchas

Do not delete or weaken the runtime adapter inclusion paths when retiring this legacy provider. They are separate surfaces.
