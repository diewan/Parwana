# RFC-0003: Finality Model

## Status

Proposed

## Motivation

The repository currently treats finality too uniformly across chains:

- Bitcoin: confirmations
- Aptos: validator certification
- Solana: commitment levels
- Ethereum: probabilistic finality
- Sui: checkpoint finality

This is protocol-risky. Proofs from different chains are incomparable without explicit finality classes.

## Proposed Change

### 1. Create Explicit Finality Classes

```rust
pub enum FinalityType {
    Probabilistic(ProbabilisticFinality),
    Economic(EconomicFinality),
    Checkpoint(CheckpointFinality),
    ValidatorQuorum(ValidatorQuorumFinality),
    Instant(InstantFinality),
}
```

### 2. Define Finality Semantics Per Chain

Each chain MUST expose:

- Finality type
- Confirmation requirements
- Rollback probability
- Reorg handling rules
- Finality downgrade behavior

### 3. Create Finality Abstraction

```rust
pub trait ChainFinality {
    fn finality_type(&self) -> FinalityType;
    fn confirmations_required(&self) -> u64;
    fn rollback_probability(&self, confirmations: u64) -> f64;
    fn is_final(&self, height: u64) -> bool;
}
```

### 4. Add Finality to Verification Context

All verification MUST include finality assumptions:

```rust
pub struct VerificationContext {
    finality_policy: FinalityPolicy,
    // ...
}
```

## Rationale

Explicit finality classes prevent:

- Cross-chain proof comparison errors
- Incorrect rollback assumptions
- Verification ambiguity
- Security model confusion

## Impact

BREAKING CHANGE: All chain adapters must implement finality traits.

- Update all chain adapters
- Update verification logic
- Update proof construction
- Add finality tests

## Alternatives

- Keep uniform finality treatment (REJECTED - incorrect)
- Use ad hoc finality checks (REJECTED - not canonical)

## Unresolved Questions

- How to handle cross-chain finality coordination?
- Finality downgrade thresholds?
- Reorg detection strategy?
