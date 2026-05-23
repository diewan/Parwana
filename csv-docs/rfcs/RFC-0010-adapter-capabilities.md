# RFC-0010: Adapter Capabilities

## Status

Proposed

## Motivation

Chains differ fundamentally:

- Bitcoin: UTXO
- Ethereum: Account
- Solana: Account + Program
- Sui: Object
- Aptos: Resource

Yet the codebase attempts to unify them too early. This is dangerous.

We need capability traits instead of semantic flattening.

## Proposed Change

### 1. Create Capability Traits

```rust
trait HasFinalityProof
trait HasEventProof
trait HasStateRoot
trait HasObjectOwnership
trait HasReplayProtection
trait HasDeterministicExecution
```

### 2. Define Chain Capability Model

```rust
pub trait ChainCapabilities {
    fn supports_state_proofs(&self) -> bool;
    fn supports_finality_proofs(&self) -> bool;
    fn supports_event_proofs(&self) -> bool;
    fn supports_objects(&self) -> bool;
    fn supports_replay_protection(&self) -> bool;
    fn supports_deterministic_execution(&self) -> bool;
}
```

### 3. Remove Semantic Flattening

DO NOT assume all chains support similar semantics.

Each adapter MUST:

- Expose only capabilities it actually has
- Fail gracefully for unsupported operations
- Document capability limitations
- Test capability boundaries

### 4. Add Capability Governance

Create `/docs/governance/capability-governance.md` defining:

- How new chains integrate
- Required proof guarantees
- Capability registration
- Compliance testing

## Rationale

Capability model prevents:

- Incorrect assumptions about chain capabilities
- Adapter impurity
- Semantic flattening errors
- Cross-chain incompatibility

## Impact

BREAKING CHANGE: All adapters must implement capability traits.

- Update all chain adapters
- Remove semantic flattening
- Add capability tests
- Update documentation

## Alternatives

- Keep semantic flattening (REJECTED - incorrect)
- Assume all capabilities (REJECTED - unsafe)

## Unresolved Questions

- Capability test suite?
- Capability discovery mechanism?
- Fallback behavior for missing capabilities?
