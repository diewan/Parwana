# RFC-0002: Proof Taxonomy

## Status

Proposed

## Motivation

The repository currently mixes multiple proof types without a rigid taxonomy:

- Inclusion proofs
- State proofs
- Replay proofs
- Chain finality proofs
- Ownership proofs
- Commitment proofs
- Cross-chain proofs
- ZK proofs

This fragmentation creates future incompatibility and makes verification ambiguous.

## Proposed Change

### 1. Create Formal Proof Taxonomy

```rust
pub enum Proof {
    Inclusion(InclusionProof),
    Finality(FinalityProof),
    Ownership(OwnershipProof),
    Transition(TransitionProof),
    Replay(ReplayProof),
    Execution(ExecutionProof),
    ZK(ZKProof),
    Composite(CompositeProofBundle),
}
```

### 2. Define Proof Semantics

Each proof type MUST have:

- Canonical encoding
- Domain-separated hashing
- Explicit verification context
- Chain capability requirements
- Finality assumptions

### 3. Consolidate Proof Modules

Remove proof duplication:

- `proof_bundle`
- `proof_material`
- `proof_pipeline`
- `proof_context`

Consolidate into `csv-proof` crate.

### 4. Create Proof DAG System

Proofs must become composable DAGs:

```rust
pub struct ProofNode {
    id: ProofId,
    dependencies: Vec<ProofId>,
    proof: Proof,
}
```

## Rationale

A formal proof taxonomy prevents:

- Semantic drift across implementations
- Incompatible verification paths
- Ambiguous proof composition
- Cross-chain proof confusion

## Impact

BREAKING CHANGE: All proof types must be updated to use new taxonomy.

- Update all proof construction
- Update all verification logic
- Update proof serialization
- Migration path for existing proofs

## Alternatives

- Keep current fragmented proofs (REJECTED - too risky)
- Use ad hoc proof composition (REJECTED - not canonical)

## Unresolved Questions

- How to handle cross-chain proof composition?
- Proof size limits?
- Proof caching strategy?
