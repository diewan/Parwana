# RFC-0007: Hash Registry

## Status

Proposed

## Motivation

Current hash domain separation is not strong enough:

- No global registry
- No reserved namespaces
- No collision governance
- No mandatory tag uniqueness
- No tag versioning
- No chain-specific namespaces

This becomes dangerous once third parties extend the protocol.

## Proposed Change

### 1. Create Global Hash Registry

All hash domains MUST be registered in `csv-hash/src/hash_registry.rs`:

```rust
pub enum HashDomain {
    // Seal domains
    BitcoinSealV1,
    EthereumSealV1,
    // ... all domains
}
```

NO freeform tags allowed.

### 2. Reserve Namespaces

Define reserved namespaces:

- `csv.*` - Protocol namespace (reserved)
- `chain.*` - Chain-specific namespace
- `custom.*` - Third-party namespace (requires governance)

### 3. Add Collision Governance

Create hash governance process:

- Domain registration process
- Collision resolution policy
- Deprecation process
- Versioning rules

### 4. Add Tag Versioning

All domains MUST have version:

```rust
BitcoinSealV1,
BitcoinSealV2, // Breaking change
```

### 5. Add Chain-Specific Namespaces

Chain adapters MUST use chain-specific domains:

```rust
BitcoinSealV1,
EthereumSealV1,
// NOT generic SealV1
```

## Rationale

Global hash registry prevents:

- Hash collisions across implementations
- Semantic drift
- Unregistered domain usage
- Cross-chain confusion

## Impact

BREAKING CHANGE: All hash usage must use registered domains.

- Update all hash calls
- Update domain markers
- Add governance process
- Version bump required

## Alternatives

- Allow freeform tags (REJECTED - too risky)
- Per-adapter hash domains (REJECTED - causes drift)

## Unresolved Questions

- Governance process for new domains?
- Collision resolution mechanism?
- Deprecation timeline?
