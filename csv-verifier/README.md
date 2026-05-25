# csv-verifier

Canonical proof verification for CSV Protocol.

## Overview

`csv-verifier` provides the canonical proof verification logic for the CSV protocol. It ensures consistent verification semantics across all protocol implementations.

## Key Features

- **Canonical verification**: Standardized proof verification logic
- **Verification context**: Context-aware verification
- **Anchor verification**: Commitment anchor validation
- **Signature verification**: Multi-scheme signature validation
- **Inclusion proof verification**: Merkle proof validation
- **Finality proof verification**: Finality evidence validation

## Architecture Role

`csv-verifier` is the verification layer that:
- Provides the single source of truth for proof verification
- Ensures all implementations verify proofs identically
- Delegates cryptographic operations to appropriate libraries
- Enforces protocol verification rules

## Dependencies

- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof bundle types
- `csv-hash`: Hash types and operations
- `thiserror`: Error handling

## Verification Process

The verifier checks:
1. **Signature scheme**: Proof bundle signature matches source chain
2. **Anchor validity**: Commitment anchor is valid
3. **Inclusion proof**: Merkle proof is valid
4. **Finality proof**: Finality evidence is sufficient
5. **Replay protection**: Transfer has not been replayed
6. **Protocol invariants**: All protocol rules are satisfied

## Usage Example

```rust
use csv_verifier::{CanonicalVerifier, VerificationContext};

let verifier = CanonicalVerifier::new();
let context = VerificationContext {
    chain_id: /* ... */,
    required_finality: /* ... */,
};

let result = verifier.verify(&proof_bundle, &context)?;
```

## Design Principles

- **Canonical**: Single verification logic for all implementations
- **Context-aware**: Verification depends on chain and finality requirements
- **Delegated**: Cryptographic operations delegated to specialized libraries
- **Protocol-enforcing**: Rejects proofs that violate protocol invariants

## License

MIT OR Apache-2.0
