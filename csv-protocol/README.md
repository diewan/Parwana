# csv-protocol

Protocol orchestration layer for CSV Protocol - state machines, protocol constants, types, invariants, replay semantics, transition legality, and versioning.

## Overview

`csv-protocol` contains the core protocol logic without dependencies on serialization, hashing, or proof systems. It defines the state machines, invariants, and transition rules that all other protocol components must follow.

## Key Features

- **Protocol state machines**: Transfer lifecycle and state transitions
- **Type definitions**: Core protocol types (Sanad, Seal, Proof, etc.)
- **Invariants**: Protocol invariants and validation rules
- **Replay semantics**: Nullifier tracking and replay protection
- **Transition legality**: Valid state transition rules
- **Versioning**: Protocol version management
- **Backend traits**: Chain adapter interface definitions
- **Cross-chain registry**: Transfer tracking and double-spend prevention
- **Finality requirements**: Capability requirements per chain
- **Lease management**: Coordinator lease types and validation

## Architecture Role

`csv-protocol` is the central orchestration layer that:
- Defines the protocol contract that all implementations must follow
- Provides types and traits used across all other crates
- Enforces protocol invariants at the type level
- Serves as the source of truth for protocol semantics

## Modules

- **backend**: Chain adapter trait definitions (ChainBackend, ChainQuery, ChainSigner, etc.)
- **canonical_proof**: Canonical proof types and validation
- **chain_config**: Chain-specific configuration
- **commitment**: Commitment chain and anchor types
- **cross_chain**: Cross-chain transfer registry and HashEntry types
- **deterministic_recovery**: Recovery checkpoint types
- **envelope**: Event envelope and transport types
- **error**: Protocol error types
- **events**: Protocol event types
- **failure_domains**: Failure domain classification
- **lease**: Coordinator lease types and validation
- **proof**: Proof bundle types
- **proof_verification**: Proof verification requirements
- **sanad**: Sanad (Hash) types and operations
- **seal**: Seal types and operations
- **signature**: Signature types and verification
- **finality**: Finality requirements and capability negotiation

## Dependencies

- `csv-hash`: Hash types and operations
- `csv-proof`: Proof bundle types
- `thiserror`: Error handling
- `serde`: Serialization (for types only, not protocol logic)

## Design Principles

- **No serialization logic**: All serde lives in csv-wire
- **No hashing logic**: All hashing lives in csv-hash
- **No proof verification**: Verification lives in csv-verifier
- **Protocol purity**: Defines what is correct, not how to implement it

## Usage Example

```rust
use csv_protocol::backend::{ChainBackend, ChainQuery};
use csv_protocol::cross_chain::HashEntry;
use csv_protocol::finality::CapabilityRequirements;

// Define chain requirements
let requirements = CapabilityRequirements {
    requires_deterministic_finality: true,
    min_reorg_depth: 0,
    min_honesty_threshold: 0.67,
};

// Record cross-chain transfer
let entry = HashEntry {
    sanad_id: /* ... */,
    source_chain: /* ... */,
    // ...
};
```

## Protocol Invariants

1. **Finality is never optional**: All chains must provide finality guarantees
2. **Replay protection**: All transfers must be tracked to prevent double-spending
3. **Signature scheme validation**: Proof bundles must match source chain's signature scheme
4. **Lease authority**: Only one coordinator may hold a lease at a time
5. **Deterministic recovery**: All checkpoints must be reproducible

## License

MIT OR Apache-2.0
