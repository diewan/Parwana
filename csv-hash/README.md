# csv-hash

Hash types, SanadId, replay ID types, and cryptographic operations for Parwana.

## Overview

`csv-hash` provides the cryptographic foundation for the Parwana, including hash types, domain-specific hashing, seal identifiers, and replay protection identifiers.

## Key Features

- **Hash types**: Domain-specific hash types (SanadId, SealId, etc.)
- **Chain identifiers**: Chain ID types and operations
- **Seal types**: Seal point and seal reference types
- **Replay IDs**: Nullifier and replay identifier derivation
- **Domain hashing**: Context-aware hashing for different domains
- **Cryptographic primitives**: SHA-256, SHA-3, Keccak-256

## Modules

- **hash**: Core hash type and operations
- **chain_id**: Chain identifier types
- **seal**: Seal point and seal reference types
- **sanad_id**: Sanad (Hash) identifier types
- **domain_hash**: Domain-specific hashing
- **canonical**: Canonical hashing utilities

## Architecture Role

`csv-hash` is the cryptographic foundation that:

- Provides all hash types used across the protocol
- Ensures consistent hashing across all implementations
- Derives replay IDs for nullifier tracking
- Supports domain-specific hashing for different contexts

## Dependencies

- `sha2`: SHA-256 hashing
- `sha3`: SHA-3 hashing
- `thiserror`: Error handling
- `serde`: Serialization (for hash types only)

## Usage Example

```rust
use csv_hash::{Hash, chain_id::ChainId, seal::SealPoint};

// Create a hash from bytes
let hash = Hash::try_from(&[0u8; 32])?;

// Create a chain ID
let chain_id = ChainId::new("bitcoin");

// Create a seal point
let seal = SealPoint::new(vec![1, 2, 3], None)?;
```

## Hash Types

- **Hash**: 32-byte cryptographic hash
- **SanadId**: Unique identifier for a Sanad (Hash)
- **SealId**: Unique identifier for a seal
- **ReplayId**: Identifier for replay protection
- **ChainId**: Chain identifier (string-based)

## Design Principles

- **Deterministic**: Same input always produces same hash
- **Collision-resistant**: Uses industry-standard cryptographic primitives
- **Domain separation**: Different domains use different hash contexts
- **Type safety**: Strongly typed hash identifiers

## License

MIT OR Apache-2.0
