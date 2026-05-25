# csv-core

**Legacy crate - migration in progress**

Core protocol types, traits, and implementations for the CSV (Client-Side Validation) protocol.

## Status

This crate is being refactored as part of the Phase 1 restructuring. Many components have been moved to dedicated crates:

- **Signature types** → `csv-protocol`
- **Backend traits** → `csv-protocol`
- **Verification levels** → `csv-protocol`
- **Hash types** → `csv-hash`
- **Proof types** → `csv-proof`

## Features

- **std** — Standard library support (enabled by default)
- **observability** — Metrics and logging integration
- **experimental** — Experimental features

## Architecture

`csv-core` defines the protocol's type system and traits without depending on any chain adapter. Chain-specific implementations live in separate adapter crates.

**Note:** Chain-specific features (bitcoin, ethereum, solana, sui, aptos, secp256k1, pq, zk, quorum) have been removed from csv-core and moved to chain adapters.

## Migration Guide

When migrating from csv-core to the new architecture:

- Use `csv-protocol` for protocol types and traits
- Use `csv-hash` for hash types
- Use `csv-proof` for proof types
- Use `csv-verifier` for verification
- Use chain adapters for chain-specific operations

## License

MIT OR Apache-2.0
