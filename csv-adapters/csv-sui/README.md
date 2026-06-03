# csv-sui

Sui adapter for the CSV Protocol — implements `SealProtocol` and `ChainBackend` traits for Sui seal protocols.

## Overview

`csv-sui` provides the Sui-specific implementation of the CSV Protocol chain adapter interface, enabling seal operations, proof generation, and minting on the Sui blockchain.

## Features

- **rpc** — Sui gRPC support via sui-rust-sdk

## Architecture Role

`csv-sui` is the Sui chain adapter that:

- Implements the `ChainBackend` trait for Sui
- Provides Sui-specific seal operations
- Generates Merkle proofs for Sui state
- Handles Sui transaction submission and finality

## Sui-Specific Features

- **Object-based seals**: Uses Sui object model
- **Move-based operations**: Interacts with Sui Move programs
- **Dynamic fields**: Supports dynamic field operations
- **Event-based proofs**: Uses Sui events for proof generation

## Dependencies

- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof types
- `csv-hash`: Hash types
- `thiserror`: Error handling
- `sui-rust-sdk`: Official Sui Rust SDK with gRPC client (rpc feature)

## License

MIT OR Apache-2.0
