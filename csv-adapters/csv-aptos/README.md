# csv-aptos

Aptos adapter for the Parwana — implements `SealProtocol` and `ChainBackend` traits for Aptos seal protocols.

## Overview

`csv-aptos` provides the Aptos-specific implementation of the Parwana chain adapter interface, enabling seal operations, proof generation, and minting on the Aptos blockchain.

## Features

- **rpc** — Aptos JSON-RPC support
- **aptos-sdk** — Full Aptos SDK integration
- **dev-mocks** — Development mock support

## Architecture Role

`csv-aptos` is the Aptos chain adapter that:

- Implements the `ChainBackend` trait for Aptos
- Provides Aptos-specific seal operations
- Generates Merkle proofs for Aptos state
- Handles Aptos transaction submission and finality

## Aptos-Specific Features

- **Resource-based seals**: Uses Aptos resource model
- **Move-based operations**: Interacts with Aptos Move modules
- **Account resources**: Uses Aptos account resources
- **Event-based proofs**: Uses Aptos events for proof generation

## Dependencies

- `aptos-sdk`: Aptos SDK
- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof types
- `csv-hash`: Hash types
- `thiserror`: Error handling

## License

MIT OR Apache-2.0
