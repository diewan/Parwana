# csv-celestia

Celestia adapter for the Parwana — implements `SealProtocol` and `ChainBackend` traits for Celestia data availability seals.

## Overview

`csv-celestia` provides the Celestia-specific implementation of the Parwana chain adapter interface, enabling data availability operations and proof generation on the Celestia network.

## Roadmap Decision

ROADMAP-CELESTIA-001 resolves Celestia as DA-only, intentionally outside the transfer-adapter registry. `csv-runtime` may expose Celestia capabilities for data availability, but Celestia does not authorize source locks or destination mints. Inclusion/finality verification must use DA-layer/RPC evidence and fail closed when the required proof data is unavailable.

## Features

- **rpc** — Celestia JSON-RPC support
- **quorum** — Multi-node quorum verification

## Architecture Role

`csv-celestia` is the Celestia chain adapter that:

- Implements the `ChainBackend` trait for Celestia
- Provides Celestia-specific data availability operations
- Generates namespace Merkle proofs
- Handles blob submission and retrieval

## Celestia-Specific Features

- **Namespace-based seals**: Uses Celestia namespaces
- **Data availability**: Focus on data availability rather than computation
- **Namespace proofs**: Merkle proofs for namespace data
- **Blob storage**: Stores data as blobs on Celestia

## Dependencies

- `celestia-rpc`: Celestia RPC client
- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof types
- `csv-hash`: Hash types
- `thiserror`: Error handling

## License

MIT OR Apache-2.0
