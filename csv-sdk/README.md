# csv-sdk

Unified SDK for the CSV (Client-Side Validation) protocol — single entry point for all CSV operations.

## Overview

`csv-sdk` provides a unified, high-level API for CSV protocol operations, abstracting away the complexity of cross-chain transfers. It delegates to `csv-runtime` for orchestration and chain adapters for chain-specific operations.

## Features

- **std** — Standard library support
- **tokio** — Tokio async runtime
- **native** — Native-only features (filesystem, full chain support)
- **bitcoin**, **ethereum**, **sui**, **aptos**, **solana** — Chain-specific support
- **all-chains** — Enable all chain features
- **wallet** — Wallet integration (via csv-keys)
- **p2p** — P2P proof delivery (via csv-p2p)
- **rpc** — RPC query support
- **wasm** — WebAssembly support
- **sqlite** — SQLite storage backend

## Architecture

```
csv-sdk (public facade)
  └── csv-runtime (orchestration + execution journal)
        └── csv-protocol / csv-core (protocol types & traits)
              ├── csv-adapters/csv-bitcoin
              ├── csv-adapters/csv-ethereum
              ├── csv-adapters/csv-solana
              ├── csv-adapters/csv-sui
              ├── csv-adapters/csv-aptos
              └── csv-adapters/csv-celestia
```

## Quick Start

```rust
use csv_sdk::prelude::*;

// Initialize SDK
let sdk = CsvSdk::builder()
    .with_chain("bitcoin")?
    .with_chain("ethereum")?
    .build()?;

// Execute cross-chain transfer
let result = sdk.transfer_seal(
    source_chain,
    dest_chain,
    seal_id,
).await?;
```

## Dependencies

- `csv-runtime`: Runtime orchestration
- `csv-protocol`: Protocol types
- `csv-keys`: Key management
- `csv-p2p`: P2P transport
- `csv-storage`: Storage backends
- Chain adapters for chain-specific operations

## License

MIT OR Apache-2.0
