# csv-sdk

Unified SDK for the CSV (Client-Side Validation) protocol — single entry point for all CSV operations.

## Features

- **std** — Standard library support
- **tokio** — Tokio async runtime
- **native** — Native-only features (filesystem, full chain support)
- **bitcoin**, **ethereum**, **sui**, **aptos**, **solana** — Chain-specific support
- **all-chains** — Enable all chain features
- **wallet** — Wallet integration
- **p2p** — P2P proof delivery
- **rpc** — RPC query support
- **wasm** — WebAssembly support

## Quick Start

```rust
use csv_sdk::prelude::*;
```

## License

MIT OR Apache-2.0
