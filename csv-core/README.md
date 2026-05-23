# csv-core

Core protocol types, traits, and implementations for the CSV (Client-Side Validation) protocol.

## Features

- **std** — Standard library support (enabled by default)
- **secp256k1** — Secp256k1 cryptographic support
- **pq** — Post-quantum cryptography (Dilithium)
- **bitcoin** — Bitcoin-specific types
- **ethereum** — Ethereum-specific types
- **solana** — Solana-specific types
- **sui** — Sui-specific types
- **aptos** — Aptos-specific types
- **quorum** — RPC quorum engine
- **observability** — Metrics and logging integration
- **zk** — Zero-knowledge proof support
- **experimental** — Experimental features

## Architecture

`csv-core` defines the protocol's type system and traits without depending on any chain adapter. Chain-specific implementations live in separate adapter crates.

## License

MIT OR Apache-2.0
