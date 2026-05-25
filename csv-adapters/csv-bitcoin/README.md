# csv-bitcoin

Bitcoin adapter for the CSV Protocol — implements `SealProtocol` and `ChainBackend` traits for Bitcoin UTXO seals and SPV proofs.

## Overview

`csv-bitcoin` provides the Bitcoin-specific implementation of the CSV Protocol chain adapter interface, enabling seal operations, proof generation, and minting on the Bitcoin blockchain.

## Features

- **rpc** — Bitcoin RPC backend
- **signet-rest** — Signet REST API support
- **production** — Production configuration (enables rpc)

## Architecture Role

`csv-bitcoin` is the Bitcoin chain adapter that:

- Implements the `ChainBackend` trait for Bitcoin
- Provides Bitcoin-specific seal operations
- Generates SPV proofs for Bitcoin UTXOs
- Handles Bitcoin transaction submission and finality

## Bitcoin-Specific Features

- **UTXO-based seals**: Uses Bitcoin UTXO model
- **SPV proofs**: Simplified Payment Verification
- **Tapret support**: Taproot commitment support (optional)
- **Signet support**: Signet testnet support

## Dependencies

- `bitcoin`: Bitcoin types and cryptography
- `secp256k1`: Secp256k1 cryptography
- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof types
- `csv-hash`: Hash types
- `thiserror`: Error handling

## License

MIT OR Apache-2.0
