# csv-ethereum

Ethereum adapter for the Parwana — implements `SealProtocol` and `ChainBackend` traits for Ethereum seal protocols.

## Overview

`csv-ethereum` provides the Ethereum-specific implementation of the Parwana chain adapter interface, enabling seal operations, proof generation, and minting on the Ethereum blockchain.

## Features

- **rpc** — Ethereum JSON-RPC support
- **real-groth16** — Real Groth16 proof verification
- **quorum** — Multi-node quorum verification
- **production** — Production configuration

## Architecture Role

`csv-ethereum` is the Ethereum chain adapter that:

- Implements the `ChainBackend` trait for Ethereum
- Provides Ethereum-specific seal operations
- Generates Merkle proofs for Ethereum state
- Handles Ethereum transaction submission and finality

## Ethereum-Specific Features

- **Account-based seals**: Uses Ethereum account model
- **ZK proof support**: Groth16 proof verification
- **Quorum verification**: Multi-node RPC quorum
- **ERC-20 support**: Token-based seals

## Dependencies

- `ethers`: Ethereum SDK
- `alloy`: Alternative Ethereum types
- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof types
- `csv-hash`: Hash types
- `thiserror`: Error handling

## License

MIT OR Apache-2.0
