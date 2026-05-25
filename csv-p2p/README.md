# csv-p2p

P2P proof transport layer for the CSV protocol using Nostr.

## Overview

`csv-p2p` provides peer-to-peer proof transport using the Nostr protocol, enabling decentralized proof dissemination without relying on centralized infrastructure.

## Features

- **nostr** — Nostr protocol support (enabled by default)
- **ipfs** — IPFS integration (future)

## Architecture Role

`csv-p2p` provides:

- Decentralized proof transport
- Nostr relay integration
- Proof discovery and retrieval
- P2P network abstraction

## Usage

Proofs can be published to Nostr relays and discovered by other participants in the network, enabling:

- Decentralized proof sharing
- Redundancy and availability
- Censorship resistance

## Dependencies

- `nostr-sdk`: Nostr protocol implementation
- `tokio`: Async runtime

## License

MIT OR Apache-2.0
