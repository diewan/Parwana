# csv-wire

Wire encoding and transport layer for CSV Protocol.

## Overview

`csv-wire` provides the wire format encoding, transport serialization, and RPC type conversions for the CSV Protocol. This crate owns ALL serde serialization, ALL transport encoding, and ALL RPC wire format conversions.

## Key Features

- **Wire format definitions**: Canonical proof, transfer, and RPC wire types
- **Serde serialization**: All JSON/CBOR encoding for network transport
- **RPC client types**: Chain-specific RPC request/response types
- **Hex encoding**: Binary-to-hex conversions for wire transport
- **Transport-agnostic**: Works with HTTP, WebSocket, and P2P transports

## Architecture Role

`csv-wire` serves as the serialization boundary between:
- Pure algebra types (`csv-algebra`) → Wire format types
- Internal protocol types → External RPC messages
- Binary data → Hex-encoded strings for transport

## Modules

- **canonical**: Wire format for canonical proofs
- **proof**: Proof serialization and deserialization
- **transfer**: Transfer wire format types
- **rpc**: Chain-specific RPC client types (Bitcoin, Ethereum, Solana, Sui, Aptos, Celestia)

## Dependencies

- `csv-algebra`: Pure typestate algebra (单向依赖 - csv-algebra must NOT depend on csv-wire)
- `serde`: Serialization framework
- `hex`: Binary-to-hex encoding

## Usage Example

```rust
use csv_wire::canonical::CanonicalProofWire;
use csv_algebra::proof::CanonicalProof;

// Convert algebra proof to wire format
let algebra_proof = CanonicalProof::new(/* ... */);
let wire_proof: CanonicalProofWire = algebra_proof.into();

// Serialize for transport
let json = serde_json::to_string(&wire_proof)?;
```

## Design Constraints

Per `deny.toml` architecture rules:
- `csv-algebra` MUST NOT depend on `csv-wire` (enforced by lints)
- All serde/transport code lives in this crate
- No chain adapter should implement its own serialization

## License

MIT OR Apache-2.0
