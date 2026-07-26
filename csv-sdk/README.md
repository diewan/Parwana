# csv-sdk

Unified SDK for the CSV (Client-Side Validation) protocol — single entry point for all CSV operations.

## Overview

`csv-sdk` provides a unified, high-level API for Parwana operations, abstracting away the complexity of cross-chain transfers. It delegates to `csv-runtime` for orchestration and chain adapters for chain-specific operations.

## Accountability protocol facade

Applications import accountability objects through `csv_sdk::accountability`,
not through Parwana's internal crate layout. The facade exposes supported
semantic types, strict JSON wire types, and `encode_action_intent`.

`encode_action_intent` calls the canonical serializer owned by
`csv-accountability` and returns a `CanonicalAccountabilityObjectWire`. The SDK
does not maintain authority state or define an alternate serializer.

```rust
use csv_sdk::accountability::{
    ActionIntentWireV1, action_intent_from_json, encode_action_intent,
};

# fn example(wire: ActionIntentWireV1) -> Result<(), String> {
let intent = action_intent_from_json(wire).map_err(|error| format!("{error:?}"))?;
let artifact = encode_action_intent(&intent).map_err(|error| format!("{error:?}"))?;
assert_eq!(artifact.object_version, 1);
# Ok(())
# }
```

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

## Portable V2 consumer facade

Consumers use `csv_sdk::v2` for the supported V2 contract. The facade keeps
inspection, cryptographic verification, and atomic acceptance distinct:

```rust,ignore
use csv_sdk::v2;

let inspected = v2::inspect(&consignment_bytes)?;
// Inspection is structural and does not establish proof validity.

let accepted = v2::accept(
    &consignment_bytes,
    &recipient_context, // exact context, checkpoint, trust and signer inputs
    &proof_provider,
    &accepted_state_store,
).await?;
let assurance = accepted.assurance;
```

`v2::emit` constructs and sends a canonical, closure-carrying consignment using
a real proof provider, authorizer, and atomic emission journal. No V2 API
accepts a caller-supplied proof-validation boolean.

The portable inspection, emission, and acceptance APIs are available on native
and WASM when consumers supply compatible proof-provider and storage
implementations. Filesystem-backed persistence is native-only:
`v2::require_capability(v2::Capability::NativePersistence)` returns
`SDK.V2.UNSUPPORTED_CAPABILITY` on WASM instead of degrading to volatile state.

V1 artifacts remain inspection-only through the legacy inspector. There is
deliberately no V1-to-V2 conversion: obtain a newly authorized V2 consignment
from its issuer.

## Architecture

```
csv-sdk (public facade)
  └── csv-runtime (orchestration + execution journal)
        └── csv-protocol (protocol types & traits)
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
