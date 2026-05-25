# csv-coordinator

Per-chain execution cells with isolated failure domains for CSV Protocol.

## Overview

`csv-coordinator` provides per-chain execution cells with isolated failure domains. Each chain has its own bounded queue, circuit breaker, and memory ceiling to prevent cascading failures.

## Key Features

- **Execution cells**: Isolated execution per chain
- **Bounded queues**: Prevent memory exhaustion
- **Circuit breakers**: Automatic failure isolation
- **Memory ceilings**: Per-chain memory limits
- **Capability negotiation**: Security requirement negotiation
- **Transfer routing**: Route transfers to appropriate cells

## Modules

- **cell**: Chain cell implementation
- **circuit**: Circuit breaker implementation
- **memory**: Memory ceiling enforcement
- **negotiation**: Capability negotiation
- **router**: Transfer routing

## Architecture Role

`csv-coordinator` is the execution layer that:

- Provides isolated execution domains per chain
- Prevents cascading failures across chains
- Enforces resource limits (queue, memory)
- Negotiates security requirements
- Routes transfers to appropriate cells

## Dependencies

- `csv-verifier`: Cryptographic anchor verification
- `csv-protocol`: Finality requirements
- `thiserror`: Error handling
- `tokio`: Async runtime

## Cell Architecture

Each chain cell has:

- **Bounded mpsc queue**: Limits pending operations
- **Circuit breaker**: Opens on repeated failures
- **Memory ceiling**: Enforces memory limits
- **Isolated state**: No shared state with other cells

## Failure Isolation

- **Queue isolation**: Each cell has its own queue
- **Circuit isolation**: Circuit breakers are per-cell
- **Memory isolation**: Memory limits are per-cell
- **No propagation**: Cell degradation doesn't affect siblings

## Usage Example

```rust
use csv_coordinator::{TransferRouter, ChainCell, CellConfig};

let mut router = TransferRouter::new();
router.register_cell(chain_id, anchor);

let transfer = InboundTransfer {
    transfer_id: [0u8; 32],
    source_chain: 1,
    dest_chain: 2,
};

router.route(transfer).await?;
```

## Design Principles

- **Isolation**: Each chain is isolated from others
- **Bounded**: All resources are bounded
- **Resilient**: Circuit breakers prevent cascading failures
- **Negotiated**: Security requirements are negotiated

## License

MIT OR Apache-2.0
