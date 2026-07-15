# csv-algebra

Pure no_std typestate algebra for Parwana transfer state machine.

## Overview

`csv-algebra` provides a compiler-enforced state machine for cross-chain transfers using Rust's type system. It ensures that invalid state transitions are caught at compile time, not runtime.

## Key Features

- **no_std compatible**: Zero runtime dependencies on std
- **Typestate pattern**: Compile-time enforcement of valid state transitions
- **Pure algebra**: No side effects, no I/O, no network calls
- **Zero-cost abstractions**: All state checks happen at compile time

## State Machine

The transfer state machine enforces the following valid transitions:

```
Locked → ProofBuilding → AwaitingFinality → ProofValidated → Minting → Completed
  ↓         ↓                  ↓                  ↓           ↓
Rollback  Rollback          Rollback          Rollback    Rollback
```

### States

- **Locked**: Source chain lock confirmed, no proof yet
- **ProofBuilding**: Proof construction underway
- **AwaitingFinality**: Proof submitted, finality window pending
- **ProofValidated**: Finality confirmed, verifier accepted proof
- **Minting**: Mint transaction submitted to destination chain
- **Completed**: Terminal state (success)
- **RolledBack**: Terminal state (failure)

## Usage Example

```rust
use csv_algebra::state::{Locked, ProofBuilding};
use csv_algebra::transfer::SealId;

let locked = Locked {
    seal_id: SealId([1u8; 32]),
    source_chain: 1,
    dest_chain: 2,
};

// Valid transition
let proof_building = locked.begin_proof();

// Invalid transition - compile error!
// let _minting = locked.mint([4u8; 32]); // ERROR: no such method
```

## Modules

- **state**: Typestate structs and transition methods
- **transfer**: Transfer ID and seal ID types
- **proof**: Canonical proof types
- **finality**: Finality evidence types
- **replay**: Replay protection types
- **error**: Error types

## Architecture Role

`csv-algebra` is the foundational typestate layer that:

- Provides compile-time guarantees for transfer state transitions
- Ensures protocol invariants are enforced by the type system
- Serves as the pure algebraic foundation for higher-level crates

## Dependencies

None (no_std, alloc only)

## License

MIT OR Apache-2.0
