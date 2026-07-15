# csv-admission

Admission control and pressure boundaries for Parwana runtime.

## Overview

`csv-admission` provides admission control for runtime work, serving as the runtime's pressure boundary. It rejects excess work before protocol state is mutated, preventing RPC stalls or adversarial traffic from amplifying into replay consumption, proof backlog, or mint starvation.

## Key Features

- **Admission limits**: Configurable limits for concurrent operations
- **Per-chain limits**: Chain-specific capacity limits
- **Runtime-wide limits**: Global capacity limits
- **Pressure snapshots**: Current admission pressure monitoring
- **RAII permits**: Automatic capacity release
- **Zero dependencies**: No chain adapter dependencies

## Architecture Role

`csv-admission` is the admission control layer that:

- Rejects excess work before state mutation
- Prevents RPC stalls under load
- Protects against adversarial traffic amplification
- Ensures fair resource allocation across chains

## Dependencies

None (zero dependencies on chain adapters)

## Admission Limits

- **max_in_flight_transfers**: Maximum concurrent transfers (default: 128)
- **max_in_flight_per_chain**: Maximum concurrent transfers per chain (default: 32)

## Usage Example

```rust
use csv_admission::{AdmissionController, AdmissionLimits};

let limits = AdmissionLimits {
    max_in_flight_transfers: 128,
    max_in_flight_per_chain: 32,
};

let controller = AdmissionController::new(limits);

let permit = controller.acquire_transfer("bitcoin", "ethereum")?;
// Transfer executes here
// Permit is automatically released when dropped
```

## Admission Rejection

The controller rejects transfers when:

- **Transfer limit reached**: Runtime-wide capacity exhausted
- **Chain limit reached**: Chain-specific capacity exhausted

## Pressure Monitoring

```rust
let snapshot = controller.snapshot();
println!("In-flight transfers: {}", snapshot.in_flight_transfers);
println!("Per-chain: {:?}", snapshot.in_flight_by_chain);
```

## Design Principles

- **Zero chain dependencies**: Pure admission logic
- **Early rejection**: Reject before state mutation
- **Fair allocation**: Per-chain limits prevent starvation
- **Automatic cleanup**: RAII permits ensure resource release

## License

MIT OR Apache-2.0
