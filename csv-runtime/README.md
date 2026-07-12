# csv-runtime

Runtime orchestration engine for the CSV protocol. Manages transfer coordination, lease management, replay detection, circuit breakers, and crash-safe execution journaling.

## Overview

`csv-runtime` provides the high-level orchestration layer for cross-chain transfers, serving as the single source of truth for transfer execution. It consumes the chain-agnostic protocol, adapter interface, verifier, proof/hash, wire/codec, storage, coordinator, admission, and observability crates. It does not depend on a concrete chain adapter.

## Features

- **persistent** — Persistent storage with RocksDB (enabled by default)
- **postgres** — PostgreSQL-backed replay database via `csv-storage`
- **serde** — Serialization support

## Architecture

`csv-runtime` depends on `csv-protocol` and orchestration support crates. It provides:

- **TransferCoordinator** — Single source of truth for cross-chain transfer execution
- **ExecutionJournal** — Phase-by-phase audit trail for crash-safe recovery
- **EventBus** — Structured events for observability
- **EventStore** — Durable event sourcing storage
- **Policy** — Runtime policies and circuit breakers (finality is NEVER optional)
- **AdapterRegistry** — Chain adapter registration and dispatch
- **AdmissionController** — Pressure boundary and admission control (via csv-admission)

The runtime does not import chain adapters directly. Chain adapters register themselves via the `AdapterRegistry` trait.

## Security-Critical Runtime Guarantees

- Proof verification uses `ProofBundle.signature_scheme` and rejects source-chain scheme mismatches
- Seal registry checks are wired into the canonical verifier context through the adapter registry
- Lock and mint transaction hashes must be exactly 32 bytes after decoding; malformed hashes fail instead of being re-hashed
- Confirmed mints call `confirm_consumed` and persist the completed transfer entry; failed mint paths call `mark_rolled_back`
- Recovery checkpoints store canonical CBOR payloads for transfer state
- PostgreSQL HA/event-store scaffolding is archived; runtime Postgres support is limited to the `csv-storage` replay database re-export.
- Finality is NEVER optional — all runtime modes enforce strict finality
- CLI holds NO protocol authority state (leases, transfers) — all delegated to csv-runtime

## Dependencies

- `csv-adapter-core`: Chain-agnostic adapter interfaces
- `csv-protocol`, `csv-proof`, `csv-verifier`: Protocol and verification types
- `csv-hash`, `csv-codec`, `csv-wire`: Hashing and encoding boundaries
- `csv-admission`: Admission control and pressure boundaries
- `csv-coordinator`: Per-chain execution cells
- `csv-storage`: Storage backends
- `csv-observability`: Runtime events and health reporting
- `tokio`: Async runtime

## License

MIT OR Apache-2.0
