# csv-runtime

Runtime orchestration engine for the CSV protocol. Manages transfer coordination, lease management, replay detection, circuit breakers, and crash-safe execution journaling.

## Features

- **persistent** — Persistent storage with RocksDB (enabled by default)
- **postgres** — PostgreSQL-backed replay database
- **serde** — Serialization support

## Architecture

`csv-runtime` depends only on `csv-core` and `csv-protocol`. It provides the high-level orchestration layer including:

- **TransferCoordinator** — Single source of truth for cross-chain transfer execution
- **ExecutionJournal** — Phase-by-phase audit trail for crash-safe recovery
- **EventBus** — Structured events for observability
- **EventStore** — Durable event sourcing storage
- **Policy** — Runtime policies and circuit breakers (finality is NEVER optional)
- **Verifier** — All proof verification delegated to csv-verifier::CanonicalVerifier

The runtime does not import chain adapters directly. Chain adapters register themselves via the `AdapterRegistry` trait.

## Security-Critical Runtime Guarantees

- Proof verification uses `ProofBundle.signature_scheme` and rejects source-chain scheme mismatches.
- Seal registry checks are wired into the canonical verifier context through the adapter registry.
- Lock and mint transaction hashes must be exactly 32 bytes after decoding; malformed hashes fail instead of being re-hashed.
- Confirmed mints call `confirm_consumed` and persist the completed transfer entry; failed mint paths call `mark_rolled_back`.
- Recovery checkpoints store canonical CBOR payloads for transfer state.
- PostgreSQL event sourcing is async-only; use `AsyncPostgresEventStore` for PostgreSQL-backed event persistence.

## License

MIT OR Apache-2.0
