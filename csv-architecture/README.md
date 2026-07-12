# csv-architecture

Architecture guardrails for the CSV Protocol workspace.

## Overview

`csv-architecture` provides compile-time and runtime checks to enforce architectural rules and prevent architectural drift in the CSV Protocol workspace.

## Key Features

- **Dependency graph validation**: Enforces dependency rules
- **Architecture tests**: Compile-time architecture verification
- **Layer enforcement**: Prevents forbidden dependencies
- **Workspace conformance**: Ensures workspace structure compliance

## Architecture Rules

Per `AGENTS.md` and workspace configuration:

- `csv-core` is retired from the workspace and no production source may import it
- `csv-cli` must NOT import chain adapters directly (use csv-runtime)
- `csv-runtime` depends on chain-agnostic protocol/interface/verification/storage/orchestration crates only (no concrete chain adapter dependencies)
- `csv-coordinator` and `csv-adapter-factory` may assemble concrete adapters behind chain feature flags
- every internal path dependency carries a compatible release version and every workspace crate shares the pinned MSRV
- `serde_json` is forbidden in canonical hashing paths (use canonical_cbor)
- `persistent` feature is incompatible with wasm32
- Finality is NEVER optional (all runtime modes enforce strict finality)
- CLI holds NO protocol authority state (delegated to csv-runtime)

## Tests

- **dep_graph_constitution**: Validates dependency graph constitution
- **layer_enforcement**: Ensures proper layering

## Dependencies

- `cargo_metadata`: For dependency graph analysis

## Usage

Architecture tests run automatically as part of the test suite:

```bash
cargo test -p csv-architecture
```

## Design Principles

- **Compiler-enforced**: Rules enforced at compile time when possible
- **Runtime validation**: Fallback runtime checks
- **Zero false positives**: Rules are precise and necessary
- **Clear errors**: Helpful error messages for violations

## License

MIT OR Apache-2.0
